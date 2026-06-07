"use strict";

// Lifecycle gate engine. Cycle G.2 of the frontier-topology realization
// hypergraph establishes the bob_advance_session lifecycle machine and
// reserves this module as the place where future cycles (F.3, C.3, C.7)
// hang real prerequisite checks on per-transition gate hooks.
//
// Today the gates are intentionally minimal: every transition listed in
// ALLOWED_TRANSITIONS returns an empty blocker list. The hook architecture
// must exist so later cycles can extend it without rewriting the surface.
//
// Decision D3 from the hypergraph is honored verbatim: OPEN_FRONTIER ⇄
// CLAIM_FREEZE is bidirectional, and REPORT → OPEN_FRONTIER is allowed so
// the operator can re-enter the open frontier from any later state.

const {
  LIFECYCLE_STATE_VALUES,
} = require("./governance-contracts.js");
const {
  readSessionStateStrict,
} = require("./session-state-store.js");
const {
  missingReachabilityStampsForReportableFindings,
} = require("./reachability-ceiling.js");

const ALLOWED_TRANSITIONS = Object.freeze({
  SETUP: Object.freeze(["OPEN_FRONTIER"]),
  OPEN_FRONTIER: Object.freeze(["CLAIM_FREEZE"]),
  CLAIM_FREEZE: Object.freeze(["VERIFY", "OPEN_FRONTIER"]),
  VERIFY: Object.freeze(["GRADE", "OPEN_FRONTIER"]),
  GRADE: Object.freeze(["REPORT", "OPEN_FRONTIER"]),
  REPORT: Object.freeze(["OPEN_FRONTIER"]),
});

// Per-transition gate functions. Each is keyed by `${from}->${to}` and
// receives a context object with the target_domain, the current and target
// lifecycle states, and the persisted session nucleus. The gate returns an
// array of structured blocker entries; an empty array means "transition is
// permitted by this gate".
//
// Cycle G.2 ships the gate architecture; Cycle D.1 retires the legacy
// phase-gates module and migrates the VERIFY -> GRADE freshness check here.
// The gate consults requireVerificationCompleteForGrade and surfaces blocked
// entries that mirror the legacy "VERIFY -> GRADE blocked" message.
const TRANSITION_GATES = Object.freeze({
  "VERIFY->GRADE": gateVerifyToGrade,
  "GRADE->REPORT": gateGradeToReport,
  "OPEN_FRONTIER->CLAIM_FREEZE": gateOpenFrontierToClaimFreeze,
});

function compactError(error) {
  return error && error.message ? error.message : String(error);
}

function gateVerifyToGrade(context) {
  const blockers = [];
  try {
    require("./verification.js").requireVerificationCompleteForGrade(context.target_domain);
  } catch (error) {
    const message = compactError(error);
    const evidenceLike = /Evidence packs|evidence packs|Missing evidence packs|final reportable/i.test(message);
    const prefix = evidenceLike
      ? "evidence packs are missing or invalid for final reportable findings"
      : "verification v2 chain is incomplete or stale";
    blockers.push({
      code: evidenceLike ? "evidence_packs_invalid" : "verification_chain_incomplete",
      blocked_by: "verification_stale",
      message: `VERIFY -> GRADE blocked: ${prefix}: ${message}`,
      error: message,
    });
  }
  if (blockers.length > 0) return blockers;
  try {
    const { state } = readSessionStateStrict(context.target_domain);
    if (!state || state.target_repo == null) return blockers;
  } catch (error) {
    const message = compactError(error);
    blockers.push({
      code: "reachability_stamp_missing",
      blocked_by: "reachability_absent",
      message: `VERIFY -> GRADE blocked: session state unavailable for reachability checks: ${message}`,
      error: message,
      remediation:
        "restore valid session state and rerun bob_repo_inventory so reachability stamps can be resolved",
    });
    return blockers;
  }
  try {
    const reachability = missingReachabilityStampsForReportableFindings(context.target_domain);
    if (reachability.missing.length === 0) return blockers;
    const inventoryAbsent = reachability.inventory_absent === true;
    blockers.push({
      code: "reachability_stamp_missing",
      blocked_by: "reachability_absent",
      missing_finding_ids: reachability.missing,
      message: inventoryAbsent
        ? `VERIFY -> GRADE blocked: repo session has no reachability inventory; ${reachability.missing.length}`
          + " final reportable repo-module finding(s) would be graded without an I9 ceiling"
        : `VERIFY -> GRADE blocked: ${reachability.missing.length} final reportable finding(s)`
          + " lack an I9 reachability stamp",
      remediation: inventoryAbsent
        ? "run bob_repo_inventory so repo-inventory.json carries surface_ceilings before grading"
        : "rerun bob_repo_inventory so repo-inventory.json carries surface_ceilings for the frozen claim surfaces",
    });
  } catch (error) {
    blockers.push({
      code: "reachability_stamp_missing",
      blocked_by: "reachability_absent",
      message: `VERIFY -> GRADE blocked: reachability stamp check failed: ${compactError(error)}`,
      error: compactError(error),
      remediation:
        "rerun bob_repo_inventory and verify candidate claims cite repo surface_ids emitted by the inventory",
    });
  }
  return blockers;
}

function gateGradeToReport(context) {
  // GRADE -> REPORT keeps the legacy invariant that final reportable
  // findings have valid evidence packs at advance time. The new finalize-
  // report tool re-verifies the four-hash binding (C.7); this gate keeps
  // the legacy refusal so callers receive a structured blocker before they
  // start writing report.md.
  const blockers = [];
  try {
    require("./verification.js").requireVerificationCompleteForGrade(context.target_domain);
  } catch (error) {
    const message = compactError(error);
    blockers.push({
      code: "evidence_packs_invalid",
      blocked_by: "evidence_incomplete",
      message: `GRADE -> REPORT blocked: ${message}`,
      error: message,
    });
  }
  return blockers;
}

// Y.10 (Y-P12) — partial-surface runtime gate. Refuses
// OPEN_FRONTIER -> CLAIM_FREEZE while the latest merged wave-handoff has
// any surface in `surface_status: "partial"` AND the operator has not
// extended bob_set_queue_policy({partial_surface_advance_acknowledgements: [...]}).
// Reads partial_surface_ids via mcp/lib/scheduler-preconditions.js
// (partial_surfaces_drained), which consults the latest merge snapshot
// persisted by mergeWaveHandoffs to <sessionDir>/wave-handoffs/
// wave-<N>-merge-snapshot.json.
function gateOpenFrontierToClaimFreeze(context) {
  const blockers = [];
  let evaluation;
  try {
    evaluation = require("./scheduler-preconditions.js").evaluateSchedulerPrecondition(
      "partial_surfaces_drained",
      { target_domain: context.target_domain },
    );
  } catch (error) {
    blockers.push({
      code: "scheduler_precondition_error",
      blocked_by: "scheduler_precondition_error",
      message: `OPEN_FRONTIER -> CLAIM_FREEZE precondition evaluation failed: ${compactError(error)}`,
      error: compactError(error),
    });
    return blockers;
  }
  if (evaluation.satisfied) return blockers;

  const partialSurfaceIds = Array.isArray(evaluation.blocked_surface_ids)
    ? evaluation.blocked_surface_ids.slice()
    : [];

  // Operator may pre-acknowledge specific partial surfaces via queue-policy.
  // We intersect the acknowledged set with the partial set and report only
  // the leftover (unacknowledged) surfaces as blockers.
  //
  // Each acknowledgement carries an `attestation_token`. When the operator
  // has provisioned `~/.bob/session-cap` (mode 0600) the token MUST equal
  // that nonce; when the nonce file is absent we accept any non-empty token
  // (the audit trail records `cap_status: "uninitialized"`). A mismatched
  // token causes the acknowledgement to be ignored, so the surface remains
  // blocked — Y-D12/D6 require that the gate refuse to advance on a forged
  // token rather than treat any non-empty string as authority.
  let acknowledgedSurfaceIds = [];
  let mismatchedAcks = [];
  try {
    const { loadQueuePolicy } = require("./queue-policy.js");
    const { verifyAttestationToken } = require("./session-cap.js");
    const policy = loadQueuePolicy(context.target_domain);
    const acks = Array.isArray(policy.partial_surface_advance_acknowledgements)
      ? policy.partial_surface_advance_acknowledgements
      : [];
    for (const entry of acks) {
      if (!entry || typeof entry.surface_id !== "string") continue;
      const verification = verifyAttestationToken(entry.attestation_token);
      if (verification.ok) {
        acknowledgedSurfaceIds.push(entry.surface_id);
      } else {
        mismatchedAcks.push({
          surface_id: entry.surface_id,
          cap_status: verification.cap_status,
        });
      }
    }
  } catch {
    acknowledgedSurfaceIds = [];
    mismatchedAcks = [];
  }
  const acknowledgedSet = new Set(acknowledgedSurfaceIds);
  const remaining = partialSurfaceIds.filter((id) => !acknowledgedSet.has(id));

  if (remaining.length === 0) return blockers;

  const blocker = {
    code: "partial_surfaces_remaining",
    blocked_by: "partial_surfaces_remaining",
    surfaces: remaining,
    message:
      `OPEN_FRONTIER -> CLAIM_FREEZE blocked: ${remaining.length} partial surface(s) remain`
      + ` in the latest merged wave (${remaining.join(", ")})`,
    remediation:
      "call bob_set_queue_policy({partial_surface_advance_acknowledgements: [...]}) "
      + "with operator_attested token (matching ~/.bob/session-cap) "
      + "or schedule wave-N+1 via bob_start_next_wave",
  };
  if (mismatchedAcks.length > 0) {
    blocker.mismatched_acknowledgements = mismatchedAcks;
  }
  blockers.push(blocker);
  return blockers;
}

function transitionKey(fromState, toState) {
  return `${fromState}->${toState}`;
}

function isTransitionAllowed(fromState, toState) {
  const targets = ALLOWED_TRANSITIONS[fromState];
  return Array.isArray(targets) && targets.includes(toState);
}

function allowedTargetsFor(fromState) {
  const targets = ALLOWED_TRANSITIONS[fromState];
  return Array.isArray(targets) ? targets.slice() : [];
}

function buildNoTransitionBlocker(fromState, toState) {
  return {
    blocked_by: "no_transition",
    code: "no_transition",
    from: fromState,
    to: toState,
    allowed: allowedTargetsFor(fromState),
    message: `Transition ${fromState} -> ${toState} is not in allowedTransitions`,
  };
}

function runTransitionGate(context) {
  const fromState = context.from_state;
  const toState = context.to_state;
  const gate = TRANSITION_GATES[transitionKey(fromState, toState)];
  if (typeof gate !== "function") return [];
  const result = gate(context);
  if (!Array.isArray(result)) return [];
  return result.filter((entry) => entry && typeof entry === "object");
}

function evaluateLifecycleTransition(context = {}) {
  const fromState = context.from_state;
  const toState = context.to_state;
  if (!LIFECYCLE_STATE_VALUES.includes(fromState)) {
    throw new Error(`unknown from_state: ${fromState}`);
  }
  if (!LIFECYCLE_STATE_VALUES.includes(toState)) {
    throw new Error(`unknown to_state: ${toState}`);
  }
  const blockers = [];
  if (!isTransitionAllowed(fromState, toState)) {
    blockers.push(buildNoTransitionBlocker(fromState, toState));
    // No-transition is a structural rejection; per-transition gates are not
    // consulted for a transition the engine does not recognize.
    return { from_state: fromState, to_state: toState, blockers };
  }
  const gateBlockers = runTransitionGate(context);
  for (const entry of gateBlockers) {
    blockers.push(entry);
  }
  return { from_state: fromState, to_state: toState, blockers };
}

module.exports = {
  ALLOWED_TRANSITIONS,
  TRANSITION_GATES,
  allowedTargetsFor,
  buildNoTransitionBlocker,
  evaluateLifecycleTransition,
  isTransitionAllowed,
  transitionKey,
};
