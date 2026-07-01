"use strict";

// Lifecycle gate engine. Cycle G.2 of the frontier-topology realization
// hypergraph establishes the bob_advance_session lifecycle machine and
// reserves this module as the place where future cycles (F.3, C.3, C.7)
// hang real prerequisite checks on per-transition gate hooks.
//
// The gates hang real prerequisite checks on per-transition hooks. SETUP ->
// OPEN_FRONTIER requires at least one routed seed surface (seed_surfaces_present);
// OPEN_FRONTIER -> CLAIM_FREEZE drains chain work, coverage cells, recon
// producers, and partial surfaces; the VERIFY/GRADE gates enforce verification
// and evidence completeness. A transition with no registered gate returns an
// empty blocker list. The hook architecture stays open so later checks extend
// it without rewriting the surface.
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

// I6 (CR-4): lifecycle reopenability. The CLAIM_FREEZE/VERIFY/GRADE/REPORT ->
// OPEN_FRONTIER back-edges are load-bearing operator re-entry, NOT redundancy.
// Registry: mcp/lib/invariant-registry.js REGISTRY["I6"]. Removing a back-edge
// is a breaking change; update the registry entry in the same commit.
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
  "SETUP->OPEN_FRONTIER": gateSetupToOpenFrontier,
  "VERIFY->GRADE": gateVerifyToGrade,
  "GRADE->REPORT": gateGradeToReport,
  "OPEN_FRONTIER->CLAIM_FREEZE": gateOpenFrontierToClaimFreeze,
  "CLAIM_FREEZE->VERIFY": gateClaimFreezeToVerify,
  // I6 reopenability back-edges stay in ALLOWED_TRANSITIONS, but a routine
  // requeue re-entry from VERIFY must not silently bounce an IN-PROGRESS
  // verification snapshot. A VERIFY -> OPEN_FRONTIER move while a v2 attempt is
  // live (the a7/distributor-v2 bounce) re-enters VERIFY later and triggers
  // archiveCurrentV2Attempt (mcp/lib/verification.js), forcing a full re-freeze
  // + re-verification. The gate refuses unless override:"operator_force" — the
  // deliberate operator abandon-and-reopen path recorded as
  // governance.lifecycle.override. GRADE -> OPEN_FRONTIER is intentionally NOT
  // gated: reaching GRADE means verification already COMPLETED (gateVerifyToGrade
  // required completeness), so the canonical grader-HOLD re-mine archives a
  // finished attempt and re-freezes fresh — that is the intended flow, not a
  // bounce. REPORT -> OPEN_FRONTIER (post-report re-mine) likewise stays open.
  "VERIFY->OPEN_FRONTIER": gateVerificationReopen,
});

function compactError(error) {
  return error && error.message ? error.message : String(error);
}

// Mirrors session-state.js isSensitiveMaterialError (the two messages
// validateNoSensitiveMaterial raises). Replicated locally to avoid a require
// cycle (session-state.js requires this module). readCandidateClaims re-runs the
// sensitive-material validator over every persisted claim; when one carries
// legitimately secret-shaped evidence without a persisted bypass, the read throws.
// That is the VERIFY snapshot bootstrap's concern (it raises the specific
// claim_evidence_secret_blocked block and honors operator_force) — the
// CLAIM_FREEZE->VERIFY gate must DEFER it, not preempt it with its own blocker.
function isSensitiveMaterialReadError(error) {
  const message = error && typeof error.message === "string" ? error.message : "";
  return /appears to contain secrets, auth headers, cookies, or tokens/.test(message)
    || /is too large; do not persist raw large response bodies/.test(message);
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
  // Cycle C / F3: verdict-level sandbox-isolation gate. When a reportable medium+
  // finding draws on one of the four keyed verdict ledgers (offensive / invariant
  // / repro / freeze) AND the LIVE re-probe cannot prove the signer key is
  // isolated (or a legacy/v1-HMAC row backs a NEW claim), enforce mode pushes a
  // STATE_CONFLICT blocker; degrade mode lets the transition through but stamps a
  // loud downgrade note onto the blocker-free path (the report door downgrades
  // those sections to advisory). A clean / advisory-only / pure-OSINT session is
  // unaffected (the gate is inert — RANK != BOUND). The probe is verdict-LEVEL
  // (one syscall here), never on the per-row read path (CONSTRAINT 1).
  for (const entry of sandboxIsolationBlockersForReportableVerdictClaims(context.target_domain)) {
    blockers.push(entry);
  }
  return blockers;
}

// Verdict-level sandbox blocker producer for gateVerifyToGrade. Returns [] when
// the gate is inert OR when degrade mode lets the transition proceed (the loud
// downgrade is surfaced at the report door, not as a transition blocker). Under
// enforce with a non-isolated signer (or a legacy/v1-HMAC backing row), returns a
// single STATE_CONFLICT blocker so bob_advance_session refuses VERIFY -> GRADE
// with a legible reason. Any internal failure fails CLOSED with a blocker rather
// than silently allowing the transition.
function sandboxIsolationBlockersForReportableVerdictClaims(targetDomain) {
  let decision;
  try {
    decision = require("./sandbox-isolation-gate.js").evaluateVerdictSandboxGate(targetDomain);
  } catch (error) {
    return [{
      code: "sandbox_isolation_unattested",
      blocked_by: "sandbox_isolation_unattested",
      message:
        "VERIFY -> GRADE blocked: sandbox-isolation gate evaluation failed (failing closed): "
        + compactError(error),
      error: compactError(error),
      remediation: require("./sandbox-isolation-gate.js").SANDBOX_REMEDIATION,
    }];
  }
  if (!decision.applies || decision.decision === "allow") return [];
  if (decision.decision === "downgrade") {
    // degrade mode: do NOT block the transition. Emit the loud warning here so a
    // headless harness still surfaces it; the report door turns the affected
    // sections advisory. The transition proceeds (CONSTRAINT 7: in-flight
    // sessions are never hard-crashed under degrade).
    try {
      require("./sandbox-isolation-gate.js").emitSandboxDowngradeWarning(decision, "VERIFY -> GRADE:");
    } catch {
      // warning emission is best-effort; never block on it.
    }
    return [];
  }
  // enforce + block.
  return [{
    code: "sandbox_isolation_unattested",
    blocked_by: "sandbox_isolation_unattested",
    reason: decision.reason,
    reportable_finding_ids: decision.reportable_finding_ids,
    message:
      "VERIFY -> GRADE blocked: "
      + `${decision.reportable_finding_ids.length} reportable medium+ finding(s) draw on a keyed verdict `
      + `ledger but the signing key is not isolated (mode=enforce, reason=${decision.reason}); a same-uid `
      + "agent could forge the backing MAC",
    remediation: require("./sandbox-isolation-gate.js").SANDBOX_REMEDIATION,
  }];
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

function gateClaimFreezeToVerify(context) {
  const blockers = [];

  // (1) Read the CANDIDATE claims — the authoritative set at THIS transition. The claim-freeze.json
  // SNAPSHOT does not exist yet here: bob_advance_session evaluates this gate (session-state.js:502)
  // BEFORE the durable write, and the freeze snapshot is built lazily by the VERIFY bootstrap
  // (prepareVerificationEntry -> buildClaimFreeze, session-state.js:590) only AFTER this gate passes.
  // Reading readCurrentClaimFreeze here would therefore see null and no-op (the gate would never
  // fire in production). readCandidateClaims (claims.jsonl) is exactly the set buildClaimFreeze will
  // snapshot verbatim, and it exists now — recorded during the hunt before CLAIM_FREEZE. It also
  // re-normalizes each record and fail-closes on a malformed line (readJsonlStrict), so a tampered
  // claims.jsonl surfaces as a read error -> blocker below.
  let claims;
  try {
    claims = require("./claims.js").readCandidateClaims(context.target_domain);
  } catch (error) {
    // A persisted claim's secret-shaped evidence trips the sensitive-material re-scan inside
    // readCandidateClaims. That is the VERIFY snapshot bootstrap's job (it raises the specific
    // claim_evidence_secret_blocked block and honors operator_force); this gate defers rather than
    // preempting it with a generic blocker.
    if (isSensitiveMaterialReadError(error)) return blockers;
    blockers.push({
      code: "candidate_claims_unreadable",
      blocked_by: "candidate_claims_unreadable",
      message: `CLAIM_FREEZE -> VERIFY blocked: could not read the candidate claims: ${compactError(error)}`,
      error: compactError(error),
      remediation:
        "repair claims.jsonl (it failed the strict read) before advancing to VERIFY",
    });
    return blockers;
  }
  if (!Array.isArray(claims) || claims.length === 0) return blockers;

  // (2) NO-BRICK EARLY EXIT. Select every claim that the exploit-proof contract has anything to say
  // about: it either asserts exploited_safely OR carries an exploit_run evidence_ref. A normal
  // session has zero such claims and returns [] here WITHOUT reading the offensive ledger or the
  // signing key, so a session with NO signing key on disk is never bricked. FAIL-CLOSED
  // (CodeRabbit/Codex): both tamper shapes are caught — (a) an exploited_safely claim lacking an
  // exploit_run ref, and (b) a claim still carrying an exploit_run ref after its outcome was
  // changed/removed (the VERIFY severity-rise guard consumes exploit_run refs regardless of
  // outcome) — because both flow into assertExploitedClaimHasProof below, which throws
  // (exploit_proof_missing_exploit_run_evidence / exploit_run_ref_without_exploited_outcome) BEFORE
  // any ledger/key read. No-brick is unaffected: a normal claim matches neither arm of the filter.
  const claimsRequiringProof = claims.filter((claim) => (
    claim
    && typeof claim === "object"
    && (
      (claim.exploit_outcome && claim.exploit_outcome.outcome === "exploited_safely")
      || (Array.isArray(claim.evidence_refs)
        && claim.evidence_refs.some((ref) => ref && ref.kind === "exploit_run"))
    )
  ));
  if (claimsRequiringProof.length === 0) return blockers;

  // (3) Re-confirm each proof-bearing claim still has a fresh, matching, signed offensive row
  // backing every cited exploit_run ref. Reuse the record-time contract verbatim. The assert reads
  // the offensive ledger and reads the signing key ONLY when runRows.length > 0, so the
  // conditional-key-read no-brick rule holds via reuse. Pass the FULL candidate-claim set as
  // existingClaims (Codex) so the assert's run_id-single-use check catches a tampered claims.jsonl
  // that duplicates one signed exploit_run across multiple findings; the assert self-skips the same
  // claim_id, so a legitimately unique frozen set never false-blocks (record-time single-use
  // already guarantees uniqueness on the normal path).
  const { assertExploitedClaimHasProof } = require("./claims.js");
  for (const claim of claimsRequiringProof) {
    try {
      assertExploitedClaimHasProof(claim, { existingClaims: claims });
    } catch (error) {
      // Gate RETURNS blockers; the assert THROWS. Convert any throw into a structured blocker.
      const underlying = (error && error.details && typeof error.details.code === "string")
        ? error.details.code
        : null;
      blockers.push({
        code: "exploited_claim_proof_unbacked_at_freeze",
        blocked_by: "exploited_claim_proof_unbacked_at_freeze",
        claim_id: typeof claim.claim_id === "string" ? claim.claim_id : null,
        underlying_code: underlying,
        message:
          `CLAIM_FREEZE -> VERIFY blocked: claim`
          + ` ${typeof claim.claim_id === "string" ? claim.claim_id : "(unknown)"}`
          + ` cites exploit-proof that no longer holds: ${compactError(error)}`,
        error: compactError(error),
        remediation:
          "re-run the offensive confirmer/producer for this finding so a fresh MAC-signed"
          + " offensive-runs.jsonl row backs every cited exploit_run ref, then re-record/re-freeze before VERIFY",
      });
    }
  }
  return blockers;
}

// SETUP -> OPEN_FRONTIER seed gate. A frontier with zero routed seed surfaces
// has nothing to schedule, so SETUP is not complete. Consumes the
// seed_surfaces_present precondition (mcp/lib/scheduler-preconditions.js) — the
// single source of truth for routed-seed counting; the gate never re-implements
// route counting, keeping the closed-enum precondition authoritative and the
// @precondition coherence check satisfied. Producer-agnostic: a seed surface
// from ANY producer (web recon, repo inventory, or the contract-seeding funnel)
// satisfies it. A reported_gap (a transient/setup error — e.g. a fresh session
// with no surface input materialized yet) PASSES: a setup error must never read
// as "no surfaces exist", so only a bare satisfied:false (a successful route
// build that genuinely yields zero routes) pushes a blocker. The gate runs
// inside advanceSession's withSessionLock and the precondition's forced
// materializeFrontier(write:true) re-enters the same reentrant session lock, so
// the in-lock call cannot deadlock. Fails closed: a precondition throw blocks.
function gateSetupToOpenFrontier(context) {
  const blockers = [];
  let evaluation;
  try {
    evaluation = require("./scheduler-preconditions.js").evaluateSchedulerPrecondition(
      "seed_surfaces_present",
      { target_domain: context.target_domain },
    );
  } catch (error) {
    blockers.push({
      code: "scheduler_precondition_error",
      blocked_by: "scheduler_precondition_error",
      message: `SETUP -> OPEN_FRONTIER precondition evaluation failed: ${compactError(error)}`,
      error: compactError(error),
    });
    return blockers;
  }
  // PASS on a genuine routed seed surface (satisfied) OR a reported gap (a
  // transient/setup error mapped non-terminal by the precondition).
  if (evaluation.satisfied === true || evaluation.reported_gap === true) {
    return blockers;
  }
  // BLOCK only on a bare satisfied:false — route building succeeded and the
  // frontier genuinely carries zero routed seed surfaces.
  blockers.push({
    code: "seed_surfaces_absent",
    blocked_by: "seed_surfaces_absent",
    seed_surface_count: Number.isInteger(evaluation.seed_surface_count) ? evaluation.seed_surface_count : 0,
    message:
      "SETUP -> OPEN_FRONTIER blocked: zero routed seed surfaces - the frontier has nothing to schedule",
    remediation:
      "seed the frontier from a root producer before advancing: run seed mapping / "
      + "bob_materialize_producer_floor for a web or repo target, OR initialize the contracts axis via "
      + "bob_init_contract_session (which seeds one smart_contract surface per bound contract), then retry the transition",
  });
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

  // Recorded chain work must yield a terminal structured chain attempt before
  // CLAIM_FREEZE. Evaluated before the partial-surface gate and accumulated
  // into the same blockers[] so a drained-but-unchained frontier still refuses;
  // every return path below carries any chain-work blocker already pushed here.
  let chainEvaluation;
  try {
    chainEvaluation = require("./scheduler-preconditions.js").evaluateSchedulerPrecondition(
      "chain_work_terminal",
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
  if (!chainEvaluation.satisfied) {
    blockers.push({
      code: "chain_work_terminal_required",
      blocked_by: "chain_work_terminal_required",
      findings: chainEvaluation.findings_total,
      handoff_chain_notes: chainEvaluation.chain_notes_count,
      chain_attempts_terminal: chainEvaluation.terminal_total,
      message:
        "OPEN_FRONTIER -> CLAIM_FREEZE blocked: chain work is recorded "
        + `(${chainEvaluation.findings_total} finding(s), ${chainEvaluation.chain_notes_count} handoff chain-note(s)) `
        + "but no terminal structured chain attempt exists",
      remediation:
        "record terminal CHAIN-phase outcomes via bob_write_chain_attempt "
        + "(confirmed / denied / blocked / inconclusive / not_applicable) for the recorded chain work, "
        + "then retry the transition",
    });
  }

  // Coverage-cell closure teeth: a materialized cell floor must reach closure
  // (every reachable cell covered by a verified probe) before CLAIM_FREEZE.
  // Self-activating — vacuously satisfied when no cell floor was materialized,
  // so surface-only runs are unaffected. Accumulated into blockers[] like the
  // chain-work gate above.
  let cellClosure;
  try {
    cellClosure = require("./scheduler-preconditions.js").evaluateSchedulerPrecondition(
      "uncovered_reachable_cells",
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
  if (!cellClosure.satisfied) {
    blockers.push({
      code: "uncovered_reachable_cells",
      blocked_by: "uncovered_reachable_cells",
      uncovered_count: cellClosure.uncovered_count,
      uncovered_surface_ids: cellClosure.uncovered_surface_ids || [],
      message:
        "OPEN_FRONTIER -> CLAIM_FREEZE blocked: "
        + `${cellClosure.uncovered_count} reachable coverage cell(s) remain uncovered`,
      remediation:
        "dispatch the coverage-cell floor to closure (bob_materialize_cell_floor "
        + "then the bob_schedule_graph_nodes loop) so every reachable cell is "
        + "covered by a verified probe, then retry the transition",
    });
  }

  // Recon-producer floor teeth: a materialized producer floor must reach its
  // fixpoint (no READY non-advisory producer) before CLAIM_FREEZE. Self-
  // activating — vacuously satisfied when no producer node was materialized, so
  // recon-angle-only / legacy / surface-only runs are unaffected. RANK != BOUND:
  // reported producer_gaps[] do not block; only a ready producer does.
  // Accumulated into blockers[] like the chain-work / cell-closure gates above.
  let seedProducers;
  try {
    seedProducers = require("./scheduler-preconditions.js").evaluateSchedulerPrecondition(
      "seed_producers_drained",
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
  if (!seedProducers.satisfied) {
    const readyProducerIds = Array.isArray(seedProducers.ready_producer_ids)
      ? seedProducers.ready_producer_ids
      : [];
    blockers.push({
      code: "seed_producers_undrained",
      blocked_by: "seed_producers_undrained",
      ready_count: seedProducers.ready_count,
      ready_producer_ids: readyProducerIds,
      message:
        "OPEN_FRONTIER -> CLAIM_FREEZE blocked: "
        + `${seedProducers.ready_count} recon producer(s) remain ready and undrained`
        + (readyProducerIds.length > 0 ? ` (${readyProducerIds.join(", ")})` : ""),
      remediation:
        "dispatch the recon-producer floor to fixpoint via bob_materialize_producer_floor "
        + "then the bob_schedule_seed_producers loop, then retry the transition",
    });
  }

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

// I6-compatible reopen guard. The VERIFY/GRADE -> OPEN_FRONTIER back-edges
// remain ALLOWED (operator re-entry is load-bearing), but when a live v2
// verification attempt exists, re-entering OPEN_FRONTIER and then re-entering
// VERIFY archives the in-flight attempt and re-freezes from scratch. A
// requeued surface must not bounce that snapshot as a side effect of routine
// frontier re-entry. The operator can still do it deliberately via
// override:"operator_force" (advanceSession records a
// governance.lifecycle.override event with this blocker list).
function gateVerificationReopen(context) {
  const blockers = [];
  let state;
  try {
    ({ state } = readSessionStateStrict(context.target_domain));
  } catch {
    // No readable state means no in-flight attempt to protect; allow.
    return blockers;
  }
  if (!state) return blockers;
  let attemptId = typeof state.verification_attempt_id === "string" && state.verification_attempt_id.length > 0
    ? state.verification_attempt_id
    : null;
  // state.json sometimes loses verification_attempt_id while the snapshot/round
  // files still hold an in-flight v2 attempt (verification.js). Falling through
  // there would let the exact a7/distributor-v2 bounce recur silently, so when
  // the state field is absent, recover the attempt from the on-disk v2 files.
  if (!attemptId) {
    try {
      const verification = require("./verification.js");
      if (verification.hasCurrentV2Files(context.target_domain)) {
        attemptId = verification.inferOrphanedAttemptId(context.target_domain);
      }
    } catch {
      // verification module/files unavailable; nothing to protect.
    }
  }
  if (!attemptId) return blockers;
  blockers.push({
    code: "verification_attempt_in_flight",
    blocked_by: "verification_attempt_in_flight",
    verification_attempt_id: attemptId,
    verification_snapshot_hash:
      typeof state.verification_snapshot_hash === "string"
        ? state.verification_snapshot_hash
        : null,
    message:
      `${context.from_state} -> OPEN_FRONTIER blocked: a verification attempt `
      + `(${attemptId}) is in flight; re-entering the open frontier would force `
      + "a re-freeze and re-verification of the frozen claim batch when VERIFY is "
      + "re-entered",
    remediation:
      "finish the current verification (advance VERIFY -> GRADE), or, if you "
      + "deliberately intend to discard the in-flight verification snapshot and "
      + "re-open the frontier (e.g. to requeue a surface), rerun "
      + "bob_advance_session with override=\"operator_force\"",
  });
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
  // Exported so the verdict-level sandbox blocker is testable in isolation
  // (the upstream verification/reachability checks short-circuit gateVerifyToGrade
  // before this block, so a focused test exercises the production producer directly).
  sandboxIsolationBlockersForReportableVerdictClaims,
};
