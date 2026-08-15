"use strict";

// Decides whether a tier-3 advisory mechanism-class candidate may be PROMOTED
// to tier-2 (validated, high-trust REUSE). Tier-3 templates (see
// authorization-differential-family.js TEMPLATE_TIER=3 / CLAIM_AUTHORITY=false
// and mechanism-template-ingest.js tier:3 / candidate:true / claim_authority:
// false) are advisory: they RANK attention but re-verify on every reuse. A
// tier-2 template is the opposite — it is trusted enough to be REUSED without
// re-verifying each instance. That makes promotion the single most dangerous
// transition in the corpus: a wrong promotion poisons EVERY future reuse of the
// mechanism class (a false tier-2 forever). So this gate is STRICTER than one
// confirmation.
//
// MINT != CONFIRM, taken one step further. A single executed differential
// (the SYNTH_VERIFIED-style executed row from composition-experiment-harness.js:
// verdict "verified", reason "executed_differential_bound", claim_authority
// true, bound to an executed verified_pass row by bound_path_hash) confirms ONE
// instance. Promoting a CLASS for trusted reuse requires more than one instance,
// because reuse generalizes across instances the gate has never seen. Promotion
// holds ONLY when ALL of:
//
//   (a) K independent EXECUTED differentials on DISTINCT findings. Each must be
//       an executed flip in the SYNTH_VERIFIED shape (claim_authority true,
//       bound to an executed verified_pass row by bound_path_hash) — a DECLARED
//       pass, an unexecuted verdict, or a verdict with no binding hash is
//       refused. The K rows must be DISTINCT (deduped by bound_path_hash /
//       finding id) so the same flip cannot be counted K times. K is
//       configurable; default DEFAULT_K.
//
//   (b) a REFUTED-FORGERY record on file for the class: a known forgery that the
//       verifier CORRECTLY refused. This proves the discriminator is not
//       trivially satisfiable — that the K flips were not all passing a control
//       that anything would pass. Without it, K green flips could all be
//       false-greens of a non-discriminating oracle.
//
//   (c) a human-confirmed discriminating-control attestation: an explicit
//       operator flag that the negative control TRULY discriminates (i.e. the
//       confounder set is, to the operator's knowledge, complete). The
//       refuted-forgery record (b) proves the discriminator catches ONE planted
//       forgery; the operator attestation (c) covers the residual confounder-
//       completeness gap that no finite forgery corpus closes.
//
// Absent ANY of (a)/(b)/(c) the candidate STAYS tier-3 (re-verify each reuse).
//
// This module is PURE and STANDALONE. It does not execute, does not mint, does
// not read or write any ledger, does not register into the corpus, and does not
// feed the live loadMechanismTemplates loader. It is a decision function over
// the executed-ledger-shaped evidence it is GIVEN: it AUDITS that evidence
// against the three conditions and returns a verdict object. Wiring it to the
// live promotion path is deferred. CWE / known-class membership is an
// ANNOTATION carried through for routing, never a drop-gate.

// The source tier a candidate must already be in to be a promotion subject, and
// the tier promotion grants. Promotion is a single 3 -> 2 step; this module
// never mints tier-1 and never crosses more than one tier.
const SOURCE_TIER = 3;
const PROMOTED_TIER = 2;

// Default number of distinct executed differentials required. Reuse generalizes
// across instances, so one confirmation is insufficient; two distinct executed
// flips is the floor.
const DEFAULT_K = 2;

// The executed-row contract a differential must satisfy to COUNT. Mirrors the
// SYNTH_VERIFIED executed verdict minted by
// resolveSynthesizedDifferentialVerdict: a verdict string of `verified`, a
// truthy claim_authority, and a non-empty bound_path_hash tying the verdict to
// an executed verified_pass ledger row. The flip is mechanism-AGNOSTIC: this
// gate never inspects WHAT flipped, only that an executed, bound, authoritative
// flip is on record.
const EXECUTED_VERIFIED_VERDICT = "verified";

// Promotion verdict reasons. `promoted` is the only one that grants tier-2; the
// rest keep the candidate at tier-3 and name the missing condition.
const PROMOTE_GRANTED = "promoted";
const STAY_NOT_TIER3 = "not_a_tier3_candidate";
const STAY_INSUFFICIENT_DISTINCT = "insufficient_distinct_executed_differentials";
const STAY_NO_REFUTED_FORGERY = "no_refuted_forgery_on_record";
const STAY_NO_HUMAN_CONTROL = "no_human_confirmed_discriminating_control";

function isPlainObject(value) {
  return value != null && typeof value === "object" && !Array.isArray(value);
}

function nonEmptyString(value) {
  return typeof value === "string" && value.trim().length > 0;
}

// A candidate is a promotion SUBJECT only if it is currently tier-3 and
// advisory (no claim authority). Both markers must agree — a record claiming
// tier-3 but already carrying claim_authority is malformed and refused, mirroring
// the source modules where tier and claim_authority are set together.
function isTier3Candidate(candidate) {
  if (!isPlainObject(candidate)) return false;
  if (candidate.tier !== SOURCE_TIER) return false;
  // claim_authority must be explicitly false (advisory). A missing field is
  // treated as not-yet-advisory-marked and refused: promotion never infers
  // advisory status, it requires it stated.
  if (candidate.claim_authority !== false) return false;
  return true;
}

// One executed differential COUNTS toward K only if it is an executed,
// authoritative, bound flip. A declared verdict (claim_authority not true), an
// unexecuted verdict, or a verdict missing its bound_path_hash is NOT a counted
// flip — it is exactly the laundering surface the harness refuses. Returns the
// distinctness key (bound_path_hash, else an explicit finding id) when the row
// counts, else null.
function executedFlipKey(row) {
  if (!isPlainObject(row)) return null;
  if (row.verdict !== EXECUTED_VERIFIED_VERDICT) return null;
  // claim_authority must be exactly true: a SYNTH_VERIFIED executed row carries
  // claim_authority:true; every refused/declared verdict carries false.
  if (row.claim_authority !== true) return null;
  // The binding to an executed verified_pass row. Without it the verdict is not
  // tied to a re-executed differential and cannot count.
  if (!nonEmptyString(row.bound_path_hash)) return null;
  // Distinctness key. The bound_path_hash already uniquely identifies the
  // executed path; a finding_id, when present, must AGREE-or-extend but the hash
  // is the canonical key so the same executed flip cannot be re-counted under a
  // different finding label.
  return row.bound_path_hash.trim();
}

// Count DISTINCT executed flips. Dedup is by bound_path_hash (the canonical
// executed-path key). The same flip presented K times collapses to one, so K
// genuinely means K independent findings, never one finding counted K times.
// Returns { distinctKeys, counted, rejected } where rejected lists rows that did
// not qualify as executed flips (advisory, for the caller's audit trail).
function countDistinctExecutedFlips(differentials) {
  const rows = Array.isArray(differentials) ? differentials : [];
  const distinct = new Set();
  let rejected = 0;
  for (const row of rows) {
    const key = executedFlipKey(row);
    if (key === null) {
      rejected += 1;
      continue;
    }
    distinct.add(key);
  }
  return {
    distinct_keys: Object.freeze([...distinct]),
    distinct_count: distinct.size,
    rejected_count: rejected,
  };
}

// A refuted-forgery record proves the class's discriminator is not trivially
// satisfiable: a KNOWN forgery was handed to the verifier and the verifier
// CORRECTLY REFUSED it. The record must name the forgery and state that the
// verdict was a refusal (refuted true), and the refusal must itself be executed
// — a DECLARED refusal proves nothing, exactly as a declared pass proves
// nothing. claim_authority:true marks the refusal as an executed, ledger-bound
// outcome rather than an asserted one.
function hasRefutedForgeryOnRecord(refutedForgery) {
  if (!isPlainObject(refutedForgery)) return false;
  if (refutedForgery.refuted !== true) return false;
  if (!nonEmptyString(refutedForgery.forgery_id)) return false;
  // The refusal must be an executed, bound outcome — the negative control of the
  // whole gate. A non-executed/declared refusal is refused.
  if (refutedForgery.claim_authority !== true) return false;
  if (!nonEmptyString(refutedForgery.bound_path_hash)) return false;
  return true;
}

// The human-confirmed discriminating-control attestation. An explicit operator
// flag stating the negative control truly discriminates (the confounder set is,
// to the operator's knowledge, complete for the class). This is MANDATORY: no
// finite forgery corpus closes the confounder-completeness gap, so a human must
// attest to it. The attestation must name the operator and be explicitly
// confirmed; an implicit or defaulted attestation is refused.
function hasHumanConfirmedControl(humanControl) {
  if (!isPlainObject(humanControl)) return false;
  if (humanControl.confirmed !== true) return false;
  if (!nonEmptyString(humanControl.operator)) return false;
  if (!nonEmptyString(humanControl.attestation)) return false;
  return true;
}

// The promotion predicate. Decides whether `candidate` (a tier-3 advisory
// mechanism template) may be promoted to tier-2 given the executed-ledger-shaped
// evidence in `evidence`:
//   evidence.executed_differentials : array of executed SYNTH_VERIFIED-style
//                                     rows (condition a)
//   evidence.refuted_forgery        : a refuted-forgery record (condition b)
//   evidence.human_control          : an operator attestation (condition c)
// options.k overrides the distinct-flip floor (default DEFAULT_K, min 1).
//
// Returns a frozen verdict:
//   { promote, target_tier, reason, distinct_count, required_k, conditions:{a,b,c} }
// promote is true ONLY when all three conditions hold; otherwise the candidate
// STAYS tier-3 and `reason` names the FIRST unmet condition. This function never
// mutates inputs, never executes, never mints a ledger row — it AUDITS.
function evaluatePromotion(candidate, evidence, options) {
  const required = Math.max(
    1,
    options && Number.isInteger(options.k) && options.k > 0 ? options.k : DEFAULT_K,
  );
  const ev = isPlainObject(evidence) ? evidence : {};
  const flips = countDistinctExecutedFlips(ev.executed_differentials);
  const refuted = hasRefutedForgeryOnRecord(ev.refuted_forgery);
  const human = hasHumanConfirmedControl(ev.human_control);

  const conditions = Object.freeze({
    distinct_executed_flips: flips.distinct_count >= required,
    refuted_forgery: refuted,
    human_control: human,
  });

  // Subject gate first: a non-tier-3 / non-advisory record is not a promotion
  // subject at all. Promotion is a single 3 -> 2 step; nothing else qualifies.
  if (!isTier3Candidate(candidate)) {
    return Object.freeze({
      promote: false,
      target_tier: SOURCE_TIER,
      reason: STAY_NOT_TIER3,
      distinct_count: flips.distinct_count,
      required_k: required,
      conditions,
    });
  }

  // Conditions are AND-ed; the first unmet one names the verdict so the caller
  // learns exactly what is missing. Order is a -> b -> c.
  let reason = PROMOTE_GRANTED;
  let promote = true;
  if (!conditions.distinct_executed_flips) {
    promote = false;
    reason = STAY_INSUFFICIENT_DISTINCT;
  } else if (!conditions.refuted_forgery) {
    promote = false;
    reason = STAY_NO_REFUTED_FORGERY;
  } else if (!conditions.human_control) {
    promote = false;
    reason = STAY_NO_HUMAN_CONTROL;
  }

  return Object.freeze({
    promote,
    // Tier-2 ONLY when promoted; otherwise the candidate stays tier-3.
    target_tier: promote ? PROMOTED_TIER : SOURCE_TIER,
    reason,
    distinct_count: flips.distinct_count,
    required_k: required,
    distinct_keys: flips.distinct_keys,
    conditions,
  });
}

module.exports = {
  SOURCE_TIER,
  PROMOTED_TIER,
  DEFAULT_K,
  EXECUTED_VERIFIED_VERDICT,
  PROMOTE_GRANTED,
  STAY_NOT_TIER3,
  STAY_INSUFFICIENT_DISTINCT,
  STAY_NO_REFUTED_FORGERY,
  STAY_NO_HUMAN_CONTROL,
  isTier3Candidate,
  executedFlipKey,
  countDistinctExecutedFlips,
  hasRefutedForgeryOnRecord,
  hasHumanConfirmedControl,
  evaluatePromotion,
};
