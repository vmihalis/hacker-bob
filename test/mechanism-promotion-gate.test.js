"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const {
  SOURCE_TIER,
  PROMOTED_TIER,
  DEFAULT_K,
  PROMOTE_GRANTED,
  STAY_NOT_TIER3,
  STAY_INSUFFICIENT_DISTINCT,
  STAY_NO_REFUTED_FORGERY,
  STAY_NO_HUMAN_CONTROL,
  STAY_LEARNED_MEASUREMENT_ADVISORY_ONLY,
  HOLD_LEARNED_MEASUREMENT_ADVISORY_ONLY,
  HOLD_LEARNED_MEASUREMENT_NOT_ADMISSIBLE,
  isTier3Candidate,
  isLearnedMeasurementCandidate,
  executedFlipKey,
  countDistinctExecutedFlips,
  hasRefutedForgeryOnRecord,
  hasHumanConfirmedControl,
  evaluatePromotion,
  evaluateLearnedMeasurementClosure,
} = require("../mcp/core/mechanism-promotion-gate.js");

// A tier-3 advisory candidate, the only kind that is a promotion subject. Shaped
// like the markers in authorization-differential-family.js (tier 3,
// claim_authority false) / mechanism-template-ingest.js (tier 3, candidate
// true, claim_authority false).
function tier3Candidate(overrides) {
  return Object.assign(
    {
      id: "cand-cwe-639",
      mechanism_id: "CWE-639",
      tier: 3,
      candidate: true,
      claim_authority: false,
    },
    overrides,
  );
}

// An executed SYNTH_VERIFIED-style differential row: verdict "verified",
// claim_authority true, bound to an executed verified_pass row by
// bound_path_hash. This is the only shape that COUNTS toward K.
function executedFlip(hash, extra) {
  return Object.assign(
    {
      verdict: "verified",
      reason: "executed_differential_bound",
      bound_path_hash: hash,
      claim_authority: true,
    },
    extra,
  );
}

function refutedForgery() {
  return {
    forgery_id: "planted-forgery-1",
    refuted: true,
    bound_path_hash: "forge-hash-1",
    claim_authority: true,
  };
}

function humanControl() {
  return {
    confirmed: true,
    operator: "eric@commons.email",
    attestation: "negative control discriminates; confounder set reviewed",
  };
}

function learnedMeasurementRow(overrides) {
  return Object.assign(
    {
      kind: "learned_semantic_measurement",
      proof_mode: "learned_measurement_advisory_v1",
      advisory: true,
      claim_authority: false,
      closure_authority: false,
      admission: { admissible: true, reason: "admitted_advisory_measurement", hold_reasons: [] },
      result: { score: 0.99, label: "harmful", abstain: false, ood: false, shifted: false },
    },
    overrides,
  );
}

function fullEvidence(overrides) {
  return Object.assign(
    {
      executed_differentials: [executedFlip("path-a"), executedFlip("path-b")],
      refuted_forgery: refutedForgery(),
      human_control: humanControl(),
    },
    overrides,
  );
}

// --- the subject gate ------------------------------------------------------

test("only a tier-3 advisory record is a promotion subject", () => {
  assert.equal(isTier3Candidate(tier3Candidate()), true);
  // already promoted / higher tier is not a subject
  assert.equal(isTier3Candidate(tier3Candidate({ tier: 2 })), false);
  // a record already carrying claim authority is malformed for promotion
  assert.equal(isTier3Candidate(tier3Candidate({ claim_authority: true })), false);
  // a missing advisory marker is refused, not inferred
  assert.equal(isTier3Candidate({ tier: 3 }), false);
  assert.equal(isTier3Candidate(null), false);
});

test("a non-tier-3 input stays put with the subject reason", () => {
  const verdict = evaluatePromotion(tier3Candidate({ tier: 2 }), fullEvidence());
  assert.equal(verdict.promote, false);
  assert.equal(verdict.reason, STAY_NOT_TIER3);
  assert.equal(verdict.target_tier, SOURCE_TIER);
});

// --- condition (a): K distinct executed flips ------------------------------

test("an executed flip counts only when verified + authoritative + bound", () => {
  assert.equal(executedFlipKey(executedFlip("h1")), "h1");
  // a DECLARED verdict (no claim authority) does not count
  assert.equal(executedFlipKey(executedFlip("h1", { claim_authority: false })), null);
  // an unexecuted / wrong verdict does not count
  assert.equal(executedFlipKey(executedFlip("h1", { verdict: "unverified" })), null);
  // missing the binding hash does not count (the laundering surface)
  assert.equal(executedFlipKey(executedFlip("")), null);
  assert.equal(executedFlipKey({ verdict: "verified", claim_authority: true }), null);
  assert.equal(executedFlipKey(null), null);
});

test("distinct flips dedup by bound_path_hash so one flip cannot count K times", () => {
  // the SAME executed flip presented twice collapses to one distinct key
  const dup = countDistinctExecutedFlips([executedFlip("same"), executedFlip("same")]);
  assert.equal(dup.distinct_count, 1);
  // two genuinely distinct findings count as two
  const two = countDistinctExecutedFlips([executedFlip("a"), executedFlip("b")]);
  assert.equal(two.distinct_count, 2);
  // non-qualifying rows are rejected, not counted
  const mixed = countDistinctExecutedFlips([
    executedFlip("a"),
    executedFlip("a", { claim_authority: false }),
    executedFlip("b"),
  ]);
  assert.equal(mixed.distinct_count, 2);
  assert.equal(mixed.rejected_count, 1);
});

test("the same flip repeated K times does NOT satisfy K (the dedup invariant)", () => {
  const verdict = evaluatePromotion(
    tier3Candidate(),
    fullEvidence({
      executed_differentials: [
        executedFlip("one-and-only"),
        executedFlip("one-and-only"),
        executedFlip("one-and-only"),
      ],
    }),
  );
  assert.equal(verdict.promote, false);
  assert.equal(verdict.reason, STAY_INSUFFICIENT_DISTINCT);
  assert.equal(verdict.distinct_count, 1);
  assert.equal(verdict.required_k, DEFAULT_K);
});

test("a single distinct executed flip is below the default floor", () => {
  const verdict = evaluatePromotion(
    tier3Candidate(),
    fullEvidence({ executed_differentials: [executedFlip("solo")] }),
  );
  assert.equal(verdict.promote, false);
  assert.equal(verdict.reason, STAY_INSUFFICIENT_DISTINCT);
});

test("K is configurable and must be met by DISTINCT flips", () => {
  const ev = fullEvidence({
    executed_differentials: [executedFlip("a"), executedFlip("b")],
  });
  // raising K above the distinct count keeps it tier-3
  const tooFew = evaluatePromotion(tier3Candidate(), ev, { k: 3 });
  assert.equal(tooFew.promote, false);
  assert.equal(tooFew.reason, STAY_INSUFFICIENT_DISTINCT);
  assert.equal(tooFew.required_k, 3);
  // meeting the raised K promotes
  const enough = evaluatePromotion(
    tier3Candidate(),
    fullEvidence({
      executed_differentials: [executedFlip("a"), executedFlip("b"), executedFlip("c")],
    }),
    { k: 3 },
  );
  assert.equal(enough.promote, true);
});

// --- condition (b): refuted-forgery on record ------------------------------

test("a refuted-forgery record requires an executed, bound refusal", () => {
  assert.equal(hasRefutedForgeryOnRecord(refutedForgery()), true);
  // a forgery that was NOT refused proves nothing
  assert.equal(hasRefutedForgeryOnRecord({ ...refutedForgery(), refuted: false }), false);
  // a DECLARED (non-executed) refusal is refused
  assert.equal(hasRefutedForgeryOnRecord({ ...refutedForgery(), claim_authority: false }), false);
  // an unbound refusal is refused
  assert.equal(hasRefutedForgeryOnRecord({ ...refutedForgery(), bound_path_hash: "" }), false);
  assert.equal(hasRefutedForgeryOnRecord(null), false);
});

test("K distinct flips without a refuted-forgery record stay tier-3", () => {
  const verdict = evaluatePromotion(
    tier3Candidate(),
    fullEvidence({ refuted_forgery: null }),
  );
  assert.equal(verdict.promote, false);
  assert.equal(verdict.reason, STAY_NO_REFUTED_FORGERY);
  // the flips DID satisfy (a) — this proves (b) is mandatory, not subsumed
  assert.ok(verdict.conditions.distinct_executed_flips);
});

// --- condition (c): human-confirmed discriminating control -----------------

test("a human control attestation must be explicitly confirmed by a named operator", () => {
  assert.equal(hasHumanConfirmedControl(humanControl()), true);
  assert.equal(hasHumanConfirmedControl({ ...humanControl(), confirmed: false }), false);
  assert.equal(hasHumanConfirmedControl({ ...humanControl(), operator: "" }), false);
  assert.equal(hasHumanConfirmedControl({ ...humanControl(), attestation: "" }), false);
  assert.equal(hasHumanConfirmedControl(null), false);
});

test("K distinct flips + refuted forgery but NO human control stay tier-3", () => {
  const verdict = evaluatePromotion(
    tier3Candidate(),
    fullEvidence({ human_control: null }),
  );
  assert.equal(verdict.promote, false);
  assert.equal(verdict.reason, STAY_NO_HUMAN_CONTROL);
  assert.ok(verdict.conditions.distinct_executed_flips);
  assert.ok(verdict.conditions.refuted_forgery);
});

// --- the AND of all three: the only promote path ---------------------------

test("promotion is granted ONLY when all three conditions hold", () => {
  const verdict = evaluatePromotion(tier3Candidate(), fullEvidence());
  assert.equal(verdict.promote, true);
  assert.equal(verdict.reason, PROMOTE_GRANTED);
  assert.equal(verdict.target_tier, PROMOTED_TIER);
  assert.equal(verdict.conditions.distinct_executed_flips, true);
  assert.equal(verdict.conditions.refuted_forgery, true);
  assert.equal(verdict.conditions.human_control, true);
});

test("empty evidence keeps the candidate at tier-3", () => {
  const verdict = evaluatePromotion(tier3Candidate(), {});
  assert.equal(verdict.promote, false);
  assert.equal(verdict.target_tier, SOURCE_TIER);
  assert.equal(verdict.reason, STAY_INSUFFICIENT_DISTINCT);
});

test("tier-2 learned judge candidates are advisory-only and cannot promote", () => {
  const candidate = tier3Candidate({
    kind: "learned_semantic_measurement",
    proof_mode: "learned_measurement_advisory_v1",
    oracle_tier: "tier2_learned_judge",
  });
  assert.equal(isLearnedMeasurementCandidate(candidate), true);

  const verdict = evaluatePromotion(candidate, fullEvidence());
  assert.equal(verdict.promote, false);
  assert.equal(verdict.reason, STAY_LEARNED_MEASUREMENT_ADVISORY_ONLY);
  assert.equal(verdict.target_tier, SOURCE_TIER);
  assert.equal(verdict.conditions.distinct_executed_flips, true);
  assert.equal(verdict.conditions.refuted_forgery, true);
  assert.equal(verdict.conditions.human_control, true);
});

test("learned measurements never close; forged soft unknown rows hold", () => {
  const positive = evaluateLearnedMeasurementClosure({
    learned_measurements: [learnedMeasurementRow()],
  });
  assert.equal(positive.close, false);
  assert.equal(positive.disposition, "HOLD");
  assert.equal(positive.reason, HOLD_LEARNED_MEASUREMENT_ADVISORY_ONLY);
  assert.equal(positive.independent_registered_proof_required, true);

  const forged = evaluateLearnedMeasurementClosure({
    learned_measurements: [
      learnedMeasurementRow({
        class_id: "unknown_class",
        source_authority: "generated_hypothesis",
        closure_authority: false,
        admission: {
          admissible: false,
          reason: "unknown_class_hold",
          hold_reasons: [
            "unknown_class_hold",
            "soft_or_generated_source_hold",
            "unsigned_or_unverified_capture_hold",
          ],
        },
      }),
    ],
  });
  assert.equal(forged.close, false);
  assert.equal(forged.disposition, "HOLD");
  assert.equal(forged.reason, HOLD_LEARNED_MEASUREMENT_NOT_ADMISSIBLE);
});

test("the verdict is frozen and never mutates inputs", () => {
  const candidate = tier3Candidate();
  const evidence = fullEvidence();
  const snapshot = JSON.stringify(evidence);
  const verdict = evaluatePromotion(candidate, evidence);
  assert.throws(() => {
    verdict.promote = false;
  });
  // inputs are untouched: this gate audits, it never executes or mutates
  assert.equal(JSON.stringify(evidence), snapshot);
  assert.equal(candidate.tier, 3);
  assert.equal(candidate.claim_authority, false);
});
