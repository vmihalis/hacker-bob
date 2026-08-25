"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");

const {
  signRowWithMac,
  verifyRowWithMac,
  MAC_SCHEME_ED25519,
} = require("../mcp/core/ledger-integrity/index.js");
const {
  OBJECT_STATE_LEASE_ROW_MAC_CONTEXT,
  RACE_ACTUATOR_SCHEDULE_MAC_CONTEXT,
  RACE_ACTUATOR_CAPTURE_MAC_CONTEXT,
  RACE_ACTUATOR_PROOF_MAC_CONTEXT,
  RACE_ACTUATOR_PROOF_MODE,
  RACE_ACTUATOR_CLASS_ID,
  DISPOSITION_CLOSED,
  DISPOSITION_HOLD,
  objectStateLeaseKey,
  evaluateRaceActuatorProof,
  verifyRaceActuatorProof,
} = require("../mcp/core/leases/index.js");

const TARGET_DOMAIN = "race-actuator.example.test";
const SURFACE_ID = "POST /api/coupons/redeem";
const OBJECT_STATE_KEY = "coupon:fixture-coupon-1";
const ATTEMPT_ID = "attempt-race-1";
const EPISODE_ID = "episode-race-1";

function sign(context, row, keys) {
  const signed = { ...row };
  signRowWithMac(context, signed, { scheme: MAC_SCHEME_ED25519, privateKey: keys.privateKey });
  return signed;
}

function fixtureRows(overrides = {}) {
  const scheduleKeys = crypto.generateKeyPairSync("ed25519");
  const leaseKeys = crypto.generateKeyPairSync("ed25519");
  const captureKeys = crypto.generateKeyPairSync("ed25519");
  const proofKeys = crypto.generateKeyPairSync("ed25519");

  const common = {
    target_domain: TARGET_DOMAIN,
    surface_id: SURFACE_ID,
    object_state_key: OBJECT_STATE_KEY,
    attempt_id: ATTEMPT_ID,
    episode_id: EPISODE_ID,
    source_plane: "executed",
  };

  const schedule = sign(RACE_ACTUATOR_SCHEDULE_MAC_CONTEXT, {
    ...common,
    row_id: "schedule-1",
    class_id: RACE_ACTUATOR_CLASS_ID,
    proof_mode: RACE_ACTUATOR_PROOF_MODE,
    harness_owned: true,
    scheduler_owner: "harness",
    barrier_owner: "harness",
    executor_fired: false,
    reset_strength: "washout",
    reset_witness_ref: "reset-witness:fixture-washout-1",
    post_state_invariant: {
      id: "post_state_field_equals_v1",
      path: ["coupon", "remaining_uses"],
      treatment_post_state_equals: 1,
      negative_control_post_state_equals: 0,
    },
    ...(overrides.schedule || {}),
  }, scheduleKeys);

  const lease = sign(OBJECT_STATE_LEASE_ROW_MAC_CONTEXT, {
    ...common,
    row_id: "lease-1",
    lease_type: "web_object_state",
    lease_key: objectStateLeaseKey({
      targetDomain: TARGET_DOMAIN,
      surfaceId: SURFACE_ID,
      objectStateKey: OBJECT_STATE_KEY,
    }),
    active: true,
    holder: "race-actuator-fixture",
    ...(overrides.lease || {}),
  }, leaseKeys);

  const treatment = sign(RACE_ACTUATOR_CAPTURE_MAC_CONTEXT, {
    ...common,
    row_id: "capture-treatment-1",
    arm: "treatment",
    barrier_owner: "harness",
    instrument_admitted: true,
    response_statuses: [200, 200],
    post_state: { coupon: { remaining_uses: 1 } },
    ...(overrides.treatment || {}),
  }, captureKeys);

  const negativeControl = sign(RACE_ACTUATOR_CAPTURE_MAC_CONTEXT, {
    ...common,
    row_id: "capture-control-1",
    arm: "negative_control",
    barrier_owner: "harness",
    instrument_admitted: true,
    response_statuses: [200, 200],
    post_state: { coupon: { remaining_uses: 0 } },
    ...(overrides.negativeControl || {}),
  }, captureKeys);

  const rowVerifier = (context, row) => {
    if (context === RACE_ACTUATOR_SCHEDULE_MAC_CONTEXT) {
      return verifyRowWithMac(context, row, { publicKey: scheduleKeys.publicKey });
    }
    if (context === OBJECT_STATE_LEASE_ROW_MAC_CONTEXT) {
      return verifyRowWithMac(context, row, { publicKey: leaseKeys.publicKey });
    }
    if (context === RACE_ACTUATOR_CAPTURE_MAC_CONTEXT) {
      return verifyRowWithMac(context, row, { publicKey: captureKeys.publicKey });
    }
    return false;
  };

  return {
    schedule,
    lease,
    treatment,
    negativeControl,
    rowVerifier,
    proofSigner: { scheme: MAC_SCHEME_ED25519, privateKey: proofKeys.privateKey },
    proofVerifier: { publicKey: proofKeys.publicKey },
  };
}

function evaluate(rows) {
  return evaluateRaceActuatorProof({
    schedule_row: rows.schedule,
    lease_row: rows.lease,
    treatment_capture_row: rows.treatment,
    negative_control_capture_row: rows.negativeControl,
    row_verifier: rows.rowVerifier,
    proof_signer: rows.proofSigner,
  });
}

test("race actuator closes only on a harness-owned schedule and registered post-state invariant", () => {
  const rows = fixtureRows();
  const proof = evaluate(rows);

  assert.equal(proof.disposition, DISPOSITION_CLOSED);
  assert.equal(proof.closes, true);
  assert.equal(proof.proof_mode, RACE_ACTUATOR_PROOF_MODE);
  assert.equal(proof.target_domain, TARGET_DOMAIN);
  assert.equal(proof.surface_id, SURFACE_ID);
  assert.equal(proof.object_state_key, OBJECT_STATE_KEY);
  assert.equal(proof.invariant.predicate, "post_state_field_equals_v1");
  assert.deepEqual(proof.invariant.observed, {
    path: ["coupon", "remaining_uses"],
    treatment_post_state: 1,
    negative_control_post_state: 0,
  });
  assert.equal(verifyRaceActuatorProof(proof, rows.proofVerifier), true);
});

test("forged, soft, unknown, and no-washout race inputs are held/non-reportable", () => {
  const forged = fixtureRows();
  forged.treatment = { ...forged.treatment, post_state: { coupon: { remaining_uses: 999 } } };
  const forgedProof = evaluate(forged);
  assert.equal(forgedProof.disposition, DISPOSITION_HOLD);
  assert.equal(forgedProof.closes, false);
  assert.match(forgedProof.reason, /treatment capture refused/);

  const soft = fixtureRows({ treatment: { generated_hypothesis: true } });
  const softProof = evaluate(soft);
  assert.equal(softProof.disposition, DISPOSITION_HOLD);
  assert.match(softProof.reason, /soft or generated/);

  const unknown = fixtureRows({ schedule: { class_id: "autonomous_new_race_class" } });
  const unknownProof = evaluate(unknown);
  assert.equal(unknownProof.disposition, DISPOSITION_HOLD);
  assert.match(unknownProof.hold_reasons.join("\n"), /unknown race\/stateful class/);

  const noWashout = fixtureRows({ schedule: { reset_strength: "unknown", reset_witness_ref: null } });
  const noWashoutProof = evaluate(noWashout);
  assert.equal(noWashoutProof.disposition, DISPOSITION_HOLD);
  assert.match(noWashoutProof.hold_reasons.join("\n"), /reset\/washout is non-reportable/);
  assert.match(noWashoutProof.hold_reasons.join("\n"), /reset\/washout witness/);

  const unowned = fixtureRows({ schedule: { scheduler_owner: "executor", barrier_owner: "executor", executor_fired: true } });
  const unownedProof = evaluate(unowned);
  assert.equal(unownedProof.disposition, DISPOSITION_HOLD);
  assert.match(unownedProof.hold_reasons.join("\n"), /scheduler_owner is not harness/);
  assert.match(unownedProof.hold_reasons.join("\n"), /executor-fired/);
});
