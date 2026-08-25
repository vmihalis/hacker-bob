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
  RACE_ACTUATOR_SCHEDULE_MAC_CONTEXT,
  OBJECT_STATE_LEASE_ROW_MAC_CONTEXT,
  RACE_ACTUATOR_CAPTURE_MAC_CONTEXT,
  RACE_ACTUATOR_PROOF_MODE,
  RACE_ACTUATOR_CLASS_ID,
  DISPOSITION_CLOSED,
  DISPOSITION_HOLD: PROOF_DISPOSITION_HOLD,
  evaluateRaceActuatorProof,
} = require("../mcp/core/leases/index.js");
const {
  DISPOSITION_ADMITTED,
  DISPOSITION_HOLD,
  DISPOSITION_OPERATOR_GATE,
  ENVIRONMENT_SELF_TENANT,
  ENVIRONMENT_PRODUCTION,
  buildWebInstrumentRows,
  evaluateWebInstrumentAdmission,
} = require("../mcp/domains/web/instrument-plane.js");

const TARGET_DOMAIN = "web-instrument.example.test";
const SURFACE_ID = "POST /api/coupons/redeem";
const OBJECT_STATE_KEY = "coupon:web-instrument-fixture";
const ATTEMPT_ID = "attempt-web-instrument-1";
const EPISODE_ID = "episode-web-instrument-1";

function baseDesign(overrides = {}) {
  return {
    target_domain: TARGET_DOMAIN,
    surface_id: SURFACE_ID,
    object_state_key: OBJECT_STATE_KEY,
    attempt_id: ATTEMPT_ID,
    episode_id: EPISODE_ID,
    class_id: RACE_ACTUATOR_CLASS_ID,
    proof_mode: RACE_ACTUATOR_PROOF_MODE,
    environment_kind: ENVIRONMENT_SELF_TENANT,
    destructive: true,
    blast_radius_confined: true,
    harness_owned: true,
    instrument_ref: "web-instrument:self-tenant-coupon-runner",
    instrument_admitted: true,
    scheduler_owner: "harness",
    barrier_owner: "harness",
    capture_owner: "harness",
    executor_fired: false,
    reset_strength: "washout",
    reset_witness_ref: "reset-witness:web-self-tenant-washout-1",
    pre_state_ref: "state-capture:pre:coupon-1",
    pre_state: { coupon: { remaining_uses: 1 } },
    fidelity_controls: [
      { kind: "instrument_present", evidence_ref: "fidelity:instrument-present:1" },
      { kind: "environment_equivalence", evidence_ref: "fidelity:env-equivalence:1" },
    ],
    post_state_invariant: {
      id: "post_state_field_equals_v1",
      path: ["coupon", "remaining_uses"],
      treatment_post_state_equals: 1,
      negative_control_post_state_equals: 0,
    },
    ...overrides,
  };
}

function baseCaptures(overrides = {}) {
  return {
    treatment_capture: {
      barrier_owner: "harness",
      instrument_admitted: true,
      response_statuses: [200, 200],
      post_state_ref: "state-capture:post:treatment",
      post_state: { coupon: { remaining_uses: 1 } },
      ...(overrides.treatment_capture || {}),
    },
    negative_control_capture: {
      barrier_owner: "harness",
      instrument_admitted: true,
      response_statuses: [200, 200],
      post_state_ref: "state-capture:post:negative-control",
      post_state: { coupon: { remaining_uses: 0 } },
      ...(overrides.negative_control_capture || {}),
    },
  };
}

function sign(context, row, keys) {
  const signed = { ...row };
  signRowWithMac(context, signed, { scheme: MAC_SCHEME_ED25519, privateKey: keys.privateKey });
  return signed;
}

function signedRowsFromRun(run) {
  const scheduleKeys = crypto.generateKeyPairSync("ed25519");
  const leaseKeys = crypto.generateKeyPairSync("ed25519");
  const captureKeys = crypto.generateKeyPairSync("ed25519");

  return {
    schedule: sign(RACE_ACTUATOR_SCHEDULE_MAC_CONTEXT, run.schedule_row, scheduleKeys),
    lease: sign(OBJECT_STATE_LEASE_ROW_MAC_CONTEXT, run.lease_row, leaseKeys),
    treatment: sign(RACE_ACTUATOR_CAPTURE_MAC_CONTEXT, run.treatment_capture_row, captureKeys),
    negativeControl: sign(RACE_ACTUATOR_CAPTURE_MAC_CONTEXT, run.negative_control_capture_row, captureKeys),
    rowVerifier(context, row) {
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
    },
  };
}

function evaluateSignedRows(rows) {
  return evaluateRaceActuatorProof({
    schedule_row: rows.schedule,
    lease_row: rows.lease,
    treatment_capture_row: rows.treatment,
    negative_control_capture_row: rows.negativeControl,
    row_verifier: rows.rowVerifier,
  });
}

test("self-tenant destructive web instrument emits signed reset/pre/post rows that close via harness-owned proof", () => {
  const run = buildWebInstrumentRows({
    design: baseDesign(),
    ...baseCaptures(),
  });

  assert.equal(run.admission.disposition, DISPOSITION_ADMITTED);
  assert.ok(run.schedule_row.pre_state_digest);
  assert.equal(run.schedule_row.reset_witness_ref, "reset-witness:web-self-tenant-washout-1");
  assert.ok(run.treatment_capture_row.post_state_digest);
  assert.ok(run.negative_control_capture_row.post_state_digest);

  const proof = evaluateSignedRows(signedRowsFromRun(run));
  assert.equal(proof.disposition, DISPOSITION_CLOSED);
  assert.equal(proof.closes, true);
  assert.equal(proof.reset_strength, "washout");
  assert.equal(proof.target_domain, TARGET_DOMAIN);
});

test("production destructive web design stays operator-gated and produces no closure-capable rows", () => {
  const run = buildWebInstrumentRows({
    design: baseDesign({
      environment_kind: ENVIRONMENT_PRODUCTION,
      blast_radius_confined: false,
    }),
    ...baseCaptures(),
  });

  assert.equal(run.admission.disposition, DISPOSITION_OPERATOR_GATE);
  assert.equal(run.admission.admits_closure_rows, false);
  assert.equal(run.schedule_row, null);
  assert.match(run.admission.reason, /operator gate/);
});

test("unknown, soft, and no-reset web instrument designs fail closed before row emission", () => {
  const unknown = buildWebInstrumentRows({
    design: baseDesign({ class_id: "autonomous_new_race_class" }),
    ...baseCaptures(),
  });
  assert.equal(unknown.admission.disposition, DISPOSITION_HOLD);
  assert.equal(unknown.schedule_row, null);
  assert.match(unknown.admission.hold_reasons.join("\n"), /unknown web instrument class/);

  const soft = buildWebInstrumentRows({
    design: baseDesign({ source_plane: "generated" }),
    ...baseCaptures(),
  });
  assert.equal(soft.admission.disposition, DISPOSITION_HOLD);
  assert.equal(soft.schedule_row, null);
  assert.match(soft.admission.reason, /soft source generated/);

  const noReset = buildWebInstrumentRows({
    design: baseDesign({ reset_strength: "unknown", reset_witness_ref: null }),
    ...baseCaptures(),
  });
  assert.equal(noReset.admission.disposition, DISPOSITION_HOLD);
  assert.equal(noReset.schedule_row, null);
  assert.match(noReset.admission.hold_reasons.join("\n"), /reset\/washout is non-reportable/);
  assert.match(noReset.admission.hold_reasons.join("\n"), /reset_witness_ref is required/);
});

test("forged signed web capture bytes are refused by the proof evaluator", () => {
  const run = buildWebInstrumentRows({
    design: baseDesign(),
    ...baseCaptures(),
  });
  const rows = signedRowsFromRun(run);
  rows.treatment = {
    ...rows.treatment,
    post_state: { coupon: { remaining_uses: 999 } },
  };

  const proof = evaluateSignedRows(rows);
  assert.equal(proof.disposition, PROOF_DISPOSITION_HOLD);
  assert.equal(proof.closes, false);
  assert.match(proof.reason, /treatment capture refused/);
});

test("unowned barrier/capture does not admit a web instrument", () => {
  const admission = evaluateWebInstrumentAdmission(baseDesign({
    scheduler_owner: "executor",
    barrier_owner: "executor",
    capture_owner: "executor",
    executor_fired: true,
  }));

  assert.equal(admission.disposition, DISPOSITION_HOLD);
  assert.match(admission.hold_reasons.join("\n"), /scheduler_owner is not harness/);
  assert.match(admission.hold_reasons.join("\n"), /barrier_owner is not harness/);
  assert.match(admission.hold_reasons.join("\n"), /capture_owner is not harness/);
  assert.match(admission.hold_reasons.join("\n"), /executor-fired design is inert/);
});
