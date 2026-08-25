"use strict";

const {
  signRowWithMac,
  verifyRowWithMac,
} = require("../ledger-integrity/index.js");
const {
  hashCanonicalJson,
} = require("../verification/verification-contracts.js");

const OBJECT_STATE_LEASE_ROW_MAC_CONTEXT = "hacker-bob:object-state-lease-row:v1";
const RACE_ACTUATOR_SCHEDULE_MAC_CONTEXT = "hacker-bob:race-actuator-schedule-row:v1";
const RACE_ACTUATOR_CAPTURE_MAC_CONTEXT = "hacker-bob:race-actuator-capture-row:v1";
const RACE_ACTUATOR_PROOF_MAC_CONTEXT = "hacker-bob:race-actuator-proof:v1";

const RACE_ACTUATOR_PROOF_MODE = "trajectory_stateful_race_v1";
const RACE_ACTUATOR_CLASS_ID = "race_stateful_write_then_read";
const RACE_ACTUATOR_DESIGN_HASH = hashCanonicalJson({
  version: 1,
  proof_mode: RACE_ACTUATOR_PROOF_MODE,
  class_id: RACE_ACTUATOR_CLASS_ID,
  invariant_registry: ["post_state_field_equals_v1"],
});

const DISPOSITION_CLOSED = "closed";
const DISPOSITION_HOLD = "hold";

const REPORTABLE_RESET_STRENGTHS = new Set(["exact_snapshot", "semantic_cleanup", "washout"]);
const NON_REPORTABLE_RESET_STRENGTHS = new Set(["irreversible", "unknown"]);
const SOFT_SOURCE_VALUES = new Set(["belief", "posterior", "llm", "model", "generated", "hypothesis"]);

function isPlainObject(value) {
  return value != null && typeof value === "object" && !Array.isArray(value);
}

function isNonEmptyString(value) {
  return typeof value === "string" && value.length > 0;
}

function objectStateLeaseKey({ targetDomain, surfaceId, objectStateKey }) {
  if (!isNonEmptyString(targetDomain)) throw new TypeError("targetDomain must be a non-empty string");
  if (!isNonEmptyString(surfaceId)) throw new TypeError("surfaceId must be a non-empty string");
  if (!isNonEmptyString(objectStateKey)) throw new TypeError("objectStateKey must be a non-empty string");
  return [
    "web_object_state",
    targetDomain,
    hashCanonicalJson(surfaceId),
    hashCanonicalJson(objectStateKey),
  ].join(":");
}

function unsignedProjection(row) {
  const out = {};
  for (const key of Object.keys(row).sort()) {
    if (key === "row_mac") continue;
    out[key] = row[key];
  }
  return out;
}

function proofHashPreimage(proof) {
  const out = {};
  for (const key of Object.keys(proof).sort()) {
    if (key === "row_mac" || key === "proof_hash") continue;
    out[key] = proof[key];
  }
  return out;
}

function rowDigest(row) {
  return hashCanonicalJson(unsignedProjection(row));
}

function rowSoftReason(row) {
  if (!isPlainObject(row)) return "row is not an object";
  if (row.soft === true || row.advisory === true || row.generated_hypothesis === true) {
    return "soft or generated row is not closure input";
  }
  const source = isNonEmptyString(row.source_plane) ? row.source_plane : row.source;
  if (SOFT_SOURCE_VALUES.has(source)) return `soft source ${source} is not closure input`;
  return null;
}

function verifySignedRow(row, context, verifier) {
  if (!isPlainObject(row)) return { ok: false, reason: "row is not an object" };
  const soft = rowSoftReason(row);
  if (soft) return { ok: false, reason: soft };
  if (!isPlainObject(row.row_mac)) return { ok: false, reason: "unsigned row" };
  const ok = typeof verifier === "function"
    ? verifier(row) === true
    : verifyRowWithMac(context, row, verifier);
  if (!ok) return { ok: false, reason: "unverifiable row" };
  return { ok: true, row: Object.freeze(unsignedProjection(row)) };
}

function holdProof(reason, input = {}) {
  const rows = [input.schedule_row, input.lease_row, input.treatment_capture_row, input.negative_control_capture_row]
    .filter(isPlainObject);
  const proofBody = {
    version: 1,
    proof_mode: RACE_ACTUATOR_PROOF_MODE,
    design_hash: RACE_ACTUATOR_DESIGN_HASH,
    class_id: RACE_ACTUATOR_CLASS_ID,
    disposition: DISPOSITION_HOLD,
    closes: false,
    reason,
    hold_reasons: [reason].concat(Array.isArray(input.hold_reasons) ? input.hold_reasons : []).sort(),
    target_domain: input.target_domain || null,
    surface_id: input.surface_id || null,
    object_state_key: input.object_state_key || null,
    attempt_id: input.attempt_id || null,
    episode_id: input.episode_id || null,
    row_digests: rows.map(rowDigest).sort(),
  };
  const proof = {
    ...proofBody,
    proof_hash: hashCanonicalJson(proofBody),
  };
  if (input.proof_signer) signRowWithMac(RACE_ACTUATOR_PROOF_MAC_CONTEXT, proof, input.proof_signer);
  return Object.freeze(proof);
}

function getPath(obj, path) {
  if (!Array.isArray(path) || path.length === 0) return undefined;
  let current = obj;
  for (const part of path) {
    if (!isPlainObject(current) && !Array.isArray(current)) return undefined;
    current = current[part];
  }
  return current;
}

function evaluatePostStateFieldEquals({ invariant, treatment, negativeControl }) {
  const path = invariant && invariant.path;
  const treatmentExpected = invariant && invariant.treatment_post_state_equals;
  const controlExpected = invariant && invariant.negative_control_post_state_equals;
  const treatmentObserved = getPath(treatment.post_state, path);
  const controlObserved = getPath(negativeControl.post_state, path);
  const treatmentOk = Object.is(treatmentObserved, treatmentExpected);
  const controlOk = Object.is(controlObserved, controlExpected);
  return {
    ok: treatmentOk && controlOk,
    predicate: "post_state_field_equals_v1",
    observed: {
      path,
      treatment_post_state: treatmentObserved,
      negative_control_post_state: controlObserved,
    },
    expected: {
      treatment_post_state: treatmentExpected,
      negative_control_post_state: controlExpected,
    },
  };
}

function evaluateRegisteredPostStateInvariant({ schedule, treatment, negativeControl }) {
  const invariant = schedule.post_state_invariant;
  if (!isPlainObject(invariant)) return { ok: false, reason: "missing post_state_invariant" };
  if (invariant.id !== "post_state_field_equals_v1") {
    return { ok: false, reason: "unknown post-state invariant" };
  }
  if (!Array.isArray(invariant.path) || invariant.path.length === 0) {
    return { ok: false, reason: "post-state invariant path is required" };
  }
  return evaluatePostStateFieldEquals({ invariant, treatment, negativeControl });
}

function sameField(rows, field) {
  const values = Array.from(new Set(rows.map((row) => row[field]).filter(isNonEmptyString))).sort();
  return values.length === 1 ? values[0] : null;
}

function verifyObjectStateLease({ lease, schedule }) {
  if (lease.lease_type !== "web_object_state") return "lease is not a web object-state lease";
  if (lease.target_domain !== schedule.target_domain) return "lease target_domain does not match schedule";
  if (lease.surface_id !== schedule.surface_id) return "lease surface_id does not match schedule";
  if (lease.object_state_key !== schedule.object_state_key) return "lease object_state_key does not match schedule";
  if (lease.attempt_id !== schedule.attempt_id) return "lease attempt_id does not match schedule";
  const expectedKey = objectStateLeaseKey({
    targetDomain: schedule.target_domain,
    surfaceId: schedule.surface_id,
    objectStateKey: schedule.object_state_key,
  });
  if (lease.lease_key !== expectedKey) return "lease_key does not match object-state scope";
  if (lease.active !== true) return "object-state lease is not active";
  return null;
}

function normalizeVerifier(input, field, context) {
  if (typeof input[field] === "function") return (row) => input[field](row);
  if (isPlainObject(input.row_verifiers) && typeof input.row_verifiers[context] === "function") {
    return (row) => input.row_verifiers[context](row);
  }
  if (typeof input.row_verifier === "function") return (row) => input.row_verifier(context, row);
  return input.verifier || null;
}

function evaluateRaceActuatorProof(input) {
  if (!isPlainObject(input)) return holdProof("input must be a race actuator proof request");
  const scheduleChecked = verifySignedRow(
    input.schedule_row,
    RACE_ACTUATOR_SCHEDULE_MAC_CONTEXT,
    normalizeVerifier(input, "schedule_verifier", RACE_ACTUATOR_SCHEDULE_MAC_CONTEXT),
  );
  if (!scheduleChecked.ok) return holdProof(`schedule row refused: ${scheduleChecked.reason}`, input);

  const leaseChecked = verifySignedRow(
    input.lease_row,
    OBJECT_STATE_LEASE_ROW_MAC_CONTEXT,
    normalizeVerifier(input, "lease_verifier", OBJECT_STATE_LEASE_ROW_MAC_CONTEXT),
  );
  if (!leaseChecked.ok) return holdProof(`object-state lease refused: ${leaseChecked.reason}`, input);

  const treatmentChecked = verifySignedRow(
    input.treatment_capture_row,
    RACE_ACTUATOR_CAPTURE_MAC_CONTEXT,
    normalizeVerifier(input, "capture_verifier", RACE_ACTUATOR_CAPTURE_MAC_CONTEXT),
  );
  if (!treatmentChecked.ok) return holdProof(`treatment capture refused: ${treatmentChecked.reason}`, input);

  const controlChecked = verifySignedRow(
    input.negative_control_capture_row,
    RACE_ACTUATOR_CAPTURE_MAC_CONTEXT,
    normalizeVerifier(input, "capture_verifier", RACE_ACTUATOR_CAPTURE_MAC_CONTEXT),
  );
  if (!controlChecked.ok) return holdProof(`negative control capture refused: ${controlChecked.reason}`, input);

  const schedule = scheduleChecked.row;
  const lease = leaseChecked.row;
  const treatment = treatmentChecked.row;
  const negativeControl = controlChecked.row;
  const rows = [schedule, lease, treatment, negativeControl];
  const holdReasons = [];

  if (schedule.class_id !== RACE_ACTUATOR_CLASS_ID) holdReasons.push("unknown race/stateful class");
  if (schedule.proof_mode !== RACE_ACTUATOR_PROOF_MODE) holdReasons.push("schedule proof_mode is not race/stateful trajectory");
  if (schedule.harness_owned !== true) holdReasons.push("schedule is not harness-owned");
  if (schedule.scheduler_owner !== "harness") holdReasons.push("scheduler_owner is not harness");
  if (schedule.barrier_owner !== "harness") holdReasons.push("barrier_owner is not harness");
  if (schedule.executor_fired === true) holdReasons.push("executor-fired schedules are inert");
  if (!isNonEmptyString(schedule.reset_strength)) holdReasons.push("reset_strength is required");
  else if (NON_REPORTABLE_RESET_STRENGTHS.has(schedule.reset_strength)) holdReasons.push("reset/washout is non-reportable");
  else if (!REPORTABLE_RESET_STRENGTHS.has(schedule.reset_strength)) holdReasons.push("reset_strength is unknown");
  if (!isNonEmptyString(schedule.reset_witness_ref)) holdReasons.push("signed reset/washout witness is required");

  const leaseIssue = verifyObjectStateLease({ lease, schedule });
  if (leaseIssue) holdReasons.push(leaseIssue);

  const attemptId = sameField(rows, "attempt_id");
  const episodeId = sameField(rows, "episode_id");
  if (!attemptId) holdReasons.push("rows do not share one non-empty attempt_id");
  if (!episodeId) holdReasons.push("rows do not share one non-empty episode_id");
  if (treatment.arm !== "treatment") holdReasons.push("treatment capture arm is not treatment");
  if (negativeControl.arm !== "negative_control") holdReasons.push("negative control capture arm is not negative_control");
  if (treatment.instrument_admitted !== true || negativeControl.instrument_admitted !== true) {
    holdReasons.push("post-state captures require admitted instruments");
  }
  if (treatment.barrier_owner !== "harness" || negativeControl.barrier_owner !== "harness") {
    holdReasons.push("post-state captures are not harness-barrier-owned");
  }

  const invariantResult = evaluateRegisteredPostStateInvariant({ schedule, treatment, negativeControl });
  if (!invariantResult.ok) holdReasons.push(invariantResult.reason || "post-state invariant did not hold");

  if (holdReasons.length > 0) {
    return holdProof("race actuator proof refused", {
      ...input,
      target_domain: schedule.target_domain || null,
      surface_id: schedule.surface_id || null,
      object_state_key: schedule.object_state_key || null,
      attempt_id: attemptId,
      episode_id: episodeId,
      hold_reasons: holdReasons,
    });
  }

  const proofBody = {
    version: 1,
    proof_mode: RACE_ACTUATOR_PROOF_MODE,
    design_hash: RACE_ACTUATOR_DESIGN_HASH,
    class_id: RACE_ACTUATOR_CLASS_ID,
    disposition: DISPOSITION_CLOSED,
    closes: true,
    reason: "harness-owned race schedule closed on registered post-state invariant",
    target_domain: schedule.target_domain,
    surface_id: schedule.surface_id,
    object_state_key: schedule.object_state_key,
    attempt_id: attemptId,
    episode_id: episodeId,
    reset_strength: schedule.reset_strength,
    reset_witness_ref: schedule.reset_witness_ref,
    lease_key: lease.lease_key,
    invariant: invariantResult,
    row_digests: [input.schedule_row, input.lease_row, input.treatment_capture_row, input.negative_control_capture_row]
      .map(rowDigest)
      .sort(),
  };
  const proof = {
    ...proofBody,
    proof_hash: hashCanonicalJson(proofBody),
  };
  if (input.proof_signer) signRowWithMac(RACE_ACTUATOR_PROOF_MAC_CONTEXT, proof, input.proof_signer);
  return Object.freeze(proof);
}

function verifyRaceActuatorProof(proof, verifier) {
  if (!isPlainObject(proof)) return false;
  if (proof.proof_hash !== hashCanonicalJson(proofHashPreimage(proof))) return false;
  if (!isPlainObject(proof.row_mac)) return true;
  return verifyRowWithMac(RACE_ACTUATOR_PROOF_MAC_CONTEXT, proof, verifier);
}

module.exports = {
  OBJECT_STATE_LEASE_ROW_MAC_CONTEXT,
  RACE_ACTUATOR_SCHEDULE_MAC_CONTEXT,
  RACE_ACTUATOR_CAPTURE_MAC_CONTEXT,
  RACE_ACTUATOR_PROOF_MAC_CONTEXT,
  RACE_ACTUATOR_PROOF_MODE,
  RACE_ACTUATOR_CLASS_ID,
  RACE_ACTUATOR_DESIGN_HASH,
  DISPOSITION_CLOSED,
  DISPOSITION_HOLD,
  objectStateLeaseKey,
  evaluateRaceActuatorProof,
  verifyRaceActuatorProof,
};
