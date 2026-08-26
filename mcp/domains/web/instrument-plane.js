"use strict";

// Harness-owned web/SaaS instrument plane. This module is pure contract glue:
// it admits a stateful/destructive design only when the harness owns the
// scheduler/barrier/capture/reset facts, then projects closure-capable rows for
// mcp/core/leases. Production destructive designs remain operator-gated.

const {
  OBJECT_STATE_LEASE_ROW_MAC_CONTEXT,
  RACE_ACTUATOR_SCHEDULE_MAC_CONTEXT,
  RACE_ACTUATOR_CAPTURE_MAC_CONTEXT,
  RACE_ACTUATOR_PROOF_MODE,
  RACE_ACTUATOR_CLASS_ID,
  objectStateLeaseKey,
} = require("../../core/leases/index.js");
const {
  hashCanonicalJson,
} = require("../../core/verification/verification-contracts.js");

const WEB_INSTRUMENT_PLANE_VERSION = 1;

const DISPOSITION_ADMITTED = "admitted";
const DISPOSITION_HOLD = "hold";
const DISPOSITION_OPERATOR_GATE = "operator_gate";

const ENVIRONMENT_SELF_TENANT = "self_tenant";
const ENVIRONMENT_PRODUCTION = "production";
const ENVIRONMENT_REPLICA = "replica";

const RESET_STRENGTH_REPORTABLE = new Set(["exact_snapshot", "semantic_cleanup", "washout"]);
const RESET_STRENGTH_NON_REPORTABLE = new Set(["irreversible", "unknown"]);
const FIDELITY_CONTROL_KINDS = new Set([
  "instrument_present",
  "instrument_absent",
  "environment_equivalence",
]);
const SOFT_SOURCE_VALUES = new Set(["belief", "posterior", "llm", "model", "generated", "hypothesis"]);

function isPlainObject(value) {
  return value != null && typeof value === "object" && !Array.isArray(value);
}

function isNonEmptyString(value) {
  return typeof value === "string" && value.length > 0;
}

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function cloneJson(value) {
  return JSON.parse(JSON.stringify(value));
}

function stateDigest(value) {
  return hashCanonicalJson(value == null ? null : value);
}

function softReason(value) {
  if (!isPlainObject(value)) return null;
  if (value.soft === true || value.advisory === true || value.generated_hypothesis === true) {
    return "soft or generated input is not closure input";
  }
  const source = isNonEmptyString(value.source_plane) ? value.source_plane : value.source;
  if (SOFT_SOURCE_VALUES.has(source)) return `soft source ${source} is not closure input`;
  return null;
}

function requireString(value, label, holdReasons) {
  if (!isNonEmptyString(value)) {
    holdReasons.push(`${label} is required`);
    return null;
  }
  return value;
}

function normalizeFidelityControls(input, holdReasons) {
  const controls = Array.isArray(input) ? input : [];
  if (controls.length === 0) {
    holdReasons.push("instrument fidelity control is required");
    return [];
  }
  const normalized = [];
  for (let index = 0; index < controls.length; index += 1) {
    const control = controls[index];
    const label = `fidelity_controls[${index}]`;
    if (!isPlainObject(control)) {
      holdReasons.push(`${label} must be an object`);
      continue;
    }
    if (!FIDELITY_CONTROL_KINDS.has(control.kind)) {
      holdReasons.push(`${label}.kind is not a registered fidelity control`);
    }
    if (!isNonEmptyString(control.evidence_ref)) {
      holdReasons.push(`${label}.evidence_ref is required`);
    }
    normalized.push({
      kind: control.kind || null,
      evidence_ref: control.evidence_ref || null,
      digest: hashCanonicalJson({
        kind: control.kind || null,
        evidence_ref: control.evidence_ref || null,
        details: isPlainObject(control.details) ? control.details : null,
      }),
    });
  }
  return normalized.sort((left, right) => left.digest.localeCompare(right.digest));
}

function admissionBody(input, disposition, reason, holdReasons = [], extras = {}) {
  const body = {
    version: WEB_INSTRUMENT_PLANE_VERSION,
    disposition,
    admits_closure_rows: disposition === DISPOSITION_ADMITTED,
    reason,
    hold_reasons: holdReasons.slice().sort(),
    target_domain: input.target_domain || null,
    surface_id: input.surface_id || null,
    object_state_key: input.object_state_key || null,
    attempt_id: input.attempt_id || null,
    episode_id: input.episode_id || null,
    class_id: input.class_id || null,
    proof_mode: input.proof_mode || null,
    environment_kind: input.environment_kind || null,
    destructive: input.destructive === true,
    harness_owned: input.harness_owned === true,
    ...extras,
  };
  return deepFreeze({ ...body, admission_digest: hashCanonicalJson(body) });
}

function evaluateWebInstrumentAdmission(input) {
  if (!isPlainObject(input)) {
    return admissionBody({}, DISPOSITION_HOLD, "input must be a web instrument design", [
      "input must be a web instrument design",
    ]);
  }

  const initialSoftReason = softReason(input);
  if (initialSoftReason) {
    return admissionBody(input, DISPOSITION_HOLD, initialSoftReason, [initialSoftReason]);
  }

  const holdReasons = [];
  requireString(input.target_domain, "target_domain", holdReasons);
  requireString(input.surface_id, "surface_id", holdReasons);
  requireString(input.object_state_key, "object_state_key", holdReasons);
  requireString(input.attempt_id, "attempt_id", holdReasons);
  requireString(input.episode_id, "episode_id", holdReasons);
  requireString(input.instrument_ref, "instrument_ref", holdReasons);
  requireString(input.pre_state_ref, "pre_state_ref", holdReasons);
  requireString(input.reset_witness_ref, "reset_witness_ref", holdReasons);

  if (input.class_id !== RACE_ACTUATOR_CLASS_ID) holdReasons.push("unknown web instrument class");
  if (input.proof_mode !== RACE_ACTUATOR_PROOF_MODE) {
    holdReasons.push("proof_mode is not the registered stateful/race trajectory");
  }
  if (input.harness_owned !== true) holdReasons.push("instrument is not harness-owned");
  if (input.instrument_admitted !== true) holdReasons.push("instrument is not admitted");
  if (input.scheduler_owner !== "harness") holdReasons.push("scheduler_owner is not harness");
  if (input.barrier_owner !== "harness") holdReasons.push("barrier_owner is not harness");
  if (input.capture_owner !== "harness") holdReasons.push("capture_owner is not harness");
  if (input.executor_fired === true) holdReasons.push("executor-fired design is inert");

  const environmentKind = input.environment_kind;
  if (![ENVIRONMENT_SELF_TENANT, ENVIRONMENT_PRODUCTION, ENVIRONMENT_REPLICA].includes(environmentKind)) {
    holdReasons.push("environment_kind is not registered");
  }

  const destructive = input.destructive === true;
  const blastRadiusConfined = input.blast_radius_confined === true;
  if (destructive && environmentKind === ENVIRONMENT_PRODUCTION && input.operator_approval_ref == null) {
    return admissionBody(input, DISPOSITION_OPERATOR_GATE, "production destructive design requires operator gate", [
      "production destructive design requires operator gate",
    ], {
      gate: "operator_destructive_production",
      non_reportable: true,
    });
  }
  if (destructive && environmentKind === ENVIRONMENT_SELF_TENANT && !blastRadiusConfined) {
    holdReasons.push("self-tenant destructive design is not blast-radius-confined");
  }
  if (destructive && environmentKind !== ENVIRONMENT_SELF_TENANT && environmentKind !== ENVIRONMENT_REPLICA) {
    holdReasons.push("destructive web instrument is not self-tenant or replica confined");
  }

  if (!isNonEmptyString(input.reset_strength)) holdReasons.push("reset_strength is required");
  else if (RESET_STRENGTH_NON_REPORTABLE.has(input.reset_strength)) {
    holdReasons.push("reset/washout is non-reportable");
  } else if (!RESET_STRENGTH_REPORTABLE.has(input.reset_strength)) {
    holdReasons.push("reset_strength is unknown");
  }

  const fidelityControls = normalizeFidelityControls(input.fidelity_controls, holdReasons);
  if (!isPlainObject(input.post_state_invariant)) holdReasons.push("post_state_invariant is required");

  if (holdReasons.length > 0) {
    return admissionBody(input, DISPOSITION_HOLD, "web instrument admission refused", holdReasons, {
      non_reportable: holdReasons.some((reason) => /reset\/washout|operator|destructive/.test(reason)),
      fidelity_controls: fidelityControls,
    });
  }

  return admissionBody(input, DISPOSITION_ADMITTED, "harness-owned web instrument admitted", [], {
    reset_strength: input.reset_strength,
    reset_witness_ref: input.reset_witness_ref,
    pre_state_ref: input.pre_state_ref,
    pre_state_digest: stateDigest(input.pre_state),
    fidelity_controls: fidelityControls,
  });
}

function normalizeCapture(input, arm, admission, holdReasons) {
  if (!isPlainObject(input)) {
    holdReasons.push(`${arm} capture is required`);
    return null;
  }
  const captureSoftReason = softReason(input);
  if (captureSoftReason) holdReasons.push(`${arm} capture refused: ${captureSoftReason}`);
  if (input.instrument_admitted !== true) holdReasons.push(`${arm} capture was not from an admitted instrument`);
  if (input.barrier_owner !== "harness") holdReasons.push(`${arm} capture barrier_owner is not harness`);
  if (!isPlainObject(input.post_state)) holdReasons.push(`${arm} post_state is required`);
  return {
    version: WEB_INSTRUMENT_PLANE_VERSION,
    target_domain: admission.target_domain,
    surface_id: admission.surface_id,
    object_state_key: admission.object_state_key,
    attempt_id: admission.attempt_id,
    episode_id: admission.episode_id,
    source_plane: "executed",
    arm,
    barrier_owner: input.barrier_owner,
    instrument_admitted: input.instrument_admitted === true,
    response_statuses: Array.isArray(input.response_statuses) ? input.response_statuses.slice() : [],
    pre_state_ref: admission.pre_state_ref,
    pre_state_digest: admission.pre_state_digest,
    post_state_ref: input.post_state_ref || null,
    post_state_digest: stateDigest(input.post_state),
    post_state: cloneJson(input.post_state),
  };
}

function buildWebInstrumentRows(input) {
  const design = isPlainObject(input) && isPlainObject(input.design) ? input.design : input;
  const admission = evaluateWebInstrumentAdmission(design);
  if (admission.disposition !== DISPOSITION_ADMITTED) {
    return deepFreeze({
      admission,
      row_contexts: {},
      schedule_row: null,
      lease_row: null,
      treatment_capture_row: null,
      negative_control_capture_row: null,
    });
  }

  const holdReasons = [];
  const treatment = normalizeCapture(input.treatment_capture, "treatment", admission, holdReasons);
  const negativeControl = normalizeCapture(
    input.negative_control_capture,
    "negative_control",
    admission,
    holdReasons,
  );
  if (holdReasons.length > 0) {
    const captureAdmission = admissionBody(design, DISPOSITION_HOLD, "web instrument capture refused", holdReasons, {
      parent_admission_digest: admission.admission_digest,
    });
    return deepFreeze({
      admission: captureAdmission,
      row_contexts: {},
      schedule_row: null,
      lease_row: null,
      treatment_capture_row: null,
      negative_control_capture_row: null,
    });
  }

  const common = {
    target_domain: admission.target_domain,
    surface_id: admission.surface_id,
    object_state_key: admission.object_state_key,
    attempt_id: admission.attempt_id,
    episode_id: admission.episode_id,
    source_plane: "executed",
  };
  const leaseKey = objectStateLeaseKey({
    targetDomain: admission.target_domain,
    surfaceId: admission.surface_id,
    objectStateKey: admission.object_state_key,
  });

  return deepFreeze({
    admission,
    row_contexts: {
      schedule: RACE_ACTUATOR_SCHEDULE_MAC_CONTEXT,
      lease: OBJECT_STATE_LEASE_ROW_MAC_CONTEXT,
      capture: RACE_ACTUATOR_CAPTURE_MAC_CONTEXT,
    },
    schedule_row: {
      ...common,
      row_id: `${admission.attempt_id}:web-instrument-schedule`,
      class_id: RACE_ACTUATOR_CLASS_ID,
      proof_mode: RACE_ACTUATOR_PROOF_MODE,
      harness_owned: true,
      scheduler_owner: "harness",
      barrier_owner: "harness",
      executor_fired: false,
      instrument_ref: design.instrument_ref,
      instrument_admitted: true,
      environment_kind: admission.environment_kind,
      blast_radius_confined: design.blast_radius_confined === true,
      destructive: design.destructive === true,
      reset_strength: admission.reset_strength,
      reset_witness_ref: admission.reset_witness_ref,
      pre_state_ref: admission.pre_state_ref,
      pre_state_digest: admission.pre_state_digest,
      fidelity_controls: admission.fidelity_controls,
      post_state_invariant: cloneJson(design.post_state_invariant),
    },
    lease_row: {
      ...common,
      row_id: `${admission.attempt_id}:web-object-state-lease`,
      lease_type: "web_object_state",
      lease_key: leaseKey,
      active: true,
      holder: "web-instrument-plane",
      instrument_ref: design.instrument_ref,
    },
    treatment_capture_row: treatment,
    negative_control_capture_row: negativeControl,
  });
}

module.exports = {
  WEB_INSTRUMENT_PLANE_VERSION,
  DISPOSITION_ADMITTED,
  DISPOSITION_HOLD,
  DISPOSITION_OPERATOR_GATE,
  ENVIRONMENT_SELF_TENANT,
  ENVIRONMENT_PRODUCTION,
  ENVIRONMENT_REPLICA,
  FIDELITY_CONTROL_KINDS,
  evaluateWebInstrumentAdmission,
  buildWebInstrumentRows,
};
