"use strict";

// CB-D1 -- deterministic object-authorization differential tester.
//
// The PRIMARY path of the belief engine: where the discriminating controls can be
// run, the verdict is a deterministic AND-over-controls over observed effects -- a
// hard confirmed/denied label, no probability, no LLM, replayable from the recorded
// control outcomes. The verdict feeds CB-C2's causal-support fields on a claim; it
// never records a claim itself (claim authority stays in the claim plane).
//
// Each control's observed `reached` is the only decision input. A control is
// "safe" when its observed reach matches the outcome that rules out its confounder;
// an unsafe discriminating control means the confounder is PRESENT (=> denied). The
// primary effect is the attack: the attacker principal reaching the victim object.

const { hashCanonicalJson } = require("../verification-contracts.js");
const { OBJECT_AUTH_CONTROLS } = require("./intervention-calculus.js");

const DIFFERENTIAL_TESTER_MODEL_VERSION = "belief-differential-tester.v1";
const DISPOSITION_VALUES = Object.freeze(["confirmed", "denied", "inconclusive"]);
// Authorization Bypass Through User-Controlled Key (IDOR).
const DEFAULT_MECHANISM_ID = "CWE-639";

// kind: positive controls must reach to validate the test; discriminating controls
// rule out a confounder when their observed reach equals safe_reached.
const CONTROL_SEMANTICS = Object.freeze({
  attacker_owned_control: { kind: "positive", safe_reached: true },
  victim_auth_same_object: { kind: "positive", safe_reached: true },
  no_auth_same_object: { kind: "discriminating", safe_reached: false, confounder: "public_object" },
  public_object_check: { kind: "discriminating", safe_reached: false, confounder: "public_object" },
  nonexistent_object: { kind: "discriminating", safe_reached: false, confounder: "response_reflection" },
  stale_session_check: { kind: "discriminating", safe_reached: false, confounder: "expired_auth" },
  cache_nonce_check: { kind: "discriminating", safe_reached: true, confounder: "cache_bleed" },
});

function uniqueSorted(values) {
  return Array.from(new Set(values)).sort();
}

// input: { primary_effect: { reached: bool }, controls: { <control>: { reached: bool, evidence_ref? } } }
function evaluateObjectAuthDifferential(input) {
  if (input == null || typeof input !== "object") {
    throw new TypeError("input must be { primary_effect, controls }");
  }
  const primary = input.primary_effect;
  const primaryReached = primary != null && primary.reached === true;
  const controls = input.controls && typeof input.controls === "object" ? input.controls : {};

  const controlsRun = [];
  const ruledOut = [];
  const confoundersPresent = [];
  const missing = [];
  const unruled = [];
  const positiveFailed = [];

  for (const name of OBJECT_AUTH_CONTROLS.slice().sort()) {
    const sem = CONTROL_SEMANTICS[name];
    const obs = controls[name];
    if (obs == null || typeof obs !== "object") {
      missing.push(name);
      if (sem.confounder) unruled.push(sem.confounder);
      continue;
    }
    const reached = obs.reached === true;
    const entry = {
      control: name,
      expected_effect: sem.safe_reached ? "reached" : "blocked",
      observed_effect: reached ? "reached" : "blocked",
    };
    if (typeof obs.evidence_ref === "string" && obs.evidence_ref.length > 0) {
      entry.evidence_ref = obs.evidence_ref;
    }
    controlsRun.push(entry);

    if (sem.kind === "positive") {
      if (reached !== sem.safe_reached) positiveFailed.push(name);
      continue;
    }
    if (reached === sem.safe_reached) ruledOut.push(sem.confounder);
    else confoundersPresent.push(sem.confounder);
  }

  let disposition;
  let reason;
  if (!primaryReached) {
    disposition = "denied";
    reason = "attacker principal did not reach the victim object";
  } else if (positiveFailed.length > 0) {
    disposition = "inconclusive";
    reason = `positive control failed (${positiveFailed.sort().join(", ")}): test setup invalid`;
  } else if (confoundersPresent.length > 0) {
    disposition = "denied";
    reason = `confounder present: ${uniqueSorted(confoundersPresent).join(", ")}`;
  } else if (missing.length > 0) {
    disposition = "inconclusive";
    reason = `missing discriminating controls: ${missing.sort().join(", ")}`;
  } else {
    disposition = "confirmed";
    reason = "attacker principal reached a private victim object; controls rule out public access, reflection, stale auth, and cache bleed";
  }

  const body = {
    model_version: DIFFERENTIAL_TESTER_MODEL_VERSION,
    disposition,
    reason,
    primary_reached: primaryReached,
    controls_run: controlsRun,
    confounders_ruled_out: uniqueSorted(ruledOut),
    confounders_present: uniqueSorted(confoundersPresent),
    missing_controls: missing.slice().sort(),
    unruled_confounders: uniqueSorted(unruled),
    advisory: true,
    derived: true,
    dispatch_authority: false,
    claim_authority: false,
  };
  return Object.freeze({ ...body, verdict_hash: hashCanonicalJson(body) });
}

// Shape a confirmed verdict into the CB-C2 causal-support payload accepted by
// bob_record_candidate_claim. Returns null for non-confirmed verdicts (no claim).
function buildCausalSupport(verdict, { mechanism_id = DEFAULT_MECHANISM_ID } = {}) {
  if (!verdict || verdict.disposition !== "confirmed") return null;
  return {
    mechanism_id,
    intervention: "principal_fixed_object_swap",
    expected_effect: "attacker principal obtains a private read/write effect on a victim object",
    controls_run: verdict.controls_run.map((entry) => ({ ...entry })),
    confounders_ruled_out: verdict.confounders_ruled_out.slice(),
  };
}

module.exports = {
  DIFFERENTIAL_TESTER_MODEL_VERSION,
  DISPOSITION_VALUES,
  CONTROL_SEMANTICS,
  evaluateObjectAuthDifferential,
  buildCausalSupport,
};
