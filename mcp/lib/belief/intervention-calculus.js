"use strict";

const crypto = require("crypto");
const { getMechanismTemplate } = require("../invariant-template-corpus.js");
const { buildBeliefWindow } = require("./belief-window.js");
const { _internals } = require("./authority.js");

const INTERVENTION_CALCULUS_MODEL_VERSION = "intervention-calculus.v1";
const DEFAULT_SEED = "intervention-calculus-default";
const DEFAULT_RANK_LIMIT = 25;
const MAX_RANK_LIMIT = 100;

const OBJECT_AUTH_CONFOUNDERS = Object.freeze([
  "public_object",
  "role_inheritance",
  "expired_auth",
  "cache_bleed",
  "response_reflection",
  "eventual_consistency",
  "egress_drift",
  "policy_allows_delegation",
]);

const OBJECT_AUTH_CONTROLS = Object.freeze([
  "attacker_owned_control",
  "victim_auth_same_object",
  "no_auth_same_object",
  "nonexistent_object",
  "public_object_check",
  "stale_session_check",
  "cache_nonce_check",
]);

function sha256Hex(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function normalizePositiveInteger(value, fallback, max) {
  if (!Number.isInteger(value) || value <= 0) return fallback;
  return Math.min(value, max);
}

function entropy(distribution) {
  let result = 0;
  for (const value of Object.values(distribution || {})) {
    const p = Number(value) || 0;
    if (p > 0) result -= p * Math.log2(p);
  }
  return Number(result.toFixed(6));
}

function effectivePermissionVariables(window) {
  return (window.variables || [])
    .filter((variable) => variable.type === "effective_permission")
    .sort((a, b) => a.variable_id.localeCompare(b.variable_id));
}

// CB-B2 (path A-prime): no regex on the effect id, no hardcoded posterior, no hand
// bonuses. An intervention's expected_state is the EXPERIMENTAL DESIGN (the outcome
// the control should yield if the object-auth hypothesis holds), not a belief
// estimate; the confounder it discriminates is fixed by the control's role.
const EXPECTED_STATE_BY_INTERVENTION = Object.freeze({
  principal_fixed_object_swap: "allowed",
  attacker_owned_control: "allowed",
  victim_auth_same_object: "allowed",
  cache_nonce_check: "allowed",
  no_auth_same_object: "blocked",
  nonexistent_object: "blocked",
  public_object_check: "blocked",
  stale_session_check: "blocked",
});

const CONFOUNDER_BY_INTERVENTION = Object.freeze({
  no_auth_same_object: Object.freeze(["public_object"]),
  public_object_check: Object.freeze(["public_object"]),
  nonexistent_object: Object.freeze(["response_reflection"]),
  stale_session_check: Object.freeze(["expired_auth"]),
  cache_nonce_check: Object.freeze(["cache_bleed"]),
});

// victim_auth_same_object needs the victim's credential, so it is not runnable by
// default; the caller passes the runnable set derived from available auth profiles.
function defaultRunnable(interventions) {
  return interventions.filter((i) => i !== "victim_auth_same_object");
}

function candidateDoOperation(variable, intervention) {
  if (intervention === "principal_fixed_object_swap") {
    return Object.freeze({
      operation: "do",
      assignment: "selector := victim_object",
      fixed: Object.freeze(["principal", "auth_profile"]),
      variable_id: variable.variable_id,
    });
  }
  if (intervention === "public_object_check") {
    return Object.freeze({
      operation: "do",
      assignment: "selector := known_public_object",
      fixed: Object.freeze(["principal", "auth_profile"]),
      variable_id: variable.variable_id,
    });
  }
  return Object.freeze({
    operation: "do",
    assignment: intervention,
    fixed: Object.freeze(["principal", "auth_profile"]),
    variable_id: variable.variable_id,
  });
}

function buildCandidate({ template, variable, intervention }) {
  const beliefEntropy = entropy(variable.posterior);
  const expectedState = EXPECTED_STATE_BY_INTERVENTION[intervention] || "allowed";
  return Object.freeze({
    candidate_id: sha256Hex(`${variable.variable_id}:${intervention}`).slice(0, 24),
    template_id: template.id,
    mechanism_id: template.mechanism_id,
    variable_id: variable.variable_id,
    scope: variable.scope,
    intervention,
    do_operation: candidateDoOperation(variable, intervention),
    predicted_effect: Object.freeze({ expected_state: expectedState }),
    // Value of information: the most a discriminating test can resolve is the current
    // entropy of the (elicited-or-uniform) belief over this latent. A function of the
    // elicited belief -- no hand bonuses, no fabricated posterior.
    expected_information_gain_bits: beliefEntropy,
    belief_entropy_bits: beliefEntropy,
    prior_source: variable.prior_source || "uniform",
    confounders_discriminated: CONFOUNDER_BY_INTERVENTION[intervention] || Object.freeze([]),
    controls: OBJECT_AUTH_CONTROLS,
    advisory: true,
  });
}

function rankInterventions({ window, target_domain, template_id = "object_authorization", seed = DEFAULT_SEED, rank_limit, runnable_controls } = {}) {
  const beliefWindow = window || buildBeliefWindow({ target_domain, template_id });
  const template = getMechanismTemplate(template_id);
  if (!template) throw new Error(`unknown mechanism template: ${template_id}`);
  const rankLimit = normalizePositiveInteger(rank_limit, DEFAULT_RANK_LIMIT, MAX_RANK_LIMIT);
  const variables = effectivePermissionVariables(beliefWindow);
  const allInterventions = Array.from(new Set([
    ...template.interventions,
    ...OBJECT_AUTH_CONTROLS,
  ]));
  const runnableSet = Array.isArray(runnable_controls) && runnable_controls.length > 0
    ? new Set(runnable_controls)
    : new Set(defaultRunnable(allInterventions));
  const interventions = allInterventions.filter((i) => runnableSet.has(i)).sort();
  const candidates = [];
  for (const variable of variables) {
    for (const intervention of interventions) {
      candidates.push(buildCandidate({ template, variable, intervention }));
    }
  }
  const ranking = Object.freeze(candidates
    .sort((a, b) => (
      b.expected_information_gain_bits - a.expected_information_gain_bits
      || a.intervention.localeCompare(b.intervention)
      || a.variable_id.localeCompare(b.variable_id)
    ))
    .slice(0, rankLimit));
  const body = {
    model_version: INTERVENTION_CALCULUS_MODEL_VERSION,
    target_domain: beliefWindow.target_domain,
    window_hash: beliefWindow.window_hash,
    seed: String(seed || DEFAULT_SEED),
    template_id: template.id,
    mechanism_id: template.mechanism_id,
    confounders: OBJECT_AUTH_CONFOUNDERS,
    controls: OBJECT_AUTH_CONTROLS,
    runnable_controls: interventions,
    ranking,
    advisory: true,
    derived: true,
    writes_artifacts: false,
    dispatch_authority: false,
    claim_authority: false,
  };
  return Object.freeze({
    ...body,
    calculus_hash: sha256Hex(_internals.canonicalJson(body)),
  });
}

module.exports = {
  INTERVENTION_CALCULUS_MODEL_VERSION,
  OBJECT_AUTH_CONFOUNDERS,
  OBJECT_AUTH_CONTROLS,
  rankInterventions,
};
