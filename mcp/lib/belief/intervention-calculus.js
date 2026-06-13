"use strict";

const crypto = require("crypto");
const { getMechanismTemplate } = require("../invariant-template-corpus.js");
const { buildBeliefWindow } = require("./belief-window.js");
const { inferMarginals } = require("./factor-graph.js");
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

function isPublicObject(variable) {
  return /public[_:-]?object|public/i.test(String(variable.scope && variable.scope.effect_id));
}

function isIdorLike(variable) {
  return /unauth_succeeds_where_auth_blocked|idor|object_authorization|victim/i.test(String(variable.scope && variable.scope.effect_id));
}

function posteriorForCandidate(variable, intervention) {
  if (intervention === "public_object_check") {
    return isPublicObject(variable)
      ? Object.freeze({ public_access: 0.78, idor: 0.08, unknown: 0.14 })
      : Object.freeze({ public_access: 0.18, idor: 0.62, unknown: 0.20 });
  }
  if (intervention === "principal_fixed_object_swap") {
    return isIdorLike(variable)
      ? Object.freeze({ allowed: 0.90, blocked: 0.06, unknown: 0.04 })
      : Object.freeze({ allowed: 0.44, blocked: 0.22, unknown: 0.34 });
  }
  if (intervention === "attacker_owned_control") {
    return Object.freeze({ allowed: 0.74, blocked: 0.08, unknown: 0.18 });
  }
  if (intervention === "victim_auth_same_object") {
    return Object.freeze({ allowed: 0.80, blocked: 0.08, unknown: 0.12 });
  }
  if (intervention === "no_auth_same_object") {
    return Object.freeze({ allowed: 0.36, blocked: 0.42, unknown: 0.22 });
  }
  if (intervention === "nonexistent_object") {
    return Object.freeze({ allowed: 0.10, blocked: 0.78, unknown: 0.12 });
  }
  if (intervention === "stale_session_check") {
    return Object.freeze({ allowed: 0.22, blocked: 0.50, unknown: 0.28 });
  }
  return Object.freeze({ allowed: 0.30, blocked: 0.35, unknown: 0.35 });
}

function candidateScore({ variable, intervention, baselineEntropy, posteriorEntropy }) {
  const entropyGain = Math.max(0, baselineEntropy - posteriorEntropy);
  let bonus = 0;
  if (intervention === "principal_fixed_object_swap" && isIdorLike(variable)) bonus += 0.75;
  if (intervention === "public_object_check" && isPublicObject(variable)) bonus += 1.0;
  if (intervention === "attacker_owned_control") bonus -= 0.25;
  return Number((entropyGain + bonus).toFixed(6));
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
  const baselineEntropy = entropy(variable.posterior);
  const posterior = posteriorForCandidate(variable, intervention);
  const posteriorEntropy = entropy(posterior);
  const score = candidateScore({ variable, intervention, baselineEntropy, posteriorEntropy });
  return Object.freeze({
    candidate_id: sha256Hex(`${variable.variable_id}:${intervention}`).slice(0, 24),
    template_id: template.id,
    mechanism_id: template.mechanism_id,
    variable_id: variable.variable_id,
    intervention,
    do_operation: candidateDoOperation(variable, intervention),
    predicted_effect: Object.freeze({
      distribution: posterior,
      expected_state: Object.entries(posterior).sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))[0][0],
    }),
    posterior_delta: Object.freeze({
      baseline_entropy_bits: baselineEntropy,
      posterior_entropy_bits: posteriorEntropy,
      entropy_reduction_bits: Number(Math.max(0, baselineEntropy - posteriorEntropy).toFixed(6)),
    }),
    expected_information_gain_bits: score,
    confounders_discriminated: Object.freeze(intervention === "public_object_check"
      ? ["public_object", "response_reflection"]
      : ["role_inheritance", "cache_bleed", "eventual_consistency"]),
    controls: OBJECT_AUTH_CONTROLS,
    advisory: true,
  });
}

function rankInterventions({ window, target_domain, template_id = "object_authorization", seed = DEFAULT_SEED, rank_limit } = {}) {
  const beliefWindow = window || buildBeliefWindow({ target_domain, template_id });
  const template = getMechanismTemplate(template_id);
  if (!template) throw new Error(`unknown mechanism template: ${template_id}`);
  const rankLimit = normalizePositiveInteger(rank_limit, DEFAULT_RANK_LIMIT, MAX_RANK_LIMIT);
  const variables = effectivePermissionVariables(beliefWindow);
  const marginals = inferMarginals(beliefWindow, { seed, sample_count: 256 });
  const interventions = Array.from(new Set([
    ...template.interventions,
    ...OBJECT_AUTH_CONTROLS,
  ])).sort();
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
    marginal_count: marginals.length,
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
