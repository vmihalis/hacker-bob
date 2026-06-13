"use strict";

const crypto = require("crypto");
const {
  buildFactorGraphSample,
} = require("./factor-graph.js");
const {
  writeBeliefSignalScratch,
  _internals,
} = require("./authority.js");

const RESIDUAL_MODEL_VERSION = "belief-residual.v1";
const DEFAULT_DECOMPOSITION_LIMIT = 25;
const MAX_DECOMPOSITION_LIMIT = 100;

function sha256Hex(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function normalizePositiveInteger(value, fallback, max) {
  if (!Number.isInteger(value) || value <= 0) return fallback;
  return Math.min(value, max);
}

function maxMass(distribution) {
  let max = 0;
  for (const value of Object.values(distribution || {})) {
    const number = Number(value) || 0;
    if (number > max) max = number;
  }
  return max;
}

function negativeLog2Likelihood(probability) {
  const p = Math.max(Number(probability) || 0, 1e-9);
  return Number((-Math.log2(p)).toFixed(6));
}

function decomposeMarginal(marginal) {
  const likelihood = maxMass(marginal.marginal);
  const surprise = negativeLog2Likelihood(likelihood);
  const score = Number((surprise + marginal.entropy_bits).toFixed(6));
  return Object.freeze({
    variable_id: marginal.variable_id,
    variable_type: marginal.type,
    scope: marginal.scope,
    likelihood,
    negative_log2_likelihood: surprise,
    entropy_bits: marginal.entropy_bits,
    residual_score: score,
    reason: "low_max_marginal_mass_plus_entropy",
  });
}

function classifyResidual(score) {
  if (score >= 1.5) return "high";
  if (score >= 0.75) return "medium";
  return "low";
}

function buildResidualDiagnostic({
  sample,
  target_domain,
  seed,
  sample_count,
  rank_limit,
  chain_depth,
  decomposition_limit,
} = {}) {
  const factorSample = sample || buildFactorGraphSample({
    target_domain,
    seed,
    sample_count,
    rank_limit,
    chain_depth,
  });
  const limit = normalizePositiveInteger(
    decomposition_limit,
    DEFAULT_DECOMPOSITION_LIMIT,
    MAX_DECOMPOSITION_LIMIT,
  );
  const decomposition = Object.freeze((factorSample.marginals || [])
    .map(decomposeMarginal)
    .sort((a, b) => b.residual_score - a.residual_score || a.variable_id.localeCompare(b.variable_id))
    .slice(0, limit));
  const residualScore = decomposition.length
    ? Number((decomposition.reduce((sum, item) => sum + item.residual_score, 0) / decomposition.length).toFixed(6))
    : 0;
  const body = {
    model_version: RESIDUAL_MODEL_VERSION,
    target_domain: factorSample.target_domain,
    window_hash: factorSample.window_hash,
    sample_hash: factorSample.sample_hash,
    seed: factorSample.seed,
    sample_count: factorSample.sample_count,
    residual_score: residualScore,
    residual_band: classifyResidual(residualScore),
    provenance: "residual_anomaly",
    role: "diagnostic",
    decomposition,
    priority_hint: Object.freeze({
      sink: "CB-C1",
      score: residualScore,
      band: classifyResidual(residualScore),
      non_gating: true,
      dispatch_authority: false,
    }),
    human_router_record: Object.freeze({
      route: "human_review",
      summary: `Residual ${classifyResidual(residualScore)}: modeled templates explain the top marginals with score ${residualScore}`,
      decomposition_count: decomposition.length,
      non_gating: true,
    }),
    advisory: true,
    derived: true,
    scratch: true,
    claim_authority: false,
    dispatch_authority: false,
    template_promotion_authority: false,
  };
  return Object.freeze({
    ...body,
    residual_hash: sha256Hex(_internals.canonicalJson(body)),
  });
}

function runBeliefResidual({ target_domain, seed, sample_count, rank_limit, chain_depth, decomposition_limit } = {}) {
  const diagnostic = buildResidualDiagnostic({
    target_domain,
    seed,
    sample_count,
    rank_limit,
    chain_depth,
    decomposition_limit,
  });
  const signal = writeBeliefSignalScratch({
    target_domain: diagnostic.target_domain,
    kind: "belief_signal",
    source: "mcp/lib/belief/residual.js#runBeliefResidual",
    provenance: "residual_anomaly",
    artifact_ref: `belief_sample:${diagnostic.sample_hash}`,
    role: "diagnostic",
    payload: {
      model_version: diagnostic.model_version,
      residual_hash: diagnostic.residual_hash,
      window_hash: diagnostic.window_hash,
      sample_hash: diagnostic.sample_hash,
      residual_score: diagnostic.residual_score,
      residual_band: diagnostic.residual_band,
      decomposition: diagnostic.decomposition,
      priority_hint: diagnostic.priority_hint,
      human_router_record: diagnostic.human_router_record,
      claim_authority: false,
      dispatch_authority: false,
      template_promotion_authority: false,
    },
  });
  return Object.freeze({
    ...diagnostic,
    signal_hash: signal.signal_hash,
    artifact_path: signal.artifact_path,
  });
}

module.exports = {
  RESIDUAL_MODEL_VERSION,
  buildResidualDiagnostic,
  runBeliefResidual,
};
