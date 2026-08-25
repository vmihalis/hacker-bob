"use strict";

const {
  priorityFromScore,
  priorityRank,
} = require("../ranking.js");
const {
  rankInterventions,
} = require("./intervention-calculus.js");
const {
  queryBeliefSignals,
} = require("./authority.js");
const {
  readBeliefModelInfo,
} = require("./model.js");
const {
  applyRecalibration,
} = require("./recalibration.js");

const BELIEF_SCHEDULER_MODEL_VERSION = "belief-scheduler-priority.v1";
const DEFAULT_RANK_LIMIT = 25;

// Circularity guard (scheduler side): a residual is built by sampling the
// belief window's OWN marginals, so on its own it is self-generated belief. The only
// outcomes allowed to move dispatch order are EXECUTED ones, so a residual hint is
// admitted here ONLY when its provenance chain traces to an executed outcome — a
// verified_intervention signal, a realized dead-end, or a realized-vs-predicted
// coverage delta — cited via {kind, artifact_ref} in the residual_anomaly payload.
// A residual with no executed citation returns NO hint (residualBoost stays 0).
const ADMISSIBLE_RESIDUAL_PROVENANCE_KINDS = Object.freeze([
  "verified_intervention",
  "dead_end",
  "coverage_delta",
]);

function executedProvenanceChain(payload) {
  const hint = payload && payload.priority_hint;
  const fromHint = hint && Array.isArray(hint.executed_provenance) ? hint.executed_provenance : null;
  const raw = fromHint || (Array.isArray(payload && payload.executed_provenance) ? payload.executed_provenance : []);
  return raw.filter((entry) => (
    entry && typeof entry === "object"
    && ADMISSIBLE_RESIDUAL_PROVENANCE_KINDS.includes(entry.kind)
    && typeof entry.artifact_ref === "string"
    && entry.artifact_ref.trim().length > 0
  ));
}

function textTokens(value) {
  return String(value == null ? "" : value)
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter((token) => token.length >= 3);
}

function surfaceText(surface) {
  const parts = [
    surface && surface.id,
    surface && surface.title,
    surface && surface.name,
    ...(Array.isArray(surface && surface.hosts) ? surface.hosts : []),
    ...(Array.isArray(surface && surface.endpoints) ? surface.endpoints : []),
    ...(Array.isArray(surface && surface.evidence) ? surface.evidence : []),
    ...(Array.isArray(surface && surface.bug_class_hints) ? surface.bug_class_hints : []),
    ...(Array.isArray(surface && surface.high_value_flows) ? surface.high_value_flows : []),
    ...(Array.isArray(surface && surface.interesting_params) ? surface.interesting_params : []),
  ];
  return parts.join("\n").toLowerCase();
}

function candidateTokens(candidate) {
  const scope = candidate && candidate.scope && typeof candidate.scope === "object"
    ? candidate.scope
    : {};
  return new Set([
    ...textTokens(candidate && candidate.intervention),
    ...textTokens(candidate && candidate.variable_id),
    ...textTokens(scope.effect_id),
    ...textTokens(scope.policy_gate_id),
    ...textTokens(scope.principal_id),
  ]);
}

function candidateMatchesSurface(candidate, surface) {
  const text = surfaceText(surface);
  if (!text) return false;
  for (const token of candidateTokens(candidate)) {
    if (text.includes(token)) return true;
  }
  return false;
}

function latestResidualHint(targetDomain) {
  try {
    const read = queryBeliefSignals({
      target_domain: targetDomain,
      provenance: "residual_anomaly",
      role: "diagnostic",
      limit: 25,
    });
    const signals = Array.isArray(read.signals) ? read.signals : [];
    for (let i = signals.length - 1; i >= 0; i -= 1) {
      const payload = signals[i] && signals[i].payload;
      const hint = payload && payload.priority_hint;
      if (!hint || hint.non_gating !== true) continue;
      // Admit a residual hint ONLY when its provenance chain traces to an
      // executed outcome. A self-sampled-only residual (no executed citation) is
      // skipped so belief can never reorder dispatch from belief.
      const executedProvenance = executedProvenanceChain(payload);
      if (executedProvenance.length === 0) continue;
      return {
        residual_hash: payload.residual_hash || null,
        residual_score: typeof hint.score === "number" ? hint.score : null,
        residual_band: typeof hint.band === "string" ? hint.band : null,
        executed_provenance: executedProvenance,
      };
    }
  } catch {}
  return null;
}

// Model loop (advisory + deterministic): the trained belief model is an
// isotonic RECALIBRATION map fit against EXECUTED labels (grade verdicts /
// verification-round outcomes — see model.js trainBeliefModel.label_source), never
// belief. We load it read-only and apply it to ORDER only: the recalibrated value is
// a monotonic re-map of the candidate's information-gain proxy that breaks ties and
// nudges score, but it gates nothing (no verdict/closure/claim) and, being a function
// of the pinned model_hash, is replayable (same model_hash + same signals => identical
// order). When the model is absent or the map is identity (needs_more_data), the value
// is the raw proxy and order is byte-identical to the no-model path.
function loadRecalibrationModel(targetDomain) {
  try {
    const info = readBeliefModelInfo({ target_domain: targetDomain });
    if (!info || !info.exists || !info.model) return null;
    const model = info.model;
    const map = model.recalibration_map;
    if (!map || typeof map !== "object") return null;
    return {
      model_hash: typeof model.model_hash === "string" ? model.model_hash : null,
      model_id: typeof model.model_id === "string" ? model.model_id : null,
      label_source: typeof model.label_source === "string" ? model.label_source : null,
      recalibration_map: map,
      needs_more_data: Boolean(map.needs_more_data),
    };
  } catch {
    return null;
  }
}

function scoreForCandidate(candidate, residualHint, model) {
  const informationGain = Number(candidate && candidate.expected_information_gain_bits) || 0;
  const residualBoost = residualHint && typeof residualHint.residual_score === "number"
    ? Math.min(15, Math.round(residualHint.residual_score * 5))
    : 0;
  const base = Math.round(45 + informationGain * 30 + residualBoost);
  // Advisory recalibration: re-map the EIG proxy ([0,1]) through the
  // executed-label-trained isotonic map and fold the (monotonic) delta back as a
  // bounded order nudge. Identity map / absent model => modelBoost 0 (no-op).
  let modelBoost = 0;
  if (model && model.recalibration_map) {
    const proxy = Math.max(0, Math.min(1, informationGain));
    const recalibrated = applyRecalibration(model.recalibration_map, proxy);
    modelBoost = Math.round((recalibrated - proxy) * 10);
  }
  return Math.max(0, Math.min(100, base + modelBoost));
}

function existingRanking(surface) {
  return surface && surface.ranking && typeof surface.ranking === "object" && !Array.isArray(surface.ranking)
    ? surface.ranking
    : {};
}

function mergeReasons(existing, additions) {
  const out = [];
  const seen = new Set();
  for (const reason of [...(Array.isArray(existing) ? existing : []), ...additions]) {
    if (typeof reason !== "string" || !reason || seen.has(reason)) continue;
    seen.add(reason);
    out.push(reason);
  }
  return out.slice(0, 12);
}

function decorateSurface(surface, hint) {
  const ranking = existingRanking(surface);
  const existingScore = typeof ranking.score === "number" && Number.isFinite(ranking.score)
    ? ranking.score
    : 0;
  const score = Math.max(existingScore, hint.score);
  const beliefPriority = priorityFromScore(score);
  const existingPriority = String(surface && surface.priority || "LOW").toUpperCase();
  const nextPriority = priorityRank(beliefPriority) > priorityRank(existingPriority)
    ? beliefPriority
    : existingPriority;
  const nextSurface = {
    ...surface,
    ranking: {
      ...ranking,
      version: 1,
      score,
      priority: beliefPriority,
      reasons: mergeReasons(ranking.reasons, ["belief_expected_information_gain"]),
      score_reasons: mergeReasons(ranking.score_reasons, ["belief_expected_information_gain"]),
      belief: {
        model_version: BELIEF_SCHEDULER_MODEL_VERSION,
        calculus_hash: hint.calculus_hash,
        window_hash: hint.window_hash,
        candidate_id: hint.candidate.candidate_id,
        variable_id: hint.candidate.variable_id,
        intervention: hint.candidate.intervention,
        expected_information_gain_bits: hint.candidate.expected_information_gain_bits,
        residual_hash: hint.residual_hint ? hint.residual_hint.residual_hash : null,
        non_gating: true,
        dispatch_authority: false,
      },
    },
  };
  if (nextPriority !== existingPriority) {
    if (!nextSurface.original_priority) nextSurface.original_priority = existingPriority;
    nextSurface.priority = nextPriority;
  }
  return nextSurface;
}

function buildBeliefSchedulerHints({
  target_domain,
  surfaces,
  seed,
  rank_limit,
} = {}) {
  const targetDomain = typeof target_domain === "string" && target_domain.trim()
    ? target_domain.trim()
    : null;
  if (!targetDomain) {
    return {
      enabled: false,
      applied: false,
      hint_count: 0,
      reason: "missing_target_domain",
      hints: [],
    };
  }
  const surfaceList = Array.isArray(surfaces) ? surfaces : [];
  if (surfaceList.length === 0) {
    return {
      enabled: true,
      applied: false,
      hint_count: 0,
      reason: "no_surfaces",
      hints: [],
    };
  }
  let calculus;
  try {
    calculus = rankInterventions({
      target_domain: targetDomain,
      seed: seed || "belief-scheduler-priority",
      rank_limit: rank_limit || DEFAULT_RANK_LIMIT,
    });
  } catch (error) {
    return {
      enabled: true,
      applied: false,
      hint_count: 0,
      reason: "belief_ranking_unavailable",
      error: error.message || String(error),
      hints: [],
    };
  }
  const residualHint = latestResidualHint(targetDomain);
  const model = loadRecalibrationModel(targetDomain);
  const hints = [];
  for (const surface of surfaceList) {
    const candidate = (calculus.ranking || []).find((entry) => candidateMatchesSurface(entry, surface));
    if (!candidate) continue;
    hints.push({
      surface_id: surface.id,
      score: scoreForCandidate(candidate, residualHint, model),
      candidate,
      calculus_hash: calculus.calculus_hash,
      window_hash: calculus.window_hash,
      residual_hint: residualHint,
    });
  }
  hints.sort((a, b) => (
    b.score - a.score
    || b.candidate.expected_information_gain_bits - a.candidate.expected_information_gain_bits
    || String(a.surface_id).localeCompare(String(b.surface_id))
  ));
  return {
    enabled: true,
    applied: hints.length > 0,
    hint_count: hints.length,
    model_version: BELIEF_SCHEDULER_MODEL_VERSION,
    calculus_hash: calculus.calculus_hash,
    window_hash: calculus.window_hash,
    residual_hash: residualHint ? residualHint.residual_hash : null,
    // Replayability pin: the exact model + fed-signal set that produced this
    // order. A run replays identically iff these match; a different model_hash is
    // RECORDED here (not silently consumed) so an audit can see the order moved.
    belief_replay: {
      model_hash: model ? model.model_hash : null,
      model_id: model ? model.model_id : null,
      model_label_source: model ? model.label_source : null,
      model_needs_more_data: model ? model.needs_more_data : null,
      fed_signals: {
        calculus_hash: calculus.calculus_hash,
        window_hash: calculus.window_hash,
        residual_hash: residualHint ? residualHint.residual_hash : null,
        residual_admitted: Boolean(residualHint),
      },
    },
    reason: hints.length > 0 ? "belief_hints_applied" : "no_surface_match",
    hints,
  };
}

function applyBeliefSchedulerPriority({
  target_domain,
  surfaces,
  enabled = false,
  seed,
  rank_limit,
} = {}) {
  const surfaceList = Array.isArray(surfaces) ? surfaces : [];
  if (enabled !== true) {
    return {
      surfaces: surfaceList,
      metadata: {
        enabled: false,
        applied: false,
        hint_count: 0,
        reason: "disabled",
      },
    };
  }
  const metadata = buildBeliefSchedulerHints({
    target_domain,
    surfaces: surfaceList,
    seed,
    rank_limit,
  });
  if (!metadata.applied) {
    return { surfaces: surfaceList, metadata };
  }
  const bySurfaceId = new Map(metadata.hints.map((hint) => [hint.surface_id, hint]));
  return {
    surfaces: surfaceList.map((surface) => {
      const hint = bySurfaceId.get(surface.id);
      return hint ? decorateSurface(surface, hint) : surface;
    }),
    metadata: {
      ...metadata,
      hints: metadata.hints.map((hint) => ({
        surface_id: hint.surface_id,
        score: hint.score,
        candidate_id: hint.candidate.candidate_id,
        variable_id: hint.candidate.variable_id,
        intervention: hint.candidate.intervention,
        expected_information_gain_bits: hint.candidate.expected_information_gain_bits,
      })),
    },
  };
}

module.exports = {
  BELIEF_SCHEDULER_MODEL_VERSION,
  applyBeliefSchedulerPriority,
  buildBeliefSchedulerHints,
};
