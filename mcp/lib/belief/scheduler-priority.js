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

const BELIEF_SCHEDULER_MODEL_VERSION = "belief-scheduler-priority.v1";
const DEFAULT_RANK_LIMIT = 25;

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
      if (hint && hint.non_gating === true) {
        return {
          residual_hash: payload.residual_hash || null,
          residual_score: typeof hint.score === "number" ? hint.score : null,
          residual_band: typeof hint.band === "string" ? hint.band : null,
        };
      }
    }
  } catch {}
  return null;
}

function scoreForCandidate(candidate, residualHint) {
  const informationGain = Number(candidate && candidate.expected_information_gain_bits) || 0;
  const residualBoost = residualHint && typeof residualHint.residual_score === "number"
    ? Math.min(15, Math.round(residualHint.residual_score * 5))
    : 0;
  return Math.max(0, Math.min(100, Math.round(45 + informationGain * 30 + residualBoost)));
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
  const hints = [];
  for (const surface of surfaceList) {
    const candidate = (calculus.ranking || []).find((entry) => candidateMatchesSurface(entry, surface));
    if (!candidate) continue;
    hints.push({
      surface_id: surface.id,
      score: scoreForCandidate(candidate, residualHint),
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
