"use strict";

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { MECHANISM_TEMPLATES, TEMPLATES } = require("../mechanism/index.js");
const { beliefSamplesJsonlPath } = require("../io/paths.js");
const { assertBeliefScratchWritePath, _internals } = require("./authority.js");
const { buildBeliefWindow } = require("./belief-window.js");

const FACTOR_GRAPH_MODEL_VERSION = "factor-graph-sampler.v1";
const DEFAULT_SEED = "belief-sampler-default";
const DEFAULT_SAMPLE_COUNT = 256;
const MAX_SAMPLE_COUNT = 4096;
const DEFAULT_CHAIN_DEPTH = 2;
const MAX_CHAIN_DEPTH = 4;
const DEFAULT_RANK_LIMIT = 25;
const MAX_RANK_LIMIT = 100;

function sha256Hex(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function normalizePositiveInteger(value, fallback, max) {
  if (!Number.isInteger(value) || value <= 0) return fallback;
  return Math.min(value, max);
}

function makeRng(seedMaterial) {
  let state = parseInt(sha256Hex(seedMaterial).slice(0, 8), 16) >>> 0;
  return () => {
    state = (state + 0x6D2B79F5) >>> 0;
    let next = state;
    next = Math.imul(next ^ (next >>> 15), next | 1);
    next ^= next + Math.imul(next ^ (next >>> 7), next | 61);
    return ((next ^ (next >>> 14)) >>> 0) / 4294967296;
  };
}

function entropy(distribution) {
  let total = 0;
  for (const value of Object.values(distribution || {})) total += Number(value) || 0;
  if (total <= 0) return 0;
  let result = 0;
  for (const value of Object.values(distribution || {})) {
    const p = (Number(value) || 0) / total;
    if (p > 0) result -= p * Math.log2(p);
  }
  return Number(result.toFixed(6));
}

function normalizeDistribution(distribution) {
  const entries = Object.entries(distribution || {})
    .filter(([, value]) => Number.isFinite(Number(value)) && Number(value) > 0)
    .sort(([a], [b]) => a.localeCompare(b));
  const total = entries.reduce((sum, [, value]) => sum + Number(value), 0);
  if (total <= 0) return Object.freeze({ unknown: 1 });
  return Object.freeze(Object.fromEntries(
    entries.map(([key, value]) => [key, Number((Number(value) / total).toFixed(6))]),
  ));
}

function sampleState(distribution, rng) {
  const normalized = normalizeDistribution(distribution);
  const roll = rng();
  let cumulative = 0;
  const entries = Object.entries(normalized);
  for (const [state, mass] of entries) {
    cumulative += mass;
    if (roll <= cumulative) return state;
  }
  return entries[entries.length - 1][0];
}

function factorWeightForVariable(variableId, factors) {
  let weight = 0;
  for (const factor of factors) {
    if (Array.isArray(factor.variable_ids) && factor.variable_ids.includes(variableId)) {
      weight += Number(factor.weight) || 0;
    }
  }
  return Number(weight.toFixed(6));
}

function inferMarginals(window, { seed = DEFAULT_SEED, sample_count } = {}) {
  const sampleCount = normalizePositiveInteger(sample_count, DEFAULT_SAMPLE_COUNT, MAX_SAMPLE_COUNT);
  const rng = makeRng(`${seed}:${window.window_hash}`);
  const counts = new Map();
  for (const variable of window.variables || []) {
    counts.set(variable.variable_id, Object.fromEntries((variable.states || []).map((state) => [state, 0])));
  }
  for (let sampleIndex = 0; sampleIndex < sampleCount; sampleIndex += 1) {
    for (const variable of window.variables || []) {
      const state = sampleState(variable.posterior, rng);
      const bucket = counts.get(variable.variable_id);
      bucket[state] = (bucket[state] || 0) + 1;
    }
  }
  return Object.freeze((window.variables || []).map((variable) => {
    const marginal = normalizeDistribution(counts.get(variable.variable_id) || {});
    return Object.freeze({
      variable_id: variable.variable_id,
      type: variable.type,
      scope: variable.scope,
      states: variable.states,
      marginal,
      entropy_bits: entropy(marginal),
      factor_weight: factorWeightForVariable(variable.variable_id, window.factors || []),
    });
  }).sort((a, b) => a.variable_id.localeCompare(b.variable_id)));
}

function variableRankScore(marginal) {
  return Number((marginal.entropy_bits + marginal.factor_weight).toFixed(6));
}

function rankFrontierLeaves(window, marginals, limit) {
  const rankLimit = normalizePositiveInteger(limit, DEFAULT_RANK_LIMIT, MAX_RANK_LIMIT);
  return Object.freeze(marginals
    .map((marginal) => Object.freeze({
      rank_id: `belief-leaf:${marginal.variable_id}`,
      variable_id: marginal.variable_id,
      variable_type: marginal.type,
      scope: marginal.scope,
      score: variableRankScore(marginal),
      reason: "entropy_plus_factor_support",
      advisory: true,
    }))
    .sort((a, b) => b.score - a.score || a.variable_id.localeCompare(b.variable_id))
    .slice(0, rankLimit));
}

function interventionCandidates(window, marginals, limit) {
  const byType = new Map(marginals.map((marginal) => [marginal.type, marginal]));
  const rankLimit = normalizePositiveInteger(limit, DEFAULT_RANK_LIMIT, MAX_RANK_LIMIT);
  const candidates = [];
  for (const template of MECHANISM_TEMPLATES.slice().sort((a, b) => a.id.localeCompare(b.id))) {
    const base = byType.get("effective_permission") || byType.get("gate_effectiveness") || marginals[0];
    for (const intervention of template.interventions || []) {
      const score = base ? variableRankScore(base) : 0;
      candidates.push(Object.freeze({
        intervention_id: `${template.id}:${intervention}`,
        template_id: template.id,
        mechanism_id: template.mechanism_id,
        intervention,
        expected_information_gain_bits: Number((score * 0.5).toFixed(6)),
        source_window_hash: window.window_hash,
        advisory: true,
      }));
    }
  }
  return Object.freeze(candidates
    .sort((a, b) => (
      b.expected_information_gain_bits - a.expected_information_gain_bits
      || a.intervention_id.localeCompare(b.intervention_id)
    ))
    .slice(0, rankLimit));
}

function registryTemplateAtoms() {
  const mechanism = MECHANISM_TEMPLATES.map((template) => ({
    template_id: template.id,
    family: "mechanism",
    mechanism_id: template.mechanism_id,
    slots: template.required_entities || [],
  }));
  const invariant = TEMPLATES.map((template) => ({
    template_id: template.id,
    family: "invariant",
    mechanism_id: template.vulnerability_class,
    slots: template.parameter_slots || [],
  }));
  return mechanism.concat(invariant).sort((a, b) => a.template_id.localeCompare(b.template_id));
}

function sharedSlotCount(left, right) {
  const rightSlots = new Set(right.slots || []);
  return (left.slots || []).filter((slot) => rightSlots.has(slot)).length;
}

function searchTemplateCompositions({ window, marginals, chain_depth, limit } = {}) {
  const depth = normalizePositiveInteger(chain_depth, DEFAULT_CHAIN_DEPTH, MAX_CHAIN_DEPTH);
  const rankLimit = normalizePositiveInteger(limit, DEFAULT_RANK_LIMIT, MAX_RANK_LIMIT);
  const atoms = registryTemplateAtoms();
  const averageEntropy = marginals.length
    ? marginals.reduce((sum, marginal) => sum + marginal.entropy_bits, 0) / marginals.length
    : 0;
  const candidates = [];
  for (let i = 0; i < atoms.length; i += 1) {
    for (let j = i + 1; j < atoms.length; j += 1) {
      const left = atoms[i];
      const right = atoms[j];
      const shared = sharedSlotCount(left, right);
      candidates.push(Object.freeze({
        composition_id: sha256Hex(`${window.window_hash}:${left.template_id}:${right.template_id}`).slice(0, 24),
        template_ids: Object.freeze([left.template_id, right.template_id]),
        depth: 2,
        shared_slot_count: shared,
        score: Number((averageEntropy + shared + (left.family === right.family ? 0.1 : 0.25)).toFixed(6)),
        advisory: true,
      }));
    }
  }
  if (depth > 2) {
    for (let i = 0; i < atoms.length && candidates.length < rankLimit * 4; i += 1) {
      const chain = atoms.slice(i, i + depth);
      if (chain.length !== depth) continue;
      candidates.push(Object.freeze({
        composition_id: sha256Hex(`${window.window_hash}:${chain.map((item) => item.template_id).join(">")}`).slice(0, 24),
        template_ids: Object.freeze(chain.map((item) => item.template_id)),
        depth,
        shared_slot_count: 0,
        score: Number((averageEntropy + chain.length * 0.2).toFixed(6)),
        advisory: true,
      }));
    }
  }
  return Object.freeze(candidates
    .sort((a, b) => b.score - a.score || a.composition_id.localeCompare(b.composition_id))
    .slice(0, rankLimit));
}

function buildFactorGraphSample({ window, target_domain, seed = DEFAULT_SEED, sample_count, rank_limit, chain_depth } = {}) {
  const beliefWindow = window || buildBeliefWindow({ target_domain });
  const sampleCount = normalizePositiveInteger(sample_count, DEFAULT_SAMPLE_COUNT, MAX_SAMPLE_COUNT);
  const rankLimit = normalizePositiveInteger(rank_limit, DEFAULT_RANK_LIMIT, MAX_RANK_LIMIT);
  const marginals = inferMarginals(beliefWindow, { seed, sample_count: sampleCount });
  const body = {
    model_version: FACTOR_GRAPH_MODEL_VERSION,
    target_domain: beliefWindow.target_domain,
    window_hash: beliefWindow.window_hash,
    seed: String(seed || DEFAULT_SEED),
    sample_count: sampleCount,
    marginals,
    frontier_leaf_ranking: rankFrontierLeaves(beliefWindow, marginals, rankLimit),
    intervention_ranking: interventionCandidates(beliefWindow, marginals, rankLimit),
    composition_search: searchTemplateCompositions({
      window: beliefWindow,
      marginals,
      chain_depth,
      limit: rankLimit,
    }),
    advisory: true,
    derived: true,
    scratch: true,
    dispatch_authority: false,
    claim_authority: false,
  };
  return Object.freeze({
    ...body,
    sample_hash: sha256Hex(_internals.canonicalJson(body)),
  });
}

function appendJsonl(filePath, record) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.appendFileSync(filePath, `${JSON.stringify(record)}\n`);
}

function runBeliefSampler({ target_domain, seed, sample_count, rank_limit, chain_depth } = {}) {
  const sample = buildFactorGraphSample({ target_domain, seed, sample_count, rank_limit, chain_depth });
  const artifactPath = assertBeliefScratchWritePath({
    target_domain: sample.target_domain,
    file_path: beliefSamplesJsonlPath(sample.target_domain),
  });
  appendJsonl(artifactPath, sample);
  return Object.freeze({
    ...sample,
    artifact_path: artifactPath,
  });
}

function readBeliefSamples({ target_domain, limit = 100 } = {}) {
  const artifactPath = assertBeliefScratchWritePath({
    target_domain,
    file_path: beliefSamplesJsonlPath(target_domain),
  });
  const max = normalizePositiveInteger(limit, 100, 1000);
  if (!fs.existsSync(artifactPath)) {
    return Object.freeze({ target_domain, artifact_path: artifactPath, samples: Object.freeze([]) });
  }
  const samples = fs.readFileSync(artifactPath, "utf8")
    .split(/\n/)
    .filter(Boolean)
    .slice(-max)
    .map((line) => Object.freeze(JSON.parse(line)));
  return Object.freeze({ target_domain, artifact_path: artifactPath, samples: Object.freeze(samples) });
}

module.exports = {
  FACTOR_GRAPH_MODEL_VERSION,
  buildFactorGraphSample,
  inferMarginals,
  readBeliefSamples,
  runBeliefSampler,
  searchTemplateCompositions,
};
