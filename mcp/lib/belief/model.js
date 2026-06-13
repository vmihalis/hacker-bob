"use strict";

const fs = require("fs");
const path = require("path");
const {
  assertSafeDomain,
  beliefModelInfoPath,
  gradeArtifactPaths,
  verificationRoundPaths,
} = require("../paths.js");
const {
  readJsonFile,
  writeFileAtomic,
} = require("../storage.js");
const {
  hashCanonicalJson,
} = require("../verification-contracts.js");
const {
  readCandidateClaims,
} = require("../claims.js");

const BELIEF_MODEL_VERSION = "belief-calibrated-factors.v1";
const FEATURE_NAMES = Object.freeze([
  "bias",
  "causal_support_present",
  "controls_run_count",
  "confounders_ruled_out_count",
  "final_confirmed",
  "final_reportable",
  "final_confidence_high",
  "fresh_replay_passed",
  "missing_control",
  "unruled_confounder",
]);

function sigmoid(x) {
  return 1 / (1 + Math.exp(-Math.max(-30, Math.min(30, x))));
}

function logit(p) {
  const clamped = Math.max(0.001, Math.min(0.999, p));
  return Math.log(clamped / (1 - clamped));
}

function readJsonSafe(filePath) {
  try {
    if (!fs.existsSync(filePath)) return null;
    return readJsonFile(filePath, { label: path.basename(filePath) });
  } catch {
    return null;
  }
}

function findingIdForClaim(claim) {
  for (const ref of Array.isArray(claim && claim.evidence_refs) ? claim.evidence_refs : []) {
    if (ref && ref.kind === "finding" && typeof ref.finding_id === "string") return ref.finding_id;
  }
  return null;
}

function finalResultsByFinding(domain) {
  const doc = readJsonSafe(verificationRoundPaths(domain, "final").json);
  const byId = new Map();
  for (const result of Array.isArray(doc && doc.results) ? doc.results : []) {
    if (result && typeof result.finding_id === "string") byId.set(result.finding_id, result);
  }
  return byId;
}

function gradeScoresByFinding(domain) {
  const doc = readJsonSafe(gradeArtifactPaths(domain).json);
  const byId = new Map();
  for (const result of Array.isArray(doc && doc.findings) ? doc.findings : []) {
    if (result && typeof result.finding_id === "string") byId.set(result.finding_id, result);
  }
  return { verdict: doc && typeof doc.verdict === "string" ? doc.verdict : null, byId };
}

function featureVector({ claim, finalResult }) {
  const support = claim && claim.payload && claim.payload.causal_support;
  const reasons = Array.isArray(finalResult && finalResult.confidence_reasons)
    ? finalResult.confidence_reasons
    : [];
  return {
    bias: 1,
    causal_support_present: support && typeof support === "object" ? 1 : 0,
    controls_run_count: Math.min(5, Array.isArray(support && support.controls_run) ? support.controls_run.length : 0),
    confounders_ruled_out_count: Math.min(5, Array.isArray(support && support.confounders_ruled_out) ? support.confounders_ruled_out.length : 0),
    final_confirmed: finalResult && finalResult.disposition === "confirmed" ? 1 : 0,
    final_reportable: finalResult && finalResult.reportable === true ? 1 : 0,
    final_confidence_high: finalResult && finalResult.confidence === "high" ? 1 : 0,
    fresh_replay_passed: reasons.includes("fresh_replay_passed") ? 1 : 0,
    missing_control: reasons.includes("missing_control") ? 1 : 0,
    unruled_confounder: reasons.includes("unruled_confounder") ? 1 : 0,
  };
}

function labelFor({ finalResult, gradeResult, gradeVerdict }) {
  if (gradeResult && Number.isInteger(gradeResult.total_score)) return gradeResult.total_score >= 40 ? 1 : 0;
  if (gradeVerdict === "SUBMIT") return 1;
  if (!finalResult) return null;
  if (finalResult.reportable === true && finalResult.disposition === "confirmed") return 1;
  if (finalResult.reportable === false || finalResult.disposition === "denied") return 0;
  return null;
}

function normalizeOptionalModelId(value) {
  if (value == null || value === "") return null;
  if (typeof value !== "string") throw new Error("model_id must be a string when present");
  const trimmed = value.trim();
  if (!/^[A-Za-z0-9._:-]{1,80}$/.test(trimmed)) {
    throw new Error("model_id must be 1-80 chars of letters, digits, dot, underscore, colon, or hyphen");
  }
  return trimmed;
}

function examplesForDomain(domain) {
  let claims;
  try {
    claims = readCandidateClaims(domain);
  } catch {
    return [];
  }
  const finals = finalResultsByFinding(domain);
  const grade = gradeScoresByFinding(domain);
  const examples = [];
  for (const claim of claims) {
    const findingId = findingIdForClaim(claim);
    if (!findingId) continue;
    const finalResult = finals.get(findingId) || null;
    const gradeResult = grade.byId.get(findingId) || null;
    const label = labelFor({ finalResult, gradeResult, gradeVerdict: grade.verdict });
    if (label == null) continue;
    examples.push({
      target_domain: domain,
      claim_id: claim.claim_id,
      finding_id: findingId,
      label,
      features: featureVector({ claim, finalResult }),
    });
  }
  return examples;
}

function normalizeDomains(value, fieldName) {
  if (!Array.isArray(value) || value.length === 0) {
    throw new Error(`${fieldName} must be a non-empty array`);
  }
  const seen = new Set();
  const out = [];
  for (const item of value) {
    if (typeof item !== "string" || !item.trim()) throw new Error(`${fieldName} entries must be non-empty strings`);
    const domain = assertSafeDomain(item.trim());
    if (!seen.has(domain)) {
      seen.add(domain);
      out.push(domain);
    }
  }
  return out.sort((a, b) => a.localeCompare(b));
}

function collectExamples(domains) {
  return domains.flatMap((domain) => examplesForDomain(domain));
}

function featureStats(examples, feature) {
  const positives = examples.filter((item) => item.label === 1);
  const negatives = examples.filter((item) => item.label === 0);
  const mean = (items) => {
    if (items.length === 0) return 0;
    return items.reduce((sum, item) => sum + (Number(item.features[feature]) || 0), 0) / items.length;
  };
  return { pos: mean(positives), neg: mean(negatives) };
}

function trainWeights(examples) {
  const positives = examples.filter((item) => item.label === 1).length;
  const baseRate = examples.length > 0 ? positives / examples.length : 0.5;
  const weights = { bias: Number(logit(baseRate).toFixed(6)) };
  for (const feature of FEATURE_NAMES.filter((name) => name !== "bias")) {
    const stats = featureStats(examples, feature);
    weights[feature] = Number(((stats.pos - stats.neg) * 2).toFixed(6));
  }
  return weights;
}

function scoreExample(example, weights) {
  let z = weights.bias || 0;
  for (const feature of FEATURE_NAMES.filter((name) => name !== "bias")) {
    z += (weights[feature] || 0) * (Number(example.features[feature]) || 0);
  }
  return sigmoid(z);
}

function handScore(example) {
  let score = 0.2;
  score += 0.18 * example.features.final_confirmed;
  score += 0.18 * example.features.final_reportable;
  score += 0.12 * example.features.fresh_replay_passed;
  score += 0.08 * example.features.causal_support_present;
  score += 0.03 * example.features.controls_run_count;
  score += 0.03 * example.features.confounders_ruled_out_count;
  score -= 0.14 * example.features.missing_control;
  score -= 0.14 * example.features.unruled_confounder;
  return Math.max(0.001, Math.min(0.999, score));
}

function brier(examples, scorer) {
  if (examples.length === 0) return null;
  const total = examples.reduce((sum, example) => {
    const p = scorer(example);
    return sum + ((p - example.label) ** 2);
  }, 0);
  return Number((total / examples.length).toFixed(6));
}

function precisionAtK(examples, scorer, k = 5) {
  if (examples.length === 0) return null;
  const top = examples.slice()
    .sort((a, b) => scorer(b) - scorer(a) || a.finding_id.localeCompare(b.finding_id))
    .slice(0, Math.min(k, examples.length));
  return Number((top.filter((item) => item.label === 1).length / top.length).toFixed(6));
}

function reliabilityCurve(examples, scorer) {
  const buckets = Array.from({ length: 5 }, (_, index) => ({
    bucket: index,
    min_score: Number((index / 5).toFixed(1)),
    max_score: Number(((index + 1) / 5).toFixed(1)),
    count: 0,
    predicted_mean: 0,
    observed_rate: 0,
  }));
  for (const example of examples) {
    const p = scorer(example);
    const index = Math.min(4, Math.floor(p * 5));
    const bucket = buckets[index];
    bucket.count += 1;
    bucket.predicted_mean += p;
    bucket.observed_rate += example.label;
  }
  return buckets.map((bucket) => ({
    ...bucket,
    predicted_mean: bucket.count ? Number((bucket.predicted_mean / bucket.count).toFixed(6)) : null,
    observed_rate: bucket.count ? Number((bucket.observed_rate / bucket.count).toFixed(6)) : null,
  }));
}

function evaluateModel(examples, weights) {
  const modelBrier = brier(examples, (example) => scoreExample(example, weights));
  const handBrier = brier(examples, handScore);
  const modelPrecision = precisionAtK(examples, (example) => scoreExample(example, weights));
  const handPrecision = precisionAtK(examples, handScore);
  return {
    example_count: examples.length,
    positives: examples.filter((item) => item.label === 1).length,
    negatives: examples.filter((item) => item.label === 0).length,
    brier_model: modelBrier,
    brier_hand_weights: handBrier,
    brier_lift_over_hand: modelBrier == null || handBrier == null ? null : Number((handBrier - modelBrier).toFixed(6)),
    precision_at_5_model: modelPrecision,
    precision_at_5_hand_weights: handPrecision,
    precision_at_5_lift_over_hand: modelPrecision == null || handPrecision == null ? null : Number((modelPrecision - handPrecision).toFixed(6)),
    reliability_curve: reliabilityCurve(examples, (example) => scoreExample(example, weights)),
  };
}

function trainBeliefModel({
  target_domain,
  training_domains,
  holdout_domains = [],
  model_id = null,
} = {}) {
  if (typeof target_domain !== "string" || !target_domain.trim()) {
    throw new Error("target_domain is required");
  }
  const targetDomain = assertSafeDomain(target_domain.trim());
  const trainingDomains = normalizeDomains(training_domains, "training_domains");
  const holdoutDomains = Array.isArray(holdout_domains) && holdout_domains.length > 0
    ? normalizeDomains(holdout_domains, "holdout_domains")
    : [];
  const normalizedModelId = normalizeOptionalModelId(model_id);
  const trainingExamples = collectExamples(trainingDomains);
  if (trainingExamples.length === 0) {
    throw new Error("no labeled training examples found in supplied training_domains");
  }
  const weights = trainWeights(trainingExamples);
  const holdoutExamples = holdoutDomains.length > 0 ? collectExamples(holdoutDomains) : [];
  const evalExamples = holdoutExamples.length > 0 ? holdoutExamples : trainingExamples;
  const evaluation = evaluateModel(evalExamples, weights);
  const body = {
    model_version: BELIEF_MODEL_VERSION,
    model_id: normalizedModelId || `BM-${hashCanonicalJson({ trainingDomains, holdoutDomains, weights }).slice(0, 24)}`,
    target_domain: targetDomain,
    training_domains: trainingDomains,
    holdout_domains: holdoutDomains,
    feature_names: FEATURE_NAMES,
    calibrated_logistic_factors: weights,
    training_summary: {
      example_count: trainingExamples.length,
      positives: trainingExamples.filter((item) => item.label === 1).length,
      negatives: trainingExamples.filter((item) => item.label === 0).length,
    },
    calibration_report: {
      held_out: holdoutExamples.length > 0,
      ...evaluation,
    },
    label_source: "verification_round_and_grade_outcomes",
    sanitized: true,
    excluded_raw_material: [
      "report.md",
      "evidence-packs.md",
      "request_or_response_bodies",
      "proof_of_concept_text",
      "secret_values",
    ],
    advisory: true,
    claim_authority: false,
    verification_authority: false,
    grade_authority: false,
    dispatch_authority: false,
    default_enablement_ready: false,
    default_enablement_reason: "requires held-out equal-budget lift review before default use",
  };
  const document = {
    ...body,
    model_hash: hashCanonicalJson(body),
  };
  writeFileAtomic(beliefModelInfoPath(targetDomain), `${JSON.stringify(document, null, 2)}\n`);
  return document;
}

function readBeliefModelInfo({ target_domain } = {}) {
  if (typeof target_domain !== "string" || !target_domain.trim()) {
    throw new Error("target_domain is required");
  }
  const targetDomain = assertSafeDomain(target_domain.trim());
  const filePath = beliefModelInfoPath(targetDomain);
  if (!fs.existsSync(filePath)) {
    return {
      target_domain: targetDomain,
      exists: false,
      model_info_path: filePath,
    };
  }
  const document = readJsonFile(filePath, { label: "belief-model-info.json" });
  return {
    target_domain: targetDomain,
    exists: true,
    model_info_path: filePath,
    model: document,
  };
}

module.exports = {
  BELIEF_MODEL_VERSION,
  FEATURE_NAMES,
  readBeliefModelInfo,
  trainBeliefModel,
  _internals: {
    examplesForDomain,
    featureVector,
    handScore,
    labelFor,
    normalizeOptionalModelId,
    scoreExample,
  },
};
