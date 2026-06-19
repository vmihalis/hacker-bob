"use strict";

// Surface-lead scoring + priority signals.
//
// Source of evidence-derived score, confidence band, and priority normalization
// helpers consumed by lead-intake (during normalization) and lead-promotion
// (during candidate selection / preview tooling). The promotion-gate predicate
// (shouldPromoteLead) and the selection helpers also live here because they
// are pure priority-signal computation over normalized leads.

const {
  assertBoolean,
  assertEnumValue,
  assertInteger,
} = require("./validation.js");
const { surfaceLeadsPath, attackSurfacePath } = require("./paths.js");
const { priorityFromScore } = require("./ranking.js");

const LEAD_CONFIDENCE_VALUES = ["high", "medium", "low"];
const PRIORITY_VALUES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

function normalizeScore(value) {
  if (value == null) return null;
  if (typeof value !== "number" || !Number.isFinite(value)) {
    throw new Error("score must be a finite number");
  }
  return Math.max(0, Math.min(100, Math.round(value)));
}

function normalizePriority(value, score) {
  if (value == null) return priorityFromScore(score == null ? 0 : score);
  return assertEnumValue(String(value).toUpperCase(), PRIORITY_VALUES, "priority");
}

function evidenceScore(lead) {
  let score = 0;
  if (lead.hosts.length > 0) score += 15;
  if (lead.endpoints.length > 0) score += Math.min(30, 8 + lead.endpoints.length);
  if (lead.interesting_params.length > 0) score += 15;
  if (lead.nuclei_hits.length > 0) score += 18;
  if (lead.bug_class_hints.length > 0) score += 12;
  if (lead.evidence.some((item) => /secret|token|admin|billing|auth|graphql|upload|idor|cve/i.test(item))) {
    score += 18;
  }
  return Math.min(100, score);
}

function staticLeadEvidenceInput(lead) {
  const arrayField = (field) => (Array.isArray(lead && lead[field]) ? lead[field] : []);
  return {
    hosts: arrayField("hosts"),
    endpoints: arrayField("endpoints"),
    interesting_params: arrayField("interesting_params"),
    nuclei_hits: arrayField("nuclei_hits"),
    bug_class_hints: arrayField("bug_class_hints"),
    evidence: arrayField("evidence"),
  };
}

function reachabilitySummary(reachability = {}) {
  const attackVector = typeof reachability.attack_vector === "string"
    ? reachability.attack_vector
    : "unknown";
  const networkReachable = typeof reachability.network_reachable === "boolean"
    ? String(reachability.network_reachable)
    : "unknown";
  const severityCeiling = typeof reachability.severity_ceiling === "string"
    ? reachability.severity_ceiling
    : "unknown";
  return `attack_vector=${attackVector}; network_reachable=${networkReachable}; severity_ceiling=${severityCeiling}`;
}

function scoreStaticLeadWithReachability(lead, reachability = {}) {
  const baseScore = evidenceScore(staticLeadEvidenceInput(lead || {}));
  const networkReachable = reachability
    && reachability.network_reachable === true
    && reachability.attack_vector === "network";
  const score = networkReachable
    ? Math.max(baseScore, 72)
    : Math.min(Math.max(baseScore, 45), 59);
  const rationale = lead && typeof lead.rationale === "string" && lead.rationale.trim()
    ? lead.rationale
    : (
      networkReachable
        ? `Static analysis lead is network-reachable (${reachabilitySummary(reachability)}); trace source to sink and replay before finding promotion.`
        : `Static analysis lead is capped but retained (${reachabilitySummary(reachability)}); record as a lower-priority hypothesis until live replay proves impact.`
    );
  return {
    ...lead,
    score,
    confidence: confidenceFromScore(score),
    priority: normalizePriority(lead && lead.priority, score),
    rationale,
  };
}

function confidenceFromScore(score) {
  if (score >= 70) return "high";
  if (score >= 40) return "medium";
  return "low";
}

function isAssignableSurfaceLead(lead) {
  return !!(lead && (
    (Array.isArray(lead.hosts) && lead.hosts.length > 0) ||
    (Array.isArray(lead.endpoints) && lead.endpoints.length > 0)
  ));
}

function shouldPromoteLead(lead, { minScore, includeMedium }) {
  if (lead.status === "promoted" || lead.promoted_surface_id) return false;
  if (!isAssignableSurfaceLead(lead)) return false;
  if (lead.promote) return true;
  if (lead.confidence === "high") return true;
  if (includeMedium && lead.confidence === "medium") return true;
  return (lead.score || 0) >= minScore;
}

function normalizePromotionOptions(options = {}) {
  const limit = options.limit == null ? 8 : assertInteger(options.limit, "limit", { min: 1, max: 50 });
  const minScore = options.min_score == null ? 60 : assertInteger(options.min_score, "min_score", { min: 0, max: 100 });
  const includeMedium = options.include_medium == null ? false : assertBoolean(options.include_medium, "include_medium");
  return { limit, minScore, includeMedium };
}

function sortLeadsByScore(leads) {
  return [...leads].sort((a, b) => (b.score || 0) - (a.score || 0)
    || String(a.id).localeCompare(String(b.id)));
}

function partitionLeadPromotion(document, options = {}) {
  const { limit, minScore, includeMedium } = normalizePromotionOptions(options);
  const leads = Array.isArray(document && document.leads) ? document.leads : [];
  const assignableLeads = leads.filter((lead) => (
    lead.status !== "promoted" &&
    !lead.promoted_surface_id &&
    isAssignableSurfaceLead(lead)
  ));
  const promotableLeads = sortLeadsByScore(assignableLeads.filter(
    (lead) => shouldPromoteLead(lead, { minScore, includeMedium }),
  ));
  const promotableSet = new Set(promotableLeads);
  return {
    limit,
    assignableLeads,
    promotableLeads,
    filteredLeads: assignableLeads.filter((lead) => !promotableSet.has(lead)),
    selectedLeads: promotableLeads.slice(0, limit),
  };
}

function selectPromotableSurfaceLeads(document, options = {}) {
  return partitionLeadPromotion(document, options).selectedLeads;
}

function summarizeLeadPromotion(document, options = {}) {
  const promotion = partitionLeadPromotion(document, options);
  return {
    assignable: promotion.assignableLeads.length,
    promoted: promotion.selectedLeads.length,
    filtered: promotion.filteredLeads.length,
    deferred_by_limit: Math.max(0, promotion.promotableLeads.length - promotion.limit),
  };
}

function leadPathsEnvelope(domain) {
  return {
    leads_path: surfaceLeadsPath(domain),
    attack_surface_path: attackSurfacePath(domain),
  };
}

function buildPromotionPreview(domain, candidates) {
  return {
    would_promote: candidates.length,
    would_promote_lead_ids: candidates.map((lead) => lead.id),
    ...leadPathsEnvelope(domain),
  };
}

function buildPromotionEnvelope(domain, ids) {
  return {
    promoted: ids.length,
    promoted_surface_ids: ids,
    ...leadPathsEnvelope(domain),
  };
}

module.exports = {
  LEAD_CONFIDENCE_VALUES,
  PRIORITY_VALUES,
  buildPromotionEnvelope,
  buildPromotionPreview,
  confidenceFromScore,
  evidenceScore,
  isAssignableSurfaceLead,
  normalizePriority,
  normalizePromotionOptions,
  normalizeScore,
  partitionLeadPromotion,
  selectPromotableSurfaceLeads,
  shouldPromoteLead,
  scoreStaticLeadWithReachability,
  sortLeadsByScore,
  summarizeLeadPromotion,
};
