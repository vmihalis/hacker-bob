"use strict";

const crypto = require("crypto");
const fs = require("fs");
const {
  assertBoolean,
  assertEnumValue,
  assertInteger,
  assertNonEmptyString,
  normalizeStringArray,
  pushUnique,
} = require("./validation.js");
const {
  attackSurfacePath,
  surfaceLeadsPath,
} = require("./paths.js");
const {
  readSessionStateStrict,
  writeSessionStateDocument,
} = require("./session-state-store.js");
const {
  readJsonFile,
  withSessionLock,
  writeFileAtomic,
} = require("./storage.js");
const {
  priorityFromScore,
  priorityRank,
} = require("./ranking.js");

const LEAD_CONFIDENCE_VALUES = ["high", "medium", "low"];
const LEAD_STATUS_VALUES = ["new", "promoted", "dismissed"];
const PRIORITY_VALUES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
const SURFACE_LEAD_ARRAY_LIMITS = Object.freeze({
  hosts: 20,
  endpoints: 120,
  interesting_params: 40,
  tech_stack: 20,
  nuclei_hits: 30,
  bug_class_hints: 20,
  high_value_flows: 20,
  evidence: 25,
});
const SURFACE_LEAD_ITEM_MAX_CHARS = 500;
// Deep-mode surface-lead promotion policy. Single source of truth shared by the
// gate preview (phase-gates.js), the start_next_wave dry-run preview, and the
// promotion execution (waves.js). These three call sites MUST agree or the gate
// preview will disagree with what actually gets promoted — keep them reading
// from this constant rather than re-inlining the literal.
const DEEP_MODE_PROMOTION_POLICY = Object.freeze({
  limit: 25,
  min_score: 40,
  include_medium: true,
});

function clampStringArray(value, fieldName, limit) {
  return normalizeStringArray(value, fieldName)
    .map((item) => item.length > SURFACE_LEAD_ITEM_MAX_CHARS
      ? item.slice(0, SURFACE_LEAD_ITEM_MAX_CHARS)
      : item)
    .slice(0, limit);
}

function normalizeOptionalString(value, fieldName, { maxChars = 240 } = {}) {
  if (value == null) return null;
  const normalized = assertNonEmptyString(value, fieldName);
  return normalized.length > maxChars ? normalized.slice(0, maxChars) : normalized;
}

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

function confidenceFromScore(score) {
  if (score >= 70) return "high";
  if (score >= 40) return "medium";
  return "low";
}

function leadDedupeKey(lead) {
  const source = [
    lead.title || "",
    lead.surface_type || "",
    ...lead.hosts,
    ...lead.endpoints.slice(0, 20),
  ].join("\n").toLowerCase();
  return crypto.createHash("sha256").update(source || "surface-lead", "utf8").digest("hex");
}

function isAssignableSurfaceLead(lead) {
  return !!(lead && (
    (Array.isArray(lead.hosts) && lead.hosts.length > 0) ||
    (Array.isArray(lead.endpoints) && lead.endpoints.length > 0)
  ));
}

function normalizeSurfaceLead(input, context = {}) {
  if (input == null || typeof input !== "object" || Array.isArray(input)) {
    throw new Error("surface lead entries must be objects");
  }
  const arrays = {};
  for (const [field, limit] of Object.entries(SURFACE_LEAD_ARRAY_LIMITS)) {
    arrays[field] = clampStringArray(input[field], field, limit);
  }
  const initial = {
    id: input.id == null ? null : assertNonEmptyString(input.id, "id"),
    title: normalizeOptionalString(input.title, "title"),
    source: normalizeOptionalString(input.source || context.source || "hunter", "source", { maxChars: 120 }),
    source_wave: normalizeOptionalString(input.source_wave || context.source_wave, "source_wave", { maxChars: 20 }),
    source_agent: normalizeOptionalString(input.source_agent || context.source_agent, "source_agent", { maxChars: 20 }),
    source_surface_id: normalizeOptionalString(input.source_surface_id || context.source_surface_id, "source_surface_id", { maxChars: 160 }),
    status: input.status == null ? "new" : assertEnumValue(input.status, LEAD_STATUS_VALUES, "status"),
    promote: input.promote == null ? false : assertBoolean(input.promote, "promote"),
    created_at: input.created_at == null ? null : assertNonEmptyString(input.created_at, "created_at"),
    confidence: input.confidence == null ? null : assertEnumValue(input.confidence, LEAD_CONFIDENCE_VALUES, "confidence"),
    surface_type: normalizeOptionalString(input.surface_type, "surface_type", { maxChars: 80 }),
    promoted_surface_id: input.promoted_surface_id == null
      ? null
      : assertNonEmptyString(input.promoted_surface_id, "promoted_surface_id"),
    promoted_at: input.promoted_at == null ? null : assertNonEmptyString(input.promoted_at, "promoted_at"),
    ...arrays,
  };
  const score = normalizeScore(input.score == null ? evidenceScore(initial) : input.score);
  const confidence = initial.confidence || confidenceFromScore(score);
  const priority = normalizePriority(input.priority, score);
  return {
    ...initial,
    score,
    confidence,
    priority,
    key: leadDedupeKey(initial),
  };
}

function readSurfaceLeadsDocument(domain) {
  const filePath = surfaceLeadsPath(domain);
  if (!fs.existsSync(filePath)) {
    return { version: 1, leads: [] };
  }
  let parsed;
  try {
    parsed = readJsonFile(filePath, { label: "surface-leads.json" });
  } catch (error) {
    throw new Error(`Malformed surface leads JSON: ${filePath} (${error.message || String(error)})`);
  }
  if (parsed == null || typeof parsed !== "object" || Array.isArray(parsed) || !Array.isArray(parsed.leads)) {
    throw new Error(`Malformed surface leads JSON: ${filePath} (expected object with leads array)`);
  }
  return {
    version: 1,
    leads: parsed.leads.map((lead) => normalizeSurfaceLead(lead)),
  };
}

function writeSurfaceLeadsDocument(domain, document) {
  const filePath = surfaceLeadsPath(domain);
  writeFileAtomic(filePath, `${JSON.stringify({ version: 1, leads: document.leads }, null, 2)}\n`);
  return filePath;
}

function nextLeadId(existing) {
  let max = 0;
  for (const lead of existing) {
    const match = typeof lead.id === "string" && lead.id.match(/^SL-([1-9][0-9]*)$/);
    if (match) max = Math.max(max, Number(match[1]));
  }
  return `SL-${max + 1}`;
}

function mergeArrays(existing, incoming, field) {
  const values = [...existing[field]];
  pushUnique(values, new Set(values), incoming[field]);
  return values.slice(0, SURFACE_LEAD_ARRAY_LIMITS[field]);
}

function mergeSurfaceLead(existing, incoming) {
  const score = Math.max(existing.score || 0, incoming.score || 0);
  const priority = priorityRank(incoming.priority) > priorityRank(existing.priority)
    ? incoming.priority
    : existing.priority;
  const next = {
    ...existing,
    ...Object.fromEntries(Object.keys(SURFACE_LEAD_ARRAY_LIMITS).map((field) => [
      field,
      mergeArrays(existing, incoming, field),
    ])),
    title: existing.title || incoming.title,
    source: existing.source || incoming.source,
    source_wave: existing.source_wave || incoming.source_wave,
    source_agent: existing.source_agent || incoming.source_agent,
    source_surface_id: existing.source_surface_id || incoming.source_surface_id,
    surface_type: existing.surface_type || incoming.surface_type,
    promote: existing.promote || incoming.promote,
    confidence: LEAD_CONFIDENCE_VALUES.indexOf(incoming.confidence) < LEAD_CONFIDENCE_VALUES.indexOf(existing.confidence)
      ? incoming.confidence
      : existing.confidence,
    score,
    priority,
  };
  return {
    ...next,
    key: leadDedupeKey(next),
  };
}

function recordSurfaceLeadsInternal(domain, leads, context = {}) {
  if (!Array.isArray(leads) || leads.length === 0) {
    return { recorded: 0, lead_ids: [], path: surfaceLeadsPath(domain) };
  }
  const document = readSurfaceLeadsDocument(domain);
  const byKey = new Map(document.leads.map((lead) => [lead.key, lead]));
  const leadIds = [];
  let recorded = 0;
  for (const leadInput of leads) {
    const incoming = normalizeSurfaceLead(leadInput, context);
    const existing = byKey.get(incoming.key);
    if (existing) {
      const merged = mergeSurfaceLead(existing, incoming);
      const index = document.leads.findIndex((lead) => lead.id === existing.id);
      document.leads[index] = merged;
      byKey.set(merged.key, merged);
      leadIds.push(merged.id);
      continue;
    }
    const lead = {
      ...incoming,
      id: incoming.id || nextLeadId(document.leads),
      created_at: new Date().toISOString(),
    };
    document.leads.push(lead);
    byKey.set(lead.key, lead);
    leadIds.push(lead.id);
    recorded += 1;
  }
  const filePath = writeSurfaceLeadsDocument(domain, document);
  return {
    recorded,
    total: document.leads.length,
    lead_ids: leadIds,
    path: filePath,
  };
}

function slugify(value) {
  const slug = String(value || "lead")
    .toLowerCase()
    .replace(/^https?:\/\//, "")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 54);
  return slug || "lead";
}

function readAttackSurfaceDocument(domain) {
  const filePath = attackSurfacePath(domain);
  if (!fs.existsSync(filePath)) {
    return { domain, surfaces: [] };
  }
  let parsed;
  try {
    parsed = readJsonFile(filePath, { label: "attack_surface.json" });
  } catch (error) {
    throw new Error(`Malformed attack surface JSON: ${filePath} (${error.message || String(error)})`);
  }
  if (parsed == null || typeof parsed !== "object" || Array.isArray(parsed) || !Array.isArray(parsed.surfaces)) {
    throw new Error(`Malformed attack surface JSON: ${filePath} (expected object with surfaces array)`);
  }
  return parsed;
}

function uniqueSurfaceId(lead, surfaceIds) {
  const base = `lead-${slugify(lead.title || lead.hosts[0] || lead.endpoints[0] || lead.id)}`;
  let candidate = base;
  let suffix = 2;
  while (surfaceIds.has(candidate)) {
    candidate = `${base}-${suffix}`;
    suffix += 1;
  }
  surfaceIds.add(candidate);
  return candidate;
}

function leadToSurface(lead, surfaceId) {
  return {
    id: surfaceId,
    hosts: lead.hosts,
    tech_stack: lead.tech_stack,
    endpoints: lead.endpoints,
    interesting_params: lead.interesting_params,
    nuclei_hits: lead.nuclei_hits,
    priority: lead.priority,
    surface_type: lead.surface_type || "unknown",
    bug_class_hints: lead.bug_class_hints,
    high_value_flows: lead.high_value_flows,
    evidence: lead.evidence,
    ranking: {
      version: 1,
      score: lead.score || 0,
      priority: lead.priority,
      reasons: ["promoted_surface_lead", lead.confidence ? `confidence:${lead.confidence}` : null]
        .filter(Boolean),
    },
  };
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

function selectPromotableSurfaceLeads(document, options = {}) {
  const { limit, minScore, includeMedium } = normalizePromotionOptions(options);
  return document.leads
    .filter((lead) => shouldPromoteLead(lead, { minScore, includeMedium }))
    .sort((a, b) => {
      if ((b.score || 0) !== (a.score || 0)) return (b.score || 0) - (a.score || 0);
      return String(a.id).localeCompare(String(b.id));
    })
    .slice(0, limit);
}

function previewSurfaceLeadPromotion(domain, options = {}) {
  const document = readSurfaceLeadsDocument(domain);
  const candidates = selectPromotableSurfaceLeads(document, options);
  return {
    would_promote: candidates.length,
    would_promote_lead_ids: candidates.map((lead) => lead.id),
    leads_path: surfaceLeadsPath(domain),
    attack_surface_path: attackSurfacePath(domain),
  };
}

function promoteSurfaceLeadsInternal(domain, options = {}) {
  const { limit, minScore, includeMedium } = normalizePromotionOptions(options);
  const updateState = options.update_state == null ? true : assertBoolean(options.update_state, "update_state");
  const document = readSurfaceLeadsDocument(domain);
  const candidates = selectPromotableSurfaceLeads(document, { limit, min_score: minScore, include_medium: includeMedium });

  if (candidates.length === 0) {
    return {
      promoted: 0,
      promoted_surface_ids: [],
      leads_path: surfaceLeadsPath(domain),
      attack_surface_path: attackSurfacePath(domain),
    };
  }

  const attackSurface = readAttackSurfaceDocument(domain);
  const surfaceIds = new Set(attackSurface.surfaces
    .filter((surface) => surface && typeof surface === "object")
    .map((surface) => String(surface.id || ""))
    .filter(Boolean));
  const promotedSurfaceIds = [];
  const now = new Date().toISOString();

  for (const lead of candidates) {
    const surfaceId = uniqueSurfaceId(lead, surfaceIds);
    attackSurface.surfaces.push(leadToSurface(lead, surfaceId));
    promotedSurfaceIds.push(surfaceId);
    const index = document.leads.findIndex((item) => item.id === lead.id);
    if (index !== -1) {
      document.leads[index] = {
        ...document.leads[index],
        status: "promoted",
        promoted_surface_id: surfaceId,
        promoted_at: now,
      };
    }
  }

  writeFileAtomic(attackSurfacePath(domain), `${JSON.stringify(attackSurface, null, 2)}\n`);
  writeSurfaceLeadsDocument(domain, document);

  if (updateState) {
    try {
      const { raw, state } = readSessionStateStrict(domain);
      const leadSurfaceIds = [...state.lead_surface_ids];
      pushUnique(leadSurfaceIds, new Set(leadSurfaceIds), promotedSurfaceIds);
      writeSessionStateDocument(domain, raw, { ...state, lead_surface_ids: leadSurfaceIds });
    } catch {
      // Promotion can run immediately after recon before later state reads; a
      // missing or legacy state should not corrupt the promoted attack surface.
    }
  }

  return {
    promoted: promotedSurfaceIds.length,
    promoted_surface_ids: promotedSurfaceIds,
    leads_path: surfaceLeadsPath(domain),
    attack_surface_path: attackSurfacePath(domain),
  };
}

function recordSurfaceLeads(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const leads = Array.isArray(args.leads) ? args.leads : [];
  const context = {
    source: args.source,
    source_wave: args.source_wave,
    source_agent: args.source_agent,
    source_surface_id: args.source_surface_id,
  };
  return withSessionLock(domain, () => JSON.stringify({
    version: 1,
    ...recordSurfaceLeadsInternal(domain, leads, context),
  }));
}

function recordSurfaceLeadsForWaveHandoff(domain, leads, context = {}) {
  return withSessionLock(domain, () => recordSurfaceLeadsInternal(domain, leads, context));
}

function readSurfaceLeads(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const limit = args.limit == null ? 50 : assertInteger(args.limit, "limit", { min: 1, max: 200 });
  const document = readSurfaceLeadsDocument(domain);
  const leads = document.leads
    .slice()
    .sort((a, b) => {
      if ((b.score || 0) !== (a.score || 0)) return (b.score || 0) - (a.score || 0);
      return String(a.id).localeCompare(String(b.id));
    })
    .slice(0, limit);
  return JSON.stringify({
    version: 1,
    target_domain: domain,
    path: surfaceLeadsPath(domain),
    total: document.leads.length,
    returned: leads.length,
    high_confidence_unpromoted: document.leads.filter(
      (lead) => lead.status !== "promoted" && lead.confidence === "high" && isAssignableSurfaceLead(lead),
    ).length,
    leads,
  });
}

function promoteSurfaceLeads(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  return withSessionLock(domain, () => JSON.stringify({
    version: 1,
    ...promoteSurfaceLeadsInternal(domain, args),
  }));
}

function promoteSurfaceLeadsForWave(domain, options = {}) {
  return withSessionLock(domain, () => promoteSurfaceLeadsInternal(domain, {
    ...options,
    update_state: false,
  }));
}

module.exports = {
  DEEP_MODE_PROMOTION_POLICY,
  LEAD_CONFIDENCE_VALUES,
  LEAD_STATUS_VALUES,
  isAssignableSurfaceLead,
  normalizeSurfaceLead,
  promoteSurfaceLeadsForWave,
  promoteSurfaceLeads,
  previewSurfaceLeadPromotion,
  readSurfaceLeads,
  readSurfaceLeadsDocument,
  recordSurfaceLeads,
  recordSurfaceLeadsForWaveHandoff,
  selectPromotableSurfaceLeads,
  surfaceLeadsPath,
};
