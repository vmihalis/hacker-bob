"use strict";

// Surface-lead input normalization.
//
// Carved from the original surface-leads.js (F.6). normalizeSurfaceLead and
// mergeSurfaceLead are the intake contract: any handler that receives raw
// lead payloads (from agents, wave handoffs, or imported traffic) must pass
// them through this module before persisting or scoring.

const crypto = require("crypto");
const fs = require("fs");
const {
  assertBoolean,
  assertEnumValue,
  assertNonEmptyString,
  normalizeStringArray,
  pushUnique,
} = require("./validation.js");
const { priorityRank } = require("./ranking.js");
const { surfaceLeadsPath } = require("./paths.js");
const { readJsonFile, writeFileAtomic } = require("./storage.js");
const {
  LEAD_CONFIDENCE_VALUES,
  confidenceFromScore,
  evidenceScore,
  normalizePriority,
  normalizeScore,
} = require("./lead-scoring.js");

const LEAD_STATUS_VALUES = ["new", "promoted", "dismissed"];
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

function leadDedupeKey(lead) {
  const source = [
    lead.title || "",
    lead.surface_type || "",
    ...lead.hosts,
    ...lead.endpoints.slice(0, 20),
  ].join("\n").toLowerCase();
  return crypto.createHash("sha256").update(source || "surface-lead", "utf8").digest("hex");
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
    source: normalizeOptionalString(input.source || context.source || "evaluator", "source", { maxChars: 120 }),
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
    evaluator_run_avoided_recorded_at: context.preserve_internal_telemetry !== true || input.evaluator_run_avoided_recorded_at == null
      ? null
      : assertNonEmptyString(input.evaluator_run_avoided_recorded_at, "evaluator_run_avoided_recorded_at"),
    // Y.12 (rev 4.1 defect 1) — producer-side rationale captured at record
    // time. The Y.7 silent_lead_threshold_drop scanner reads this field
    // alongside the queue-policy toggle to compute `rationale_required_but_missing`.
    rationale: normalizeOptionalString(input.rationale, "rationale", { maxChars: 512 }),
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
    evaluator_run_avoided_recorded_at: existing.evaluator_run_avoided_recorded_at
      || incoming.evaluator_run_avoided_recorded_at,
    // Y.12 (rev 4.1 defect 1) — rationale on merge: incoming wins when the
    // existing entry lacked one, otherwise keep the existing rationale so
    // earlier producer-side reasoning is not overwritten by a later
    // re-record that omitted the field.
    rationale: existing.rationale || incoming.rationale,
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
    leads: parsed.leads.map((lead) => normalizeSurfaceLead(lead, { preserve_internal_telemetry: true })),
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

module.exports = {
  LEAD_STATUS_VALUES,
  SURFACE_LEAD_ARRAY_LIMITS,
  SURFACE_LEAD_ITEM_MAX_CHARS,
  leadDedupeKey,
  mergeSurfaceLead,
  nextLeadId,
  normalizeSurfaceLead,
  readSurfaceLeadsDocument,
  writeSurfaceLeadsDocument,
};
