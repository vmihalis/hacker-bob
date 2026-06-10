"use strict";

// Surface-lead promotion + recording flow. Owns the surface-leads.json
// persistence loop and emits the frontier events (frontier.enqueued and
// surface.observed) that the materializer folds into surface-index.json and
// task-queue.json. Selection and priority signals live in lead-scoring.
//
// Cycle D.3 deleted surface-mutator.js: attack_surface.json is no longer
// written; surface-index.json (materialized from frontier events) is the
// authoritative surface source. The promotion path emits one
// surface.observed event per promoted lead so the materializer sees the
// new surface without re-reading the legacy projection.

const {
  assertBoolean,
  assertInteger,
  assertNonEmptyString,
} = require("./validation.js");
const { surfaceLeadsPath } = require("./paths.js");
const { withSessionLock } = require("./storage.js");
const { appendFrontierEvent } = require("./frontier-events.js");
const { scheduleMaterialization } = require("./frontier-materialize-debounce.js");
const {
  mergeSurfaceLead,
  nextLeadId,
  normalizeSurfaceLead,
  readSurfaceLeadsDocument,
  writeSurfaceLeadsDocument,
} = require("./lead-intake.js");
const {
  buildPromotionEnvelope,
  buildPromotionPreview,
  isAssignableSurfaceLead,
  normalizePromotionOptions,
  partitionLeadPromotion,
  scoreStaticLeadWithReachability,
  sortLeadsByScore,
} = require("./lead-scoring.js");
const {
  STATIC_LEAD_SOURCE,
  staticFindingToSurfaceLead,
} = require("./static-lead-mapping.js");
const {
  normalizeStaticAnalysisIndexRecord,
  queryStaticAnalysisIndex,
  readStaticAnalysisIndex,
  registerStaticAnalysisLeadRecorder,
} = require("./static-analysis-index.js");
const {
  OSS_ROOTCAUSE_FAMILIES,
  suggestFamiliesForSurface,
} = require("./oss-rootcause-family-corpus.js");
const { ERROR_CODES, ToolError } = require("./envelope.js");
const { loadQueuePolicy } = require("./queue-policy.js");
const { safeAppendPipelineEventDirect } = require("./pipeline-events.js");
const { safeGovernanceContextForDomain } = require("./governance-context.js");

const PROMOTED_SURFACE_LEAD_LABEL = "promoted_surface_lead";

// Fix #134 — sub-threshold rationale heuristic warning for external producers.
// Known-internal source labels emitted by Bob's own producers (evaluator
// agents, orchestrator, wave handoffs, surface-discovery flows). A lead
// whose `source` string is in this set is treated as internal; anything
// outside the set (or any `external_` prefix) is treated as external for
// the soft-warning heuristic below. This list mirrors the producer entries
// in mcp/lib/stigmergic-producers.js — keep additions in sync when new
// internal lead producers are wired.
const KNOWN_INTERNAL_LEAD_SOURCES = new Set([
  "evaluator",
  "orchestrator",
  "wave_handoff",
  "surface_discovery",
  "deep_surface_discovery",
  "bob_record_surface_leads",
  "bob_promote_surface_leads",
  "bob_import_http_traffic",
  "bob_static_scan",
  "bob_http_scan",
  "bob_extract_routes",
  "bob_route_surfaces",
]);

function isExternalProducerLead(lead) {
  const producerKind = typeof lead.producer_kind === "string" ? lead.producer_kind : "";
  if (producerKind.startsWith("external_")) return true;
  const sourceTool = lead.source && typeof lead.source === "object" && !Array.isArray(lead.source)
    ? (typeof lead.source.tool === "string" ? lead.source.tool : "")
    : (typeof lead.source === "string" ? lead.source : "");
  if (!sourceTool) return false;
  if (sourceTool.startsWith("external_")) return true;
  return !KNOWN_INTERNAL_LEAD_SOURCES.has(sourceTool);
}

// Fix #134 — emit a soft observation.recorded warning for each
// below-threshold lead that came from an external producer (source not in
// the PRODUCERS manifest / KNOWN_INTERNAL_LEAD_SOURCES, or producer_kind
// prefixed with `external_`) and lacks a rationale. Complements the
// strict enforceLeadRationalePolicy gate (which only fires when the
// queue-policy toggle is on). Best-effort: append failures are swallowed
// so the record path never blocks on observability. Uses the existing
// observation.recorded top-level kind per X-P8 (no new FRONTIER_EVENT_KIND).
function warnExternalProducerMissingRationale(domain, normalizedLeads) {
  let minScore;
  try {
    ({ minScore } = normalizePromotionOptions({}));
  } catch {
    return;
  }
  for (let i = 0; i < normalizedLeads.length; i += 1) {
    const lead = normalizedLeads[i];
    const score = typeof lead.score === "number" ? lead.score : 0;
    if (score >= minScore) continue;
    const rationale = typeof lead.rationale === "string" ? lead.rationale.trim() : "";
    if (rationale) continue;
    if (!isExternalProducerLead(lead)) continue;
    const sourceLabel = lead.source && typeof lead.source === "object" && !Array.isArray(lead.source)
      ? (typeof lead.source.tool === "string" ? lead.source.tool : null)
      : (typeof lead.source === "string" ? lead.source : null);
    try {
      // eslint-disable-next-line no-console
      console.warn(
        `[surface-leads] external producer (${sourceLabel || "unknown"}) recorded sub-threshold lead `
        + `(score=${score} < min_score=${minScore}) without rationale; lead_id=${lead.id || "(unassigned)"}`,
      );
    } catch {
      // console may be unavailable in some hosts; swallow.
    }
    try {
      appendFrontierEvent({
        target_domain: domain,
        kind: "observation.recorded",
        payload: {
          observation_kind: "external_producer_missing_rationale",
          lead_id: lead.id || null,
          lead_key: lead.key || null,
          score,
          min_score: minScore,
          producer_source: sourceLabel,
          producer_kind: typeof lead.producer_kind === "string" ? lead.producer_kind : null,
          source_wave: lead.source_wave || null,
          source_agent: lead.source_agent || null,
        },
        source: { artifact: "surface-leads.json", tool: "bob_record_surface_leads" },
      });
    } catch {
      // Best-effort observability — never block the record path.
    }
  }
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

function uniqueSurfaceId(lead, existingIds) {
  const base = `lead-${slugify(lead.title || (lead.hosts && lead.hosts[0]) || (lead.endpoints && lead.endpoints[0]) || lead.id)}`;
  let candidate = base;
  let suffix = 2;
  while (existingIds.has(candidate)) {
    candidate = `${base}-${suffix}`;
    suffix += 1;
  }
  existingIds.add(candidate);
  return candidate;
}

function emitPromotedSurfaceObserved(domain, lead, surfaceId) {
  try {
    appendFrontierEvent({
      target_domain: domain,
      kind: "surface.observed",
      surface_id: surfaceId,
      payload: {
        surface_type: lead.surface_type || "unknown",
        title: lead.title,
        hosts: lead.hosts,
        endpoints: lead.endpoints,
        priority: lead.priority,
        score: lead.score,
        confidence: lead.confidence,
        labels: [PROMOTED_SURFACE_LEAD_LABEL, lead.confidence ? `confidence:${lead.confidence}` : null].filter(Boolean),
        lead_id: lead.id,
      },
      source: { artifact: "surface-leads.json", tool: "bob_promote_surface_leads" },
    });
    scheduleMaterialization(domain);
  } catch {
    // Frontier ledger append is best-effort here; materialization runs on
    // the next producer event.
  }
}

function applyPromotionToFrontier(domain, candidates) {
  if (!Array.isArray(candidates) || candidates.length === 0) {
    return { promoted_surface_ids: [] };
  }
  // Allocate unique surface_ids based on the existing materialized surfaces
  // so re-promotion across waves does not collide. The materialized view is
  // accessed via frontier-projections.currentSurfaces to avoid a direct
  // dependency on the materializer module from the producer path.
  const { currentSurfaces } = require("./frontier-projections.js");
  let knownSurfaceIds;
  try {
    const projection = currentSurfaces(domain);
    knownSurfaceIds = new Set((projection.surfaces || [])
      .map((surface) => String(surface.id || ""))
      .filter(Boolean));
  } catch {
    knownSurfaceIds = new Set();
  }
  const promotedSurfaceIds = [];
  for (const lead of candidates) {
    const surfaceId = uniqueSurfaceId(lead, knownSurfaceIds);
    emitPromotedSurfaceObserved(domain, lead, surfaceId);
    promotedSurfaceIds.push(surfaceId);
  }
  return { promoted_surface_ids: promotedSurfaceIds };
}

function emitFrontierEnqueued(domain, lead) {
  try {
    appendFrontierEvent({
      target_domain: domain,
      kind: "frontier.enqueued",
      payload: {
        lead_id: lead.id,
        surface_ref: lead.source_surface_id || lead.promoted_surface_id || null,
        score: lead.score,
        priority: lead.priority,
        confidence: lead.confidence,
        provenance: {
          source: lead.source,
          source_wave: lead.source_wave,
          source_agent: lead.source_agent,
          source_surface_id: lead.source_surface_id,
        },
      },
      source: { artifact: "surface-leads.json", tool: "bob_record_surface_leads" },
    });
    scheduleMaterialization(domain);
  } catch {
    // Frontier ledger is dual-write best-effort during the deprecation window.
  }
}

// Y.12 (rev 4.1 defect 1) — producer-side rationale enforcement on
// bob_record_surface_leads. When queue-policy.lead_rationale_required_when_below_threshold
// is TRUE and a recorded lead's score is below queue-policy min_score
// (default 60 from lead-scoring.normalizePromotionOptions), the lead MUST
// carry a non-empty rationale (≤512 chars). Validator runs BEFORE write so
// no partial state is persisted. Structural complement to the Y.7
// silent_lead_threshold_drop runtime tripwire (mcp/lib/friction-scanners.js).
function enforceLeadRationalePolicy(domain, normalizedLeads) {
  let policy;
  try {
    policy = loadQueuePolicy(domain);
  } catch {
    return;
  }
  if (!policy || policy.lead_rationale_required_when_below_threshold !== true) {
    return;
  }
  const { minScore } = normalizePromotionOptions({});
  for (let i = 0; i < normalizedLeads.length; i += 1) {
    const lead = normalizedLeads[i];
    const score = typeof lead.score === "number" ? lead.score : 0;
    if (score >= minScore) continue;
    const rationale = typeof lead.rationale === "string" ? lead.rationale.trim() : "";
    if (rationale) continue;
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      `leads[${i}] has score ${score} below queue-policy min_score ${minScore} but lacks rationale`,
      { index: i, score, min_score: minScore },
      {
        remediation: `lead at index ${i} has score ${score} below min_score ${minScore} but lacks rationale; provide a non-empty rationale (≤512 chars) explaining why this lead is being recorded despite being below threshold, OR raise the lead's score, OR set queue-policy.lead_rationale_required_when_below_threshold: false to disable the gate`,
      },
    );
  }
}

function recordSurfaceLeadsInternal(domain, leads, context = {}) {
  if (!Array.isArray(leads) || leads.length === 0) {
    return { recorded: 0, lead_ids: [], path: surfaceLeadsPath(domain) };
  }
  const document = readSurfaceLeadsDocument(domain);
  const byKey = new Map(document.leads.map((lead) => [lead.key, lead]));
  const leadIds = [];
  const ledgerEntries = [];
  let recorded = 0;
  // Pre-normalize all leads so the rationale-policy validator can read the
  // computed `score` (evidenceScore fallback when input.score is absent)
  // before any partial state is persisted.
  const normalizedLeads = leads.map((leadInput) => normalizeSurfaceLead(leadInput, context));
  enforceLeadRationalePolicy(domain, normalizedLeads);
  // Fix #134 — soft warning path for external producers (independent of
  // the strict queue-policy toggle). Runs after the strict gate so any
  // INVALID_ARGUMENTS rejection still short-circuits before we warn.
  warnExternalProducerMissingRationale(domain, normalizedLeads);
  for (const incoming of normalizedLeads) {
    const existing = byKey.get(incoming.key);
    const lead = existing
      ? mergeSurfaceLead(existing, incoming)
      : { ...incoming, id: incoming.id || nextLeadId(document.leads), created_at: new Date().toISOString() };
    if (existing) {
      document.leads[document.leads.findIndex((entry) => entry.id === existing.id)] = lead;
    } else {
      document.leads.push(lead);
      recorded += 1;
    }
    byKey.set(lead.key, lead);
    leadIds.push(lead.id);
    ledgerEntries.push(lead);
  }
  // LEGACY: removed in Plane D — surface-leads.json is the legacy projection;
  // frontier-events.jsonl is the append-only authority after F.2 materializes.
  const filePath = writeSurfaceLeadsDocument(domain, document);
  // Dual-write per Pact P2: each recorded/merged lead also appends a
  // frontier.enqueued event so the frontier projection sees the same intake.
  for (const lead of ledgerEntries) emitFrontierEnqueued(domain, lead);
  return { recorded, total: document.leads.length, lead_ids: leadIds, path: filePath };
}

function previewSurfaceLeadPromotion(domain, options = {}) {
  const document = readSurfaceLeadsDocument(domain);
  return buildPromotionPreview(domain, partitionLeadPromotion(document, options).selectedLeads);
}

function promoteSurfaceLeadsInternal(domain, options = {}) {
  // update_state is retained for argument-shape compatibility but no longer
  // mutates state.json — D.3 deleted state.lead_surface_ids; lead-surface
  // membership is derived from frontier surface.observed events.
  if (options.update_state != null) {
    assertBoolean(options.update_state, "update_state");
  }
  const document = readSurfaceLeadsDocument(domain);
  const promotion = partitionLeadPromotion(document, options);
  const candidates = promotion.selectedLeads;
  const { promoted_surface_ids: promotedSurfaceIds } = candidates.length > 0
    ? applyPromotionToFrontier(domain, candidates)
    : { promoted_surface_ids: [] };
  const now = new Date().toISOString();
  for (let i = 0; i < candidates.length; i += 1) {
    const index = document.leads.findIndex((item) => item.id === candidates[i].id);
    if (index === -1) continue;
    document.leads[index] = {
      ...document.leads[index],
      status: "promoted",
      promoted_surface_id: promotedSurfaceIds[i],
      promoted_at: now,
    };
  }
  const newlyFilteredIndexes = [];
  for (const lead of promotion.filteredLeads) {
    const index = document.leads.findIndex((item) => item.id === lead.id);
    if (index === -1 || document.leads[index].evaluator_run_avoided_recorded_at) continue;
    newlyFilteredIndexes.push(index);
  }
  const newlyFiltered = newlyFilteredIndexes.length;
  const deferredByLimit = Math.max(0, promotion.promotableLeads.length - promotion.limit);
  let avoidedEvent = null;
  if (newlyFiltered > 0 || deferredByLimit > 0) {
    avoidedEvent = safeAppendPipelineEventDirect(domain, "evaluator_run_avoided", {
      source: options.source || "bob_promote_surface_leads",
      counts: {
        assignable: promotion.assignableLeads.length,
        promoted: promotedSurfaceIds.length,
        filtered: newlyFiltered,
        deferred_by_limit: deferredByLimit,
        evaluator_runs_avoided: newlyFiltered,
      },
    }, safeGovernanceContextForDomain(domain));
  }
  if (avoidedEvent) {
    for (const index of newlyFilteredIndexes) {
      document.leads[index] = {
        ...document.leads[index],
        evaluator_run_avoided_recorded_at: now,
      };
    }
  }
  if (candidates.length > 0 || (avoidedEvent && newlyFiltered > 0)) {
    writeSurfaceLeadsDocument(domain, document);
  }
  return buildPromotionEnvelope(domain, promotedSurfaceIds);
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

function isPlainObject(value) {
  return value != null && typeof value === "object" && !Array.isArray(value);
}

const REACHABILITY_ATTACK_VECTORS = new Set(["local", "network"]);
const REACHABILITY_SEVERITY_CEILINGS = new Set(["none", "low", "medium", "high", "critical"]);

function findingFile(finding) {
  const location = isPlainObject(finding && finding.location) ? finding.location : {};
  return typeof location.path === "string"
    ? location.path
    : (typeof (finding && finding.file) === "string" ? finding.file : null);
}

function findingLine(finding) {
  const location = isPlainObject(finding && finding.location) ? finding.location : {};
  return Number.isInteger(location.line)
    ? location.line
    : (Number.isInteger(finding && finding.start_line) ? finding.start_line : null);
}

function arrayStrings(value) {
  const values = Array.isArray(value) ? value : [value];
  return values
    .filter((item) => item != null)
    .map((item) => String(item))
    .filter((item) => item.length > 0);
}

function candidateFindingKeys(finding, { includeRuleClass = false } = {}) {
  const file = findingFile(finding);
  const line = findingLine(finding);
  const keys = [
    finding && finding.finding_hash,
    finding && finding.source_result_sha256,
    finding && finding.surface_id,
    file,
    file && Number.isInteger(line) ? `${file}:${line}` : null,
  ];
  if (includeRuleClass) {
    keys.push(
      finding && finding.rule_id,
      ...arrayStrings(finding && finding.cwe),
    );
  }
  return keys.filter((key) => typeof key === "string" && key.length > 0);
}

function candidateFamilyKeys(finding) {
  return candidateFindingKeys(finding, { includeRuleClass: true });
}

function normalizedReachabilityString(value, allowed) {
  if (typeof value !== "string") return null;
  const normalized = value.trim().toLowerCase();
  return allowed.has(normalized) ? normalized : null;
}

function directReachability(value) {
  if (!isPlainObject(value)) return null;
  const reachability = {};
  if (Object.prototype.hasOwnProperty.call(value, "attack_vector")) {
    const attackVector = normalizedReachabilityString(value.attack_vector, REACHABILITY_ATTACK_VECTORS);
    if (!attackVector) return null;
    reachability.attack_vector = attackVector;
  }
  if (Object.prototype.hasOwnProperty.call(value, "severity_ceiling")) {
    const severityCeiling = normalizedReachabilityString(value.severity_ceiling, REACHABILITY_SEVERITY_CEILINGS);
    if (!severityCeiling) return null;
    reachability.severity_ceiling = severityCeiling;
  }
  if (Object.prototype.hasOwnProperty.call(value, "network_reachable")) {
    if (typeof value.network_reachable !== "boolean") return null;
    reachability.network_reachable = value.network_reachable;
  }
  return Object.keys(reachability).length > 0 ? reachability : null;
}

function reachabilityValueAt(index, keys) {
  if (!index) return null;
  if (index instanceof Map) {
    for (const key of keys) {
      const value = directReachability(index.get(key));
      if (value) return value;
    }
  }
  if (isPlainObject(index)) {
    for (const key of keys) {
      const value = directReachability(index[key]);
      if (value) return value;
    }
  }
  return null;
}

function reachabilityEntriesFromIndex(index) {
  const entries = [];
  const pushEntry = (key, value) => {
    const reachability = directReachability(value);
    if (reachability) entries.push({ key, reachability });
  };
  const scanRecord = (record) => {
    if (!isPlainObject(record)) return;
    [
      record.id,
      record.surface_id,
      record.file_path,
      record.file,
    ].forEach((key) => pushEntry(key, record));
  };
  if (index instanceof Map) {
    index.forEach((value, key) => pushEntry(key, value));
  }
  if (isPlainObject(index)) {
    if (isPlainObject(index.perSurface)) {
      for (const [key, value] of Object.entries(index.perSurface)) pushEntry(key, value);
    } else if (index.perSurface instanceof Map) {
      index.perSurface.forEach((value, key) => pushEntry(key, value));
    }
    const reachability = isPlainObject(index.reachability) ? index.reachability : index;
    if (Array.isArray(reachability.surface_ceilings)) {
      reachability.surface_ceilings.forEach(scanRecord);
    }
  }
  return entries;
}

function fileMatchesReachabilityKey(file, key) {
  if (typeof file !== "string" || typeof key !== "string" || !file || !key) return false;
  return file === key || file.startsWith(`${key}/`) || key.startsWith(`${file}/`);
}

function reachabilityForFinding(finding, reachabilityIndex) {
  const keys = candidateFindingKeys(finding);
  const keyed = reachabilityValueAt(reachabilityIndex, keys);
  if (keyed) return keyed;
  const file = findingFile(finding);
  for (const entry of reachabilityEntriesFromIndex(reachabilityIndex)) {
    if (keys.includes(entry.key) || fileMatchesReachabilityKey(file, entry.key)) {
      return entry.reachability;
    }
  }
  return {};
}

function staticFindingsForRecord(domain, findings, context = {}) {
  if (Array.isArray(findings)) return findings;
  if (context.query_static_analysis_index === true) {
    return queryStaticAnalysisIndex(domain, {
      top_k: context.top_k,
      min_severity: context.min_severity,
      rule_id: context.rule_id,
      surface_id: context.surface_id,
    });
  }
  return readStaticAnalysisIndex(domain);
}

function normalizeStaticFindingForRecord(domain, finding) {
  return normalizeStaticAnalysisIndexRecord({
    ...finding,
    target_domain: finding && finding.target_domain ? finding.target_domain : domain,
    indexed_at: finding && finding.indexed_at ? finding.indexed_at : new Date(0).toISOString(),
  });
}

const OSS_ROOTCAUSE_FAMILY_LABELS = new Set(OSS_ROOTCAUSE_FAMILIES.map((family) => family.family));

function familyFromIndexValue(value) {
  if (typeof value === "string" && value.trim()) return value.trim();
  if (isPlainObject(value) && typeof value.family === "string" && value.family.trim()) return value.family.trim();
  if (Array.isArray(value) && value.length > 0) return familyFromIndexValue(value[0]);
  return null;
}

function familyFromIndex(finding, familyIndex) {
  const keys = candidateFamilyKeys(finding);
  if (familyIndex && typeof familyIndex.get === "function") {
    for (const key of keys) {
      const family = familyFromIndexValue(familyIndex.get(key));
      if (family) return family;
    }
  }
  if (isPlainObject(familyIndex)) {
    for (const key of keys) {
      const family = familyFromIndexValue(familyIndex[key]);
      if (family) return family;
    }
  }
  return null;
}

function familyFromCorpus(finding, context = {}) {
  const file = findingFile(finding);
  const surface = {
    id: finding && finding.surface_id,
    title: finding && finding.rule_id,
    surface_type: "oss_static_sink",
    file_path: file,
    endpoints: file && Number.isInteger(findingLine(finding)) ? [`${file}:${findingLine(finding)}`] : [],
    bug_class_hints: [
      finding && finding.rule_id,
      ...arrayStrings(finding && finding.cwe),
      ...arrayStrings(finding && finding.tags),
    ],
    evidence: [finding && finding.message].filter(Boolean),
    task_lens: context.task_lens || "taint_trace",
  };
  try {
    const result = suggestFamiliesForSurface(surface, {
      lens: context.task_lens || "taint_trace",
      limit: 3,
    });
    const matched = (result.suggestions || []).find((suggestion) => (
      OSS_ROOTCAUSE_FAMILY_LABELS.has(suggestion.family)
      && Array.isArray(suggestion.matched_signature)
      && suggestion.matched_signature.length > 0
    ));
    return matched ? matched.family : null;
  } catch {
    return null;
  }
}

function familyForFinding(finding, familyIndex, context = {}) {
  return familyFromIndex(finding, familyIndex)
    || familyFromCorpus(finding, context)
    || null;
}

function recordStaticAnalysisLeads(domainRaw, findings, reachabilityIndex = {}, familyIndex = {}, context = {}) {
  const domain = assertNonEmptyString(domainRaw, "target_domain");
  const inputFindings = staticFindingsForRecord(domain, findings, context);
  const leads = [];
  const warnings = [];
  for (let i = 0; i < inputFindings.length; i += 1) {
    const rawFinding = inputFindings[i];
    try {
      const finding = normalizeStaticFindingForRecord(domain, rawFinding);
      const reachability = reachabilityForFinding(finding, reachabilityIndex);
      const family = familyForFinding(finding, familyIndex, context);
      const lead = staticFindingToSurfaceLead(finding, reachability, family);
      if (!lead) {
        warnings.push(`skipped static finding at index ${i}: missing file or line`);
        continue;
      }
      leads.push(scoreStaticLeadWithReachability(lead, reachability));
    } catch (error) {
      warnings.push(`skipped static finding at index ${i}: ${error.message || String(error)}`);
    }
  }
  return withSessionLock(domain, () => ({
    version: 1,
    target_domain: domain,
    input_findings: inputFindings.length,
    mapped_leads: leads.length,
    skipped_findings: warnings.length,
    warnings,
    ...recordSurfaceLeadsInternal(domain, leads, {
      ...context,
      source: STATIC_LEAD_SOURCE,
    }),
  }));
}

function readSurfaceLeads(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const limit = args.limit == null ? 50 : assertInteger(args.limit, "limit", { min: 1, max: 200 });
  const document = readSurfaceLeadsDocument(domain);
  const leads = sortLeadsByScore(document.leads).slice(0, limit);
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

registerStaticAnalysisLeadRecorder(recordStaticAnalysisLeads);

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
  previewSurfaceLeadPromotion,
  promoteSurfaceLeads,
  promoteSurfaceLeadsForWave,
  readSurfaceLeads,
  recordSurfaceLeads,
  recordStaticAnalysisLeads,
  recordSurfaceLeadsForWaveHandoff,
};
