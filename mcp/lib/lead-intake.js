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
const { CHAIN_FAMILY_VALUES } = require("./constants.js");

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

// chain_id is polymorphic across chain families: EVM uses a numeric id (e.g.
// 42161), while svm/aptos/sui/substrate/cosmwasm key RPC pools by network NAME
// (a string). Preserve a finite number as-is and otherwise normalize as a short
// string, so the smart-contract sub-shape survives intake intact.
function normalizeOptionalChainId(value) {
  if (value == null) return null;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("chain_id must be a finite number when numeric");
    return value;
  }
  return normalizeOptionalString(value, "chain_id", { maxChars: 40 });
}

function collectChainContextStrings(input) {
  if (input == null || typeof input !== "object" || Array.isArray(input)) return [];
  const values = [];
  for (const field of ["evidence", "endpoints", "hosts"]) {
    const raw = input[field];
    if (!Array.isArray(raw)) continue;
    for (const entry of raw) {
      if (typeof entry === "string") {
        values.push(entry);
      } else if (entry && typeof entry === "object" && !Array.isArray(entry)) {
        for (const value of Object.values(entry)) {
          if (typeof value === "string") values.push(value);
        }
      }
    }
  }
  for (const field of ["rpc", "chain", "network"]) {
    if (typeof input[field] === "string") values.push(input[field]);
  }
  return values;
}

function knownChainFamily(value) {
  const normalized = typeof value === "string" ? value.trim().toLowerCase() : null;
  return normalized && CHAIN_FAMILY_VALUES.includes(normalized) ? normalized : null;
}

// Y-D22 - resolve chain_family/chain_id from address shape + observed
// chain context, fail-closed to a blocked_prereqs lead (never a silent
// unroutable-park). Emits only a CHAIN_FAMILY_VALUES member.
function resolveChainContext(input) {
  if (input == null || typeof input !== "object" || Array.isArray(input)) return null;
  const contractAddress = typeof input.contract_address === "string" ? input.contract_address.trim() : "";
  if (!contractAddress) return null;

  const contextText = collectChainContextStrings(input).join("\n").toLowerCase();
  const evmFamily = knownChainFamily("evm");
  const svmFamily = knownChainFamily("svm");

  if (/^0x[0-9a-fA-F]{40}$/.test(contractAddress)) {
    // Collect EVERY chain the evidence names, then require EXACTLY ONE. A base-specific token
    // is required for Base (bare "base" matches "base fee"/"base URL"); a mainnet-specific
    // token for Ethereum (bare "ethereum" matches "Ethereum-compatible"/"EVM" on every L2).
    // If the evidence names TWO different chains (e.g. "bridged via Arbitrum" on a Polygon
    // contract), fail CLOSED to a blocked_prereqs lead rather than tie-break by branch
    // priority onto the wrong chain (Y-D22).
    const chainMatches = new Set();
    if (/\bbase[-_\s]?(?:mainnet|sepolia|goerli|testnet)\b|\beip155:8453\b|\bchain[-_\s]?id[\s:=]*8453\b/.test(contextText)) chainMatches.add(8453);
    if (/\boptimism\b|\boptimistic[-_\s]?ethereum\b|\bop[-_\s]?mainnet\b/.test(contextText)) chainMatches.add(10);
    if (/\barbitrum\b|\barb[-_\s]?mainnet\b/.test(contextText)) chainMatches.add(42161);
    if (/\bpolygon\b|\bmatic\b/.test(contextText)) chainMatches.add(137);
    if (/\bethereum[-_\s]?mainnet\b|\beth[-_\s]?mainnet\b|\beip155:1\b|\bchain[-_\s]?id[\s:=]*1\b/.test(contextText)) chainMatches.add(1);
    if (chainMatches.size !== 1) return null;
    return evmFamily ? { chain_family: evmFamily, chain_id: [...chainMatches][0] } : null;
  }

  if (/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(contractAddress) && /\bsolana\b|\bsvm\b/.test(contextText)) {
    return svmFamily ? { chain_family: svmFamily, chain_id: null } : null;
  }

  return null;
}

function normalizeReachabilityMeta(value) {
  if (value == null) return null;
  if (typeof value !== "object" || Array.isArray(value)) {
    throw new Error("reachability_meta must be an object");
  }
  const meta = {};
  if (value.attack_vector != null) {
    meta.attack_vector = normalizeOptionalString(value.attack_vector, "reachability_meta.attack_vector", { maxChars: 40 });
  }
  if (value.network_reachable != null) {
    meta.network_reachable = assertBoolean(value.network_reachable, "reachability_meta.network_reachable");
  }
  if (value.severity_ceiling != null) {
    meta.severity_ceiling = normalizeOptionalString(value.severity_ceiling, "reachability_meta.severity_ceiling", { maxChars: 40 });
  }
  return Object.keys(meta).length > 0 ? meta : null;
}

function mergeReachabilityMeta(existing, incoming) {
  if (!existing && !incoming) return null;
  const merged = {
    ...(existing || {}),
    ...(incoming || {}),
  };
  return Object.keys(merged).length > 0 ? merged : null;
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
    // Smart-contract sub-shape. Carried verbatim through intake so promotion
    // can stamp it onto the surface.observed payload; capability routing
    // (classifySurfaceCapability) requires chain_family for smart_contract
    // surfaces, and assignment-brief selects the RPC pool from chain_family +
    // chain_id. Dropping them here is what produced unroutable surfaces.
    chain_family: normalizeOptionalString(input.chain_family, "chain_family", { maxChars: 40 }),
    chain_id: normalizeOptionalChainId(input.chain_id),
    contract_address: normalizeOptionalString(input.contract_address, "contract_address", { maxChars: 120 }),
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
    reachability_meta: normalizeReachabilityMeta(input.reachability_meta),
    ...arrays,
  };
  if (
    String(initial.surface_type || "").trim().toLowerCase() === "smart_contract" &&
    initial.chain_family == null &&
    initial.contract_address != null
  ) {
    const resolved = resolveChainContext({
      ...initial,
      rpc: input.rpc,
      chain: input.chain,
      network: input.network,
    });
    if (resolved && CHAIN_FAMILY_VALUES.includes(resolved.chain_family)) {
      initial.chain_family = resolved.chain_family;
      initial.chain_id = normalizeOptionalChainId(resolved.chain_id);
    } else {
      initial.blocked_prereqs = [
        {
          reason: "smart_contract lead has a contract_address but no resolvable chain_family; supply chain_family/chain_id or an RPC endpoint that resolves the address",
          needed_for: "capability routing",
        },
      ];
    }
  }
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
    chain_family: existing.chain_family || incoming.chain_family,
    chain_id: existing.chain_id == null ? incoming.chain_id : existing.chain_id,
    contract_address: existing.contract_address || incoming.contract_address,
    promote: existing.promote || incoming.promote,
    evaluator_run_avoided_recorded_at: existing.evaluator_run_avoided_recorded_at
      || incoming.evaluator_run_avoided_recorded_at,
    // Y.12 (rev 4.1 defect 1) — rationale on merge: incoming wins when the
    // existing entry lacked one, otherwise keep the existing rationale so
    // earlier producer-side reasoning is not overwritten by a later
    // re-record that omitted the field.
    rationale: existing.rationale || incoming.rationale,
    reachability_meta: mergeReachabilityMeta(existing.reachability_meta, incoming.reachability_meta),
    confidence: LEAD_CONFIDENCE_VALUES.indexOf(incoming.confidence) < LEAD_CONFIDENCE_VALUES.indexOf(existing.confidence)
      ? incoming.confidence
      : existing.confidence,
    score,
    priority,
  };
  const blockedPrereqs = Array.isArray(existing.blocked_prereqs) && existing.blocked_prereqs.length > 0
    ? existing.blocked_prereqs
    : incoming.blocked_prereqs;
  if (Array.isArray(blockedPrereqs) && blockedPrereqs.length > 0) {
    next.blocked_prereqs = blockedPrereqs;
  }
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
