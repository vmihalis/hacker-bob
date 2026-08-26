"use strict";

// Normalizes EXISTING structured mechanism knowledge into candidate mechanism
// templates shaped like loadMechanismTemplates' validated output
// (invariant-template-corpus.js): required_entities, interventions,
// positive_controls, negative_controls, confounders, evidence_predicate.
//
// Three knowledge-record shapes are accepted as input:
//   - a CWE-catalog entry (cwe-catalog.js: { id, title })
//   - an audit-report finding (audit-report-parser.js findings[*])
//   - a schema-doc contract (schema-contracts-store.js contracts[*])
//
// Every produced template is a TIER-3, ADVISORY candidate: claim_authority is
// always false and it carries NO executed proof. A normalized template is
// merely-believed knowledge — it RESOLVES only when an executed differential
// confirms the mechanism elsewhere. Many audit-report inputs arrive bundled
// with a PoC and a not-a-false-positive rationale; that is captured here as
// advisory evidence METADATA, never as a confirmation. Normalizing is free and
// self-confirms nothing.
//
// This module is standalone: it does not register, ingest, persist, or feed the
// live loadMechanismTemplates loader, and it never writes an audit-graded
// ledger. Its only product is candidate-template DATA plus a dedup key so two
// near-identical inputs do not yield duplicate candidates.

const {
  canonicalizeCwe,
  cweTitle,
} = require("../scoring/cwe-catalog.js");

// The tier of every candidate this module produces. Tier-3 is advisory: it
// ranks/seeds attention but can never mint a verdict, closure, or claim. The
// string is mirrored in evidence metadata so a downstream reader cannot lose it
// by inspecting only one field.
const CANDIDATE_TIER = 3;
const CANDIDATE_SOURCE_TIERS = Object.freeze({
  cwe_catalog: "cwe_catalog",
  audit_finding: "audit_finding",
  schema_contract: "schema_contract",
});

function isPlainObject(value) {
  return value != null && typeof value === "object" && !Array.isArray(value);
}

// A stable, lowercased token usable in a candidate id and a dedup key. Collapses
// any run of non-alphanumerics to a single dash so two inputs that differ only
// in punctuation/whitespace/casing land on the same slug.
function slugify(value, fallback) {
  const text = typeof value === "string" ? value.trim().toLowerCase() : "";
  const slug = text.replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
  return slug || fallback;
}

function nonEmptyStrings(values) {
  if (!Array.isArray(values)) return [];
  const out = [];
  for (const value of values) {
    if (typeof value === "string" && value.trim()) out.push(value.trim());
  }
  return out;
}

// The advisory evidence envelope. It records that an input MAY arrive with a PoC
// and a not-a-false-positive rationale, but flags it as unverified: there is no
// executed differential behind a candidate template, so executed_proof is always
// false. A reader must treat this as a lead, not a confirmation.
function buildAdvisoryEvidence(record, sourceTier) {
  const evidence = {
    tier: CANDIDATE_TIER,
    source_tier: sourceTier,
    claim_authority: false,
    executed_proof: false,
    verified: false,
  };
  if (!isPlainObject(record)) return Object.freeze(evidence);
  // An audit finding (or any record) may carry an attacker PoC and a rationale
  // arguing it is not a false positive. Capture both as advisory metadata so the
  // lead is not lost, while NEVER promoting them to a confirmation. The presence
  // of a PoC does not make the candidate verified — only an executed
  // differential does.
  const poc = typeof record.poc === "string" && record.poc.trim()
    ? record.poc.trim()
    : (typeof record.proof_of_concept === "string" && record.proof_of_concept.trim()
      ? record.proof_of_concept.trim()
      : null);
  if (poc) {
    evidence.advisory_poc = poc.slice(0, 4000);
    evidence.advisory_poc_present = true;
  }
  const rationale = typeof record.not_a_false_positive === "string" && record.not_a_false_positive.trim()
    ? record.not_a_false_positive.trim()
    : (typeof record.rationale === "string" && record.rationale.trim()
      ? record.rationale.trim()
      : null);
  if (rationale) {
    evidence.advisory_not_a_false_positive = rationale.slice(0, 4000);
  }
  if (typeof record.source_uri === "string" && record.source_uri.trim()) {
    evidence.source_uri = record.source_uri.trim();
  }
  if (typeof record.finding_hash === "string" && record.finding_hash.trim()) {
    evidence.source_finding_hash = record.finding_hash.trim();
  }
  return Object.freeze(evidence);
}

// Assembles a candidate template in the loadMechanismTemplates shape, plus the
// advisory tier metadata that keeps it merely-believed. The mechanism_id is a
// catalog CWE so the result validates against normalizeMechanismTemplate; the
// CWE membership is an ANNOTATION carried for routing, never a drop-gate.
function buildCandidate(parts) {
  const {
    id,
    mechanismId,
    name,
    description,
    requiredEntities,
    interventions,
    positiveControls,
    negativeControls,
    confounders,
    evidencePredicate,
    advisoryEvidence,
    sourceTier,
    dedupKey,
  } = parts;
  return Object.freeze({
    id,
    mechanism_id: mechanismId,
    name,
    description,
    required_entities: Object.freeze(requiredEntities.slice()),
    interventions: Object.freeze(interventions.slice()),
    positive_controls: Object.freeze(positiveControls.slice()),
    negative_controls: Object.freeze(negativeControls.slice()),
    confounders: Object.freeze(confounders.slice()),
    evidence_predicate: Object.freeze({ ...evidencePredicate }),
    // Advisory, non-authoritative metadata. These fields live alongside the
    // validated template shape; normalizeMechanismTemplate ignores unknown keys,
    // so a candidate validates yet stays tier-3 advisory.
    tier: CANDIDATE_TIER,
    candidate: true,
    claim_authority: false,
    source_tier: sourceTier,
    advisory_evidence: advisoryEvidence,
    dedup_key: dedupKey,
  });
}

// A negative control that MUST flip is universal: a candidate template never
// minted confirmed cannot be confirmed by a single non-discriminating run. Every
// candidate carries at least one refuting control so a downstream confirm path
// is forced to demonstrate a flip, never a single pass.
function defaultNegativeControls(extra) {
  const base = [
    "benign_baseline_must_hold",
    "non_discriminating_control_refused",
  ];
  return base.concat(nonEmptyStrings(extra));
}

// --- CWE-catalog entry -> candidate template -------------------------------
//
// Input: a CWE-catalog entry expressed as { id: "CWE-639", title?: "..." } (the
// catalog is a map of id->title; callers pass one entry). The mechanism is the
// CWE itself: a principal acting on a guarded effect. The required edges encode
// the minimal differential a confirm path must execute.
function normalizeCweEntry(entry) {
  const warnings = [];
  const record = isPlainObject(entry) ? entry : {};
  const canonical = canonicalizeCwe(record.id != null ? record.id : entry);
  if (!canonical) {
    return { template: null, warnings: ["cwe id is required and must canonicalize"] };
  }
  const title = typeof record.title === "string" && record.title.trim()
    ? record.title.trim()
    : cweTitle(canonical);
  if (!title) {
    warnings.push("cwe is not in the curated catalog; title falls back to id");
  }
  const sourceTier = CANDIDATE_SOURCE_TIERS.cwe_catalog;
  const slug = slugify(canonical, "cwe");
  const dedupKey = `${sourceTier}:${canonical}`;
  const template = buildCandidate({
    id: `cand-${slug}`,
    mechanismId: canonical,
    name: title || canonical,
    description: `Candidate mechanism normalized from CWE-catalog class ${canonical}${title ? ` (${title})` : ""}. Advisory tier-3: not confirmed until an executed differential demonstrates the flip.`,
    requiredEntities: ["principal", "guarded_resource", "policy_gate", "effect"],
    interventions: ["exercise_guarded_path_as_unauthorized_principal"],
    positiveControls: ["unauthorized_principal_obtains_effect"],
    negativeControls: defaultNegativeControls(["authorized_principal_baseline_allowed"]),
    confounders: ["preexisting_authorization", "cached_effect", "response_reflection"],
    evidencePredicate: {
      kind: "differential_effect",
      required_edges: ["principal->policy_gate", "policy_gate->effect"],
      required_cwe: canonical,
    },
    advisoryEvidence: buildAdvisoryEvidence(record, sourceTier),
    sourceTier,
    dedupKey,
  });
  return { template, warnings };
}

// --- audit-report finding -> candidate template ----------------------------
//
// Input: an audit-report-parser finding { title, description?, severity?,
// vulnerability_class?, finding_hash?, scope_paths?, poc?,
// not_a_false_positive? }. The vulnerability_class seeds the mechanism; the
// PoC + rationale (if present) become advisory evidence, NOT confirmation. The
// mechanism_id needs a catalog CWE — if the caller did not supply one that
// canonicalizes, the candidate is held back with a warning (annotate-not-gate:
// the CWE is required to VALIDATE the template shape, not to drop the lead).
function normalizeAuditFinding(finding, options) {
  const warnings = [];
  if (!isPlainObject(finding)) {
    return { template: null, warnings: ["finding must be an object"] };
  }
  const title = typeof finding.title === "string" && finding.title.trim()
    ? finding.title.trim()
    : null;
  if (!title) warnings.push("finding title is required");
  const cweHint = (options && options.cwe) || finding.cwe || finding.required_cwe;
  const canonical = canonicalizeCwe(cweHint);
  if (!canonical) {
    warnings.push("audit finding needs a catalog CWE (options.cwe or finding.cwe) to shape mechanism_id");
  }
  if (!title || !canonical) {
    return { template: null, warnings };
  }
  const vulnClass = typeof finding.vulnerability_class === "string" && finding.vulnerability_class.trim()
    ? finding.vulnerability_class.trim()
    : "unknown";
  const sourceTier = CANDIDATE_SOURCE_TIERS.audit_finding;
  // Dedup by the finding's content hash when present (idempotent re-ingest),
  // else by the stable title+class slug.
  const dedupBasis = typeof finding.finding_hash === "string" && finding.finding_hash.trim()
    ? finding.finding_hash.trim()
    : `${slugify(vulnClass, "unknown")}:${slugify(title, "finding")}`;
  const dedupKey = `${sourceTier}:${dedupBasis}`;
  const template = buildCandidate({
    id: `cand-${slugify(`${vulnClass}-${title}`, "audit-finding")}`,
    mechanismId: canonical,
    name: title,
    description: `Candidate mechanism normalized from audit finding "${title}" (class ${vulnClass}). Advisory tier-3: a bundled PoC/rationale is a lead, not a confirmation; confirmation requires an executed differential.`,
    requiredEntities: ["principal", "vulnerable_component", "guard_condition", "effect"],
    interventions: ["reproduce_reported_precondition", "exercise_vulnerable_component"],
    positiveControls: ["reported_effect_observed"],
    negativeControls: defaultNegativeControls(["patched_or_guarded_variant_holds"]),
    confounders: ["environment_specific_state", "stale_report", "response_reflection"],
    evidencePredicate: {
      kind: "differential_effect",
      required_edges: ["principal->guard_condition", "guard_condition->effect"],
      required_cwe: canonical,
    },
    advisoryEvidence: buildAdvisoryEvidence(finding, sourceTier),
    sourceTier,
    dedupKey,
  });
  return { template, warnings };
}

// --- schema-doc contract -> candidate template -----------------------------
//
// Input: a schema-contracts-store contract { endpoint?, method?,
// claimed_auth?, claimed_params?, claimed_response_shape?, contract_hash? }. The
// mechanism is doc-vs-behavior: the documented contract is the claim and a
// differential checks whether live behavior matches. CWE-345 (insufficient
// verification of data authenticity) is the default mechanism class; a caller
// may override via options.cwe.
function normalizeSchemaContract(contract, options) {
  const warnings = [];
  if (!isPlainObject(contract)) {
    return { template: null, warnings: ["contract must be an object"] };
  }
  const endpoint = typeof contract.endpoint === "string" && contract.endpoint.trim()
    ? contract.endpoint.trim()
    : null;
  if (!endpoint) warnings.push("contract endpoint is required");
  const method = typeof contract.method === "string" && contract.method.trim()
    ? contract.method.trim().toUpperCase()
    : "ANY";
  const cweHint = (options && options.cwe) || contract.cwe || "CWE-345";
  const canonical = canonicalizeCwe(cweHint);
  if (!canonical) warnings.push("schema contract cwe must canonicalize");
  if (!endpoint || !canonical) {
    return { template: null, warnings };
  }
  const sourceTier = CANDIDATE_SOURCE_TIERS.schema_contract;
  const dedupBasis = typeof contract.contract_hash === "string" && contract.contract_hash.trim()
    ? contract.contract_hash.trim()
    : `${method}:${slugify(endpoint, "endpoint")}`;
  const dedupKey = `${sourceTier}:${dedupBasis}`;
  const template = buildCandidate({
    id: `cand-${slugify(`${method}-${endpoint}`, "schema-contract")}`,
    mechanismId: canonical,
    name: `${method} ${endpoint} doc-vs-behavior`,
    description: `Candidate mechanism normalized from schema contract ${method} ${endpoint}. Advisory tier-3: the documented contract is a claim; confirmation requires an executed differential between documented and live behavior.`,
    requiredEntities: ["client", "documented_contract", "live_endpoint", "response"],
    interventions: ["send_request_violating_documented_contract"],
    positiveControls: ["live_behavior_diverges_from_documented_contract"],
    negativeControls: defaultNegativeControls(["documented_request_behaves_as_documented"]),
    confounders: ["doc_staleness", "environment_variance", "response_reflection"],
    evidencePredicate: {
      kind: "differential_effect",
      required_edges: ["client->live_endpoint", "live_endpoint->response"],
      required_cwe: canonical,
    },
    advisoryEvidence: buildAdvisoryEvidence(contract, sourceTier),
    sourceTier,
    dedupKey,
  });
  return { template, warnings };
}

// Dispatch a single knowledge record by declared kind. Returns
// { template, warnings }; template is null when the input is too sparse to shape
// a valid mechanism_id-bearing candidate.
function normalizeKnowledgeRecord(record, kind, options) {
  switch (kind) {
    case "cwe_catalog":
      return normalizeCweEntry(record);
    case "audit_finding":
      return normalizeAuditFinding(record, options);
    case "schema_contract":
      return normalizeSchemaContract(record, options);
    default:
      return { template: null, warnings: [`unknown knowledge record kind: ${String(kind)}`] };
  }
}

// The dedup key for a candidate template. Two near-identical inputs (same source
// tier + same underlying identity) collapse to one candidate. The key is the
// source tier joined with the most stable identity available: a content/contract
// hash when present, else a punctuation-insensitive slug of the salient fields.
function candidateDedupKey(template) {
  if (!isPlainObject(template)) return null;
  if (typeof template.dedup_key === "string" && template.dedup_key) {
    return template.dedup_key;
  }
  const tier = typeof template.source_tier === "string" ? template.source_tier : "unknown";
  return `${tier}:${slugify(template.mechanism_id, "mechanism")}:${slugify(template.name, "name")}`;
}

// Normalize a batch of knowledge records into a deduplicated list of candidate
// templates. Inputs may be { kind, record, options } envelopes or, when a single
// kind is passed via options.kind, bare records. Dedup ranks/keeps the first
// occurrence of each key — it never truncates a distinct candidate (rank, don't
// bound): every distinct dedup key survives.
function normalizeKnowledgeBatch(records, options) {
  const input = Array.isArray(records) ? records : [];
  const defaultKind = options && typeof options.kind === "string" ? options.kind : null;
  const candidates = [];
  const warnings = [];
  const seen = new Set();
  for (const [index, item] of input.entries()) {
    let kind = defaultKind;
    let record = item;
    let perItemOptions = options;
    if (isPlainObject(item) && typeof item.kind === "string" && "record" in item) {
      kind = item.kind;
      record = item.record;
      perItemOptions = isPlainObject(item.options) ? item.options : options;
    }
    const normalized = normalizeKnowledgeRecord(record, kind, perItemOptions);
    if (!normalized.template) {
      warnings.push({ index, warnings: normalized.warnings });
      continue;
    }
    const key = candidateDedupKey(normalized.template);
    if (seen.has(key)) {
      warnings.push({ index, warnings: [`duplicate candidate dedup_key: ${key}`] });
      continue;
    }
    seen.add(key);
    candidates.push(normalized.template);
  }
  return {
    candidates: Object.freeze(candidates),
    warnings: Object.freeze(warnings),
  };
}

module.exports = {
  CANDIDATE_TIER,
  CANDIDATE_SOURCE_TIERS,
  normalizeCweEntry,
  normalizeAuditFinding,
  normalizeSchemaContract,
  normalizeKnowledgeRecord,
  normalizeKnowledgeBatch,
  candidateDedupKey,
  buildAdvisoryEvidence,
};
