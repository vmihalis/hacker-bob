"use strict";

// PH-C10 — durable, provider-neutral finding record adapter for Plane-PH.
//
// A live PhysicalFinding is deliberately branded in memory.  Candidate claims
// must nevertheless survive restart, so this adapter serializes only the
// report-safe finding projection plus its exact physical assignment binding.
// Re-reading the record validates every digest and rejects web/SC shims; it does
// not recreate the live brand.  Grade/report adapters must re-resolve the
// server-owned verdict and campaign completion before they can mint their own
// branded bindings.

const { types: utilTypes } = require("node:util");

const {
  PHYSICAL_CAPABILITY_CONSUMER_VERSION,
  PHYSICAL_EFFECT_AUTHORITY,
  PHYSICAL_FINDING_KIND,
  PHYSICAL_LIFECYCLE_PRECONDITION,
  assertPhysicalFinding,
  derivePhysicalFindingDedupeKey,
  normalizePhysicalAssignmentContext,
} = require("./physical-capability-consumers.js");
const {
  assertSafeDomain,
} = require("../../core/io/paths.js");
const {
  validateNoPhysicalSensitiveMaterial,
} = require("../../core/physical-sensitive-material-contracts.js");
const {
  parseFindingId,
} = require("../../core/io/validation.js");

const PHYSICAL_FINDING_RECORD_ADAPTER = "physical_verified_transition_finding_v1";
const DIGEST_RE = /^[a-f0-9]{64}$/u;
const CWE_RE = /^CWE-[1-9][0-9]{0,5}$/u;
const OPAQUE_REF_RE = /^[a-z][a-z0-9._-]{0,63}:[A-Za-z0-9][A-Za-z0-9._:@-]{0,190}$/u;
const SEVERITY_VALUES = Object.freeze(["critical", "high", "medium", "low", "info"]);
const VALIDITY_KINDS = Object.freeze(["historical_event", "live_capability"]);
const FORBIDDEN_WEB_FIELDS = Object.freeze([
  "base_url",
  "endpoint",
  "proof_of_concept",
  "response_evidence",
  "sc_evidence",
]);

const REQUIRED_RECORD_FIELDS = Object.freeze([
  "id",
  "target_domain",
  "version",
  "finding_kind",
  "capability_pack",
  "capability_pack_version",
  "evaluator_agent",
  "brief_profile",
  "surface_id",
  "surface_type",
  "surface_class",
  "session_nucleus_hash",
  "asset_locator",
  "campaign_ref",
  "assignment_context_digest",
  "physical_resource_bundle_ref",
  "lifecycle_precondition",
  "effect_authority",
  "verified_verdict_ref",
  "verification_projection_digest",
  "title",
  "severity",
  "cwe",
  "description",
  "impact",
  "validity_kind",
  "decided_at",
  "finding_dedupe_key",
  "dedupe_key",
  "validated",
]);
const OPTIONAL_RECORD_FIELDS = Object.freeze(["force_record"]);

function deepFreeze(value) {
  if (value == null || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function assertExactPlainObject(value, label, required, optional = []) {
  if (value == null || typeof value !== "object" || Array.isArray(value)
      || utilTypes.isProxy(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new Error(`${label} must be a plain data object`);
  }
  const keys = Reflect.ownKeys(value);
  if (keys.some((key) => typeof key !== "string")) {
    throw new Error(`${label} cannot contain symbol fields`);
  }
  const allowed = new Set([...required, ...optional]);
  const unknown = keys.filter((key) => !allowed.has(key)).sort();
  const missing = required.filter((key) => !Object.prototype.hasOwnProperty.call(value, key));
  if (unknown.length > 0 || missing.length > 0) {
    throw new Error(
      `${label} fields are not exact (missing: ${missing.join(", ") || "none"}; unknown: ${unknown.join(", ") || "none"})`,
    );
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  for (const key of keys) {
    const descriptor = descriptors[key];
    if (!descriptor || descriptor.enumerable !== true
        || !Object.prototype.hasOwnProperty.call(descriptor, "value")) {
      throw new Error(`${label}.${key} must be an enumerable data property`);
    }
  }
  return value;
}

function assertDigest(value, label) {
  if (typeof value !== "string" || !DIGEST_RE.test(value)) {
    throw new Error(`${label} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function assertOpaqueRef(value, label, prefix = null) {
  if (typeof value !== "string" || !OPAQUE_REF_RE.test(value) || value.includes("..")) {
    throw new Error(`${label} must be a namespaced opaque reference`);
  }
  if (prefix != null && !value.startsWith(`${prefix}:`)) {
    throw new Error(`${label} must use the ${prefix}: namespace`);
  }
  return value;
}

function assertText(value, label, maximum) {
  if (typeof value !== "string" || value.length < 1 || value.length > maximum
      || value !== value.trim() || /[\u0000-\u001f\u007f]/u.test(value)) {
    throw new Error(`${label} must be trimmed control-free text of 1..${maximum} characters`);
  }
  validateNoPhysicalSensitiveMaterial(value, label, { maxTextChars: maximum });
  return value;
}

function assertTimestamp(value, label) {
  if (typeof value !== "string" || Number.isNaN(Date.parse(value))
      || new Date(value).toISOString() !== value) {
    throw new Error(`${label} must be a canonical UTC ISO-8601 timestamp`);
  }
  return value;
}

function physicalAssignmentFromFindingRecord(record) {
  return normalizePhysicalAssignmentContext({
    version: record.version,
    capability_pack: record.capability_pack,
    capability_pack_version: record.capability_pack_version,
    evaluator_agent: record.evaluator_agent,
    brief_profile: record.brief_profile,
    surface_id: record.surface_id,
    surface_type: record.surface_type,
    surface_class: record.surface_class,
    session_nucleus_hash: record.session_nucleus_hash,
    asset_locator: record.asset_locator,
    campaign_ref: record.campaign_ref,
    assignment_context_digest: record.assignment_context_digest,
    physical_resource_bundle_ref: record.physical_resource_bundle_ref,
    lifecycle_precondition: record.lifecycle_precondition,
    effect_authority: record.effect_authority,
  });
}

function normalizePhysicalFindingRecord(record, {
  expectedDomain = null,
  lineNumber = null,
} = {}) {
  try {
    assertExactPlainObject(
      record,
      "physical finding record",
      REQUIRED_RECORD_FIELDS,
      OPTIONAL_RECORD_FIELDS,
    );
    for (const field of FORBIDDEN_WEB_FIELDS) {
      if (Object.prototype.hasOwnProperty.call(record, field)) {
        throw new Error(`physical finding record cannot carry ${field}`);
      }
    }
    const targetDomain = assertSafeDomain(record.target_domain);
    if (expectedDomain != null && targetDomain !== expectedDomain) {
      throw new Error("target_domain mismatch");
    }
    if (record.version !== PHYSICAL_CAPABILITY_CONSUMER_VERSION
        || record.finding_kind !== PHYSICAL_FINDING_KIND
        || record.capability_pack !== "physical"
        || record.capability_pack_version !== 1) {
      throw new Error("physical finding record adapter identity is invalid");
    }
    if (record.lifecycle_precondition !== PHYSICAL_LIFECYCLE_PRECONDITION
        || record.effect_authority !== PHYSICAL_EFFECT_AUTHORITY) {
      throw new Error("physical finding record authority semantics drifted");
    }
    const assignment = physicalAssignmentFromFindingRecord(record);
    const cwe = record.cwe == null ? null : record.cwe;
    if (cwe != null && (typeof cwe !== "string" || !CWE_RE.test(cwe))) {
      throw new Error("physical finding record.cwe must be null or a canonical CWE identifier");
    }
    if (!SEVERITY_VALUES.includes(record.severity)) {
      throw new Error("physical finding record.severity is invalid");
    }
    if (!VALIDITY_KINDS.includes(record.validity_kind)) {
      throw new Error("physical finding record.validity_kind is invalid");
    }
    if (record.validated !== true) {
      throw new Error("physical finding record must be ledger-validated");
    }
    const findingDedupeKey = derivePhysicalFindingDedupeKey({
      asset_locator: assignment.asset_locator,
      verified_verdict_ref: assertOpaqueRef(
        record.verified_verdict_ref,
        "physical finding record.verified_verdict_ref",
        "physical-claim-verdict",
      ),
      verification_projection_digest: assertDigest(
        record.verification_projection_digest,
        "physical finding record.verification_projection_digest",
      ),
      title: assertText(record.title, "physical finding record.title", 240),
    });
    if (record.finding_dedupe_key !== findingDedupeKey
        || record.dedupe_key !== findingDedupeKey) {
      throw new Error("physical finding record dedupe binding drifted");
    }
    const normalized = {
      id: parseFindingId(record.id, "id"),
      target_domain: targetDomain,
      version: PHYSICAL_CAPABILITY_CONSUMER_VERSION,
      finding_kind: PHYSICAL_FINDING_KIND,
      capability_pack: "physical",
      capability_pack_version: 1,
      evaluator_agent: assignment.evaluator_agent,
      brief_profile: assignment.brief_profile,
      surface_id: assignment.surface_id,
      surface_type: assignment.surface_type,
      surface_class: assignment.surface_class,
      session_nucleus_hash: assignment.session_nucleus_hash,
      asset_locator: assignment.asset_locator,
      campaign_ref: assignment.campaign_ref,
      assignment_context_digest: assignment.assignment_context_digest,
      physical_resource_bundle_ref: assignment.physical_resource_bundle_ref,
      lifecycle_precondition: assignment.lifecycle_precondition,
      effect_authority: assignment.effect_authority,
      verified_verdict_ref: record.verified_verdict_ref,
      verification_projection_digest: record.verification_projection_digest,
      title: record.title,
      severity: record.severity,
      cwe,
      description: assertText(record.description, "physical finding record.description", 4000),
      impact: assertText(record.impact, "physical finding record.impact", 2000),
      validity_kind: record.validity_kind,
      decided_at: assertTimestamp(record.decided_at, "physical finding record.decided_at"),
      finding_dedupe_key: findingDedupeKey,
      dedupe_key: findingDedupeKey,
      validated: true,
    };
    if (record.force_record === true) normalized.force_record = true;
    else if (record.force_record != null) {
      throw new Error("physical finding record.force_record must equal true when present");
    }
    return deepFreeze(normalized);
  } catch (error) {
    if (lineNumber == null) throw error;
    throw new Error(
      `Malformed findings.jsonl at line ${lineNumber}: ${error.message || String(error)}`,
    );
  }
}

function buildPersistedPhysicalFindingRecord(input) {
  assertExactPlainObject(
    input,
    "persisted physical finding input",
    ["finding", "id", "target_domain", "assignment"],
    ["force_record"],
  );
  const finding = assertPhysicalFinding(input.finding);
  const assignment = normalizePhysicalAssignmentContext(input.assignment);
  const targetDomain = assertSafeDomain(input.target_domain);
  if (finding.asset_locator !== assignment.asset_locator
      || finding.session_nucleus_hash !== assignment.session_nucleus_hash) {
    throw new Error("physical finding and assignment do not bind the same asset and session");
  }
  const record = {
    id: parseFindingId(input.id, "id"),
    target_domain: targetDomain,
    version: finding.version,
    finding_kind: finding.finding_kind,
    capability_pack: assignment.capability_pack,
    capability_pack_version: assignment.capability_pack_version,
    evaluator_agent: assignment.evaluator_agent,
    brief_profile: assignment.brief_profile,
    surface_id: assignment.surface_id,
    surface_type: assignment.surface_type,
    surface_class: assignment.surface_class,
    session_nucleus_hash: assignment.session_nucleus_hash,
    asset_locator: assignment.asset_locator,
    campaign_ref: assignment.campaign_ref,
    assignment_context_digest: assignment.assignment_context_digest,
    physical_resource_bundle_ref: assignment.physical_resource_bundle_ref,
    lifecycle_precondition: assignment.lifecycle_precondition,
    effect_authority: assignment.effect_authority,
    verified_verdict_ref: finding.verified_verdict_ref,
    verification_projection_digest: finding.verification_projection_digest,
    title: finding.title,
    severity: finding.severity,
    cwe: finding.cwe,
    description: finding.description,
    impact: finding.impact,
    validity_kind: finding.validity_kind,
    decided_at: finding.decided_at,
    finding_dedupe_key: finding.finding_dedupe_key,
    dedupe_key: finding.finding_dedupe_key,
    validated: true,
  };
  if (input.force_record === true) record.force_record = true;
  else if (input.force_record != null) {
    throw new Error("persisted physical finding input.force_record must equal true when present");
  }
  return normalizePhysicalFindingRecord(record, { expectedDomain: targetDomain });
}

require("../../core/physical-domain-runtime-ports.js")
  .configurePhysicalDomainRuntimePorts({ normalizePhysicalFindingRecord });

module.exports = Object.freeze({
  FORBIDDEN_WEB_FIELDS,
  PHYSICAL_FINDING_RECORD_ADAPTER,
  buildPersistedPhysicalFindingRecord,
  normalizePhysicalFindingRecord,
  physicalAssignmentFromFindingRecord,
});
