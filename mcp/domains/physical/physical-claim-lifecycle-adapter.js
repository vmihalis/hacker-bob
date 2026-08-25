"use strict";

// PH-C10 — pack-declared read/verify adapter for persisted physical claims.
//
// Persisted CandidateClaims are data, not authority.  Every verification,
// grading, or report consumer calls this adapter, which revalidates the claim
// hash, exact physical record, assignment digest, finding evidence reference,
// current session nucleus, and the server-owned experiment verdict.  Only the
// returned branded object may enter the physical grade/completion adapters.

const {
  readCandidateClaims,
} = require("../../core/claims/claims.js");
const {
  withSessionLock,
} = require("../../core/io/storage.js");
const {
  assertSafeDomain,
} = require("../../core/io/paths.js");
const {
  parseFindingId,
} = require("../../core/io/validation.js");
const {
  buildPhysicalFinding,
  normalizePhysicalAssignmentContext,
} = require("./physical-capability-consumers.js");
const {
  normalizePhysicalFindingRecord,
  physicalAssignmentFromFindingRecord,
} = require("./physical-finding-record-adapter.js");
const {
  physicalVerdictRuntimeReadiness,
  resolvePhysicalVerdict,
} = require("./physical-verdict-runtime.js");
const {
  canonicalJson,
  hashCanonicalJson,
} = require("../../core/verification/verification-contracts.js");

const RESOLVED_PHYSICAL_CLAIMS = new WeakSet();
const FINDING_BINDING_FIELDS = Object.freeze([
  "version",
  "finding_kind",
  "capability_pack",
  "asset_locator",
  "verified_verdict_ref",
  "verification_projection_digest",
  "session_nucleus_hash",
  "title",
  "severity",
  "cwe",
  "description",
  "impact",
  "validity_kind",
  "decided_at",
  "finding_dedupe_key",
]);

function deepFreeze(value) {
  if (value == null || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function physicalClaimRows(domain, findingId) {
  const matches = [];
  for (const claim of readCandidateClaims(domain)) {
    const payload = claim && claim.payload && typeof claim.payload === "object"
      ? claim.payload
      : null;
    const finding = payload && payload.finding && typeof payload.finding === "object"
      ? payload.finding
      : null;
    if (finding && finding.id === findingId) matches.push({ claim, payload, finding });
  }
  if (matches.length !== 1) {
    throw new Error(
      matches.length === 0
        ? `physical finding ${findingId} is not present in the CandidateClaim ledger`
        : `physical finding ${findingId} is ambiguous in the CandidateClaim ledger`,
    );
  }
  return matches[0];
}

function assertClaimRecordBinding(domain, row, record, assignment) {
  const { claim, payload } = row;
  if (claim.target_domain !== domain) throw new Error("physical claim target_domain drifted");
  if (!Array.isArray(claim.surface_ids) || claim.surface_ids.length !== 1
      || claim.surface_ids[0] !== assignment.surface_id) {
    throw new Error("physical claim surface binding drifted");
  }
  if (payload.dedupe_key !== record.dedupe_key
      || payload.subject_id !== record.asset_locator
      || payload.surface_ref !== record.surface_id) {
    throw new Error("physical claim payload binding drifted");
  }
  const persistedAssignment = normalizePhysicalAssignmentContext(payload.physical_assignment);
  if (canonicalJson(persistedAssignment) !== canonicalJson(assignment)) {
    throw new Error("physical claim assignment payload drifted");
  }
  const findingRefs = Array.isArray(claim.evidence_refs)
    ? claim.evidence_refs.filter((ref) => ref && ref.kind === "finding")
    : [];
  if (findingRefs.length !== 1
      || findingRefs[0].finding_id !== record.id
      || findingRefs[0].content_hash !== hashCanonicalJson(record)) {
    throw new Error("physical claim finding evidence reference drifted");
  }
}

function assertLiveFindingMatchesRecord(liveFinding, record) {
  for (const field of FINDING_BINDING_FIELDS) {
    if (liveFinding[field] !== record[field]) {
      throw new Error(`physical finding live verdict binding drifted at ${field}`);
    }
  }
}

function resolvePhysicalCandidateClaim(targetDomain, findingIdInput) {
  const domain = assertSafeDomain(targetDomain);
  const findingId = parseFindingId(findingIdInput, "finding_id");
  return withSessionLock(domain, () => {
    if (physicalVerdictRuntimeReadiness().production_ready !== true) {
      throw new Error("production physical verdict resolver is not installed");
    }
    const row = physicalClaimRows(domain, findingId);
    const record = normalizePhysicalFindingRecord(row.finding, {
      expectedDomain: domain,
    });
    const assignment = physicalAssignmentFromFindingRecord(record);
    assertClaimRecordBinding(domain, row, record, assignment);

    const verdict = resolvePhysicalVerdict({
      target_domain: domain,
      asset_locator: record.asset_locator,
      verified_verdict_ref: record.verified_verdict_ref,
    });
    if (physicalVerdictRuntimeReadiness().production_ready !== true) {
      throw new Error("production physical verdict resolver changed during claim resolution");
    }
    const liveFinding = buildPhysicalFinding({
      title: record.title,
      severity: record.severity,
      cwe: record.cwe,
      description: record.description,
      impact: record.impact,
      verdict,
    });
    assertLiveFindingMatchesRecord(liveFinding, record);

    const resolved = deepFreeze({
      version: 1,
      adapter: "physical_verified_transition_claim_lifecycle_v1",
      target_domain: domain,
      finding_id: record.id,
      claim_id: row.claim.claim_id,
      claim_hash: row.claim.claim_hash,
      assignment,
      record,
      finding: liveFinding,
      verdict,
      production_ready: true,
    });
    RESOLVED_PHYSICAL_CLAIMS.add(resolved);
    return resolved;
  });
}

function assertResolvedPhysicalCandidateClaim(value) {
  if (value == null || typeof value !== "object"
      || !RESOLVED_PHYSICAL_CLAIMS.has(value)
      || value.production_ready !== true) {
    throw new Error("physical claim must be resolved by the pack lifecycle adapter");
  }
  return value;
}

function projectPhysicalCandidateVerification(value) {
  const resolved = assertResolvedPhysicalCandidateClaim(value);
  return deepFreeze({
    version: 1,
    verification_adapter: "physical_verified_transition_claim_lifecycle_v1",
    finding_id: resolved.finding_id,
    claim_id: resolved.claim_id,
    capability_pack: "physical",
    asset_locator: resolved.record.asset_locator,
    verified_verdict_ref: resolved.record.verified_verdict_ref,
    verification_projection_digest: resolved.record.verification_projection_digest,
    session_nucleus_hash: resolved.record.session_nucleus_hash,
    disposition: "verified",
    severity: resolved.record.severity,
    reportable: true,
    reasoning: "Server-owned physical experiment ledger revalidated the differential transition and exact CandidateClaim binding.",
    validity_kind: resolved.record.validity_kind,
    decided_at: resolved.record.decided_at,
    hardware_effects_invoked: false,
    production_ready: true,
  });
}

module.exports = Object.freeze({
  assertResolvedPhysicalCandidateClaim,
  projectPhysicalCandidateVerification,
  resolvePhysicalCandidateClaim,
});
