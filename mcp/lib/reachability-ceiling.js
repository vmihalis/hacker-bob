"use strict";

const fs = require("fs");
const {
  ATTACK_VECTOR_VALUES,
  SEVERITY_VALUES,
} = require("./constants.js");
const {
  repoInventoryPath,
  verificationRoundPaths,
} = require("./paths.js");
const {
  loadJsonDocumentStrict,
} = require("./storage.js");
const {
  assertBoolean,
  assertEnumValue,
  normalizeOptionalText,
} = require("./validation.js");
const {
  readCurrentClaimFreeze,
} = require("./claim-freeze.js");
const {
  findingSupportsReachabilityAssertion,
  normalizeReachabilityAssertion,
} = require("./finding-contracts.js");
const {
  normalizeVerificationRoundDocument,
} = require("./verification-round-store.js");

const REACHABILITY_DISPOSITION_VALUES = Object.freeze([
  "capped",
  "lifted",
  "unchanged",
  "unknown",
]);
const REACHABILITY_SOURCE_VALUES = Object.freeze([
  "asserted",
  "heuristic",
  "none",
]);
const REACHABILITY_INPUT_SOURCE_VALUES = Object.freeze([
  "asserted",
  "heuristic",
]);
const SEVERITY_CEILING_VALUES = Object.freeze([
  ...SEVERITY_VALUES,
  "unknown",
]);
const REACHABILITY_SEVERITY_RANK = Object.freeze({
  info: 1,
  low: 2,
  medium: 3,
  high: 4,
  critical: 5,
});
const REACHABILITY_STAMPED_SURFACE_PREFIXES = Object.freeze([
  "repo:module:",
]);

// C9 truth table:
// - unknown reachability => preserve recorded severity, disposition unknown.
// - local ceiling below recorded severity => cap graded_severity to ceiling.
// - network reachable + recorded high/critical => mark as lifted without
//   inventing severity above the verified round. Heuristic reachability is
//   independently defensible; evaluator assertions carry their source for
//   operator review instead of self-certifying defensibility.
// - otherwise preserve recorded severity as unchanged.
function computeReachabilityDisposition(recordedSeverity, reachability = null) {
  const normalizedRecorded = normalizeRecordedSeverity(recordedSeverity);
  const normalizedReachability = normalizeReachabilityInput(reachability);
  if (!normalizedReachability) return unknownDisposition(normalizedRecorded);

  const ceiling = normalizedReachability.severity_ceiling;
  const ceilingRank = REACHABILITY_SEVERITY_RANK[ceiling] || 0;
  const recordedRank = REACHABILITY_SEVERITY_RANK[normalizedRecorded] || 0;
  if (ceilingRank > 0 && ceilingRank < recordedRank) {
    return {
      recorded_severity: normalizedRecorded,
      severity_ceiling: ceiling,
      attack_vector: normalizedReachability.attack_vector,
      network_reachable: normalizedReachability.network_reachable,
      graded_severity: ceiling,
      disposition: "capped",
      defensible: false,
      ...reachabilityMetadata(normalizedReachability),
    };
  }

  const networkLifted = normalizedReachability.network_reachable === true
    && normalizedReachability.attack_vector === "network"
    && (normalizedRecorded === "high" || normalizedRecorded === "critical");
  if (networkLifted) {
    return {
      recorded_severity: normalizedRecorded,
      severity_ceiling: ceiling,
      attack_vector: "network",
      network_reachable: true,
      graded_severity: normalizedRecorded,
      disposition: "lifted",
      defensible: normalizedReachability.reachability_source !== "asserted"
        && !normalizedReachability.reachability_divergence,
      ...reachabilityMetadata(normalizedReachability),
    };
  }

  return {
    recorded_severity: normalizedRecorded,
    severity_ceiling: ceiling,
    attack_vector: normalizedReachability.attack_vector,
    network_reachable: normalizedReachability.network_reachable,
    graded_severity: normalizedRecorded,
    disposition: "unchanged",
    defensible: false,
    ...reachabilityMetadata(normalizedReachability),
  };
}

function unknownDisposition(recordedSeverity) {
  return {
    recorded_severity: recordedSeverity,
    severity_ceiling: "unknown",
    attack_vector: "unknown",
    network_reachable: null,
    graded_severity: recordedSeverity,
    disposition: "unknown",
    defensible: false,
    reachability_source: "none",
  };
}

function normalizeRecordedSeverity(value) {
  return assertEnumValue(value, SEVERITY_VALUES, "recorded_severity");
}

function normalizeReachabilityInput(reachability) {
  if (reachability == null || typeof reachability !== "object" || Array.isArray(reachability)) return null;
  const ceiling = typeof reachability.severity_ceiling === "string"
    ? reachability.severity_ceiling
    : reachability.max_credible_severity_ceiling;
  if (!SEVERITY_VALUES.includes(ceiling)) return null;
  const rawAttackVector = typeof reachability.attack_vector === "string" ? reachability.attack_vector : "unknown";
  const attackVector = rawAttackVector === "network" || rawAttackVector === "local"
    ? rawAttackVector
    : "unknown";
  const networkReachable = typeof reachability.network_reachable === "boolean"
    ? reachability.network_reachable
    : null;
  const reachabilitySource = reachability.reachability_source == null
    ? "heuristic"
    : assertEnumValue(
      reachability.reachability_source,
      REACHABILITY_INPUT_SOURCE_VALUES,
      "reachability.reachability_source",
    );
  const reachabilityDivergence = normalizeOptionalText(
    reachability.reachability_divergence,
    "reachability.reachability_divergence",
  );
  const callPath = normalizeReachabilityCallPathMetadata(
    reachability.call_path,
    "reachability.call_path",
  );
  if (reachabilitySource === "asserted" && !callPath) {
    throw new Error("reachability.call_path is required when reachability_source is \"asserted\"");
  }
  if (callPath && reachabilitySource !== "asserted") {
    throw new Error("reachability.call_path is only allowed when reachability_source is \"asserted\"");
  }
  return {
    severity_ceiling: ceiling,
    attack_vector: attackVector,
    network_reachable: networkReachable,
    reachability_source: reachabilitySource,
    reachability_divergence: reachabilityDivergence,
    call_path: callPath,
  };
}

function reachabilityMetadata(normalizedReachability) {
  const metadata = {
    reachability_source: normalizedReachability.reachability_source,
  };
  if (normalizedReachability.reachability_divergence) {
    metadata.reachability_divergence = normalizedReachability.reachability_divergence;
  }
  if (normalizedReachability.call_path) {
    metadata.call_path = normalizedReachability.call_path;
  }
  return metadata;
}

function normalizeReachabilityDispositionStamp(value, fieldName = "reachability") {
  if (value == null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${fieldName} must be an object`);
  }
  const networkReachable = value.network_reachable == null
    ? null
    : assertBoolean(value.network_reachable, `${fieldName}.network_reachable`);
  const disposition = assertEnumValue(value.disposition, REACHABILITY_DISPOSITION_VALUES, `${fieldName}.disposition`);
  const defaultSource = disposition === "unknown" ? "none" : "heuristic";
  const reachabilitySource = value.reachability_source == null
    ? defaultSource
    : assertEnumValue(value.reachability_source, REACHABILITY_SOURCE_VALUES, `${fieldName}.reachability_source`);
  const reachabilityDivergence = normalizeOptionalText(
    value.reachability_divergence,
    `${fieldName}.reachability_divergence`,
  );
  const callPath = normalizeReachabilityCallPathMetadata(value.call_path, `${fieldName}.call_path`);
  if (disposition === "unknown" && reachabilitySource !== "none") {
    throw new Error(`${fieldName}.reachability_source must be "none" when disposition is "unknown"`);
  }
  if (disposition !== "unknown" && reachabilitySource === "none") {
    throw new Error(`${fieldName}.reachability_source must not be "none" unless disposition is "unknown"`);
  }
  if (reachabilitySource === "asserted" && !callPath) {
    throw new Error(`${fieldName}.call_path is required when reachability_source is "asserted"`);
  }
  if (callPath && reachabilitySource !== "asserted") {
    throw new Error(`${fieldName}.call_path is only allowed when reachability_source is "asserted"`);
  }
  const stamp = {
    recorded_severity: assertEnumValue(value.recorded_severity, SEVERITY_VALUES, `${fieldName}.recorded_severity`),
    severity_ceiling: assertEnumValue(value.severity_ceiling, SEVERITY_CEILING_VALUES, `${fieldName}.severity_ceiling`),
    attack_vector: assertEnumValue(value.attack_vector, ATTACK_VECTOR_VALUES, `${fieldName}.attack_vector`),
    network_reachable: networkReachable,
    graded_severity: assertEnumValue(value.graded_severity, SEVERITY_VALUES, `${fieldName}.graded_severity`),
    disposition,
    defensible: assertBoolean(value.defensible, `${fieldName}.defensible`),
    reachability_source: reachabilitySource,
  };
  if (reachabilityDivergence) stamp.reachability_divergence = reachabilityDivergence;
  if (callPath) stamp.call_path = callPath;
  return stamp;
}

function normalizeReachabilityCallPathMetadata(value, fieldName) {
  const callPath = normalizeOptionalText(value, fieldName);
  if (callPath && /[\r\n]/.test(callPath)) {
    throw new Error(`${fieldName} must not contain line breaks`);
  }
  return callPath;
}

function isMediumOrHigher(severity) {
  return severity === "medium" || severity === "high" || severity === "critical";
}

function severityRank(severity) {
  return REACHABILITY_SEVERITY_RANK[severity] || 0;
}

function readReachabilityInventory(domain) {
  const filePath = repoInventoryPath(domain);
  if (!fs.existsSync(filePath)) return null;
  const document = loadJsonDocumentStrict(filePath, "repo inventory JSON");
  const reachability = document.reachability;
  if (reachability == null) return null;
  if (typeof reachability !== "object" || Array.isArray(reachability)) return { surface_ceilings: [] };
  if (!Array.isArray(reachability.surface_ceilings)) return { ...reachability, surface_ceilings: [] };
  return reachability;
}

function hasReachabilityInventory(domain) {
  return readReachabilityInventory(domain) != null;
}

function claimsForFinding(domain, findingId) {
  const freeze = readCurrentClaimFreeze(domain);
  if (!freeze) return [];
  if (!Array.isArray(freeze.claims)) {
    throw new Error("claim-freeze.json claims must be an array for reachability resolution");
  }
  const claims = freeze.claims;
  return claims.filter((claim) => {
    const refs = Array.isArray(claim.evidence_refs) ? claim.evidence_refs : [];
    return refs.some((ref) => (
      ref && typeof ref === "object" && ref.kind === "finding" && ref.finding_id === findingId
    ));
  });
}

function claimCreatedAtMs(claim) {
  const raw = claim && typeof claim.created_at === "string" ? claim.created_at : "";
  const parsed = Date.parse(raw);
  return Number.isFinite(parsed) ? parsed : Number.MAX_SAFE_INTEGER;
}

function compareClaimsByCreatedAtThenId(a, b) {
  const byCreatedAt = claimCreatedAtMs(a) - claimCreatedAtMs(b);
  if (byCreatedAt !== 0) return byCreatedAt;
  const aId = a && typeof a.claim_id === "string" ? a.claim_id : "";
  const bId = b && typeof b.claim_id === "string" ? b.claim_id : "";
  return aId.localeCompare(bId);
}

function reachabilityAssertionRecordForFinding(domain, findingId) {
  const assertions = [];
  const byKey = new Map();
  const auditNotes = [];
  for (const claim of claimsForFinding(domain, findingId).slice().sort(compareClaimsByCreatedAtThenId)) {
    const payload = claim && claim.payload && typeof claim.payload === "object" && !Array.isArray(claim.payload)
      ? claim.payload
      : {};
    const finding = payload.finding && typeof payload.finding === "object" && !Array.isArray(payload.finding)
      ? payload.finding
      : null;
    if (!finding) continue;
    if (finding.id !== findingId) continue;
    if (!findingSupportsReachabilityAssertion(finding)) continue;
    let assertion = null;
    try {
      assertion = normalizeReachabilityAssertion(finding.reachability_assertion);
    } catch (error) {
      // Frozen claims are durable session input. A corrupt assertion should not
      // crash grading for every finding in the domain, but it must stay visible
      // so fallback heuristic grades are not mistaken for clean provenance.
      const claimId = claim && typeof claim.claim_id === "string" ? claim.claim_id : "unknown-claim";
      auditNotes.push(`invalid reachability assertion in ${claimId}: ${normalizeErrorMessage(error)}`);
      continue;
    }
    if (!assertion) continue;
    const key = JSON.stringify({
      attack_vector: assertion.attack_vector,
      network_reachable: assertion.network_reachable,
    });
    const existing = byKey.get(key);
    if (existing) {
      if (existing.assertion.call_path !== assertion.call_path) {
        existing.assertion = {
          ...existing.assertion,
          call_path: assertion.call_path,
        };
      }
      continue;
    }
    const entry = { assertion };
    byKey.set(key, entry);
    assertions.push(entry);
  }
  if (assertions.length === 0) {
    if (auditNotes.length === 0) return null;
    return {
      assertion: null,
      conflict_note: null,
      audit_note: combineReachabilityDivergenceNotes(...auditNotes),
    };
  }
  const selected = assertions[0];
  if (assertions.length > 1) {
    // Frozen conflict policy: first distinct valid classification wins. Later
    // classification corrections require operator amendment / re-freeze, while
    // same-classification call_path refinements update the selected metadata.
    return {
      assertion: selected.assertion,
      conflict_note: `conflicting reachability assertions present (${assertions.length}); using earliest`,
      audit_note: combineReachabilityDivergenceNotes(...auditNotes),
    };
  }
  return {
    assertion: selected.assertion,
    conflict_note: null,
    audit_note: combineReachabilityDivergenceNotes(...auditNotes),
  };
}

function reachabilityAssertionForFinding(domain, findingId) {
  const record = reachabilityAssertionRecordForFinding(domain, findingId);
  return record && record.assertion ? record.assertion : null;
}

function findingHasReachabilityAssertion(domain, findingId) {
  return reachabilityAssertionForFinding(domain, findingId) != null;
}

function surfaceIdsForFinding(domain, findingId) {
  const ids = [];
  const seen = new Set();
  for (const claim of claimsForFinding(domain, findingId)) {
    const surfaceIds = Array.isArray(claim.surface_ids) ? claim.surface_ids : [];
    for (const surfaceId of surfaceIds) {
      if (typeof surfaceId !== "string" || !surfaceId.trim() || seen.has(surfaceId)) continue;
      seen.add(surfaceId);
      ids.push(surfaceId);
    }
  }
  return ids;
}

function isReachabilityStampedSurfaceId(surfaceId) {
  return typeof surfaceId === "string"
    && REACHABILITY_STAMPED_SURFACE_PREFIXES.some((prefix) => surfaceId.startsWith(prefix));
}

function findingHasReachabilityStampedSurface(domain, findingId) {
  return surfaceIdsForFinding(domain, findingId).some(isReachabilityStampedSurfaceId);
}

function stampedSurfaceIdsForFinding(domain, findingId) {
  return surfaceIdsForFinding(domain, findingId).filter(isReachabilityStampedSurfaceId);
}

function normalizeSurfaceCeilingEntry(entry) {
  if (entry == null || typeof entry !== "object" || Array.isArray(entry)) return null;
  if (typeof entry.id !== "string" || !entry.id) return null;
  const reachability = normalizeReachabilityInput({
    severity_ceiling: entry.severity_ceiling,
    attack_vector: entry.attack_vector,
    network_reachable: entry.network_reachable,
  });
  if (!reachability) return null;
  return {
    id: entry.id,
    severity_ceiling: reachability.severity_ceiling,
    attack_vector: reachability.attack_vector,
    network_reachable: reachability.network_reachable,
  };
}

function assertResolveFindingReachabilityArgs({ domain, findingId } = {}) {
  if (typeof domain !== "string" || !domain.trim()) {
    throw new Error("domain must be a non-empty string");
  }
  if (typeof findingId !== "string" || !findingId.trim()) {
    throw new Error("findingId must be a non-empty string");
  }
}

function severityCeilingForAssertedAttackVector(attackVector) {
  return attackVector === "network" ? "critical" : "medium";
}

function stricterSeverityCeiling(primary, candidate) {
  if (!candidate) return primary;
  const primaryRank = severityRank(primary);
  const candidateRank = severityRank(candidate);
  if (primaryRank === 0 || candidateRank === 0) return primary;
  return candidateRank < primaryRank ? candidate : primary;
}

function severityCeilingForAssertedReachability(assertion, heuristic) {
  const assertedCeiling = severityCeilingForAssertedAttackVector(assertion.attack_vector);
  // Delta 2 assertions set AV/reachability only; severity lift on locality under-counts waits for Delta 3 taint provenance.
  return stricterSeverityCeiling(assertedCeiling, heuristic && heuristic.severity_ceiling);
}

function reachabilityDivergenceNote(assertion, heuristic, severityCeiling = null) {
  if (!assertion) return null;
  if (!heuristic) return "asserted reachability has no producer inventory or stamped-surface fallback";
  const notes = [];
  if (
    assertion.attack_vector !== heuristic.attack_vector
    || assertion.network_reachable !== heuristic.network_reachable
  ) {
    const assertedReachable = assertion.network_reachable === true ? "true" : "false";
    const heuristicReachable = heuristic.network_reachable === true
      ? "true"
      : (heuristic.network_reachable === false ? "false" : "null");
    notes.push(`asserted ${assertion.attack_vector}/${assertedReachable} overrides heuristic ${heuristic.attack_vector}/${heuristicReachable}`);
  }
  const assertedCeiling = severityCeilingForAssertedAttackVector(assertion.attack_vector);
  if (severityCeiling && severityCeiling !== assertedCeiling && heuristic.severity_ceiling === severityCeiling) {
    notes.push(`producer ceiling ${severityCeiling} constrains asserted ${assertion.attack_vector} ceiling ${assertedCeiling}`);
  }
  if (
    severityCeiling
    && severityCeiling === assertedCeiling
    && heuristic.severity_ceiling !== assertedCeiling
    && severityRank(assertedCeiling) < severityRank(heuristic.severity_ceiling)
  ) {
    notes.push(`asserted ${assertion.attack_vector} ceiling ${assertedCeiling} constrains producer ceiling ${heuristic.severity_ceiling}`);
  }
  return notes.length > 0 ? notes.join("; ") : null;
}

function combineReachabilityDivergenceNotes(...notes) {
  const filtered = notes.filter((note) => typeof note === "string" && note.trim()).map((note) => note.trim());
  return filtered.length > 0 ? filtered.join("; ") : null;
}

function normalizeErrorMessage(error) {
  const raw = error && typeof error.message === "string" ? error.message : String(error || "unknown error");
  return raw.replace(/\s+/g, " ").trim().slice(0, 240);
}

function resolveFindingReachabilityFromHeuristic({ domain, findingId } = {}) {
  const inventory = readReachabilityInventory(domain);
  if (!inventory) return null;
  const surfaceIds = stampedSurfaceIdsForFinding(domain, findingId);
  if (surfaceIds.length === 0) return null;
  const wanted = new Set(surfaceIds);
  const matchedById = new Map();
  for (const entry of inventory.surface_ceilings) {
    const normalized = normalizeSurfaceCeilingEntry(entry);
    if (normalized && wanted.has(normalized.id) && !matchedById.has(normalized.id)) {
      matchedById.set(normalized.id, normalized);
    }
  }
  const matched = [];
  for (const surfaceId of surfaceIds) {
    const entry = matchedById.get(surfaceId);
    if (!entry) return null;
    matched.push(entry);
  }

  let selectedCeiling = matched[0].severity_ceiling;
  let allNetwork = true;
  let anyLocal = false;
  for (const entry of matched) {
    if (severityRank(entry.severity_ceiling) < severityRank(selectedCeiling)) {
      selectedCeiling = entry.severity_ceiling;
    }
    if (!(entry.network_reachable === true && entry.attack_vector === "network")) allNetwork = false;
    if (entry.network_reachable === false || entry.attack_vector === "local") anyLocal = true;
  }

  return {
    severity_ceiling: selectedCeiling,
    attack_vector: allNetwork ? "network" : (anyLocal ? "local" : "unknown"),
    network_reachable: allNetwork ? true : (anyLocal ? false : null),
    reachability_source: "heuristic",
  };
}

function resolveFindingReachability({ domain, findingId } = {}) {
  assertResolveFindingReachabilityArgs({ domain, findingId });
  const assertionRecord = reachabilityAssertionRecordForFinding(domain, findingId);
  const assertion = assertionRecord ? assertionRecord.assertion : null;
  if (assertion) {
    const heuristic = resolveFindingReachabilityFromHeuristic({ domain, findingId });
    const severityCeiling = severityCeilingForAssertedReachability(assertion, heuristic);
    const divergence = combineReachabilityDivergenceNotes(
      assertionRecord.audit_note,
      assertionRecord.conflict_note,
      reachabilityDivergenceNote(assertion, heuristic, severityCeiling),
    );
    return {
      severity_ceiling: severityCeiling,
      attack_vector: assertion.attack_vector,
      network_reachable: assertion.network_reachable,
      reachability_source: "asserted",
      call_path: assertion.call_path,
      ...(divergence ? { reachability_divergence: divergence } : {}),
    };
  }
  const heuristic = resolveFindingReachabilityFromHeuristic({ domain, findingId });
  if (!heuristic || !assertionRecord || !assertionRecord.audit_note) return heuristic;
  return {
    ...heuristic,
    reachability_divergence: assertionRecord.audit_note,
  };
}

function readFinalVerificationResults(domain) {
  const paths = verificationRoundPaths(domain, "final");
  const document = loadJsonDocumentStrict(paths.json, "final verification round JSON");
  return normalizeVerificationRoundDocument(document, {
    expectedDomain: domain,
    expectedRound: "final",
  }).results;
}

function finalSeverityByFinding(domain) {
  const out = new Map();
  for (const result of readFinalVerificationResults(domain)) {
    if (typeof result.finding_id === "string" && SEVERITY_VALUES.includes(result.severity)) {
      out.set(result.finding_id, result.severity);
    }
  }
  return out;
}

function finalReportableFindingSeverities(domain) {
  const out = new Map();
  for (const result of readFinalVerificationResults(domain)) {
    if (result.reportable === true && isMediumOrHigher(result.severity)) {
      out.set(result.finding_id, result.severity);
    }
  }
  return out;
}

function reachabilityDispositionForFinding({ domain, findingId, recordedSeverity } = {}) {
  return computeReachabilityDisposition(
    recordedSeverity,
    resolveFindingReachability({ domain, findingId }),
  );
}

function missingReachabilityStampsForReportableFindings(domain) {
  if (!hasReachabilityInventory(domain)) {
    const missing = [];
    for (const [findingId] of finalReportableFindingSeverities(domain)) {
      if (findingHasReachabilityAssertion(domain, findingId)) continue;
      if (findingHasReachabilityStampedSurface(domain, findingId)) {
        missing.push(findingId);
      }
    }
    return {
      reachability_present: false,
      inventory_absent: true,
      missing,
    };
  }
  const missing = [];
  for (const [findingId, severity] of finalReportableFindingSeverities(domain)) {
    if (!findingHasReachabilityStampedSurface(domain, findingId) && !findingHasReachabilityAssertion(domain, findingId)) {
      continue;
    }
    const disposition = reachabilityDispositionForFinding({
      domain,
      findingId,
      recordedSeverity: severity,
    });
    if (disposition.disposition === "unknown") {
      missing.push(findingId);
    }
  }
  return {
    reachability_present: true,
    inventory_absent: false,
    missing,
  };
}

module.exports = {
  ATTACK_VECTOR_VALUES,
  REACHABILITY_DISPOSITION_VALUES,
  REACHABILITY_SOURCE_VALUES,
  REACHABILITY_STAMPED_SURFACE_PREFIXES,
  SEVERITY_CEILING_VALUES,
  computeReachabilityDisposition,
  finalSeverityByFinding,
  findingHasReachabilityAssertion,
  findingHasReachabilityStampedSurface,
  hasReachabilityInventory,
  isReachabilityStampedSurfaceId,
  missingReachabilityStampsForReportableFindings,
  normalizeReachabilityDispositionStamp,
  reachabilityDispositionForFinding,
  readReachabilityInventory,
  resolveFindingReachability,
};
