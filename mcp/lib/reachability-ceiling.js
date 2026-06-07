"use strict";

const fs = require("fs");
const {
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
} = require("./validation.js");
const {
  readCurrentClaimFreeze,
} = require("./claim-freeze.js");
const {
  normalizeVerificationRoundDocument,
} = require("./verification-round-store.js");

const REACHABILITY_DISPOSITION_VALUES = Object.freeze([
  "capped",
  "lifted",
  "unchanged",
  "unknown",
]);
const ATTACK_VECTOR_VALUES = Object.freeze([
  "network",
  "local",
  "unknown",
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
// - network reachable + recorded high/critical => certify as lifted/defensible,
//   without inventing severity above the verified round.
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
    };
  }

  const networkDefensible = normalizedReachability.network_reachable === true
    && normalizedReachability.attack_vector === "network"
    && (normalizedRecorded === "high" || normalizedRecorded === "critical");
  if (networkDefensible) {
    return {
      recorded_severity: normalizedRecorded,
      severity_ceiling: ceiling,
      attack_vector: "network",
      network_reachable: true,
      graded_severity: normalizedRecorded,
      disposition: "lifted",
      defensible: true,
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
  return {
    severity_ceiling: ceiling,
    attack_vector: attackVector,
    network_reachable: networkReachable,
  };
}

function normalizeReachabilityDispositionStamp(value, fieldName = "reachability") {
  if (value == null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${fieldName} must be an object`);
  }
  const networkReachable = value.network_reachable == null
    ? null
    : assertBoolean(value.network_reachable, `${fieldName}.network_reachable`);
  return {
    recorded_severity: assertEnumValue(value.recorded_severity, SEVERITY_VALUES, `${fieldName}.recorded_severity`),
    severity_ceiling: assertEnumValue(value.severity_ceiling, SEVERITY_CEILING_VALUES, `${fieldName}.severity_ceiling`),
    attack_vector: assertEnumValue(value.attack_vector, ATTACK_VECTOR_VALUES, `${fieldName}.attack_vector`),
    network_reachable: networkReachable,
    graded_severity: assertEnumValue(value.graded_severity, SEVERITY_VALUES, `${fieldName}.graded_severity`),
    disposition: assertEnumValue(value.disposition, REACHABILITY_DISPOSITION_VALUES, `${fieldName}.disposition`),
    defensible: assertBoolean(value.defensible, `${fieldName}.defensible`),
  };
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
    ...reachability,
  };
}

function resolveFindingReachability({ domain, findingId } = {}) {
  if (typeof domain !== "string" || !domain.trim()) {
    throw new Error("domain must be a non-empty string");
  }
  if (typeof findingId !== "string" || !findingId.trim()) {
    throw new Error("findingId must be a non-empty string");
  }
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
    if (!findingHasReachabilityStampedSurface(domain, findingId)) continue;
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
  REACHABILITY_STAMPED_SURFACE_PREFIXES,
  SEVERITY_CEILING_VALUES,
  computeReachabilityDisposition,
  finalSeverityByFinding,
  findingHasReachabilityStampedSurface,
  hasReachabilityInventory,
  isReachabilityStampedSurfaceId,
  missingReachabilityStampsForReportableFindings,
  normalizeReachabilityDispositionStamp,
  reachabilityDispositionForFinding,
  readReachabilityInventory,
  resolveFindingReachability,
};
