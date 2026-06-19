"use strict";

// Claim projections.
//
// Cross-references between Findings (legacy authority, findings.jsonl) and
// CandidateClaims (claim-plane parallel write, claims.jsonl) recorded by the
// C.2 dual-write shim in tools/record-finding.js.
//
// Reads are projections over the append-only claim ledger; every CandidateClaim
// carries evidence_refs[] entries with kind="finding" pointing back to the
// originating finding_id.

const { readCandidateClaims } = require("./claims.js");

function claimReferencesFinding(claim, findingId) {
  if (!claim || !Array.isArray(claim.evidence_refs)) return false;
  for (const ref of claim.evidence_refs) {
    if (ref && typeof ref === "object" && ref.kind === "finding" && ref.finding_id === findingId) {
      return true;
    }
  }
  return false;
}

function claimsForFinding(targetDomain, findingId) {
  if (typeof findingId !== "string" || !findingId.trim()) {
    throw new Error("finding_id must be a non-empty string");
  }
  const claims = readCandidateClaims(targetDomain);
  return claims.filter((claim) => claimReferencesFinding(claim, findingId));
}

function findingForClaim(targetDomain, claimId) {
  if (typeof claimId !== "string" || !claimId.trim()) {
    throw new Error("claim_id must be a non-empty string");
  }
  const claims = readCandidateClaims(targetDomain);
  const match = claims.find((claim) => claim.claim_id === claimId);
  if (!match || !Array.isArray(match.evidence_refs)) return null;
  for (const ref of match.evidence_refs) {
    if (ref && typeof ref === "object" && ref.kind === "finding" && typeof ref.finding_id === "string") {
      return ref.finding_id;
    }
  }
  return null;
}

module.exports = {
  claimsForFinding,
  findingForClaim,
};
