"use strict";

// Verification finding-id adapter.
//
// Verification, evidence, and grade rounds still address claim membership by
// finding_id because the freeze's evidence_refs[] entries continue to carry
// kind="finding" + finding_id (the stable identifier minted at record time).
// This adapter resolves the finding_id set from the best available source:
//
//   1. The fresh verification snapshot (claim_ids/finding_ids projected from
//      the claim freeze). Authoritative when an attempt is active.
//   2. The current claim freeze. Authoritative when no attempt is active yet
//      but a freeze exists on disk.
//
// Cycle D.2 removed the legacy findings.jsonl fallback that previously sat
// behind (2). Pre-claim or empty-freeze sessions now return an empty set; the
// caller is expected to record at least one CandidateClaim and run a freeze
// before driving verification.

const {
  readCurrentClaimFreeze,
} = require("./claim-freeze.js");
const {
  claimsForFinding,
} = require("./claim-projections.js");
const {
  readCandidateClaims,
} = require("./claims.js");

function findingIdsFromFreeze(freeze) {
  if (!freeze || !Array.isArray(freeze.claims)) return [];
  const ids = [];
  const seen = new Set();
  for (const claim of freeze.claims) {
    if (!claim || !Array.isArray(claim.evidence_refs)) continue;
    for (const ref of claim.evidence_refs) {
      if (ref && typeof ref === "object" && ref.kind === "finding" && typeof ref.finding_id === "string") {
        if (!seen.has(ref.finding_id)) {
          seen.add(ref.finding_id);
          ids.push(ref.finding_id);
        }
      }
    }
  }
  return ids;
}

// Resolve the set of finding_ids for the active verification context.
//
// Priority:
//   - snapshot.finding_ids[] (when an attempt is active)
//   - claim freeze projection (when no attempt is active but freeze exists)
//   - empty set otherwise (pre-claim or empty-freeze sessions)
//
// The adapter understands two equivalent inputs: `{snapshot}` (preferred,
// pass the snapshot returned by `requireFreshVerificationState`) and the older
// `{ finding_ids }` shape kept for callers that still address claim membership
// by raw id arrays.
function findingIdSetForVerificationContext({ domain, snapshot = null, finding_ids = null }) {
  if (snapshot && Array.isArray(snapshot.finding_ids)) {
    return new Set(snapshot.finding_ids);
  }
  if (Array.isArray(finding_ids)) {
    return new Set(finding_ids);
  }
  if (typeof domain === "string" && domain) {
    const freeze = readCurrentClaimFreeze(domain);
    if (freeze) {
      const projected = findingIdsFromFreeze(freeze);
      if (projected.length > 0) return new Set(projected);
    }
    // No freeze on disk yet, but callers (legacy v1 verification, tests that
    // record claims and then drive verification directly) still need to address
    // claim membership by finding_id. Project the set from the live claim
    // ledger so the lookup remains topology-consistent without resurrecting a
    // findings.jsonl reader.
    const ids = new Set();
    for (const claim of readCandidateClaims(domain)) {
      if (!claim || !Array.isArray(claim.evidence_refs)) continue;
      for (const ref of claim.evidence_refs) {
        if (ref && typeof ref === "object" && ref.kind === "finding" && typeof ref.finding_id === "string") {
          ids.add(ref.finding_id);
        }
      }
    }
    return ids;
  }
  return new Set();
}

// Maps a `finding_ids[]` array supplied by an older caller into the matching
// `claim_ids[]` set via the claim-projections reverse lookup. Returns the
// union of claims referenced by the listed finding_ids.
function claimIdSetFromFindingIds(domain, findingIds) {
  if (!Array.isArray(findingIds)) return new Set();
  const ids = new Set();
  for (const findingId of findingIds) {
    if (typeof findingId !== "string" || !findingId) continue;
    const claims = claimsForFinding(domain, findingId);
    for (const claim of claims) {
      if (claim && typeof claim.claim_id === "string") ids.add(claim.claim_id);
    }
  }
  return ids;
}

module.exports = {
  claimIdSetFromFindingIds,
  findingIdSetForVerificationContext,
  findingIdsFromFreeze,
};
