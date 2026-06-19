"use strict";

// Cycle C.4: verification operates on a frozen claim batch, not on live disk
// scans. The verification snapshot is sourced from `claim-freeze.json` so a
// VERIFY round always references the immutable claim payload that was frozen
// when VERIFY was entered. Mutating findings.jsonl, chain-attempts.jsonl, or
// auth/surface state after the freeze cannot change verification results.
//
// Per Pact P2, the dual-write window keeps the legacy `finding_ids[]` field on
// the snapshot so callers that still address claims by finding_id (verification
// rounds, evidence, grade) continue to function. The projection is done via
// claim-projections.js:claimsForFinding inverse — each frozen CandidateClaim
// carries evidence_refs[] back to its source Finding.

const {
  ERROR_CODES,
  ToolError,
} = require("./envelope.js");
const {
  verificationSnapshotPath,
} = require("./paths.js");
const {
  loadJsonDocumentStrict,
} = require("./storage.js");
const {
  hashCanonicalJson,
  isPlainObject,
} = require("./verification-contracts.js");
const {
  buildClaimFreeze,
  readCurrentClaimFreeze,
} = require("./claim-freeze.js");
const {
  readSessionStateStrict,
} = require("./session-state-store.js");

const VERIFICATION_SCHEMA_V2 = 2;
const VERIFICATION_INPUT_CHANGED_MESSAGE = "VERIFY input changed after snapshot; restart VERIFY/adjudication.";

function requireCurrentClaimFreeze(domain, { now = new Date(), autoFreeze = true } = {}) {
  let freeze = readCurrentClaimFreeze(domain);
  if (!freeze || !isPlainObject(freeze)) {
    if (!autoFreeze) {
      throw new ToolError(
        ERROR_CODES.STATE_CONFLICT,
        "VERIFY requires a current claim freeze; freeze the claim batch before entering VERIFY.",
      );
    }
    // LEGACY: removed in Plane D — during the dual-write window, entering
    // VERIFY without an operator-issued claim freeze auto-builds one from
    // current claims.jsonl so the snapshot still anchors on an immutable
    // ClaimFreeze. Once the operator-driven CLAIM_FREEZE transition is the
    // only path, this fallback goes away.
    freeze = buildClaimFreeze(domain, { write: true, now });
  }
  if (typeof freeze.freeze_id !== "string" || !freeze.freeze_id) {
    throw new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      "Current claim freeze is missing freeze_id; rebuild claim-freeze.json.",
    );
  }
  if (typeof freeze.freeze_hash !== "string" || freeze.freeze_hash.length !== 64) {
    throw new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      "Current claim freeze is missing freeze_hash; rebuild claim-freeze.json.",
    );
  }
  return freeze;
}

function projectFindingIdsFromClaims(claims) {
  const ids = [];
  const seen = new Set();
  for (const claim of Array.isArray(claims) ? claims : []) {
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
  ids.sort((a, b) => a.localeCompare(b));
  return ids;
}

function projectEvidenceRefsFromClaims(claims) {
  const refs = [];
  for (const claim of Array.isArray(claims) ? claims : []) {
    if (!claim || !Array.isArray(claim.evidence_refs)) continue;
    for (const ref of claim.evidence_refs) {
      if (ref && typeof ref === "object") refs.push(ref);
    }
  }
  return refs;
}

function readGovernanceHashesSafe(domain) {
  // The frozen claim batch is the source of truth for claim membership; the
  // auth-context and surface-index digests are governance metadata recorded
  // alongside the snapshot so verification can detect a governance-plane shift
  // independent of the claim set. Both are best-effort: a missing
  // session-state-store entry results in `null` so older sessions still pass.
  try {
    const { state } = readSessionStateStrict(domain);
    return {
      auth_context_hash: typeof state.auth_context_hash === "string" ? state.auth_context_hash : null,
      surface_index_hash: typeof state.surface_index_hash === "string" ? state.surface_index_hash : null,
    };
  } catch {
    return { auth_context_hash: null, surface_index_hash: null };
  }
}

function buildSnapshotPayload(domain, { attemptId, createdAt, now = null, autoFreeze = true }) {
  const freeze = requireCurrentClaimFreeze(domain, {
    now: now == null ? new Date() : now,
    autoFreeze,
  });
  const claims = Array.isArray(freeze.claims) ? freeze.claims.slice() : [];
  const clusters = Array.isArray(freeze.clusters) ? freeze.clusters.slice() : [];
  const claimIds = claims.map((claim) => claim.claim_id).filter((id) => typeof id === "string").sort((a, b) => a.localeCompare(b));
  const clusterIds = clusters.map((cluster) => cluster.cluster_id).filter((id) => typeof id === "string").sort((a, b) => a.localeCompare(b));
  const evidenceRefs = projectEvidenceRefsFromClaims(claims);
  const findingIds = projectFindingIdsFromClaims(claims);
  const governance = readGovernanceHashesSafe(domain);
  return {
    version: 1,
    schema_version: VERIFICATION_SCHEMA_V2,
    target_domain: domain,
    verification_attempt_id: attemptId,
    created_at: createdAt,
    claim_freeze_id: freeze.freeze_id,
    claim_freeze_hash: freeze.freeze_hash,
    claim_ids: claimIds,
    cluster_ids: clusterIds,
    // finding_ids is projected from the frozen CandidateClaim evidence refs so
    // verification/evidence/grade callers that still index by finding_id keep
    // working.
    finding_ids: findingIds,
    input_hashes: {
      claim_freeze: freeze.freeze_hash,
      claims: hashCanonicalJson(claims),
      clusters: hashCanonicalJson(clusters),
      evidence_refs: hashCanonicalJson(evidenceRefs),
      auth_context: governance.auth_context_hash,
      surface_index: governance.surface_index_hash,
    },
  };
}

function buildVerificationSnapshot(domain, { attemptId, createdAt, now = null, autoFreeze = true } = {}) {
  const payload = buildSnapshotPayload(domain, { attemptId, createdAt, now, autoFreeze });
  return {
    ...payload,
    snapshot_hash: hashCanonicalJson(payload),
  };
}

function snapshotPayloadHash(snapshot) {
  const payload = { ...snapshot };
  delete payload.snapshot_hash;
  return hashCanonicalJson(payload);
}

function assertValidSnapshotArtifact(domain, snapshot) {
  if (!isPlainObject(snapshot)) {
    throw new ToolError(ERROR_CODES.STATE_CONFLICT, "Current VERIFY v2 snapshot artifact is invalid; restart VERIFY/adjudication.");
  }
  if (snapshot.version !== 1 || snapshot.schema_version !== VERIFICATION_SCHEMA_V2) {
    throw new ToolError(ERROR_CODES.STATE_CONFLICT, "Current VERIFY v2 snapshot artifact schema mismatch; restart VERIFY/adjudication.");
  }
  if (snapshot.target_domain !== domain) {
    throw new ToolError(ERROR_CODES.STATE_CONFLICT, "Current VERIFY v2 snapshot target mismatch; restart VERIFY/adjudication.");
  }
  if (!snapshot.snapshot_hash || snapshotPayloadHash(snapshot) !== snapshot.snapshot_hash) {
    throw new ToolError(ERROR_CODES.STATE_CONFLICT, "Current VERIFY v2 snapshot artifact hash mismatch; restart VERIFY/adjudication.");
  }
  // C.4: claim_freeze_id presence + integrity is the only freshness check.
  // A snapshot without a claim_freeze_id is by definition not frozen-payload
  // sourced and must be rebuilt.
  if (typeof snapshot.claim_freeze_id !== "string" || !snapshot.claim_freeze_id) {
    throw new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      "Current VERIFY v2 snapshot is missing claim_freeze_id; restart VERIFY/adjudication.",
    );
  }
  if (typeof snapshot.claim_freeze_hash !== "string" || snapshot.claim_freeze_hash.length !== 64) {
    throw new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      "Current VERIFY v2 snapshot is missing claim_freeze_hash; restart VERIFY/adjudication.",
    );
  }
}

function assertSnapshotMatchesFreeze(domain, snapshot) {
  // Integrity check: the snapshot's recorded claim_freeze_id and
  // claim_freeze_hash must agree with the persisted claim-freeze.json. If the
  // freeze artifact has been replaced or the snapshot's hash references a
  // tampered freeze, this signals a corrupted attempt and VERIFY must restart.
  const freeze = readCurrentClaimFreeze(domain);
  if (!freeze) {
    throw new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      VERIFICATION_INPUT_CHANGED_MESSAGE,
    );
  }
  if (freeze.freeze_id !== snapshot.claim_freeze_id) {
    throw new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      VERIFICATION_INPUT_CHANGED_MESSAGE,
    );
  }
  if (freeze.freeze_hash !== snapshot.claim_freeze_hash) {
    throw new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      VERIFICATION_INPUT_CHANGED_MESSAGE,
    );
  }
}

function loadCurrentSnapshot(domain, state) {
  const snapshot = loadJsonDocumentStrict(verificationSnapshotPath(domain), "verification input snapshot JSON");
  assertValidSnapshotArtifact(domain, snapshot);
  if (snapshot.verification_attempt_id !== state.verification_attempt_id) {
    throw new ToolError(ERROR_CODES.STATE_CONFLICT, "Current VERIFY v2 snapshot attempt mismatch; restart VERIFY/adjudication.");
  }
  if (snapshot.snapshot_hash !== state.verification_snapshot_hash) {
    throw new ToolError(ERROR_CODES.STATE_CONFLICT, "Current VERIFY v2 snapshot hash mismatch; restart VERIFY/adjudication.");
  }
  return snapshot;
}

// Frozen payloads are by definition stable, so freshness is no longer a
// disk-rescan. Instead `assertFreshVerificationSnapshot` validates that
// `claim_freeze_id` is present and that the persisted freeze still matches the
// snapshot's recorded freeze hash. Renamed callers should use the function;
// the old name is preserved for downstream importers during the dual-write
// window.
function assertFreshVerificationSnapshot(domain, state) {
  if (!state || state.verification_schema_version !== VERIFICATION_SCHEMA_V2) return null;
  const snapshot = loadCurrentSnapshot(domain, state);
  assertSnapshotMatchesFreeze(domain, snapshot);
  return snapshot;
}

function readVerificationStateSafe(domain) {
  try {
    return readSessionStateStrict(domain).state;
  } catch {
    return null;
  }
}

function requireFreshVerificationState(domain) {
  const state = readVerificationStateSafe(domain);
  if (!state || state.verification_schema_version !== VERIFICATION_SCHEMA_V2) {
    throw new ToolError(ERROR_CODES.STATE_CONFLICT, "VERIFY v2 attempt is not active for this session.");
  }
  if (!state.verification_attempt_id || !state.verification_snapshot_hash) {
    throw new ToolError(ERROR_CODES.STATE_CONFLICT, "VERIFY v2 attempt metadata is missing; transition into VERIFY again.");
  }
  const snapshot = assertFreshVerificationSnapshot(domain, state);
  return { state, snapshot };
}

// LEGACY: removed in Plane D — adapter for callers that still address claim
// membership by finding_id. Resolves the snapshot's finding_ids[] projection so
// downstream consumers (verification rounds, evidence pack, grade verdict) keep
// functioning while the dual-write window is open.
function findingIdSetFromSnapshot(snapshot) {
  if (!snapshot || !Array.isArray(snapshot.finding_ids)) return new Set();
  return new Set(snapshot.finding_ids);
}

// LEGACY: removed in Plane D — exposes the snapshot's claim-id set for callers
// that are migrating off finding_ids.
function claimIdSetFromSnapshot(snapshot) {
  if (!snapshot || !Array.isArray(snapshot.claim_ids)) return new Set();
  return new Set(snapshot.claim_ids);
}

// Recomputing the snapshot hash is no longer a disk re-read; it is a pure
// function of the snapshot payload. Preserved so callers that previously
// invoked it for tamper detection keep their guarantee.
function recomputeSnapshotHash(_domain, snapshot) {
  return snapshotPayloadHash(snapshot);
}

module.exports = {
  VERIFICATION_INPUT_CHANGED_MESSAGE,
  VERIFICATION_SCHEMA_V2,
  assertFreshVerificationSnapshot,
  buildVerificationSnapshot,
  claimIdSetFromSnapshot,
  findingIdSetFromSnapshot,
  recomputeSnapshotHash,
  requireFreshVerificationState,
};
