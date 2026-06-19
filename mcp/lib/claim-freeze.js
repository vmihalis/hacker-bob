"use strict";

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const {
  assertSafeDomain,
  claimFreezePath,
  repoChecksJsonlPath,
  repoRunsDir,
} = require("./paths.js");
const {
  hashCanonicalJson,
} = require("./verification-contracts.js");
const {
  hashDocumentExcluding,
  normalizeIsoTimestamp,
  normalizeOptionalId,
  writeJsonDocument,
} = require("./fabric-common.js");
const {
  readCandidateClaims,
} = require("./claims.js");
const {
  appendClaimCluster,
  normalizeClaimCluster,
  readClaimClusters,
} = require("./claim-clusters.js");
const {
  correlateClaims,
} = require("./claim-correlator.js");
const {
  readFrontierEvents,
} = require("./frontier-events.js");
const {
  readJsonFile,
  withSessionLock,
} = require("./storage.js");

const CLAIM_FREEZE_VERSION = 1;

// EvidenceReference helpers come from claims.js. The schema lives there because
// CandidateClaim is the first-class carrier of evidence_refs[]; this module
// composes the frozen payload over those refs.
const {
  EVIDENCE_REFERENCE_KIND_VALUES,
  evidenceReferenceLookupKey,
  normalizeEvidenceReferenceShape,
} = require("./claims.js");

function generatedClaimFreezeId(fields) {
  return `CF-${hashCanonicalJson(fields).slice(0, 24)}`;
}

// Materialize the ClaimCluster rows implied by the frozen claim batch. Each
// candidate cluster from correlateClaims is normalized (which assigns the
// deterministic cluster_id + cluster_hash); if a cluster with the same
// cluster_hash is already on disk it is skipped so re-running the freeze on
// an unchanged claim set never duplicates rows. The function returns the set
// of normalized clusters (existing + newly appended) for inclusion in the
// freeze payload.
function materializeClusters(domain, claims) {
  const candidates = correlateClaims(claims);
  if (candidates.length === 0) return [];

  const existing = readClaimClusters(domain);
  const existingHashes = new Set(existing.map((cluster) => cluster.cluster_hash));

  const materialized = [];
  for (const candidate of candidates) {
    const normalized = normalizeClaimCluster(candidate);
    if (existingHashes.has(normalized.cluster_hash)) {
      materialized.push(normalized);
      continue;
    }
    const appended = appendClaimCluster(candidate);
    existingHashes.add(appended.cluster_hash);
    materialized.push(appended);
  }
  return materialized;
}

function buildClaimFreezeDocument(domain, { write = false, now = new Date(), freezeId = null } = {}) {
  const frozenAt = normalizeIsoTimestamp(now, "frozen_at", null);
  const claims = readCandidateClaims(domain).slice().sort((a, b) => a.claim_id.localeCompare(b.claim_id));
  if (write) {
    materializeClusters(domain, claims);
  }
  const clusters = readClaimClusters(domain).slice().sort((a, b) => a.cluster_id.localeCompare(b.cluster_id));
  const clusterIds = clusters.map((cluster) => cluster.cluster_id);
  const frontierEvents = readFrontierEvents(domain);
  const sourceHashes = {
    claims_hash: hashCanonicalJson(claims),
    claim_clusters_hash: hashCanonicalJson(clusters),
    frontier_events_hash: hashCanonicalJson(frontierEvents.map((event) => event.event_hash)),
  };
  const base = {
    version: CLAIM_FREEZE_VERSION,
    target_domain: domain,
    frozen_at: frozenAt,
    claim_count: claims.length,
    cluster_count: clusters.length,
    source_event_count: frontierEvents.length,
    source_hashes: sourceHashes,
    claims,
    clusters,
    cluster_ids: clusterIds,
  };
  const normalizedFreezeId = normalizeOptionalId(freezeId, "freeze_id")
    || generatedClaimFreezeId({
      target_domain: domain,
      source_hashes: sourceHashes,
    });
  const freeze = {
    freeze_id: normalizedFreezeId,
    ...base,
  };
  freeze.freeze_hash = hashDocumentExcluding(freeze, ["frozen_at", "freeze_hash"]);

  if (write) {
    writeJsonDocument(claimFreezePath(domain), freeze);
  }
  return freeze;
}

function buildClaimFreeze(targetDomain, options = {}) {
  const domain = assertSafeDomain(targetDomain);
  if (options.write) {
    return withSessionLock(domain, () => buildClaimFreezeDocument(domain, options));
  }
  return buildClaimFreezeDocument(domain, options);
}

function verificationSnapshotFromClaimFreeze(input, { now = new Date() } = {}) {
  const freeze = input && input.freeze ? input.freeze : input;
  if (freeze == null || typeof freeze !== "object" || Array.isArray(freeze)) {
    throw new Error("claim freeze must be an object");
  }
  const createdAt = normalizeIsoTimestamp(now, "created_at", null);
  const snapshot = {
    version: 1,
    target_domain: assertSafeDomain(freeze.target_domain),
    created_at: createdAt,
    freeze_id: normalizeOptionalId(freeze.freeze_id, "freeze_id"),
    claim_freeze_hash: normalizeOptionalId(freeze.freeze_hash, "freeze_hash"),
    claim_count: Array.isArray(freeze.claims) ? freeze.claims.length : 0,
    cluster_count: Array.isArray(freeze.clusters) ? freeze.clusters.length : 0,
    claims: Array.isArray(freeze.claims) ? freeze.claims : [],
    clusters: Array.isArray(freeze.clusters) ? freeze.clusters : [],
  };
  snapshot.verification_snapshot_hash = hashDocumentExcluding(snapshot, [
    "created_at",
    "verification_snapshot_hash",
  ]);
  return snapshot;
}

function readCurrentClaimFreeze(targetDomain) {
  const domain = assertSafeDomain(targetDomain);
  const filePath = claimFreezePath(domain);
  if (!fs.existsSync(filePath)) return null;
  return readJsonFile(filePath, { label: "claim-freeze.json" });
}

// Iterate the EvidenceReference entries on every CandidateClaim in the freeze.
// Emits {claim, claimId, ref, refKey} tuples for deterministic traversal.
function* iterateFrozenEvidenceRefs(freeze) {
  if (!freeze || !Array.isArray(freeze.claims)) return;
  for (const claim of freeze.claims) {
    if (!claim || typeof claim !== "object") continue;
    const claimId = typeof claim.claim_id === "string" ? claim.claim_id : null;
    if (!Array.isArray(claim.evidence_refs)) continue;
    for (const ref of claim.evidence_refs) {
      if (!ref || typeof ref !== "object") continue;
      yield {
        claim,
        claim_id: claimId,
        ref,
        ref_key: evidenceReferenceLookupKey(ref),
      };
    }
  }
}

// Cycle C.5 completeness gate. The frozen claim batch is authoritative; the
// gate measures whether every CandidateClaim's required EvidenceReference is
// observed in the supplied evidence_refs[] payload (and whether the observed
// content_hash matches the frozen reference). Missing/mismatched refs are
// blockers; the GRADE phase must not advance while complete: false.
//
// Parameters:
//   freeze           : the claim-freeze document (typically from
//                      readCurrentClaimFreeze).
//   suppliedRefs     : observed refs (e.g., evidence-pack lookup keys) keyed
//                      by `evidenceReferenceLookupKey(ref)` with the observed
//                      content_hash as the map value, or an iterable of
//                      ref objects.
//
// Returns a structured verdict:
//   {
//     complete: boolean,
//     required: number,
//     satisfied: number,
//     missing: [{claim_id, kind, ref_key}],
//     mismatched: [{claim_id, kind, ref_key, expected_hash, observed_hash}],
//     extras: [{ref_key}], // observed refs not present in the freeze
//   }
// O.8: pick the identity hash for an EvidenceReference. Each kind exposes its
// content-identity through a kind-specific field — for repo_command_run the
// natural content-identity is `stdout_hash` (the sha256 of the captured stdout
// file, written by repoDockerRun); for every other kind the legacy
// `content_hash` field is the identity. The completeness gate uses this
// selector on both the frozen ref (expected) and the observed ref (whatever
// the verifier projected from disk or supplied directly) so the equality
// comparison is unambiguous.
function evidenceReferenceIdentityHash(ref) {
  if (!ref || typeof ref !== "object") return null;
  if (ref.kind === "repo_command_run") {
    return typeof ref.stdout_hash === "string" ? ref.stdout_hash : null;
  }
  return typeof ref.content_hash === "string" ? ref.content_hash : null;
}

function suppliedRefsAsMap(supplied) {
  if (supplied == null) return new Map();
  if (supplied instanceof Map) return supplied;
  const map = new Map();
  if (Array.isArray(supplied)) {
    for (const ref of supplied) {
      const key = evidenceReferenceLookupKey(ref);
      if (key == null) continue;
      const hash = evidenceReferenceIdentityHash(ref);
      map.set(key, hash);
    }
    return map;
  }
  if (typeof supplied === "object") {
    for (const [key, value] of Object.entries(supplied)) {
      map.set(key, typeof value === "string" ? value : null);
    }
  }
  return map;
}

function assertCompletenessAgainstFreeze(freeze, suppliedRefs) {
  const required = [];
  for (const entry of iterateFrozenEvidenceRefs(freeze)) {
    required.push(entry);
  }
  const observed = suppliedRefsAsMap(suppliedRefs);
  const missing = [];
  const mismatched = [];
  let satisfied = 0;
  const requiredKeys = new Set();
  for (const entry of required) {
    requiredKeys.add(entry.ref_key);
    if (!observed.has(entry.ref_key)) {
      missing.push({
        claim_id: entry.claim_id,
        kind: entry.ref ? entry.ref.kind || null : null,
        ref_key: entry.ref_key,
      });
      continue;
    }
    const expectedHash = evidenceReferenceIdentityHash(entry.ref);
    const observedHash = observed.get(entry.ref_key);
    if (expectedHash != null && observedHash != null && expectedHash !== observedHash) {
      mismatched.push({
        claim_id: entry.claim_id,
        kind: entry.ref.kind || null,
        ref_key: entry.ref_key,
        expected_hash: expectedHash,
        observed_hash: observedHash,
      });
      continue;
    }
    satisfied += 1;
  }
  const extras = [];
  for (const key of observed.keys()) {
    if (!requiredKeys.has(key)) extras.push({ ref_key: key });
  }
  return {
    complete: missing.length === 0 && mismatched.length === 0,
    required: required.length,
    satisfied,
    missing,
    mismatched,
    extras,
  };
}

// Plane O Cycle O.8 — verifier-side projection of code-bound EvidenceReference
// observed hashes from on-disk repo session artifacts. The verifier calls these
// when it needs to satisfy the completeness gate for repo_file /
// repo_command_run frozen refs without an explicit suppliedRefs list: each
// helper reads the on-disk artifact (repo-checks.jsonl or
// repo-runs/<run_id>.{stdout,stderr}), recomputes the sha256 of the
// authoritative bytes, and yields a ref-shaped projection the completeness
// gate compares against the frozen ref's content_hash / stdout_hash.
//
// When the on-disk artifact is missing (file deleted between freeze and
// verify) or the recomputed hash does not match the recorded one (tamper or
// drift), the projection emits the observed-hash slot as null or as the
// actually-recomputed value — `assertCompletenessAgainstFreeze` then surfaces
// the discrepancy as missing/mismatched in its verdict.

function sha256File(filePath) {
  try {
    if (!fs.existsSync(filePath)) return null;
    const data = fs.readFileSync(filePath);
    return crypto.createHash("sha256").update(data).digest("hex");
  } catch {
    return null;
  }
}

function readRepoChecksRows(domain) {
  const filePath = repoChecksJsonlPath(domain);
  if (!fs.existsSync(filePath)) return [];
  try {
    const raw = fs.readFileSync(filePath, "utf8");
    const rows = [];
    for (const line of raw.split(/\r?\n/)) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      try {
        rows.push(JSON.parse(trimmed));
      } catch {
        // Skip unparseable lines; the producer's own validation gate is
        // authoritative for write-time integrity.
      }
    }
    return rows;
  } catch {
    return [];
  }
}

// Project a `repo_file` observed ref by scanning `repo-checks.jsonl` for any
// row that recorded the same file_path. If any row's `file_hash` matches the
// frozen ref's `content_hash`, project that matching hash (completeness
// passes). If at least one row was observed for the file_path but none matched
// the expected hash, project the freshest non-null observed hash so the
// completeness gate surfaces a `mismatched` entry. If no rows touched the
// file_path at all (file removed or never probed), return null so the gate
// surfaces a `missing` entry — we explicitly do NOT add a projected ref with
// content_hash=null because the gate treats "key present, hash null" as a
// silent satisfy (legacy compatibility for `finding`-shaped refs whose
// evidence packs don't always carry hashes).
function projectRepoFileObservedRef(domain, frozenRef) {
  if (!frozenRef || frozenRef.kind !== "repo_file") return null;
  const rows = readRepoChecksRows(domain);
  if (rows.length === 0) return null;
  const matchingByPath = rows.filter((row) => row && row.file_path === frozenRef.file_path);
  if (matchingByPath.length === 0) return null;
  for (const row of matchingByPath) {
    if (typeof row.file_hash === "string" && row.file_hash === frozenRef.content_hash) {
      return { ...frozenRef, content_hash: row.file_hash };
    }
  }
  // No row carried a matching hash — project the freshest observed hash so the
  // gate reports a mismatch with the actual on-disk value. Iterate in reverse
  // because the file is append-only and the latest probe wins.
  for (let i = matchingByPath.length - 1; i >= 0; i -= 1) {
    const hash = matchingByPath[i] && matchingByPath[i].file_hash;
    if (typeof hash === "string" && hash.length > 0) {
      return { ...frozenRef, content_hash: hash };
    }
  }
  return null;
}

// Project a `repo_command_run` observed ref by recomputing the sha256 of the
// on-disk stdout capture file at `repo-runs/<run_id>.stdout`. The frozen ref's
// `stdout_hash` is the authoritative identity; the completeness gate (via
// `evidenceReferenceIdentityHash`) picks `stdout_hash` for this kind on both
// sides. When the stdout file is missing or unreadable, returns null so the
// gate surfaces a `missing` entry; when the file is present but tampered,
// projects the actually-recomputed sha so the gate reports a `mismatched`
// entry.
function projectRepoCommandRunObservedRef(domain, frozenRef) {
  if (!frozenRef || frozenRef.kind !== "repo_command_run") return null;
  if (typeof frozenRef.run_id !== "string" || !frozenRef.run_id) return null;
  const stdoutPath = path.join(repoRunsDir(domain), `${frozenRef.run_id}.stdout`);
  const observed = sha256File(stdoutPath);
  if (observed == null) return null;
  return {
    ...frozenRef,
    // The gate's identity-hash selector picks `stdout_hash` for
    // kind="repo_command_run"; supply the recomputed sha here so the gate
    // compares it against the frozen ref's `stdout_hash` slot.
    stdout_hash: observed,
  };
}

// Build the full observed-ref set for the code-bound kinds in a freeze. The
// caller (typically `assertEvidenceCompletenessForFreeze`) folds these into
// the existing finding/etc observed set before invoking
// `assertCompletenessAgainstFreeze`. Projection helpers return null when the
// underlying on-disk artifact is gone — the unified gate then surfaces those
// keys as `missing` entries (rather than silently treating them as satisfied).
function projectCodeBoundObservedRefs(domain, freeze) {
  const projected = [];
  if (!freeze) return projected;
  for (const entry of iterateFrozenEvidenceRefs(freeze)) {
    if (!entry || !entry.ref) continue;
    const kind = entry.ref.kind;
    if (kind === "repo_file") {
      const obs = projectRepoFileObservedRef(domain, entry.ref);
      if (obs) projected.push(obs);
    } else if (kind === "repo_command_run") {
      const obs = projectRepoCommandRunObservedRef(domain, entry.ref);
      if (obs) projected.push(obs);
    }
  }
  return projected;
}

module.exports = {
  CLAIM_FREEZE_VERSION,
  EVIDENCE_REFERENCE_KIND_VALUES,
  assertCompletenessAgainstFreeze,
  buildClaimFreeze,
  evidenceReferenceIdentityHash,
  evidenceReferenceLookupKey,
  generatedClaimFreezeId,
  iterateFrozenEvidenceRefs,
  normalizeEvidenceReferenceShape,
  projectCodeBoundObservedRefs,
  projectRepoCommandRunObservedRef,
  projectRepoFileObservedRef,
  readCurrentClaimFreeze,
  sha256File,
  verificationSnapshotFromClaimFreeze,
};
