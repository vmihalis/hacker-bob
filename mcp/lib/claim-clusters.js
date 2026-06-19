"use strict";

const {
  assertEnumValue,
  normalizeOptionalText,
} = require("./validation.js");
const {
  assertSafeDomain,
  claimClustersJsonlPath,
} = require("./paths.js");
const {
  appendJsonlLine,
  withSessionLock,
} = require("./storage.js");
const {
  hashCanonicalJson,
} = require("./verification-contracts.js");
const {
  normalizeId,
  normalizeIsoTimestamp,
  normalizeOptionalId,
  normalizeOptionalObject,
  normalizeOptionalTextArray,
  readJsonlStrict,
  withDocumentHash,
} = require("./fabric-common.js");

const CLAIM_CLUSTER_VERSION = 1;
const CLAIM_CLUSTERS_MAX_RECORDS = 10000;
const CLAIM_CLUSTER_STATUSES = Object.freeze(["open", "frozen", "verified", "dismissed", "reported"]);

function generatedClaimClusterId(fields) {
  return `CC-${hashCanonicalJson(fields).slice(0, 24)}`;
}

function normalizeClaimCluster(input, { targetDomain = null, now = new Date() } = {}) {
  if (input == null || typeof input !== "object" || Array.isArray(input)) {
    throw new Error("claim cluster must be an object");
  }
  const domain = assertSafeDomain(input.target_domain || targetDomain);
  const claimIds = normalizeOptionalTextArray(input.claim_ids, "claim_ids");
  if (claimIds.length === 0) {
    throw new Error("claim_ids must contain at least one claim id");
  }
  const createdAt = normalizeIsoTimestamp(input.created_at || input.ts, "created_at", now);
  const status = assertEnumValue(input.status || "open", CLAIM_CLUSTER_STATUSES, "status");
  const clusterKey = normalizeOptionalText(input.cluster_key, "cluster_key")
    || hashCanonicalJson({
      target_domain: domain,
      claim_ids: claimIds.slice().sort(),
      control_area: input.control_area || null,
    }).slice(0, 32);

  const cluster = {
    version: CLAIM_CLUSTER_VERSION,
    target_domain: domain,
    cluster_key: clusterKey,
    claim_ids: claimIds.slice().sort(),
    status,
    created_at: createdAt,
  };

  const title = normalizeOptionalText(input.title, "title");
  const controlArea = normalizeOptionalText(input.control_area, "control_area");
  const summary = normalizeOptionalText(input.summary, "summary");
  const owner = normalizeOptionalText(input.owner, "owner");
  const tags = normalizeOptionalTextArray(input.tags, "tags");
  const payload = normalizeOptionalObject(input.payload, "payload");

  if (title) cluster.title = title;
  if (controlArea) cluster.control_area = controlArea;
  if (summary) cluster.summary = summary;
  if (owner) cluster.owner = owner;
  if (tags.length > 0) cluster.tags = tags;
  if (payload) cluster.payload = payload;

  const clusterId = normalizeOptionalId(input.cluster_id, "cluster_id") || generatedClaimClusterId(cluster);
  return withDocumentHash({
    cluster_id: clusterId,
    ...cluster,
  }, "cluster_hash");
}

function appendClaimCluster(input, options = {}) {
  const cluster = normalizeClaimCluster(input, options);
  return withSessionLock(cluster.target_domain, () => {
    appendJsonlLine(claimClustersJsonlPath(cluster.target_domain), cluster, {
      maxRecords: options.maxRecords == null ? CLAIM_CLUSTERS_MAX_RECORDS : options.maxRecords,
    });
    return cluster;
  });
}

function readClaimClusters(targetDomain) {
  const domain = assertSafeDomain(targetDomain);
  return readJsonlStrict(
    claimClustersJsonlPath(domain),
    "claim-clusters.jsonl",
    (record) => normalizeClaimCluster(record, { targetDomain: domain, now: null }),
  );
}

function uniquePriorClaimKey(record) {
  const targetDomain = record && record.target_domain ? record.target_domain : "";
  const claimId = record && (record.claim_id || record.finding_id) ? (record.claim_id || record.finding_id) : "";
  return `${targetDomain}\0${claimId}`;
}

// Saturation guard: when a cross-target scan window (e.g. 200 most-recent
// domains) excludes the current target_domain because the index is saturated
// with unrelated cross-target priors, the same-target query result must still
// surface ahead of cross-target matches. Returns a deduped, ordered slice with
// same-target priors first, then by descending similarity, then by claim id
// for deterministic ordering.
function mergePriorClaimMatches(domain, sameTargetMatches, crossTargetMatches, limit) {
  const byKey = new Map();
  const sameSrc = Array.isArray(sameTargetMatches) ? sameTargetMatches : [];
  const crossSrc = Array.isArray(crossTargetMatches) ? crossTargetMatches : [];
  for (const record of [...sameSrc, ...crossSrc]) {
    if (record == null || typeof record !== "object") continue;
    byKey.set(uniquePriorClaimKey(record), record);
  }
  const merged = Array.from(byKey.values()).sort((a, b) => {
    const aSame = a.target_domain === domain;
    const bSame = b.target_domain === domain;
    if (aSame !== bSame) return aSame ? -1 : 1;
    const aSim = typeof a.similarity === "number" ? a.similarity : 0;
    const bSim = typeof b.similarity === "number" ? b.similarity : 0;
    if (bSim !== aSim) return bSim - aSim;
    const aId = String((a && (a.claim_id || a.finding_id)) || "");
    const bId = String((b && (b.claim_id || b.finding_id)) || "");
    return aId.localeCompare(bId);
  });
  if (Number.isInteger(limit) && limit > 0) {
    return merged.slice(0, limit);
  }
  return merged;
}

module.exports = {
  CLAIM_CLUSTERS_MAX_RECORDS,
  CLAIM_CLUSTER_STATUSES,
  CLAIM_CLUSTER_VERSION,
  appendClaimCluster,
  generatedClaimClusterId,
  mergePriorClaimMatches,
  normalizeClaimCluster,
  readClaimClusters,
  uniquePriorClaimKey,
};
