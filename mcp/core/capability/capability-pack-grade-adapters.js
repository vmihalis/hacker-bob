"use strict";

// Registry-driven grade adapter dispatch. Plane implementations are carried by
// their already-composed capability pack; this core transform knows only the
// adapter contract and the lifecycle projection it aggregates.

const { getCapabilityPack } = require("./capability-packs.js");
const { findingPayloadsFromClaims } = require("../../tools/record-candidate-claim.js");
const { readCurrentClaimFreeze } = require("../claims/claim-freeze.js");
const { assertSafeDomain } = require("../io/paths.js");
const { parseFindingId } = require("../io/validation.js");
const { finalSeverityByFinding } = require("../frontier/reachability-ceiling.js");

function deepFreeze(value) {
  if (value == null || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function capabilityPackGradeAdapterId(finding) {
  if (finding == null || typeof finding !== "object" || Array.isArray(finding)) return null;
  if (typeof finding.capability_pack !== "string" || !finding.capability_pack.trim()) return null;
  const pack = getCapabilityPack(finding.capability_pack.trim());
  if (!pack || !pack.grade || typeof pack.grade.adapter !== "string") return null;
  return pack.grade.adapter;
}

function gradeAdapterForPack(pack, adapterId) {
  const adapters = pack && pack.runtimeAdapters && pack.runtimeAdapters.grade;
  return adapters && adapters[adapterId];
}

function buildCapabilityPackGradeBindings(targetDomain, findingIdsInput) {
  const domain = assertSafeDomain(targetDomain);
  if (!Array.isArray(findingIdsInput)) throw new Error("grade adapter finding_ids must be an array");
  const findingIds = findingIdsInput.map((id) => parseFindingId(id, "finding_id"));
  if (new Set(findingIds).size !== findingIds.length) {
    throw new Error("grade adapter finding_ids must be unique");
  }
  const byId = new Map();
  const freeze = readCurrentClaimFreeze(domain);
  if (freeze && Array.isArray(freeze.claims)) {
    for (const claim of freeze.claims) {
      const finding = claim && claim.payload && typeof claim.payload === "object"
        && claim.payload.finding && typeof claim.payload.finding === "object"
        ? claim.payload.finding
        : null;
      if (!finding || typeof finding.id !== "string") continue;
      if (byId.has(finding.id)) {
        const existing = byId.get(finding.id);
        if (capabilityPackGradeAdapterId(existing) != null
            || capabilityPackGradeAdapterId(finding) != null) {
          throw new Error(`frozen pack-owned finding ${finding.id} is ambiguous`);
        }
        continue;
      }
      byId.set(finding.id, finding);
    }
  }
  if (freeze == null) {
    for (const finding of findingPayloadsFromClaims(domain)) {
      if (!finding || typeof finding.id !== "string") continue;
      if (byId.has(finding.id)) throw new Error(`finding ${finding.id} is ambiguous`);
      byId.set(finding.id, finding);
    }
  }

  let liveRoutingById = null;
  function liveRoutingFinding(findingId) {
    if (liveRoutingById == null) {
      liveRoutingById = new Map();
      for (const candidate of findingPayloadsFromClaims(domain)) {
        if (!candidate || typeof candidate.id !== "string") continue;
        if (liveRoutingById.has(candidate.id)) {
          throw new Error(`finding ${candidate.id} is ambiguous`);
        }
        liveRoutingById.set(candidate.id, candidate);
      }
    }
    return liveRoutingById.get(findingId) || null;
  }

  const bindings = [];
  const handled = [];
  const completionDepth = [];
  const legacy = [];
  for (const findingId of findingIds) {
    const finding = byId.get(findingId);
    if (!finding) {
      if (freeze != null) {
        const liveFinding = liveRoutingFinding(findingId);
        if (capabilityPackGradeAdapterId(liveFinding) != null) {
          throw new Error(`frozen pack-owned finding ${findingId} has no embedded routing payload`);
        }
      }
      legacy.push(findingId);
      continue;
    }
    const adapterId = capabilityPackGradeAdapterId(finding);
    if (adapterId == null) {
      legacy.push(findingId);
      continue;
    }
    const pack = getCapabilityPack(finding.capability_pack.trim());
    const adapter = gradeAdapterForPack(pack, adapterId);
    if (typeof adapter !== "function") {
      throw new Error(
        `capability_pack ${finding.capability_pack} declares unsupported grade adapter ${adapterId}`,
      );
    }
    const binding = adapter(
      domain,
      findingId,
      pack,
      () => finalSeverityByFinding(domain).get(findingId),
    );
    bindings.push(binding);
    handled.push(findingId);
    if (binding.completion_depth_satisfied === true) completionDepth.push(findingId);
  }
  bindings.sort((left, right) => left.finding_id.localeCompare(right.finding_id));
  handled.sort();
  completionDepth.sort();
  legacy.sort();
  return deepFreeze({
    version: 1,
    target_domain: domain,
    bindings,
    handled_finding_ids: handled,
    completion_depth_finding_ids: completionDepth,
    legacy_finding_ids: legacy,
    production_ready: bindings.every((binding) => binding.production_ready === true),
  });
}

module.exports = Object.freeze({
  buildCapabilityPackGradeBindings,
  capabilityPackGradeAdapterId,
});
