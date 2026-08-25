"use strict";

// Server-owned evidence-pack transform. Concrete evidence projection belongs to
// the already-composed pack selected by the generic grade pipeline.

const { getCapabilityPack } = require("./capability-packs.js");
const { buildCapabilityPackGradeBindings } = require("./capability-pack-grade-adapters.js");
const { assertSafeDomain } = require("../io/paths.js");
const { canonicalJson } = require("../verification/verification-contracts.js");
const { finalSeverityByFinding } = require("../frontier/reachability-ceiling.js");

function deepFreeze(value) {
  if (value == null || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function reportableIdsArray(input) {
  if (!(input instanceof Set)) {
    throw new Error("capability-pack evidence adapters require a reportable finding-id Set");
  }
  return [...input].sort();
}

function resolveCapabilityPackArtifacts(targetDomain, binding) {
  const domain = assertSafeDomain(targetDomain);
  const pack = binding && getCapabilityPack(binding.capability_pack);
  const adapters = pack && pack.runtimeAdapters && pack.runtimeAdapters.artifacts;
  const adapterId = `${binding && binding.capability_pack}_verified_transition_artifacts_v1`;
  const adapter = adapters && adapters[adapterId];
  if (typeof adapter !== "function") {
    throw new Error(`capability_pack ${binding && binding.capability_pack} has no artifact adapter`);
  }
  return adapter(
    domain,
    binding,
    pack,
    () => finalSeverityByFinding(domain).get(binding.finding_id),
  );
}

function buildCapabilityPackEvidencePacks(targetDomain, reportableFindingIds) {
  const domain = assertSafeDomain(targetDomain);
  const ids = reportableIdsArray(reportableFindingIds);
  const gradeProjection = buildCapabilityPackGradeBindings(domain, ids);
  const packs = [];
  const handled = [];
  for (const binding of gradeProjection.bindings) {
    const pack = getCapabilityPack(binding.capability_pack);
    const adapterId = pack && pack.evidence && pack.evidence.adapter;
    if (typeof adapterId !== "string" || !adapterId) {
      throw new Error(
        `capability_pack ${binding.capability_pack} has a grade adapter but no evidence adapter`,
      );
    }
    const adapters = pack.runtimeAdapters && pack.runtimeAdapters.evidence;
    const adapter = adapters && adapters[adapterId];
    if (typeof adapter !== "function") {
      throw new Error(
        `capability_pack ${binding.capability_pack} declares unsupported evidence adapter ${adapterId}`,
      );
    }
    packs.push(adapter(
      domain,
      binding,
      pack,
      () => finalSeverityByFinding(domain).get(binding.finding_id),
    ));
    handled.push(binding.finding_id);
  }
  packs.sort((left, right) => left.finding_id.localeCompare(right.finding_id));
  handled.sort();
  return deepFreeze({
    version: 1,
    target_domain: domain,
    handled_finding_ids: handled,
    legacy_finding_ids: gradeProjection.legacy_finding_ids.slice(),
    packs,
    production_ready: gradeProjection.production_ready === true,
  });
}

function assertCapabilityPackEvidencePacksCurrent(
  targetDomain,
  rawPacks,
  normalizedPacks,
  reportableFindingIds,
) {
  const projection = buildCapabilityPackEvidencePacks(targetDomain, reportableFindingIds);
  if (!Array.isArray(rawPacks) || !Array.isArray(normalizedPacks)) {
    throw new Error("capability-pack evidence validation requires raw and normalized packs arrays");
  }
  const rawById = new Map(rawPacks.map((pack) => [pack && pack.finding_id, pack]));
  const normalizedById = new Map(normalizedPacks.map((pack) => [pack && pack.finding_id, pack]));
  for (const expected of projection.packs) {
    const raw = rawById.get(expected.finding_id);
    const normalized = normalizedById.get(expected.finding_id);
    if (raw == null || normalized == null
        || canonicalJson(raw) !== canonicalJson(expected)
        || canonicalJson(normalized) !== canonicalJson(expected)) {
      throw new Error(
        `capability-pack evidence for ${expected.finding_id} drifted from its live server-owned projection`,
      );
    }
  }
  return projection;
}

module.exports = Object.freeze({
  assertCapabilityPackEvidencePacksCurrent,
  buildCapabilityPackEvidencePacks,
  resolveCapabilityPackArtifacts,
});
