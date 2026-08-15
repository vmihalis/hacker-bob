"use strict";

// PH-C10 — server-owned evidence packs for capability-pack findings.
//
// A pack that declares an evidence adapter cannot accept a caller-authored
// evidence payload.  The adapter rebuilds the live production grade projection
// and emits only bounded report-safe scalars.  Persisted packs are compared
// exactly (before and after generic normalization) so extra raw fields cannot
// be smuggled into evidence-packs.json.

const {
  getCapabilityPack,
} = require("./capability-packs.js");
const {
  buildCapabilityPackGradeBindings,
} = require("./capability-pack-grade-adapters.js");
const {
  resolvePhysicalCapabilityPackArtifacts,
} = require("../../domains/physical/capability-pack-physical-artifacts.js");
const {
  assertSafeDomain,
} = require("../io/paths.js");
const {
  canonicalJson,
} = require("../verification/verification-contracts.js");

function deepFreeze(value) {
  if (value == null || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function physicalEvidencePack(domain, binding, pack) {
  const artifacts = resolvePhysicalCapabilityPackArtifacts(domain, binding);
  const evidence = artifacts.report_evidence;
  return {
    finding_id: binding.finding_id,
    sample_type: pack.evidence.sample_type,
    sample_count: 1,
    aggregate_counts: {
      terminal_cells: binding.terminal_cell_count,
      matched_verified_cells: binding.matched_verified_cell_count,
      transition_edges: binding.transition_edge_count,
      reachable_nodes: binding.reachable_node_count,
      reachable_edges: binding.reachable_edge_count,
      independent_observer_domains:
        binding.external_observer_independence_domain_count,
      active_effects: 0,
      unexplained_residue: 0,
    },
    representative_samples: [{
      evidence_kind: "physical_verified_transition_projection",
      evidence_adapter: pack.evidence.adapter,
      asset_locator: binding.asset_locator,
      verified_verdict_ref: binding.verified_verdict_ref,
      verification_projection_digest: binding.verification_projection_digest,
      campaign_ref: binding.campaign_ref,
      campaign_completion_digest: binding.campaign_completion_digest,
      aggregate_closure_root: binding.aggregate_closure_root,
      terminal_cells_merkle_root: binding.terminal_cells_merkle_root,
      matched_verified_cells_digest: binding.matched_verified_cells_digest,
      no_active_effects_attestation_digest: binding.no_active_effects_attestation_digest,
      composition_adapter: binding.composition_adapter,
      composition_projection_digest: binding.composition_projection_digest,
      transition_receipt_ref: binding.transition_receipt_ref,
      transition_receipt_digest: binding.transition_receipt_digest,
      claim_predicate_digest: binding.claim_predicate_digest,
      transition_state_epoch: binding.transition_state_epoch,
      transition_state_digest: binding.transition_state_digest,
      transition_validity_kind: binding.transition_validity_kind,
      transition_edge_count: binding.transition_edge_count,
      transition_edge_set_digest: binding.transition_edge_set_digest,
      reachable_node_count: binding.reachable_node_count,
      reachable_node_set_digest: binding.reachable_node_set_digest,
      reachable_edge_count: binding.reachable_edge_count,
      reachable_edge_set_digest: binding.reachable_edge_set_digest,
      reachable_node_type_counts: binding.reachable_node_type_counts,
      blast_radius_categories: binding.blast_radius_categories,
      blast_radius_category_digest: binding.blast_radius_category_digest,
      blast_radius_class: binding.blast_radius_class,
      critical_category_pair: binding.critical_category_pair,
      attack_vector: binding.attack_vector,
      structural_severity_ceiling: binding.structural_severity_ceiling,
      verified_severity_ceiling: binding.verified_severity_ceiling,
      external_observer_independence_domain_count:
        binding.external_observer_independence_domain_count,
      external_observer_independence_domain_digest:
        binding.external_observer_independence_domain_digest,
      high_impact_corroboration_satisfied:
        binding.high_impact_corroboration_satisfied,
      observer_assurance_legacy_missing:
        binding.observer_assurance_legacy_missing,
      historical_fact_only: binding.historical_fact_only,
      live_capability_current: binding.live_capability_current,
      authority_inherited: false,
      downstream_authority_required: true,
      downstream_consumption_verified: false,
      blast_radius_grade_binding_digest:
        binding.blast_radius_grade_binding_digest,
      grade_binding_digest: binding.grade_binding_digest,
      report_evidence_digest: binding.report_evidence_digest,
      production_ready: true,
    }],
    sensitive_clusters: [],
    replay_summary:
      "Bob revalidated the server-owned physical verdict projection and durable campaign closure without invoking hardware.",
    redaction_notes:
      "Raw RF captures, credential material, stable identifiers, and provider transport data are excluded by the physical evidence adapter.",
    report_snippet: `${evidence.description} ${evidence.impact}`,
  };
}

const EVIDENCE_ADAPTERS = Object.freeze({
  physical_report_safe_evidence_pack_v1: physicalEvidencePack,
});

function reportableIdsArray(input) {
  if (!(input instanceof Set)) {
    throw new Error("capability-pack evidence adapters require a reportable finding-id Set");
  }
  return [...input].sort();
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
    const adapter = EVIDENCE_ADAPTERS[adapterId];
    if (typeof adapter !== "function") {
      throw new Error(
        `capability_pack ${binding.capability_pack} declares unsupported evidence adapter ${adapterId}`,
      );
    }
    packs.push(adapter(domain, binding, pack));
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
});
