"use strict";

// PH-C10 — machine-checkable proof bundles for capability-pack findings.
// Pack proof is generated from the same live, branded production projection as
// grade/report evidence.  It contains only opaque references, digests, counts,
// and terminal-state facts; no RF capture, credential bytes, provider command,
// or caller-authored proof prose is accepted.

const {
  getCapabilityPack,
} = require("./capability-packs.js");
const {
  buildCapabilityPackGradeBindings,
} = require("./capability-pack-grade-adapters.js");
const {
  resolvePhysicalCapabilityPackArtifacts,
} = require("./capability-pack-physical-artifacts.js");
const {
  assertSafeDomain,
} = require("./paths.js");
const {
  canonicalJson,
  hashCanonicalJson,
} = require("./verification-contracts.js");

function deepFreeze(value) {
  if (value == null || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function physicalProofBundle(domain, binding, pack) {
  const artifacts = resolvePhysicalCapabilityPackArtifacts(domain, binding);
  const evidence = artifacts.report_evidence;
  const proofArtifact = {
    artifact_kind: "capability_pack",
    proof_adapter: pack.proof.adapter,
    proof_kind: "physical_verified_transition_campaign_closure",
    capability_pack: "physical",
    asset_locator: binding.asset_locator,
    severity: binding.severity,
    verified_verdict_ref: binding.verified_verdict_ref,
    verification_projection_digest: binding.verification_projection_digest,
    campaign_ref: binding.campaign_ref,
    campaign_completion_digest: binding.campaign_completion_digest,
    aggregate_closure_root: binding.aggregate_closure_root,
    terminal_cells_merkle_root: binding.terminal_cells_merkle_root,
    terminal_cell_count: binding.terminal_cell_count,
    matched_verified_cell_count: binding.matched_verified_cell_count,
    matched_verified_cells_digest: binding.matched_verified_cells_digest,
    active_effect_count: 0,
    residue_cell_count: 0,
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
    report_evidence_digest: evidence.report_evidence_digest,
    claim_narrative_digest: evidence.claim_narrative_digest,
    raw_evidence_allowed: false,
    hardware_effects_invoked: false,
    production_ready: true,
  };
  const bundle = {
    finding_id: binding.finding_id,
    bundle_kind: pack.proof.bundle_kind,
    artifacts: [proofArtifact],
  };
  bundle.bundle_hash = hashCanonicalJson(bundle);
  return bundle;
}

const PROOF_ADAPTERS = Object.freeze({
  physical_campaign_closure_proof_bundle_v1: physicalProofBundle,
});

function reportableIdsArray(input) {
  if (!(input instanceof Set)) {
    throw new Error("capability-pack proof adapters require a reportable finding-id Set");
  }
  return [...input].sort();
}

function buildCapabilityPackProofBundles(targetDomain, reportableFindingIds) {
  const domain = assertSafeDomain(targetDomain);
  const gradeProjection = buildCapabilityPackGradeBindings(
    domain,
    reportableIdsArray(reportableFindingIds),
  );
  const packs = [];
  const handled = [];
  for (const binding of gradeProjection.bindings) {
    const pack = getCapabilityPack(binding.capability_pack);
    const adapterId = pack && pack.proof && pack.proof.adapter;
    if (typeof adapterId !== "string" || !adapterId
        || pack.proof.bundle_kind !== "capability_pack") {
      throw new Error(
        `capability_pack ${binding.capability_pack} has no coherent capability-pack proof adapter`,
      );
    }
    const adapter = PROOF_ADAPTERS[adapterId];
    if (typeof adapter !== "function") {
      throw new Error(
        `capability_pack ${binding.capability_pack} declares unsupported proof adapter ${adapterId}`,
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

function assertCapabilityPackProofBundlesCurrent(
  targetDomain,
  rawPacks,
  normalizedPacks,
  reportableFindingIds,
) {
  const projection = buildCapabilityPackProofBundles(targetDomain, reportableFindingIds);
  if (!Array.isArray(rawPacks) || !Array.isArray(normalizedPacks)) {
    throw new Error("capability-pack proof validation requires raw and normalized packs arrays");
  }
  const expectedById = new Map(projection.packs.map((pack) => [pack.finding_id, pack]));
  const rawById = new Map(rawPacks.map((pack) => [pack && pack.finding_id, pack]));
  const normalizedById = new Map(normalizedPacks.map((pack) => [pack && pack.finding_id, pack]));
  for (const expected of projection.packs) {
    const raw = rawById.get(expected.finding_id);
    const normalized = normalizedById.get(expected.finding_id);
    if (raw == null || normalized == null
        || canonicalJson(raw) !== canonicalJson(expected)
        || canonicalJson(normalized) !== canonicalJson(expected)) {
      throw new Error(
        `capability-pack proof for ${expected.finding_id} drifted from its live server-owned projection`,
      );
    }
  }
  for (const pack of rawPacks) {
    if (pack && pack.bundle_kind === "capability_pack"
        && !expectedById.has(pack.finding_id)) {
      throw new Error(
        `capability-pack proof for ${pack.finding_id || "<unknown>"} has no registered live proof adapter`,
      );
    }
  }
  return projection;
}

module.exports = Object.freeze({
  assertCapabilityPackProofBundlesCurrent,
  buildCapabilityPackProofBundles,
});
