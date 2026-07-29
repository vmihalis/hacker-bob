"use strict";

// Shared PH-C10 live projection used by the evidence, proof, and report
// adapters.  The adapter binding is only a durable scalar projection; rebuild
// the branded physical objects on every consumption so expiry, revocation,
// campaign closure, and no-active-effects state are revalidated at the point
// of use.

const {
  buildPhysicalGradeBinding,
  projectDurablePhysicalCampaignCompletion,
  renderPhysicalFindingEvidence,
} = require("./physical-capability-consumers.js");
const {
  resolvePhysicalCandidateClaim,
} = require("./physical-claim-lifecycle-adapter.js");
const {
  assertSafeDomain,
} = require("./paths.js");
const {
  parseFindingId,
} = require("./validation.js");
const {
  bindPhysicalSeverityToVerifiedBlastRadius,
  buildPhysicalCompositionProjection,
} = require("./capability-pack-composition-adapters.js");
const {
  getCapabilityPack,
} = require("./capability-packs.js");
const {
  finalSeverityByFinding,
} = require("./reachability-ceiling.js");
const {
  canonicalJson,
} = require("./verification-contracts.js");

function assertBindingField(binding, field, expected) {
  const actual = binding[field];
  const matches = (actual != null && typeof actual === "object")
    || (expected != null && typeof expected === "object")
    ? canonicalJson(actual) === canonicalJson(expected)
    : actual === expected;
  if (!matches) {
    throw new Error(`physical capability-pack binding ${field} drifted from its live projection`);
  }
}

function resolvePhysicalCapabilityPackArtifacts(targetDomain, binding) {
  const domain = assertSafeDomain(targetDomain);
  if (binding == null || typeof binding !== "object" || Array.isArray(binding)) {
    throw new Error("physical capability-pack binding must be an object");
  }
  if (binding.capability_pack !== "physical" || binding.production_ready !== true) {
    throw new Error("physical capability-pack artifacts require a production-ready physical binding");
  }
  const findingId = parseFindingId(binding.finding_id, "finding_id");
  const pack = getCapabilityPack("physical");
  if (!pack || !pack.grade || !pack.report
      || pack.grade.adapter !== "physical_verified_transition_grade_binding_v1"
      || pack.report.renderer !== "physical_report_safe_v1") {
    throw new Error("physical capability-pack artifact adapters are not registered coherently");
  }
  const verifiedSeverity = finalSeverityByFinding(domain).get(findingId);
  if (typeof verifiedSeverity !== "string") {
    throw new Error(`physical finding ${findingId} has no final verified severity`);
  }
  const resolved = resolvePhysicalCandidateClaim(domain, findingId);
  const completion = projectDurablePhysicalCampaignCompletion({
    target_domain: domain,
    assignment: resolved.assignment,
    finding: resolved.finding,
  });
  const composition = buildPhysicalCompositionProjection(domain, resolved.finding);
  const blastRadiusBinding = bindPhysicalSeverityToVerifiedBlastRadius(
    composition,
    verifiedSeverity,
  );
  const gradeBinding = buildPhysicalGradeBinding({
    finding: resolved.finding,
    completion,
    verified_severity: verifiedSeverity,
    blast_radius_binding: blastRadiusBinding,
  });
  const reportEvidence = renderPhysicalFindingEvidence({
    finding: resolved.finding,
    grade_binding: gradeBinding,
  });

  const expectedFields = {
    version: 1,
    capability_pack: "physical",
    grade_adapter: pack.grade.adapter,
    report_adapter: pack.report.renderer,
    finding_id: resolved.finding_id,
    claim_id: resolved.claim_id,
    claim_hash: resolved.claim_hash,
    assignment_context_digest: resolved.assignment.assignment_context_digest,
    session_nucleus_hash: resolved.record.session_nucleus_hash,
    asset_locator: resolved.record.asset_locator,
    verified_verdict_ref: resolved.record.verified_verdict_ref,
    verification_projection_digest: resolved.record.verification_projection_digest,
    finding_asserted_severity: resolved.record.severity,
    severity: verifiedSeverity,
    campaign_ref: completion.campaign_ref,
    campaign_completion_digest: completion.completion_digest,
    aggregate_closure_root: completion.aggregate_closure_root,
    terminal_cells_merkle_root: completion.terminal_cells_merkle_root,
    terminal_cell_count: completion.terminal_cell_count,
    matched_verified_cell_count: completion.matched_verified_cell_count,
    matched_verified_cells_digest: completion.matched_verified_cells_digest,
    active_effect_count: 0,
    residue_cell_count: 0,
    no_active_effects_attestation_digest: completion.no_active_effects_attestation_digest,
    composition_adapter: gradeBinding.composition_adapter,
    composition_projection_digest: gradeBinding.composition_projection_digest,
    transition_receipt_ref: gradeBinding.transition_receipt_ref,
    transition_receipt_digest: gradeBinding.transition_receipt_digest,
    claim_predicate_digest: gradeBinding.claim_predicate_digest,
    transition_state_epoch: gradeBinding.transition_state_epoch,
    transition_state_digest: gradeBinding.transition_state_digest,
    transition_validity_kind: gradeBinding.transition_validity_kind,
    verified_severity_ceiling: gradeBinding.verified_severity_ceiling,
    structural_severity_ceiling: gradeBinding.structural_severity_ceiling,
    blast_radius_class: gradeBinding.blast_radius_class,
    attack_vector: gradeBinding.attack_vector,
    transition_edge_count: gradeBinding.transition_edge_count,
    transition_edge_set_digest: gradeBinding.transition_edge_set_digest,
    reachable_node_count: gradeBinding.reachable_node_count,
    reachable_node_set_digest: gradeBinding.reachable_node_set_digest,
    reachable_edge_count: gradeBinding.reachable_edge_count,
    reachable_edge_set_digest: gradeBinding.reachable_edge_set_digest,
    reachable_node_type_counts: gradeBinding.reachable_node_type_counts,
    blast_radius_categories: gradeBinding.blast_radius_categories,
    blast_radius_category_digest: gradeBinding.blast_radius_category_digest,
    critical_category_pair: gradeBinding.critical_category_pair,
    external_observer_independence_domain_count:
      gradeBinding.external_observer_independence_domain_count,
    external_observer_independence_domain_digest:
      gradeBinding.external_observer_independence_domain_digest,
    high_impact_corroboration_satisfied:
      gradeBinding.high_impact_corroboration_satisfied,
    observer_assurance_legacy_missing:
      gradeBinding.observer_assurance_legacy_missing,
    historical_fact_only: gradeBinding.historical_fact_only,
    live_capability_current: gradeBinding.live_capability_current,
    authority_inherited: false,
    downstream_authority_required: true,
    downstream_consumption_verified: false,
    blast_radius_grade_binding_digest: gradeBinding.blast_radius_grade_binding_digest,
    grade_binding_digest: gradeBinding.grade_binding_digest,
    report_evidence_digest: reportEvidence.report_evidence_digest,
    completion_depth_satisfied: true,
    production_ready: true,
  };
  for (const [field, expected] of Object.entries(expectedFields)) {
    assertBindingField(binding, field, expected);
  }

  return Object.freeze({
    finding_id: findingId,
    grade_binding: gradeBinding,
    report_evidence: reportEvidence,
  });
}

module.exports = Object.freeze({
  resolvePhysicalCapabilityPackArtifacts,
});
