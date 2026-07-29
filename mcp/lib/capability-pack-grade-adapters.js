"use strict";

// PH-C10 — registry-driven grade adapter dispatch.
//
// The generic grade lifecycle asks each finding's capability pack whether it
// owns a grade adapter.  Packs without one continue through the legacy
// web/OSS/SC gates.  A declared but unknown adapter fails closed, preventing a
// pack from bypassing both its own proof contract and the legacy proof gates.

const {
  getCapabilityPack,
} = require("./capability-packs.js");
const {
  findingPayloadsFromClaims,
} = require("./tools/record-candidate-claim.js");
const {
  readCurrentClaimFreeze,
} = require("./claim-freeze.js");
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
  finalSeverityByFinding,
} = require("./reachability-ceiling.js");
const {
  bindPhysicalSeverityToVerifiedBlastRadius,
  buildPhysicalCompositionProjection,
} = require("./capability-pack-composition-adapters.js");

function deepFreeze(value) {
  if (value == null || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function physicalGradeAdapter(domain, findingId) {
  const pack = getCapabilityPack("physical");
  if (!pack || !pack.grade || !pack.report
      || pack.grade.adapter !== "physical_verified_transition_grade_binding_v1"
      || typeof pack.report.renderer !== "string" || !pack.report.renderer) {
    throw new Error("physical capability-pack grade/report adapters are not registered coherently");
  }
  const resolved = resolvePhysicalCandidateClaim(domain, findingId);
  const completion = projectDurablePhysicalCampaignCompletion({
    target_domain: domain,
    assignment: resolved.assignment,
    finding: resolved.finding,
  });
  const verifiedSeverity = finalSeverityByFinding(domain).get(findingId);
  if (typeof verifiedSeverity !== "string") {
    throw new Error(`physical finding ${findingId} has no final verified severity`);
  }
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
  return deepFreeze({
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
  });
}

const GRADE_ADAPTERS = Object.freeze({
  physical_verified_transition_grade_binding_v1: physicalGradeAdapter,
});

function capabilityPackGradeAdapterId(finding) {
  if (finding == null || typeof finding !== "object" || Array.isArray(finding)) return null;
  if (typeof finding.capability_pack !== "string" || !finding.capability_pack.trim()) return null;
  const pack = getCapabilityPack(finding.capability_pack.trim());
  if (!pack || !pack.grade || typeof pack.grade.adapter !== "string") return null;
  return pack.grade.adapter;
}

function buildCapabilityPackGradeBindings(targetDomain, findingIdsInput) {
  const domain = assertSafeDomain(targetDomain);
  if (!Array.isArray(findingIdsInput)) throw new Error("grade adapter finding_ids must be an array");
  const findingIds = findingIdsInput.map((id) => parseFindingId(id, "finding_id"));
  if (new Set(findingIds).size !== findingIds.length) {
    throw new Error("grade adapter finding_ids must be unique");
  }
  // The frozen claim batch is authoritative at GRADE.  Read its embedded
  // finding routing first; live claims are only a fallback for legacy sessions
  // without a freeze.  Some historical tests/sessions froze only finding refs
  // and no embedded payload—those remain on the legacy gate instead of being
  // rejected merely because the adapter registry cannot infer a pack.  A
  // declared physical payload, even malformed, still selects the physical
  // adapter and fails closed inside its resolver.
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
  // A present freeze is the grade-time authority even when it predates
  // embedded finding payloads.  Never repopulate a partially/wholly legacy
  // freeze from the mutable live claim ledger: doing so would let one embedded
  // legacy payload switch the lookup mode and make another pack-owned finding
  // silently fall through to the legacy gates.  The live ledger is consulted
  // below only as a fail-closed routing detector for a frozen finding whose
  // payload is absent.
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
          throw new Error(
            `frozen pack-owned finding ${findingId} has no embedded routing payload`,
          );
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
    const adapter = GRADE_ADAPTERS[adapterId];
    if (typeof adapter !== "function") {
      throw new Error(
        `capability_pack ${finding.capability_pack} declares unsupported grade adapter ${adapterId}`,
      );
    }
    const binding = adapter(domain, findingId);
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
