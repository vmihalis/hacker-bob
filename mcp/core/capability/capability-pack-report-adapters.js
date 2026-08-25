"use strict";

// PH-C10 — deterministic report sections for pack-owned findings.
//
// Physical findings are never rendered from caller prose.  The report adapter
// re-evaluates the production grade binding, compares it with grade.json, and
// emits bounded sections from the report-safe evidence projection only.

const {
  gradeArtifactPaths,
} = require("../io/paths.js");
const {
  loadJsonDocumentStrict,
} = require("../io/storage.js");
const {
  buildCapabilityPackGradeBindings,
} = require("./capability-pack-grade-adapters.js");
const {
  resolveCapabilityPackArtifacts,
} = require("./capability-pack-evidence-adapters.js");
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

function readLivePackGradeBindings(domain, reportableFindingIds) {
  const document = loadJsonDocumentStrict(gradeArtifactPaths(domain).json, "grade verdict JSON");
  if (document == null || typeof document !== "object" || Array.isArray(document)
      || document.target_domain !== domain || !Array.isArray(document.capability_pack_bindings)) {
    throw new Error("grade verdict has no capability-pack bindings for this session");
  }
  const ids = document.capability_pack_bindings.map((binding) => binding && binding.finding_id);
  const live = buildCapabilityPackGradeBindings(domain, ids);
  if (live.legacy_finding_ids.length > 0
      || canonicalJson(live.bindings) !== canonicalJson(document.capability_pack_bindings)) {
    throw new Error("grade verdict capability-pack bindings drifted from live adapter projections");
  }

  // Grade.json can contain pack bindings for graded-but-non-reportable
  // findings.  Re-resolve the current final-reportable set independently so a
  // hand-edited grade document cannot omit a reportable pack-owned finding and
  // silently route it through (or around) the legacy report gates.
  const reportable = buildCapabilityPackGradeBindings(domain, [...reportableFindingIds].sort());
  const persistedByFinding = new Map(
    document.capability_pack_bindings.map((binding) => [binding.finding_id, binding]),
  );
  for (const binding of reportable.bindings) {
    const persisted = persistedByFinding.get(binding.finding_id);
    if (!persisted || canonicalJson(persisted) !== canonicalJson(binding)) {
      throw new Error(
        `reportable capability-pack finding ${binding.finding_id} is not bound by grade.json`,
      );
    }
  }
  return reportable;
}

function physicalReportSections(domain, binding) {
  const artifacts = resolveCapabilityPackArtifacts(domain, binding);
  const evidence = artifacts.report_evidence;
  const evidenceRef = `verification_round:final:${binding.finding_id}`;
  const proofLines = [
    `Title: ${evidence.title}`,
    `Severity: ${evidence.severity}`,
    `CWE: ${evidence.cwe || "N/A"}`,
    `Candidate narrative digest: ${evidence.claim_narrative_digest}`,
    `Opaque asset: ${evidence.asset_locator}`,
    `Verified verdict: ${evidence.verified_verdict_ref}`,
    `Verification projection: ${evidence.verification_projection_digest}`,
    `Composition projection: ${evidence.composition_projection_digest}`,
    `Transition receipt: ${evidence.transition_receipt_ref}`,
    `Transition receipt digest: ${evidence.transition_receipt_digest}`,
    `Transition state: epoch ${evidence.transition_state_epoch} / ${evidence.transition_state_digest}`,
    `Transition edges: ${evidence.transition_edge_count} / ${evidence.transition_edge_set_digest}`,
    `Verified reachable nodes: ${evidence.reachable_node_count} / ${evidence.reachable_node_set_digest}`,
    `Verified reachable edges: ${evidence.reachable_edge_count} / ${evidence.reachable_edge_set_digest}`,
    `Blast-radius class: ${evidence.blast_radius_class}`,
    `Verified severity ceiling: ${evidence.verified_severity_ceiling}`,
    `Independent observer domains: ${evidence.external_observer_independence_domain_count}`,
    `Observer-domain digest: ${evidence.external_observer_independence_domain_digest}`,
    `High-impact corroboration: ${evidence.high_impact_corroboration_satisfied}`,
    `Authority inherited: ${evidence.authority_inherited}`,
    `Downstream authority required: ${evidence.downstream_authority_required}`,
    `Downstream consumption verified: ${evidence.downstream_consumption_verified}`,
    `Proof: ${evidence.proof_summary}`,
    `Campaign: ${evidence.campaign_ref}`,
    `Aggregate closure root: ${evidence.aggregate_closure_root}`,
    `Terminal cells: ${evidence.terminal_cell_count}`,
    `Matched verified cells: ${evidence.matched_verified_cell_count}`,
    `Active effects: ${binding.active_effect_count}`,
    `Unexplained residue: ${binding.residue_cell_count}`,
    `Grade binding: ${evidence.grade_binding_digest}`,
    `Report evidence: ${evidence.report_evidence_digest}`,
  ].join("\n");
  return [
    {
      section_id: `physical-${binding.finding_id}-description`,
      kind: "impact",
      heading: `${binding.finding_id} physical finding description`,
      prose: evidence.description,
      evidence_refs: [evidenceRef],
      provenance: "bob_verified",
    },
    {
      section_id: `physical-${binding.finding_id}-impact`,
      kind: "impact",
      heading: `${binding.finding_id} physical impact`,
      prose: evidence.impact,
      evidence_refs: [evidenceRef],
      provenance: "bob_verified",
    },
    {
      section_id: `physical-${binding.finding_id}-proof`,
      kind: "evidence",
      heading: `${binding.finding_id} physical proof and closure`,
      prose: proofLines,
      evidence_refs: [
        evidenceRef,
        `evidence_pack:${binding.finding_id}`,
        `proof_bundle:${binding.finding_id}`,
      ],
      provenance: "bob_verified",
    },
  ];
}

const REPORT_ADAPTERS = Object.freeze({
  physical_report_safe_v1: physicalReportSections,
});

function buildCapabilityPackReportSections(targetDomain, reportableFindingIdsInput) {
  const domain = assertSafeDomain(targetDomain);
  if (!(reportableFindingIdsInput instanceof Set)) {
    throw new Error("report adapter requires a reportable finding-id Set");
  }
  const candidate = buildCapabilityPackGradeBindings(
    domain,
    [...reportableFindingIdsInput].sort(),
  );
  // Preserve legacy/advisory report composition byte-for-byte when the final
  // reportable set has no pack-owned findings.  Such sessions legitimately
  // have older grade documents with no capability_pack_bindings member.
  if (candidate.bindings.length === 0) {
    return deepFreeze({
      version: 1,
      target_domain: domain,
      handled_finding_ids: [],
      sections: [],
      production_ready: true,
    });
  }
  const projection = readLivePackGradeBindings(domain, reportableFindingIdsInput);
  const sections = [];
  const handled = [];
  for (const binding of projection.bindings) {
    const adapter = REPORT_ADAPTERS[binding.report_adapter];
    if (typeof adapter !== "function") {
      throw new Error(
        `capability_pack ${binding.capability_pack} declares unsupported report adapter ${binding.report_adapter}`,
      );
    }
    sections.push(...adapter(domain, binding));
    handled.push(binding.finding_id);
  }
  sections.sort((left, right) => left.section_id.localeCompare(right.section_id));
  handled.sort();
  return deepFreeze({
    version: 1,
    target_domain: domain,
    handled_finding_ids: handled,
    sections,
    production_ready: projection.production_ready === true,
  });
}

module.exports = Object.freeze({
  buildCapabilityPackReportSections,
});
