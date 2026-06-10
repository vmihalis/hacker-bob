"use strict";

// Cycle Y.6 (rev 4.1) — Stigmergic producers manifest (Y-P14a).
//
// Closed registry of MCP tools, generator outputs, and recorded artifacts
// that emit decision-relevant traces consumed by other agents or systems.
// Pair the producer entries here with consumer entries in
// `mcp/lib/stigmergic-consumers.js` (Y.9). The
// `check:stigmergy-coherence` CI gate (Y-P14c, lands in Y.9) walks both
// registries and asserts (a) every manifested producer has at least one
// manifested consumer reference, (b) every manifested consumer references
// its manifested producer at a citable source location, (c) no consumer
// references a non-manifested producer.
//
// Rev 4.1 (defect 4): the producers manifest was moved forward from rev-4
// Y.9 so the Y.6 ROLE_TRACE_EXPECTATIONS cross-reference test has a
// satisfiable target. Consumers manifest stays in Y.9 because consumer
// source locations reference Y.3 paths.js + Y.5 brief renderer + Y.11
// chain-builder.md prompt body — all upstream of Y.9 but downstream of
// Y.6.
//
// Rev 4.1 (defect 5): canonical producer_id strings committed here as the
// authoritative vocabulary. ROLE_TRACE_EXPECTATIONS (Y.6) and (when it
// lands) STIGMERGIC_CONSUMERS (Y.9) use these EXACT strings — no rename
// drift.

const STIGMERGIC_PRODUCERS = Object.freeze([
  Object.freeze({
    producer_id: "technique_pack_scorer",
    mcp_tool_or_artifact: "bob_select_technique_packs",
    trace_shape_ref:
      "mcp/lib/technique-packs.js#selectTechniquePacksForSurface",
    registered_consumers: Object.freeze([
      "assignment_brief_technique_section_renderer",
    ]),
  }),
  Object.freeze({
    producer_id: "surface_discovery_ranked_leads",
    mcp_tool_or_artifact:
      "deep-surface-discovery handoff summary ranked_leads[] OR bob_record_surface_leads invocation",
    trace_shape_ref: "mcp/lib/wave-handoff-contracts.js#lead_surface_ids",
    registered_consumers: Object.freeze([
      "orchestrator_handoff_receipt_record_surface_leads",
    ]),
  }),
  Object.freeze({
    producer_id: "chain_attempts_ledger",
    mcp_tool_or_artifact: "bob_read_chain_attempts",
    trace_shape_ref: "mcp/lib/chain-attempts.js",
    registered_consumers: Object.freeze([
      "chain_builder_prompt_body_read_before_propose",
    ]),
  }),
  Object.freeze({
    producer_id: "verification_round_ledger",
    mcp_tool_or_artifact: "bob_read_verification_round",
    trace_shape_ref: "mcp/lib/tools/write-verification-round.js",
    registered_consumers: Object.freeze([
      "compose_report_provenance_gate",
    ]),
  }),
  Object.freeze({
    producer_id: "mcp_owned_body_binding_handles",
    mcp_tool_or_artifact:
      "bob_import_http_traffic | bob_resolve_body | bob_static_scan",
    trace_shape_ref:
      "mcp/lib/tools/write-chain-rollup.js#EVIDENCE_REF_HANDLE_PREFIXES",
    registered_consumers: Object.freeze([
      "write_chain_rollup_evidence_refs_validator",
    ]),
  }),
  Object.freeze({
    producer_id: "capability_friction_ledger",
    mcp_tool_or_artifact: "bob_log_capability_friction",
    trace_shape_ref: "mcp/lib/tools/log-capability-friction.js",
    registered_consumers: Object.freeze([
      "evaluator_spawn_friction_log_on_internal_error",
    ]),
  }),
  Object.freeze({
    producer_id: "repo_inventory_reachability_stamp",
    mcp_tool_or_artifact: "bob_repo_inventory / buildRepoInventory",
    trace_shape_ref: "mcp/lib/reachability.js#classifyRepoReachability",
    registered_consumers: Object.freeze([
      "assignment_brief_reachability_triage_renderer",
      "c11_static_analysis_reachability_ranker",
      "grade_verdict_reachability_ceiling_reconciler",
    ]),
  }),
  Object.freeze({
    producer_id: "oss_technique_pack_registry",
    mcp_tool_or_artifact: "OSS_TECHNIQUE_PACKS",
    trace_shape_ref: "mcp/lib/technique-packs.js#OSS_TECHNIQUE_PACKS",
    registered_consumers: Object.freeze([
      "assignment_brief_oss_technique_pack_renderer",
    ]),
  }),
  Object.freeze({
    producer_id: "oss_rootcause_family_corpus",
    mcp_tool_or_artifact: "OSS_ROOTCAUSE_FAMILIES",
    trace_shape_ref:
      "mcp/lib/oss-rootcause-family-corpus.js#suggestFamiliesForSurface",
    registered_consumers: Object.freeze([
      "assignment_brief_oss_rootcause_family_renderer",
    ]),
  }),
  Object.freeze({
    producer_id: "static_analysis_index",
    mcp_tool_or_artifact: "indexStaticResults / static-analysis-index.jsonl",
    trace_shape_ref: "mcp/lib/static-analysis-index.js#indexStaticResults",
    registered_consumers: Object.freeze([
      "c11_static_analysis_brief_slice",
    ]),
  }),
]);

const PRODUCER_IDS = Object.freeze(
  STIGMERGIC_PRODUCERS.map((p) => p.producer_id),
);

function getProducer(producerId) {
  for (const p of STIGMERGIC_PRODUCERS) {
    if (p.producer_id === producerId) return p;
  }
  return null;
}

function isKnownProducerId(producerId) {
  for (const p of STIGMERGIC_PRODUCERS) {
    if (p.producer_id === producerId) return true;
  }
  return false;
}

module.exports = {
  STIGMERGIC_PRODUCERS,
  PRODUCER_IDS,
  getProducer,
  isKnownProducerId,
};
