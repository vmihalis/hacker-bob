"use strict";

// Cycle Y.9 (rev 4.1) — Stigmergic consumers manifest (Y-P14a).
//
// Closed registry of code sites whose behavior depends on a stigmergic
// producer trace recorded in `mcp/lib/stigmergic-producers.js`. Paired
// with the producers manifest by the `check:stigmergy-coherence` CI gate
// (Y-P14c), which walks both registries and asserts:
//   (a) every manifested producer has at least one manifested consumer
//       reference (covered by stigmergic-producers.js
//       `registered_consumers[]`);
//   (b) every manifested consumer references its manifested producer at
//       a citable source location (file + token_or_regex resolves at the
//       file via grep / IR walk);
//   (c) no consumer references a non-manifested producer.
//
// Rev 4.1 (defect 4): consumers manifest lands in Y.9 because consumer
// source locations cite Y.3 paths.js, Y.5 brief renderer, and Y.11
// chain-builder.md prompt body — all upstream of Y.9's CI-gate slot but
// downstream of Y.6's producers. Producers were moved forward to Y.6
// (where ROLE_TRACE_EXPECTATIONS already cross-references them).
//
// Rev 4.1 (defect 5): consumer entries quote the canonical producer_id
// strings from `stigmergic-producers.js`. No rename drift; the shape
// test asserts every consumer's producer_id matches a producer entry.

const DECISION_BOUNDARY_VALUES = Object.freeze([
  "brief_composition",
  "handoff_receipt",
  "chain_attempt_proposal",
  "claim_recording",
  "grade_time_reconciliation",
  "validator_invocation",
]);

const STIGMERGIC_CONSUMERS = Object.freeze([
  Object.freeze({
    consumer_id: "assignment_brief_technique_section_renderer",
    source_location: Object.freeze({
      file: "mcp/lib/assignment-brief.js",
      token_or_regex: "selectTechniquePacksForSurface",
    }),
    producer_id: "technique_pack_scorer",
    decision_boundary: "brief_composition",
    rationale:
      "renderer consumes selected_packs[].score before composing technique section",
  }),
  Object.freeze({
    consumer_id: "orchestrator_handoff_receipt_record_surface_leads",
    source_location: Object.freeze({
      file: ".claude/skills/bob-evaluate-runner/SKILL.md",
      token_or_regex: "bob_record_surface_leads",
    }),
    producer_id: "surface_discovery_ranked_leads",
    decision_boundary: "handoff_receipt",
    rationale:
      "orchestrator auto-records ranked_leads on receipt of deep-surface-discovery handoff",
  }),
  Object.freeze({
    consumer_id: "chain_builder_prompt_body_read_before_propose",
    source_location: Object.freeze({
      file: ".claude/agents/chain-builder.md",
      token_or_regex: /bob_read_chain_attempts[\s\S]*bob_propose_hypothesis/,
    }),
    producer_id: "chain_attempts_ledger",
    decision_boundary: "chain_attempt_proposal",
    rationale:
      "chain-builder reads attempts ledger before proposing new hypothesis",
  }),
  Object.freeze({
    consumer_id: "compose_report_provenance_gate",
    source_location: Object.freeze({
      file: "mcp/lib/tools/compose-report.js",
      token_or_regex: "verification_round",
    }),
    producer_id: "verification_round_ledger",
    decision_boundary: "validator_invocation",
    rationale:
      "renderer rejects bob_verified without verification_round backing ref",
  }),
  Object.freeze({
    consumer_id: "write_chain_rollup_evidence_refs_validator",
    source_location: Object.freeze({
      file: "mcp/lib/tools/write-chain-rollup.js",
      token_or_regex: "EVIDENCE_REF_HANDLE_PREFIXES",
    }),
    producer_id: "mcp_owned_body_binding_handles",
    decision_boundary: "validator_invocation",
    rationale:
      "validator rejects raw evidence/ paths >262144 bytes without binding handle",
  }),
  Object.freeze({
    consumer_id: "evaluator_spawn_friction_log_on_internal_error",
    source_location: Object.freeze({
      file: ".claude/agents/evaluator-spawn.md",
      token_or_regex: "bob_log_capability_friction",
    }),
    producer_id: "capability_friction_ledger",
    decision_boundary: "validator_invocation",
    rationale:
      "evaluator-spawn logs friction on unexpected MCP INTERNAL_ERROR",
  }),
  Object.freeze({
    consumer_id: "assignment_brief_reachability_triage_renderer",
    source_location: Object.freeze({
      file: "mcp/lib/assignment-brief.js",
      token_or_regex: /attack_vector[\s\S]*severity_ceiling[\s\S]*network_reachable/,
    }),
    producer_id: "repo_inventory_reachability_stamp",
    decision_boundary: "brief_composition",
    rationale:
      "evaluator brief whitelists reachability triage fields so AV:N surfaces are pursued",
  }),
  Object.freeze({
    consumer_id: "grade_verdict_reachability_ceiling_reconciler",
    source_location: Object.freeze({
      file: "mcp/lib/grade-verdict-store.js",
      token_or_regex: "reachabilityDispositionForFinding",
    }),
    producer_id: "repo_inventory_reachability_stamp",
    decision_boundary: "grade_time_reconciliation",
    rationale:
      "grade verdicts consume I9 surface ceilings to cap local AV:L severity and certify AV:N findings",
  }),
  Object.freeze({
    consumer_id: "assignment_brief_oss_technique_pack_renderer",
    source_location: Object.freeze({
      file: "mcp/lib/assignment-brief.js",
      token_or_regex: "buildOssTechniquePacksSlice",
    }),
    producer_id: "oss_technique_pack_registry",
    decision_boundary: "brief_composition",
    rationale:
      "OSS brief composition consumes OSS_TECHNIQUE_PACKS and partitions them by task-lens affinity",
  }),
  Object.freeze({
    consumer_id: "assignment_brief_oss_rootcause_family_renderer",
    source_location: Object.freeze({
      file: "mcp/lib/assignment-brief.js",
      token_or_regex: "suggestFamiliesForSurface",
    }),
    producer_id: "oss_rootcause_family_corpus",
    decision_boundary: "brief_composition",
    rationale:
      "OSS brief composition consumes OSS_ROOTCAUSE_FAMILIES as bounded root_cause_families inside technique_packs",
  }),
  Object.freeze({
    consumer_id: "c11_static_analysis_reachability_ranker",
    source_location: Object.freeze({
      file: "mcp/lib/assignment-brief.js",
      token_or_regex: /attack_vector[\s\S]*severity_ceiling[\s\S]*network_reachable[\s\S]*static_analysis_leads/,
    }),
    producer_id: "repo_inventory_reachability_stamp",
    decision_boundary: "brief_composition",
    rationale:
      "C11 static_analysis_leads consumes I9 severity_ceiling/attack_vector/network_reachable to rank static source-audit hypotheses",
  }),
  Object.freeze({
    consumer_id: "c11_static_analysis_brief_slice",
    source_location: Object.freeze({
      file: "mcp/lib/assignment-brief.js",
      token_or_regex: /readSurfaceLeadsDocument[\s\S]*static_analysis_leads/,
    }),
    producer_id: "static_analysis_index",
    decision_boundary: "brief_composition",
    rationale:
      "C11 brief slice consumes I10 static-analysis-index rows as unverified lead seeds",
  }),
  Object.freeze({
    consumer_id: "belief_signal_read_query_tools",
    source_location: Object.freeze({
      file: "mcp/lib/tools/query-belief-signals.js",
      token_or_regex: "queryBeliefSignals",
    }),
    producer_id: "belief_scratch_signals",
    decision_boundary: "validator_invocation",
    rationale:
      "belief query tooling consumes only advisory scratch signals and does not become claim or verification authority",
  }),
  Object.freeze({
    consumer_id: "surface_graph_mechanism_query_mode",
    source_location: Object.freeze({
      file: "mcp/lib/tools/query-surface-graph.js",
      token_or_regex: "queryMechanismView",
    }),
    producer_id: "mechanism_surface_graph_projection",
    decision_boundary: "validator_invocation",
    rationale:
      "mechanism query mode consumes principal/credential/policy_gate/effect/intervention edges from surface-graph.jsonl without creating a second graph store",
  }),
  Object.freeze({
    consumer_id: "mechanism_template_loader_object_authorization",
    source_location: Object.freeze({
      file: "mcp/lib/invariant-template-corpus.js",
      token_or_regex: "getMechanismTemplate",
    }),
    producer_id: "object_authorization_mechanism_template",
    decision_boundary: "validator_invocation",
    rationale:
      "bounded mechanism-template loader consumes object_authorization as a catalog-backed template without creating a second registry",
  }),
  Object.freeze({
    consumer_id: "belief_frontier_fact_projection_reader",
    source_location: Object.freeze({
      file: "mcp/lib/belief/frontier-facts.js",
      token_or_regex: "frontierEventToTypedFact",
    }),
    producer_id: "frontier_observation_typed_fact_projection",
    decision_boundary: "validator_invocation",
    rationale:
      "belief fact intake consumes normalized observation.recorded events from frontier-events.jsonl without creating a second typed-fact ledger",
  }),
  Object.freeze({
    consumer_id: "belief_window_query_tool",
    source_location: Object.freeze({
      file: "mcp/lib/tools/query-belief-window.js",
      token_or_regex: "buildBeliefWindow",
    }),
    producer_id: "belief_window_projection",
    decision_boundary: "validator_invocation",
    rationale:
      "read-only belief-window query consumes the bounded window projection without claim, verification, grade, or report authority",
  }),
  Object.freeze({
    consumer_id: "belief_sample_scratch_reader",
    source_location: Object.freeze({
      file: "mcp/lib/belief/factor-graph.js",
      token_or_regex: "readBeliefSamples",
    }),
    producer_id: "belief_factor_graph_samples",
    decision_boundary: "validator_invocation",
    rationale:
      "belief sample readers consume only advisory scratch marginals and rankings, never scheduler or claim authority",
  }),
  Object.freeze({
    consumer_id: "belief_residual_diagnostic_reader",
    source_location: Object.freeze({
      file: "mcp/lib/belief/residual.js",
      token_or_regex: "buildResidualDiagnostic",
    }),
    producer_id: "belief_residual_anomaly_diagnostic",
    decision_boundary: "validator_invocation",
    rationale:
      "residual anomaly diagnostics are consumed as non-gating human/scheduler hints and cannot become evidence, claims, or template authority",
  }),
]);

const CONSUMER_IDS = Object.freeze(
  STIGMERGIC_CONSUMERS.map((c) => c.consumer_id),
);

function getConsumer(consumerId) {
  for (const c of STIGMERGIC_CONSUMERS) {
    if (c.consumer_id === consumerId) return c;
  }
  return null;
}

function isKnownConsumerId(consumerId) {
  for (const c of STIGMERGIC_CONSUMERS) {
    if (c.consumer_id === consumerId) return true;
  }
  return false;
}

function getConsumersForProducer(producerId) {
  const matches = [];
  for (const c of STIGMERGIC_CONSUMERS) {
    if (c.producer_id === producerId) matches.push(c);
  }
  return matches;
}

module.exports = {
  DECISION_BOUNDARY_VALUES,
  STIGMERGIC_CONSUMERS,
  CONSUMER_IDS,
  getConsumer,
  isKnownConsumerId,
  getConsumersForProducer,
};
