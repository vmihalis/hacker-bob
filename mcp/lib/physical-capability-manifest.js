"use strict";

// Dependency-light, immutable Plane-PH consumer manifest. Capability-pack
// registration, physical consumers, and composition adapters all derive their
// metadata from this one data-only source; it owns no runtime authority or
// callback surface.

const {
  TERMINAL_STATE_VALUES,
} = require("./physical-campaign-closure.js");

const PHYSICAL_CAPABILITY_CONSUMER_VERSION = 1;
const PHYSICAL_FINDING_KIND = "physical_verified_transition";
const PHYSICAL_VERDICT_KIND = "physical_verified_verdict";
const PHYSICAL_COMPLETION_GATE = "physical_campaign_terminal_closure";
const PHYSICAL_LIFECYCLE_PRECONDITION = "no_active_effects";
const PHYSICAL_EFFECT_AUTHORITY = "broker_admission_required";
const PHYSICAL_VERIFIED_TERMINAL_WITNESS_DOMAIN =
  "hacker-bob/physical-verified-terminal-witness/v1";
const PHYSICAL_CAPABILITY_PACK_DISPATCH_BLOCK_REASON =
  "physical consumers are staged, but production physical verdict resolution and no-active-effects wave-handoff integration are not installed";

function deepFreeze(value) {
  if (value == null || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

const PHYSICAL_CAPABILITY_CONSUMERS = deepFreeze({
  version: PHYSICAL_CAPABILITY_CONSUMER_VERSION,
  assignment: {
    adapter: "physical_assignment_context_v1",
    lifecycle_precondition: PHYSICAL_LIFECYCLE_PRECONDITION,
    effect_authority: PHYSICAL_EFFECT_AUTHORITY,
  },
  coverage: {
    adapter: "physical_campaign_terminal_cells_v1",
    cell_dimensions: ["asset_locator", "technique_id", "context_ref", "control_ref"],
    terminal_states: TERMINAL_STATE_VALUES,
    verified_success_closes_only_its_cell: true,
    durable_no_active_effects_backend_available: false,
  },
  finding: {
    adapter: "physical_verified_transition_finding_v1",
    verifier_tool: "bob_verify_physical_candidate_claim",
    kind: PHYSICAL_FINDING_KIND,
    asset_field: "asset_locator",
    verdict_field: "verified_verdict_ref",
    forbidden_web_fields: ["base_url", "endpoint", "proof_of_concept"],
  },
  verdict: {
    adapter: "physical_verified_verdict_v1",
    kind: PHYSICAL_VERDICT_KIND,
    tool: "bob_verify_physical_verdict",
    production_backend_available: false,
    invokes_hardware: false,
  },
  grade: {
    adapter: "physical_verified_transition_grade_binding_v1",
    requires_verified_verdict_ref: true,
    requires_terminal_coverage: true,
    production_backend_available: false,
  },
  evidence: {
    adapter: "physical_report_safe_evidence_pack_v1",
    raw_evidence_allowed: false,
    requires_live_grade_projection: true,
    production_backend_available: false,
  },
  proof: {
    adapter: "physical_campaign_closure_proof_bundle_v1",
    bundle_kind: "capability_pack",
    raw_evidence_allowed: false,
    requires_live_grade_projection: true,
    production_backend_available: false,
  },
  report: {
    renderer: "physical_report_safe_v1",
    raw_evidence_allowed: false,
    production_backend_available: false,
  },
  composition: {
    adapter: "physical_surface_transition_v1",
    requires_verified_projection: true,
    live_capability_requires_current_revalidation: true,
  },
});

module.exports = Object.freeze({
  PHYSICAL_CAPABILITY_CONSUMERS,
  PHYSICAL_CAPABILITY_CONSUMER_VERSION,
  PHYSICAL_CAPABILITY_PACK_DISPATCH_BLOCK_REASON,
  PHYSICAL_COMPLETION_GATE,
  PHYSICAL_EFFECT_AUTHORITY,
  PHYSICAL_FINDING_KIND,
  PHYSICAL_LIFECYCLE_PRECONDITION,
  PHYSICAL_VERDICT_KIND,
  PHYSICAL_VERIFIED_TERMINAL_WITNESS_DOMAIN,
});
