#!/usr/bin/env node
"use strict";

// PH-P9 non-waivable HIL plan. Import and default CLI execution are inert. It
// contains no transport, device discovery, command, button, callback, or live
// execution path; a future operator-owned runner must return separately signed
// evidence bound to this exact plan digest.

const {
  chameleonManualActionRuntimeReadiness,
  describeChameleonManualActions,
} = require("../../packages/bob-instrument-chameleon/lib/manual-actions.js");
const {
  hashCanonicalJson,
} = require("../../mcp/lib/verification-contracts.js");

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

const reviewed = describeChameleonManualActions();
const readiness = chameleonManualActionRuntimeReadiness();

const SCENARIO_BY_CAPABILITY = Object.freeze({
  "CU-ADMIN-FIELD-GENERATOR-INVOKE": Object.freeze({
    scenario_id: "ph-p9.shielded-field-generator",
    owned_fixture_ref: "hil-fixture:owned-shielded-rf-load",
    expected_workspace_delta: "none",
    required_effect_profile_refs: ["EP-ENVIRONMENT-TRANSMIT-RF-MANUAL"],
  }),
  "CU-ADMIN-BUTTON-CLONE-INVOKE": Object.freeze({
    scenario_id: "ph-p9.owned-clone-source-and-workspace",
    owned_fixture_ref: "hil-fixture:owned-clone-source-and-workspace",
    expected_workspace_delta: "staged_then_restored_or_quarantined",
    required_effect_profile_refs: [
      "EP-TARGET-TRANSMIT-RF-MANUAL",
      "EP-INSTRUMENT-CONFIGURE-MANUAL",
    ],
  }),
});

const scenarios = reviewed.actions.map((action) => {
  const definition = SCENARIO_BY_CAPABILITY[action.capability_id];
  if (!definition) throw new Error(`unplanned reviewed manual capability ${action.capability_id}`);
  if (JSON.stringify(action.effect_profile_refs)
      !== JSON.stringify(definition.required_effect_profile_refs)) {
    throw new Error(`manual HIL effect profile drift for ${action.capability_id}`);
  }
  return deepFreeze({
    version: 1,
    ...definition,
    capability_id: action.capability_id,
    procedure_id: action.procedure_id,
    procedure_binding_digest: action.procedure_binding_digest,
    parameter_digest: action.parameter_digest,
    expected_outcome_digest: action.expected_outcome_digest,
    containment: "shielded_owned_fixture",
    attempt_limit: 1,
    required_participants: [
      "enrolled_operator",
      "independently_enrolled_witness",
      "external_rf_sensor",
    ],
    required_evidence: [
      "active_grant_current_at_begin",
      "atomic_reservation_receipt",
      "fresh_one_use_operator_challenge",
      "operator_acknowledgement_signature",
      "independent_witness_acknowledgement_signature",
      "operator_completion_signature",
      "independent_witness_completion_signature",
      "observed_pre_mode_and_workspace",
      "observed_post_mode_and_workspace",
      "external_rf_on_timestamp",
      "external_rf_off_before_deadline",
      "cleanup_restoration_or_quarantine_receipt",
      "ordinary_ph_s6_execution_observation_cleanup_rows",
    ],
    forbidden_evidence_substitutions: [
      "operator_assertion_as_instrument_receipt",
      "instrument_acknowledgement_as_external_outcome",
      "same_principal_or_same_trust_domain_witness",
      "late_replayed_or_cross_attempt_receipt",
      "captured_credential_bytes_in_model_context",
    ],
    evidence_state: "pending_real_hil",
  });
});

const basis = {
  version: 1,
  plan_id: "chameleon_manual_actions_ph_p9_v1",
  node_id: "PH-P9",
  manual_action_registry_digest: reviewed.manual_action_registry_digest,
  operation_contract_digest: reviewed.operation_contract_digest,
  execution_policy: {
    import_is_inert: true,
    cli_is_plan_only: true,
    hardware_access_authorized: false,
    live_transport_available: false,
    arbitrary_button_surface_available: false,
    agent_facing_manual_surface_available: false,
    production_nonwaivable_hil: true,
    production_ready: false,
    hil_ready: false,
  },
  blockers: readiness.blockers,
  scenarios,
};

const PLAN = deepFreeze({
  ...basis,
  plan_digest: hashCanonicalJson({
    domain: "hacker-bob/chameleon-manual-action-hil-plan/v1",
    ...basis,
  }),
});

function buildPlan() {
  return PLAN;
}

function runCli(argv = process.argv.slice(2), output = process.stdout, error = process.stderr) {
  if (argv.length === 1 && argv[0] === "--print-plan") {
    output.write(`${JSON.stringify(PLAN, null, 2)}\n`);
    return 0;
  }
  error.write(
    "This PH-P9 command is inert. Use --print-plan to emit the pending HIL plan; no execution mode exists.\n",
  );
  return argv.length === 0 ? 0 : 2;
}

module.exports = Object.freeze({ buildPlan, runCli });

if (require.main === module) process.exitCode = runCli();
