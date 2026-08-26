#!/usr/bin/env node
"use strict";

// Plane-PH PH-P7 manual inventory plan. Import and default invocation are
// deliberately inert. This module imports only transport-free contracts and
// exposes no execute, enumerate, open, read, write, or native-loader function.
// A future HIL executor must consume the reviewed plan digest from a separate,
// privileged entrypoint and satisfy every gate below before contacting USB.

const {
  CHAMELEON_BOOTSTRAP_ASSURANCE_CLAIMS,
  CHAMELEON_BOOTSTRAP_COMMAND_ALLOWLIST,
  CHAMELEON_BOOTSTRAP_MANIFEST,
  CHAMELEON_BOOTSTRAP_OPERATION_REGISTRY,
} = require("../../packages/bob-instrument-chameleon/lib/bootstrap-operations.js");
const {
  CHAMELEON_BOOTSTRAP_SUBSET,
  CHAMELEON_SEMANTIC_MANIFEST,
  CHAMELEON_V220_CODEC_PROFILE,
  CHAMELEON_V220_SOURCE_PROFILE,
} = require("../../packages/bob-instrument-chameleon/lib/operations.js");
const {
  hashCanonicalJson,
} = require("../../mcp/core/verification/verification-contracts.js");

const INVENTORY_PLAN_VERSION = 1;
const INVENTORY_PLAN_ID = "chameleon_ultra_ph_p7_rf_off_inventory_v1";
const EXACT_BOOTSTRAP_OPERATIONS = Object.freeze([
  "instrument.capabilities",
  "instrument.health",
  "instrument.inventory",
]);
const EXPECTED_BOOTSTRAP_COMMAND_IDS = Object.freeze([1000, 1017, 1025, 1033, 1035]);
const EXPECTED_REVIEWED_DIGESTS = Object.freeze({
  bootstrap_manifest_digest: "0ad9202fb20734fdec58d16ee5eea10cb0549f35b0fedca57d8285aafa967623",
  semantic_manifest_digest: "3a270fa758a365e9cb4d5fa1db9c5c2f051e4b2df9aa6dd75856826050f09c29",
  source_profile_digest: "06068561354baa5d45118cfa2b11dc28f993d17eb61572030fd1edcb103c3bd9",
  codec_profile_digest: "0a0c56bd47837b54600d96993a74840c47692467115149256007465d3e8b2a38",
});
const FOUR_ASSURANCE_AXES = Object.freeze([
  "identity_enrollment",
  "firmware_provenance",
  "command_surface_conformance",
  "transport_trust",
]);
const FUTURE_EXECUTION_BLOCKERS = Object.freeze([
  "real_iousbhost_activation_not_enabled",
  "durable_native_bootstrap_multi_command_orchestration_missing",
  "native_bootstrap_source_owned_multi_response_aggregation_missing",
  "bootstrap_sequence_guard_to_native_launch_binding_missing",
  "bootstrap_authority_to_native_dispatch_binding_not_implemented",
  "signed_immutable_node20_arm64_prebuild_missing",
  "dedicated_native_worker_principal_and_device_acl_unqualified",
  "qualified_usb_cdc_endpoint_and_continuous_dtr_rts_witness_missing",
  "independent_production_vault_principal_and_signed_ingest_receipt_missing",
  "authenticated_native_terminal_receipt_and_durable_outbox_missing",
  "independent_rf_off_before_after_and_continuity_hil_missing",
  "device_mode_before_after_observation_not_allowlisted",
  "durable_broker_authenticated_inventory_receipt_store_missing",
  "production_physical_inventory_checkpoint_source_enrollment_missing",
  "opaque_preparation_input_allocation_not_implemented",
]);

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function sameArray(left, right) {
  return left.length === right.length
    && left.every((entry, index) => entry === right[index]);
}

function assertReviewedBootstrapContracts() {
  const manifestOperationIds = CHAMELEON_BOOTSTRAP_MANIFEST.operations
    .map((entry) => entry.operation_id)
    .sort((left, right) => left.localeCompare(right));
  const manifestCommandIds = [...new Set(CHAMELEON_BOOTSTRAP_MANIFEST.operations
    .flatMap((entry) => entry.command_ids))].sort((left, right) => left - right);
  const actualDigests = {
    bootstrap_manifest_digest: CHAMELEON_BOOTSTRAP_MANIFEST.manifest_digest,
    semantic_manifest_digest: CHAMELEON_SEMANTIC_MANIFEST.manifest_digest,
    source_profile_digest: CHAMELEON_V220_SOURCE_PROFILE.source_profile_digest,
    codec_profile_digest: CHAMELEON_V220_CODEC_PROFILE.codec_profile_digest,
  };
  if (!sameArray(CHAMELEON_BOOTSTRAP_OPERATION_REGISTRY.ids(), EXACT_BOOTSTRAP_OPERATIONS)
      || !sameArray(CHAMELEON_BOOTSTRAP_SUBSET.operation_ids, EXACT_BOOTSTRAP_OPERATIONS)
      || !sameArray(manifestOperationIds, EXACT_BOOTSTRAP_OPERATIONS)
      || !sameArray(CHAMELEON_BOOTSTRAP_COMMAND_ALLOWLIST, EXPECTED_BOOTSTRAP_COMMAND_IDS)
      || !sameArray(CHAMELEON_BOOTSTRAP_SUBSET.command_ids, EXPECTED_BOOTSTRAP_COMMAND_IDS)
      || !sameArray(manifestCommandIds, EXPECTED_BOOTSTRAP_COMMAND_IDS)
      || Object.entries(EXPECTED_REVIEWED_DIGESTS).some(
        ([field, expected]) => actualDigests[field] !== expected,
      )) {
    throw new Error("PH-P7 reviewed bootstrap or semantic contract drifted");
  }
}

function assertPlainDataTree(value, label = "chameleon_inventory_plan") {
  if (value === null || ["string", "number", "boolean"].includes(typeof value)) return;
  if (!value || typeof value !== "object") throw new Error(`${label} must be plain data`);
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== Array.prototype && prototype !== null) {
    throw new Error(`${label} must be plain data`);
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Reflect.ownKeys(descriptors);
  if (keys.some((key) => typeof key !== "string")) {
    throw new Error(`${label} cannot contain symbol fields`);
  }
  if (Array.isArray(value)) {
    const extra = keys.filter((key) => key !== "length" && !/^\d+$/u.test(key));
    if (extra.length > 0 || descriptors.length.value !== value.length) {
      throw new Error(`${label} must be a dense unadorned array`);
    }
    for (let index = 0; index < value.length; index += 1) {
      const descriptor = descriptors[String(index)];
      if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) {
        throw new Error(`${label} must be a dense enumerable data array`);
      }
      assertPlainDataTree(descriptor.value, `${label}[${index}]`);
    }
    return;
  }
  for (const key of keys) {
    const descriptor = descriptors[key];
    if (!("value" in descriptor) || !descriptor.enumerable) {
      throw new Error(`${label}.${key} must be an enumerable data field`);
    }
    assertPlainDataTree(descriptor.value, `${label}.${key}`);
  }
}

function exactOperationPlan() {
  return CHAMELEON_BOOTSTRAP_MANIFEST.operations
    .map((operation) => ({
      operation_id: operation.operation_id,
      operation_digest: operation.operation_digest,
      command_ids: [...operation.command_ids],
      command_set_digest: operation.command_set_digest,
      parameters: {},
      effect: { ...operation.effect },
      invariants: { ...operation.invariants },
    }))
    .sort((left, right) => left.operation_id.localeCompare(right.operation_id));
}

function assuranceAxisPlan() {
  return Object.fromEntries(FOUR_ASSURANCE_AXES.map((axis) => [axis, {
    classification: CHAMELEON_BOOTSTRAP_ASSURANCE_CLAIMS[axis],
    evidence_digest_field: `assurance_claims.${axis}.evidence_digest`,
    independently_bound: true,
  }]));
}

function buildPlanBasis() {
  const operationPlan = exactOperationPlan();
  return {
    version: INVENTORY_PLAN_VERSION,
    plan_id: INVENTORY_PLAN_ID,
    node_id: "PH-P7",
    title: "Chameleon Ultra RF-off read-only inventory and provenance observation",
    status: "blocked_pending_hil",
    execution_policy: {
      import_is_inert: true,
      default_invocation_is_inert: true,
      cli_allowlist: ["--print-plan"],
      print_plan_is_redacted_and_deterministic: true,
      execute_mode_exposed: false,
      hardware_access_authorized: false,
      device_enumeration_authorized: false,
      device_open_authorized: false,
      rf_emission_authorized: false,
      live_hil_evidence_present: false,
      production_ready: false,
      unknown_cli_commands: "disabled",
    },
    contract_path: {
      bootstrap_contract_ref:
        "packages/bob-instrument-chameleon/lib/bootstrap-operations.js",
      bootstrap_payload_contract_ref:
        "packages/bob-instrument-chameleon/lib/bootstrap-response-payloads.js",
      inventory_checkpoint_contract_ref: "mcp/domains/physical/physical-inventory-checkpoint.js",
      usb_cdc_contract_ref:
        "packages/bob-instrument-chameleon-worker-runtime/lib/usb-cdc-custody.js",
      direct_cdc_contract_ref:
        "packages/bob-instrument-chameleon-native-darwin/lib/direct-cdc-custody.js",
      native_dispatch_contract_ref:
        "packages/bob-instrument-chameleon-native-darwin/lib/native-dispatch-custodian.js",
      native_bootstrap_sequence_ref:
        "packages/bob-instrument-chameleon-native-darwin/lib/native-bootstrap-sequence.js",
      generated_native_bootstrap_semantics_ref:
        "packages/bob-instrument-chameleon-native-darwin/lib/generated-bootstrap-semantics.js",
      plan_imports_native_or_transport_modules: false,
    },
    future_execution_gate: {
      gate_state: "unavailable",
      separately_privileged_executor_required: true,
      reviewed_plan_digest_required: true,
      required_inputs: [
        "explicit_operator_hardware_gate",
        "signed_current_single_use_bootstrap_authority",
        "exact_operator_enrolled_device_binding",
        "qualified_exclusive_usb_cdc_endpoint_binding",
        "dedicated_native_worker_principal_binding",
        "independent_vault_principal_and_pre_reserved_sink_binding",
        "signed_monotonic_wall_clock",
        "exact_three_operation_ph_p8_plan",
      ],
      operator_gate_must_be_explicit: true,
      bootstrap_authority_must_be_signed_current_and_single_use: true,
      exact_enrollment_and_hardware_identity_required: true,
      usb_cdc_qualification: {
        exact_cdc_control_and_data_interfaces: true,
        exact_bulk_in_and_bulk_out_endpoint_descriptors: true,
        exclusive_custody: true,
        device_path_or_serial_selector_forbidden: true,
        dtr_rts_off_before_bulk_required: true,
        continuous_line_state_witness_required: true,
      },
      principal_separation: {
        orchestrator_may_hold_native_handle: false,
        native_worker_principal_required: true,
        independent_vault_principal_required: true,
        raw_response_must_flow_directly_to_pre_reserved_vault_sink: true,
      },
      trusted_time_mode: "signed_monotonic_wall_mapping",
      allowed_operation_ids: operationPlan.map((entry) => entry.operation_id),
      allowed_command_ids: [...CHAMELEON_BOOTSTRAP_COMMAND_ALLOWLIST],
      arbitrary_command_id_or_payload_input: false,
      blockers: [...FUTURE_EXECUTION_BLOCKERS],
    },
    operation_plan: operationPlan,
    output_contract: {
      record_kind: "ph_p7_chameleon_inventory_observation_v1",
      current_record_state: "not_minted_plan_only",
      authority_boundary: {
        broker_authenticated_observation_required: true,
        broker_authenticates: [
          "exact bootstrap authority and operation lineage",
          "exact enrolled instrument and connection generation binding",
          "observation timestamps and opaque receipt bindings",
          "provider native transport and manifest digest bindings",
        ],
        broker_does_not_authenticate: [
          "truth of firmware self_reported model application_version or git_revision",
          "truth or completeness of firmware self_reported command IDs",
          "hardware or firmware cryptographic attestation",
          "RF-off or unchanged-mode HIL unless independently witnessed",
        ],
        firmware_truth_classification: "untrusted_bounded_self_report",
        observation_authentication_is_not_firmware_attestation: true,
      },
      self_reported_firmware: {
        required_exact_fields: [
          "model",
          "application_version",
          "git_revision",
          "reported_command_ids",
        ],
        application_version_and_git_revision_preserved_exactly: true,
        inference_from_release_label_forbidden: true,
        cryptographic_attestation_inferred: false,
      },
      provider_identity: {
        required_exact_fields: ["provider_id", "provider_version"],
        provider_version_source: "measured_provider_release_and_binary_binding",
        provider_version_inferred_from_firmware: false,
      },
      capability_intersection: {
        reported_command_ids_source: "untrusted_firmware_self_report",
        reviewed_source_rule:
          CHAMELEON_V220_SOURCE_PROFILE.expected_ultra_capabilities_rule,
        reported_known_command_ids_formula:
          "reported_command_ids intersection source_pinned_expected_ultra_command_ids",
        bootstrap_callable_command_ids_formula:
          "reported_command_ids intersection ph_p8_bootstrap_command_allowlist",
        availability_input_only: true,
        inventory_alone_enables_operation: false,
        unknown_reported_command_ids: "disabled",
        unreported_reviewed_command_ids: "disabled",
        bootstrap_allowlist: [...CHAMELEON_BOOTSTRAP_COMMAND_ALLOWLIST],
      },
      invariant_bindings: {
        rf_state_before: "off",
        rf_state_after: "off",
        rf_continuity_required: true,
        independent_signed_rf_witness_required: true,
        mode_state_before_digest_required: true,
        mode_state_after_digest_required: true,
        mode_unchanged_required: true,
        workspace_state_before_digest_required: true,
        workspace_state_after_digest_required: true,
        workspace_unchanged_required: true,
        workspace_write_count_required: 0,
        current_hil_verdict: "not_performed",
      },
      four_axis_assurance: {
        profile_id: CHAMELEON_BOOTSTRAP_ASSURANCE_CLAIMS.profile_id,
        axes: assuranceAxisPlan(),
        claims_digest_field: "assurance_claims.claims_digest",
        bootstrap_claims_digest:
          CHAMELEON_BOOTSTRAP_ASSURANCE_CLAIMS.assurance_claims_digest,
        stronger_profile_inferred: false,
      },
      digest_bindings: {
        reviewed_manifest_digests: {
          bootstrap_manifest_digest: CHAMELEON_BOOTSTRAP_MANIFEST.manifest_digest,
          semantic_manifest_digest: CHAMELEON_SEMANTIC_MANIFEST.manifest_digest,
          source_profile_digest: CHAMELEON_V220_SOURCE_PROFILE.source_profile_digest,
          codec_profile_digest: CHAMELEON_V220_CODEC_PROFILE.codec_profile_digest,
        },
        runtime_required_digest_fields: [
          "provider_descriptor_digest",
          "provider_binary_digest",
          "native_loaded_image_identity_digest",
          "native_worker_bundle_digest",
          "transport_digest",
          "usb_endpoint_descriptor_set_digest",
          "vault_principal_identity_digest",
          "bootstrap_receipt_set_digest",
          "inventory_observation_digest",
        ],
        plan_contains_runtime_digest_values: false,
        all_runtime_bindings_must_match_signed_current_authority: true,
      },
      opaque_reference_bindings: {
        required_ref_fields: [
          "bootstrap_receipt_refs",
          "inventory_observation_ref",
          "inventory_checkpoint_ref",
          "preparation_input_ref",
        ],
        bootstrap_receipt_cardinality: EXACT_BOOTSTRAP_OPERATIONS.length,
        reference_representation: "bounded_opaque_ref_only",
        bootstrap_receipts_must_be_signed_current_and_broker_authenticated: true,
        bootstrap_receipts_must_be_redacted: true,
        preparation_input_must_bind_inventory_observation: true,
        preparation_grant_kind_must_be_distinct: true,
        preparation_input_grants_execution_authority: false,
        raw_receipt_or_preparation_content_projected: false,
        plan_contains_runtime_ref_values: false,
      },
      result_flags: {
        broker_authenticated_observation: "required_from_future_executor",
        firmware_truth_attested: false,
        hil_attested: false,
        production_ready: false,
        execution_authority: false,
        lifecycle_authority: false,
      },
    },
  };
}

assertReviewedBootstrapContracts();
const PLAN_BASIS = deepFreeze(buildPlanBasis());
const INVENTORY_PLAN = deepFreeze({
  ...PLAN_BASIS,
  plan_digest: hashCanonicalJson(PLAN_BASIS),
});

function validateInventoryPlan(input) {
  assertPlainDataTree(input);
  const inputBasis = { ...input };
  delete inputBasis.plan_digest;
  if (input.plan_digest !== hashCanonicalJson(inputBasis)
      || input.plan_digest !== INVENTORY_PLAN.plan_digest
      || JSON.stringify(input) !== JSON.stringify(INVENTORY_PLAN)) {
    throw new Error("Chameleon PH-P7 inventory plan drifted from the reviewed contract");
  }
  return INVENTORY_PLAN;
}

function buildInventoryPlan() {
  return INVENTORY_PLAN;
}

function runCli(argv = process.argv.slice(2), io = {}) {
  if (!Array.isArray(argv) || argv.some((entry) => typeof entry !== "string")) {
    throw new Error("Chameleon PH-P7 CLI arguments must be strings");
  }
  const stdout = typeof io.stdout === "function"
    ? io.stdout
    : (text) => process.stdout.write(text);
  const stderr = typeof io.stderr === "function"
    ? io.stderr
    : (text) => process.stderr.write(text);
  if (argv.length === 0) return 0;
  if (argv.length === 1 && argv[0] === "--print-plan") {
    stdout(`${JSON.stringify(INVENTORY_PLAN, null, 2)}\n`);
    return 0;
  }
  if (argv.includes("--execute")) {
    stderr("PH-P7 execute mode is unavailable; hardware remains disabled\n");
    return 2;
  }
  stderr("PH-P7 command is not allowlisted; hardware remains disabled\n");
  return 2;
}

module.exports = Object.freeze({
  EXACT_BOOTSTRAP_OPERATIONS,
  FOUR_ASSURANCE_AXES,
  FUTURE_EXECUTION_BLOCKERS,
  INVENTORY_PLAN_ID,
  INVENTORY_PLAN_VERSION,
  buildInventoryPlan,
  runCli,
  validateInventoryPlan,
});

if (require.main === module) process.exitCode = runCli();
