"use strict";

const assert = require("node:assert/strict");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");

const inventoryHarness = require("./manual/chameleon-inventory.js");
const {
  EXACT_BOOTSTRAP_OPERATIONS,
  FOUR_ASSURANCE_AXES,
  FUTURE_EXECUTION_BLOCKERS,
  buildInventoryPlan,
  validateInventoryPlan,
} = inventoryHarness;
const {
  CHAMELEON_BOOTSTRAP_ASSURANCE_CLAIMS,
  CHAMELEON_BOOTSTRAP_COMMAND_ALLOWLIST,
  CHAMELEON_BOOTSTRAP_MANIFEST,
  CHAMELEON_BOOTSTRAP_OPERATION_REGISTRY,
} = require("../packages/bob-instrument-chameleon/lib/bootstrap-operations.js");
const {
  CHAMELEON_BOOTSTRAP_SUBSET,
  CHAMELEON_SEMANTIC_MANIFEST,
  CHAMELEON_V220_CODEC_PROFILE,
  CHAMELEON_V220_SOURCE_PROFILE,
} = require("../packages/bob-instrument-chameleon/lib/operations.js");
const {
  hashCanonicalJson,
} = require("../mcp/core/verification/verification-contracts.js");

const ROOT = path.join(__dirname, "..");
const HARNESS_PATH = path.join(__dirname, "manual", "chameleon-inventory.js");

function invoke(args = [], env = {}) {
  return spawnSync(process.execPath, [HARNESS_PATH, ...args], {
    cwd: ROOT,
    env: { ...process.env, ...env },
    encoding: "utf8",
  });
}

test("PH-P7 inventory plan is exact, RF-off, read-only, and non-authorizing", () => {
  const plan = buildInventoryPlan();
  assert.equal(validateInventoryPlan(plan), plan);
  assert.equal(plan.version, 1);
  assert.equal(plan.node_id, "PH-P7");
  assert.equal(plan.status, "blocked_pending_hil");
  assert.match(plan.plan_digest, /^[a-f0-9]{64}$/u);
  assert.ok(Object.isFrozen(plan));
  assert.ok(Object.isFrozen(plan.operation_plan));

  assert.deepEqual(EXACT_BOOTSTRAP_OPERATIONS, CHAMELEON_BOOTSTRAP_SUBSET.operation_ids);
  assert.deepEqual(
    EXACT_BOOTSTRAP_OPERATIONS,
    CHAMELEON_BOOTSTRAP_OPERATION_REGISTRY.ids(),
  );
  assert.deepEqual(
    plan.operation_plan.map((entry) => entry.operation_id),
    EXACT_BOOTSTRAP_OPERATIONS,
  );
  assert.deepEqual(
    [...new Set(plan.operation_plan.flatMap((entry) => entry.command_ids))]
      .sort((left, right) => left - right),
    CHAMELEON_BOOTSTRAP_COMMAND_ALLOWLIST,
  );
  assert.deepEqual(
    plan.future_execution_gate.allowed_operation_ids,
    EXACT_BOOTSTRAP_OPERATIONS,
  );
  assert.deepEqual(
    plan.future_execution_gate.allowed_command_ids,
    CHAMELEON_BOOTSTRAP_COMMAND_ALLOWLIST,
  );
  assert.ok(plan.operation_plan.every((entry) => (
    entry.effect.subject_kind === "instrument"
      && entry.effect.action === "observe"
      && entry.effect.channel === "usb"
      && entry.effect.persistence === "none"
      && entry.invariants.rf_state === "off"
      && entry.invariants.mode_change === "forbidden"
      && entry.invariants.slot_access === "forbidden"
      && entry.invariants.workspace_write === "forbidden"
  )));
  assert.equal(plan.future_execution_gate.arbitrary_command_id_or_payload_input, false);
  assert.equal(plan.execution_policy.execute_mode_exposed, false);
  assert.equal(plan.execution_policy.hardware_access_authorized, false);
  assert.equal(plan.execution_policy.device_enumeration_authorized, false);
  assert.equal(plan.execution_policy.device_open_authorized, false);
  assert.equal(plan.execution_policy.rf_emission_authorized, false);
  assert.equal(plan.execution_policy.live_hil_evidence_present, false);
  assert.equal(plan.execution_policy.production_ready, false);
  assert.deepEqual(plan.future_execution_gate.blockers, FUTURE_EXECUTION_BLOCKERS);
  assert.ok(FUTURE_EXECUTION_BLOCKERS.includes("real_iousbhost_activation_not_enabled"));
  assert.ok(FUTURE_EXECUTION_BLOCKERS.includes(
    "durable_native_bootstrap_multi_command_orchestration_missing",
  ));
  assert.ok(FUTURE_EXECUTION_BLOCKERS.includes(
    "native_bootstrap_source_owned_multi_response_aggregation_missing",
  ));
  assert.ok(FUTURE_EXECUTION_BLOCKERS.includes(
    "bootstrap_sequence_guard_to_native_launch_binding_missing",
  ));
  assert.ok(FUTURE_EXECUTION_BLOCKERS.includes(
    "independent_rf_off_before_after_and_continuity_hil_missing",
  ));
  assert.equal(plan.contract_path.plan_imports_native_or_transport_modules, false);
  assert.match(plan.contract_path.native_bootstrap_sequence_ref,
    /native-bootstrap-sequence\.js$/u);
  assert.match(plan.contract_path.generated_native_bootstrap_semantics_ref,
    /generated-bootstrap-semantics\.js$/u);
  assert.equal(
    Object.keys(inventoryHarness).some((name) => (
      /^(?:execute|enumerate|open|read|write|loadNative)/u.test(name)
    )),
    false,
  );

  const serialized = JSON.stringify(plan);
  assert.doesNotMatch(serialized, /\/dev\/(?:tty|cu\.)|\/Users\/|PRIVATE KEY/u);
  assert.doesNotMatch(serialized, /"(?:device_path|serial_number|worker_uid)"\s*:/u);
  assert.equal(serialized.includes("fixture_complete_non_authorizing"), false);
});

test("PH-P7 output contract separates authenticated observation from firmware truth", () => {
  const output = buildInventoryPlan().output_contract;
  assert.equal(output.current_record_state, "not_minted_plan_only");
  assert.equal(output.authority_boundary.broker_authenticated_observation_required, true);
  assert.equal(
    output.authority_boundary.observation_authentication_is_not_firmware_attestation,
    true,
  );
  assert.equal(
    output.authority_boundary.firmware_truth_classification,
    "untrusted_bounded_self_report",
  );
  assert.ok(output.authority_boundary.broker_does_not_authenticate.some(
    (entry) => entry.includes("firmware self_reported"),
  ));
  assert.deepEqual(output.self_reported_firmware.required_exact_fields, [
    "model",
    "application_version",
    "git_revision",
    "reported_command_ids",
  ]);
  assert.equal(
    output.self_reported_firmware.application_version_and_git_revision_preserved_exactly,
    true,
  );
  assert.equal(output.self_reported_firmware.cryptographic_attestation_inferred, false);
  assert.deepEqual(output.provider_identity, {
    required_exact_fields: ["provider_id", "provider_version"],
    provider_version_source: "measured_provider_release_and_binary_binding",
    provider_version_inferred_from_firmware: false,
  });

  assert.equal(output.capability_intersection.availability_input_only, true);
  assert.equal(output.capability_intersection.inventory_alone_enables_operation, false);
  assert.equal(output.capability_intersection.unknown_reported_command_ids, "disabled");
  assert.equal(output.capability_intersection.unreported_reviewed_command_ids, "disabled");
  assert.deepEqual(
    output.capability_intersection.bootstrap_allowlist,
    CHAMELEON_BOOTSTRAP_COMMAND_ALLOWLIST,
  );
  assert.equal(
    output.capability_intersection.reviewed_source_rule,
    CHAMELEON_V220_SOURCE_PROFILE.expected_ultra_capabilities_rule,
  );

  assert.deepEqual(output.invariant_bindings, {
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
  });

  assert.deepEqual(Object.keys(output.four_axis_assurance.axes), FOUR_ASSURANCE_AXES);
  for (const axis of FOUR_ASSURANCE_AXES) {
    assert.equal(
      output.four_axis_assurance.axes[axis].classification,
      CHAMELEON_BOOTSTRAP_ASSURANCE_CLAIMS[axis],
    );
    assert.equal(output.four_axis_assurance.axes[axis].independently_bound, true);
  }
  assert.equal(
    output.four_axis_assurance.bootstrap_claims_digest,
    CHAMELEON_BOOTSTRAP_ASSURANCE_CLAIMS.assurance_claims_digest,
  );
  assert.equal(output.four_axis_assurance.stronger_profile_inferred, false);

  assert.deepEqual(output.digest_bindings.reviewed_manifest_digests, {
    bootstrap_manifest_digest: CHAMELEON_BOOTSTRAP_MANIFEST.manifest_digest,
    semantic_manifest_digest: CHAMELEON_SEMANTIC_MANIFEST.manifest_digest,
    source_profile_digest: CHAMELEON_V220_SOURCE_PROFILE.source_profile_digest,
    codec_profile_digest: CHAMELEON_V220_CODEC_PROFILE.codec_profile_digest,
  });
  for (const field of [
    "provider_descriptor_digest",
    "provider_binary_digest",
    "native_loaded_image_identity_digest",
    "native_worker_bundle_digest",
    "transport_digest",
    "usb_endpoint_descriptor_set_digest",
    "vault_principal_identity_digest",
  ]) assert.ok(output.digest_bindings.runtime_required_digest_fields.includes(field), field);
  assert.equal(output.digest_bindings.plan_contains_runtime_digest_values, false);

  assert.deepEqual(output.opaque_reference_bindings.required_ref_fields, [
    "bootstrap_receipt_refs",
    "inventory_observation_ref",
    "inventory_checkpoint_ref",
    "preparation_input_ref",
  ]);
  assert.equal(output.opaque_reference_bindings.bootstrap_receipt_cardinality, 3);
  assert.equal(
    output.opaque_reference_bindings.reference_representation,
    "bounded_opaque_ref_only",
  );
  assert.equal(
    output.opaque_reference_bindings
      .bootstrap_receipts_must_be_signed_current_and_broker_authenticated,
    true,
  );
  assert.equal(output.opaque_reference_bindings.bootstrap_receipts_must_be_redacted, true);
  assert.equal(
    output.opaque_reference_bindings.preparation_input_must_bind_inventory_observation,
    true,
  );
  assert.equal(output.opaque_reference_bindings.preparation_grant_kind_must_be_distinct, true);
  assert.equal(
    output.opaque_reference_bindings.preparation_input_grants_execution_authority,
    false,
  );
  assert.equal(output.opaque_reference_bindings.plan_contains_runtime_ref_values, false);
  assert.deepEqual(output.result_flags, {
    broker_authenticated_observation: "required_from_future_executor",
    firmware_truth_attested: false,
    hil_attested: false,
    production_ready: false,
    execution_authority: false,
    lifecycle_authority: false,
  });
});

test("reviewed plan validation rejects recomputed drift and accessors without invocation", () => {
  const drifted = structuredClone(buildInventoryPlan());
  drifted.execution_policy.hardware_access_authorized = true;
  delete drifted.plan_digest;
  drifted.plan_digest = hashCanonicalJson(drifted);
  assert.throws(() => validateInventoryPlan(drifted), /drifted from the reviewed contract/u);

  const accessor = structuredClone(buildInventoryPlan());
  let invoked = false;
  Object.defineProperty(accessor, "title", {
    enumerable: true,
    get() {
      invoked = true;
      return "laundered";
    },
  });
  assert.throws(() => validateInventoryPlan(accessor), /enumerable data field/u);
  assert.equal(invoked, false);
});

test("ordinary test/install/update/release imports cannot enumerate or open hardware", () => {
  const childSource = String.raw`
    const fs = require("node:fs");
    const childProcess = require("node:child_process");
    const Module = require("node:module");
    const blocked = () => { throw new Error("hardware side effect attempted"); };
    for (const name of [
      "open", "openSync", "opendir", "opendirSync", "readdir", "readdirSync",
      "watch", "watchFile", "createReadStream", "createWriteStream"
    ]) {
      if (typeof fs[name] === "function") fs[name] = blocked;
    }
    for (const name of ["exec", "execFile", "fork", "spawn"]) {
      if (typeof childProcess[name] === "function") childProcess[name] = blocked;
    }
    process.dlopen = blocked;
    const originalLoad = Module._load;
    Module._load = function guardedLoad(request, parent, isMain) {
      if (/chameleon-native-darwin|usb-cdc-custody|serialport|\.node$/u.test(String(request))) {
        throw new Error("native or transport module loaded");
      }
      return originalLoad.call(this, request, parent, isMain);
    };
    const harness = require(${JSON.stringify(HARNESS_PATH)});
    const plan = harness.buildInventoryPlan();
    const forbidden = Object.keys(require.cache).filter((entry) => (
      /chameleon-native-darwin|usb-cdc-custody|\.node$/u.test(entry)
    ));
    if (forbidden.length !== 0 || plan.execution_policy.hardware_access_authorized !== false) {
      process.exitCode = 9;
    } else {
      process.stdout.write(process.env.BOB_LIFECYCLE_CONTEXT + ":inert\n");
    }
  `;
  for (const context of ["test", "install", "update", "release"]) {
    const result = spawnSync(process.execPath, ["-e", childSource], {
      cwd: ROOT,
      env: { ...process.env, BOB_LIFECYCLE_CONTEXT: context },
      encoding: "utf8",
    });
    assert.equal(result.status, 0, `${context}: ${result.stderr}`);
    assert.equal(result.stdout, `${context}:inert\n`);
    assert.equal(result.stderr, "");
  }
});

test("manual CLI is default-inert, plan-only, deterministic, and fail-closed", () => {
  const idle = invoke();
  assert.equal(idle.status, 0);
  assert.equal(idle.stdout, "");
  assert.equal(idle.stderr, "");

  const environment = {
    BOB_CHAMELEON_DEVICE_PATH: "/dev/tty.usbmodem-attacker",
    BOB_CHAMELEON_SERIAL: "attacker-controlled-serial",
  };
  const first = invoke(["--print-plan"], environment);
  const second = invoke(["--print-plan"], environment);
  assert.equal(first.status, 0, first.stderr);
  assert.equal(second.status, 0, second.stderr);
  assert.equal(first.stderr, "");
  assert.equal(first.stdout, second.stdout);
  assert.equal(validateInventoryPlan(JSON.parse(first.stdout)), buildInventoryPlan());
  assert.doesNotMatch(first.stdout, /tty\.usbmodem-attacker|attacker-controlled-serial/u);

  for (const args of [["--execute"], ["--print-plan", "--execute"], ["--help"], ["scan"]]) {
    const rejected = invoke(args, environment);
    assert.equal(rejected.status, 2, `${args.join(" ")}: ${rejected.stderr}`);
    assert.equal(rejected.stdout, "");
    assert.match(rejected.stderr, /hardware remains disabled/u);
  }
});
