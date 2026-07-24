"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");

const {
  AVAILABILITY_VARIANT_COUNT,
  EFFECT_PROFILE_IDS,
  STAGES,
  buildFailureMatrix,
  canonicalCapabilityDependencies,
  canonicalNodeContracts,
  classifyTerminalObservation,
  reviewedDigest,
  validateFailureMatrix,
} = require("./manual/chameleon-failure-matrix.js");

function clone(value) {
  return structuredClone(value);
}

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value != null && typeof value === "object") {
    const output = {};
    for (const key of Object.keys(value).sort()) output[key] = canonicalize(value[key]);
    return output;
  }
  return value;
}

function canonicalDigest(value) {
  return crypto.createHash("sha256")
    .update(JSON.stringify(canonicalize(value)))
    .digest("hex");
}

function authenticate(copy) {
  delete copy.matrix_digest;
  copy.matrix_digest = canonicalDigest(copy);
  return copy;
}

test("PH-X5 failure matrix is closed, exhaustive by stage, and non-authorizing", () => {
  const matrix = buildFailureMatrix();
  assert.equal(matrix.version, 5);
  assert.equal(validateFailureMatrix(matrix), matrix);
  assert.match(matrix.matrix_digest, /^[a-f0-9]{64}$/u);
  assert.match(matrix.node_contract_registry_sha256, /^[a-f0-9]{64}$/u);
  assert.match(matrix.effect_profile_registry_sha256, /^[a-f0-9]{64}$/u);
  assert.equal(matrix.execution_policy.hardware_access_authorized, false);
  assert.equal(matrix.execution_policy.production_ready, false);
  assert.equal(matrix.execution_policy.live_hil_evidence_present, false);
  assert.equal(matrix.availability_variant_count, AVAILABILITY_VARIANT_COUNT);
  assert.equal(matrix.variant_failure_bindings.length, AVAILABILITY_VARIANT_COUNT);
  assert.equal(matrix.failure_cases.length, matrix.failure_case_count);
  assert.equal(matrix.failure_case_count, 734);
  assert.equal(
    matrix.failure_case_registry_sha256,
    "f0e53ee1d9f8934cc6783b400917f36f5207e94e7af32009bcf4a7600efff83a",
  );
  assert.equal(
    matrix.case_eligibility_registry_sha256,
    "4003aa7a56ca2683fee0f586417a06d7b992a1e8a5396d436c46aafdd511bf27",
  );
  assert.equal(
    matrix.transport_pair_registry_sha256,
    "23353ee5ad4c324f56e2522b4f56c7b9d80160902b2ef681c0e64ca4e89cefd4",
  );
  assert.equal(
    matrix.availability_variant_failure_registry_sha256,
    "90721c9619d29b7c650c97954a5b497416e0355d577e1130cc6faacdfb38e8cb",
  );
  assert.equal(new Set(matrix.failure_cases.map((row) => row.case_id)).size, matrix.failure_case_count);
  assert.equal(
    new Set(matrix.failure_cases.map((row) => row.evidence_key)).size,
    matrix.failure_case_count,
  );
  assert.equal(
    new Set(matrix.variant_failure_bindings.map(
      (row) => `${row.capability_id}/${row.variant_id}`,
    )).size,
    AVAILABILITY_VARIANT_COUNT,
  );
  const scenarioById = new Map(matrix.scenarios.map((row) => [row.scenario_id, row]));
  const casesById = new Map(matrix.failure_cases.map((row) => [row.case_id, row]));
  const bindingsByCaseId = new Map(matrix.failure_cases.map((row) => [row.case_id, []]));
  for (const binding of matrix.variant_failure_bindings) {
    for (const caseId of binding.failure_case_ids) {
      bindingsByCaseId.get(caseId).push(binding.availability_variant_digest);
    }
  }
  for (const failureCase of matrix.failure_cases) {
    const expectedDigests = new Set();
    if (failureCase.availability_variant_digest != null) {
      expectedDigests.add(failureCase.availability_variant_digest);
    }
    if (failureCase.transport_pair_id != null) {
      for (const endpoint of matrix.transport_pair_registry[failureCase.transport_pair_id].endpoints) {
        expectedDigests.add(endpoint.availability_variant_digest);
      }
    }
    assert.deepEqual(bindingsByCaseId.get(failureCase.case_id).sort(), [...expectedDigests].sort());
  }
  const incomingByScenario = new Map(matrix.scenarios.map((row) => [row.scenario_id, []]));
  for (const failureCase of matrix.failure_cases) {
    incomingByScenario.get(failureCase.scenario_id).push(failureCase);
  }
  assert.ok([...incomingByScenario.values()].every((rows) => rows.length > 0));
  for (const binding of matrix.variant_failure_bindings) {
    assert.equal(binding.status, "pending_hil");
    assert.ok(binding.failure_scenario_ids.includes("rf_off.availability_variant_formula_drift"));
    assert.ok(binding.failure_scenario_ids.includes("rf_off.normalized_operation_binding_drift"));
    if (binding.technique_bindings.length > 0) {
      assert.ok(binding.failure_scenario_ids.includes("rf_off.technique_selector_binding_drift"));
      for (const techniqueId of binding.technique_bindings) {
        assert.ok(binding.failure_case_ids.some((caseId) => {
          const failureCase = casesById.get(caseId);
          return failureCase.case_kind === "technique_binding"
            && failureCase.technique_id === techniqueId
            && failureCase.availability_variant_digest === binding.availability_variant_digest;
        }));
      }
    }
    for (const scenarioId of binding.failure_scenario_ids) assert.ok(scenarioById.has(scenarioId));
    for (const profileRef of binding.effect_profile_refs) {
      assert.ok(binding.failure_scenario_ids.some(
        (scenarioId) => scenarioById.get(scenarioId).effect_profile_refs.includes(profileRef),
      ));
    }
  }
  assert.equal(new Set(matrix.scenarios.map((row) => row.scenario_id)).size, matrix.scenarios.length);
  assert.deepEqual([...new Set(matrix.scenarios.map((row) => row.stage))].sort(), [...STAGES].sort());
  assert.ok(matrix.scenarios.every((row) => row.status === "pending_hil"));
  assert.ok(matrix.scenarios.every((row) => row.automatic_effect_retry === false));
  assert.ok(matrix.scenarios.every((row) => row.requires_signed_evidence));
  assert.ok(matrix.scenarios.every((row) => row.requires_zero_active_effects));
  assert.ok(matrix.scenarios.every((row) => row.terminal_classifier_digest
    === canonicalDigest(matrix.terminal_classifier_registry[row.terminal_classifier_id])));
  assert.deepEqual(
    [...new Set(matrix.scenarios.flatMap((row) => row.effect_profile_refs))].sort(),
    [...EFFECT_PROFILE_IDS],
  );
  assert.ok(matrix.scenarios.some((row) => row.fault_class === "transport_partial_frame"));
  assert.ok(matrix.scenarios.some((row) => row.fault_class === "ambiguous_acknowledgement"));
  assert.ok(matrix.scenarios.some((row) => row.fault_class === "transport_effect_semantic_drift"));
  assert.ok(matrix.scenarios.some((row) => row.fault_class === "irreversible_fixture_erase"));
  assert.ok(matrix.scenarios.some((row) => row.fault_class === "capability_custody_drift"));

  for (const scenarioId of [
    "shielded.usb_ble_target_transmit_parity",
    "owned_media.usb_ble_target_mutate_parity",
    "owned_media.t55xx_external_verification",
  ]) {
    const incoming = incomingByScenario.get(scenarioId);
    assert.ok(incoming.length > 0, scenarioId);
    assert.ok(incoming.every((row) => row.availability_variant_digest != null), scenarioId);
  }
  for (const binding of matrix.variant_failure_bindings.filter(
    (row) => row.capability_id === "CU-LF-T55XX-WRITE",
  )) {
    assert.ok(binding.failure_scenario_ids.includes("owned_media.t55xx_external_verification"));
    assert.ok(binding.failure_case_ids.some(
      (caseId) => casesById.get(caseId).case_kind === "external_reader_verification",
    ));
  }
  for (const parityCase of matrix.failure_cases.filter(
    (row) => row.case_kind === "same_operation_transport_parity",
  )) {
    assert.ok(parityCase.operation_id);
    assert.ok(parityCase.availability_variant_digest);
    assert.equal(parityCase.transport_pair_id, "transport-pair:chameleon-ultra.usb-ble.v1");
    assert.ok(parityCase.required_evidence_contract_refs.some(
      (entry) => entry.contract_kind === "transport_attempt_receipt_usb",
    ));
    assert.ok(parityCase.required_evidence_contract_refs.some(
      (entry) => entry.contract_kind === "transport_attempt_receipt_ble",
    ));
    assert.ok(parityCase.required_evidence_contract_refs.some(
      (entry) => entry.contract_kind === "transport_pair_comparison_verdict",
    ));
  }
  const pair = matrix.transport_pair_registry["transport-pair:chameleon-ultra.usb-ble.v1"];
  assert.deepEqual(pair.endpoints.map((endpoint) => endpoint.channel), ["ble", "usb"]);
  assert.equal(new Set(pair.endpoints.map(
    (endpoint) => endpoint.availability_variant_digest,
  )).size, 2);
  const instrumentParityCases = incomingByScenario.get("rf_off.usb_ble_transport_parity");
  assert.equal(instrumentParityCases.length, 1);
  assert.equal(instrumentParityCases[0].case_kind, "paired_transport_parity");
  assert.equal(instrumentParityCases[0].availability_variant_digest, null);
  assert.deepEqual(instrumentParityCases[0].effect_profile_refs, [
    "EP-INSTRUMENT-TRANSMIT-BLE",
    "EP-INSTRUMENT-TRANSMIT-USB",
  ]);

  const terminalRiskDestroy = matrix.failure_cases.filter((row) => (
    row.capability_id === "CU-HF-MFU-ACQUIRE"
    && row.variant_id === "terminal_risk_authenticated_read"
    && row.scenario_id === "owned_media.usb_ble_target_destroy_parity"
  ));
  assert.deepEqual(terminalRiskDestroy.map((row) => row.operation_id), ["protocol.authenticate"]);
  assert.ok(terminalRiskDestroy.every((row) => row.technique_id === null));
  assert.equal(matrix.failure_cases.filter((row) => (
    row.capability_id === "CU-ADMIN-DFU"
    && row.scenario_id === "maintenance.settings_recovery"
  )).length, 0);
  assert.deepEqual(matrix.failure_cases.filter((row) => (
    row.capability_id === "CU-ADMIN-DFU"
    && row.scenario_id === "maintenance.dfu_interruption"
  )).map((row) => row.operation_id), ["instrument.firmware_manage"]);
  const t55xxScenario = scenarioById.get("owned_media.t55xx_external_verification");
  assert.ok(t55xxScenario.node_ids.includes("PH-C5"));
  assert.equal(t55xxScenario.evidence_requirements.external_reader_required, true);
  for (const maintenance of matrix.scenarios.filter(
    (row) => row.stage === "owned_maintenance_fixture",
  )) {
    assert.equal(maintenance.evidence_requirements.pre_state_snapshot_required, true);
    assert.equal(maintenance.evidence_requirements.backup_required, true);
    assert.equal(maintenance.evidence_requirements.exact_delta_required, true);
    assert.equal(maintenance.evidence_requirements.post_operation_inventory_required, true);
    assert.equal(maintenance.evidence_requirements.assurance_invalidation_required, true);
    assert.notEqual(
      maintenance.evidence_requirements.executor_principal_ref,
      maintenance.evidence_requirements.witness_principal_ref,
    );
    for (const failureCase of incomingByScenario.get(maintenance.scenario_id)) {
      const contractKinds = failureCase.required_evidence_contract_refs.map(
        (entry) => entry.contract_kind,
      );
      for (const requiredKind of [
        "pre_state_snapshot",
        "backup",
        "exact_delta",
        "post_operation_inventory",
        "assurance_invalidation",
        "recovery_or_quarantine",
      ]) assert.ok(contractKinds.includes(requiredKind), `${maintenance.scenario_id}/${requiredKind}`);
    }
  }
  assert.match(
    scenarioById.get("maintenance.authorized_erase").independent_witness_ref,
    /independent/u,
  );
});

test("matrix validation rejects readiness, retry, destructive-terminal, and schema laundering", () => {
  const matrix = buildFailureMatrix();
  for (const mutate of [
    (copy) => { copy.execution_policy.production_ready = true; },
    (copy) => { copy.execution_policy.device_path = "/dev/tty.usbmodem"; },
    (copy) => { copy.scenarios[0].automatic_effect_retry = true; },
    (copy) => { copy.scenarios[0].production_nonwaivable = false; },
    (copy) => { copy.scenarios.find((row) => row.effect_families.includes("instrument.destroy"))
      .expected_terminal_states = ["restored"]; },
    (copy) => { copy.scenarios[0].node_ids = ["PH-C99"]; },
    (copy) => { copy.scenarios[0].effect_profile_refs = ["EP-UNREGISTERED"]; },
    (copy) => { copy.scenarios[0].effect_families = ["target.destroy"]; },
    (copy) => { copy.effect_profile_registry_sha256 = "0".repeat(64); },
    (copy) => { copy.capability_dependency_registry_sha256 = "0".repeat(64); },
    (copy) => { copy.semantic_manifest_sha256 = "0".repeat(64); },
    (copy) => { copy.case_eligibility_registry.scenario_operation_eligibility
      ["maintenance.dfu_interruption"]
      ["EP-INSTRUMENT-ADMINISTER-LOCAL"].push("instrument.admin_configure"); },
    (copy) => { copy.transport_pair_registry["transport-pair:chameleon-ultra.usb-ble.v1"]
      .endpoints[0].availability_variant_digest = "0".repeat(64); },
    (copy) => { copy.availability_variant_count -= 1; },
    (copy) => { copy.variant_failure_bindings.pop(); },
    (copy) => { copy.variant_failure_bindings[0].availability_variant_digest = "0".repeat(64); },
    (copy) => { copy.variant_failure_bindings[0].failure_scenario_ids = ["rf_off.unreviewed"]; },
    (copy) => { copy.variant_failure_bindings[0].technique_bindings = ["credential.relay"]; },
    (copy) => { copy.scenarios.find((row) => row.effectless_resolution_only)
      .expected_terminal_states = ["quarantined"]; },
    (copy) => { copy.scenarios.find((row) => row.scenario_id === "rf_off.partial_frame")
      .effect_profile_refs = ["EP-INSTRUMENT-CONFIGURE-USB"];
      copy.scenarios.find((row) => row.scenario_id === "rf_off.partial_frame")
        .effect_families = ["instrument.configure"]; },
    (copy) => { copy.scenarios[0].device_path = "/dev/tty.usbmodem"; },
    (copy) => { copy.failure_cases[0].evidence_key = "hil-evidence-key:v1:forged"; },
    (copy) => { copy.failure_cases.find((row) => row.required_evidence_contract_refs.length > 0)
      .required_evidence_contract_refs.pop(); },
    (copy) => { copy.failure_cases.find((row) => row.transport_pair_id != null)
      .transport_pair_digest = "0".repeat(64); },
    (copy) => { copy.failure_cases.find((row) => row.technique_id != null).technique_id = null; },
    (copy) => { copy.failure_cases.find(
      (row) => row.case_kind === "same_operation_transport_parity",
    ).operation_id = null; },
    (copy) => { copy.scenarios.find(
      (row) => row.stage === "owned_maintenance_fixture",
    ).evidence_requirements.assurance_invalidation_required = false; },
  ]) {
    const copy = clone(matrix);
    mutate(copy);
    assert.throws(() => validateFailureMatrix(authenticate(copy)));
  }
  const staleDigest = clone(matrix);
  staleDigest.scenarios[0].fault_class = "substituted_fault";
  assert.throws(() => validateFailureMatrix(staleDigest), /digest/u);
});

test("reviewed source digests are recomputed from canonical nodes and dependency formulas", () => {
  const nodes = JSON.parse(fs.readFileSync(
    path.join(__dirname, "..", "docs", "plane-physical", "nodes.json"),
    "utf8",
  ));
  assert.equal(reviewedDigest(canonicalNodeContracts(nodes)), nodes.node_contract_registry_sha256);
  const mutatedNodes = clone(nodes);
  mutatedNodes.nodes.find((row) => row.id === "PH-X5").intent = "substituted intent";
  assert.notEqual(
    reviewedDigest(canonicalNodeContracts(mutatedNodes)),
    nodes.node_contract_registry_sha256,
  );

  const coverage = JSON.parse(fs.readFileSync(
    path.join(__dirname, "..", "docs", "plane-physical", "coverage.json"),
    "utf8",
  ));
  assert.equal(
    reviewedDigest(canonicalCapabilityDependencies(coverage.capability_dependency_registry)),
    coverage.capability_dependency_registry_sha256,
  );
  const mutatedCoverage = clone(coverage);
  mutatedCoverage.capability_dependency_registry["CU-CORE-INVENTORY"].all_of.push(
    "command:65535",
  );
  assert.notEqual(
    reviewedDigest(canonicalCapabilityDependencies(
      mutatedCoverage.capability_dependency_registry,
    )),
    coverage.capability_dependency_registry_sha256,
  );
});

test("terminal classifiers deterministically map every closed observation tuple", () => {
  const matrix = buildFailureMatrix();
  const schema = matrix.terminal_classifier_registry.reversible_effect_v1.observation_schema;
  const fields = Object.keys(schema);
  let observations = [{}];
  for (const field of fields) {
    observations = observations.flatMap((partial) => schema[field].map((value) => ({
      ...partial,
      [field]: value,
    })));
  }
  for (const [classifierId, classifier] of Object.entries(matrix.terminal_classifier_registry)) {
    const outputs = new Set([
      ...classifier.ordered_rules.map((rule) => rule.terminal_state),
      classifier.default_terminal_state,
    ]);
    for (const observation of observations) {
      const first = classifyTerminalObservation(classifierId, observation);
      const second = classifyTerminalObservation(classifierId, observation);
      assert.ok(outputs.has(first.terminal_state));
      assert.equal(first.decision_digest, second.decision_digest);
      assert.equal(first.execution_authority, false);
      assert.equal(first.evidence_authority, false);
    }
  }

  const baseline = {
    effect_started: "yes",
    active_effects: "zero",
    independent_effect_observation: "expected",
    baseline_restoration: "not_applicable",
    containment: "proven",
    irreversible_authorization: "current",
    residue_accounting: "complete",
    witness_separation: "proven",
  };
  assert.equal(
    classifyTerminalObservation("irreversible_authorized_v1", baseline).terminal_state,
    "irreversible_authorized",
  );
  assert.equal(
    classifyTerminalObservation("reversible_effect_v1", {
      ...baseline,
      irreversible_authorization: "not_applicable",
      baseline_restoration: "proven",
    }).terminal_state,
    "restored",
  );
  assert.equal(
    classifyTerminalObservation("effectless_resolution_v1", {
      ...baseline,
      effect_started: "no",
      active_effects: "zero",
      independent_effect_observation: "none",
      containment: "not_applicable",
      irreversible_authorization: "not_applicable",
    }).terminal_state,
    "rejected_no_effect",
  );
  assert.throws(
    () => classifyTerminalObservation("reversible_effect_v1", { ...baseline, extra: true }),
    /open schema/u,
  );

  for (const unsafe of [
    { ...baseline, effect_started: "no", containment: "failed", baseline_restoration: "failed" },
    { ...baseline, active_effects: "nonzero" },
    { ...baseline, witness_separation: "failed" },
  ]) {
    assert.notEqual(
      classifyTerminalObservation("irreversible_authorized_v1", unsafe).terminal_state,
      "irreversible_authorized",
    );
  }
  for (const unsafe of [
    {
      ...baseline,
      irreversible_authorization: "not_applicable",
      baseline_restoration: "proven",
      independent_effect_observation: "unexpected",
      containment: "failed",
    },
    {
      ...baseline,
      irreversible_authorization: "not_applicable",
      baseline_restoration: "proven",
      active_effects: "nonzero",
    },
  ]) {
    assert.notEqual(
      classifyTerminalObservation("reversible_effect_v1", unsafe).terminal_state,
      "restored",
    );
  }
});

test("manual CLI prints only the plan and exposes no execution mode", () => {
  const script = path.join(__dirname, "manual", "chameleon-failure-matrix.js");
  const printed = spawnSync(process.execPath, [script, "--print-plan"], {
    encoding: "utf8",
    maxBuffer: 32 * 1024 * 1024,
    timeout: 5_000,
  });
  assert.equal(printed.status, 0, printed.stderr);
  const matrix = JSON.parse(printed.stdout);
  assert.equal(validateFailureMatrix(matrix), matrix);
  assert.equal(matrix.execution_policy.cli_is_plan_only, true);
  assert.equal(matrix.execution_policy.hardware_access_authorized, false);

  const refused = spawnSync(process.execPath, [script, "--execute"], {
    encoding: "utf8",
    timeout: 5_000,
  });
  assert.equal(refused.status, 2);
  assert.match(refused.stderr, /no execution mode exists/u);
});
