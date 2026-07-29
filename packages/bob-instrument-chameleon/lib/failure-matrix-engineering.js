"use strict";

// Pure PH-X5 value-graph evaluation only; this is not a HIL runner or authority.

const crypto = require("node:crypto");
const { types: { isProxy } } = require("node:util");

const EXECUTOR_VERSION = 1;
const LEDGER_KIND = "chameleon_failure_matrix_engineering_ledger_v1";
const SUMMARY_KIND = "chameleon_failure_matrix_digest_only_summary_v1";
const EXPECTED_MATRIX_ID = "chameleon_ultra_failure_and_recovery_v5";
const EXPECTED_MATRIX_VERSION = 5;
const EXPECTED_MATRIX_DIGEST =
  "3684ce4b277c19dcb3da9cf060d99b40469695b1ba451dbc2a7026641ef2533b";
const EXPECTED_CASE_COUNT = 734;
const EXPECTED_PARITY_CASE_COUNT = 93;
const EXPECTED_MAINTENANCE_CASE_COUNT = 12;
const EXPECTED_EXTERNAL_READER_CASE_COUNT = 9;
const EXPECTED_STAGES = Object.freeze([
  "cross_plane",
  "owned_maintenance_fixture",
  "owned_media",
  "rf_off",
  "shielded_active",
]);
const EXPECTED_PARITY_EFFECT_FAMILIES = Object.freeze([
  "instrument.transmit",
  "target.destroy",
  "target.mutate",
  "target.present",
  "target.transmit",
]);
const MAINTENANCE_CONTRACT_KINDS = Object.freeze([
  "assurance_invalidation",
  "backup",
  "exact_delta",
  "post_operation_inventory",
  "pre_state_snapshot",
  "recovery_or_quarantine",
]);
const TERMINAL_STATES = Object.freeze([
  "irreversible_authorized",
  "quarantined",
  "rejected_no_effect",
  "restored",
  "unknown_effect",
]);
const OBSERVATION_FIELDS = Object.freeze([
  "active_effects",
  "baseline_restoration",
  "containment",
  "effect_started",
  "independent_effect_observation",
  "irreversible_authorization",
  "residue_accounting",
  "witness_separation",
]);
const MATRIX_FIELDS = Object.freeze([
  "availability_variant_count",
  "availability_variant_failure_registry_sha256",
  "capability_dependency_registry_sha256",
  "case_eligibility_registry",
  "case_eligibility_registry_sha256",
  "effect_profile_registry_sha256",
  "execution_policy",
  "failure_case_count",
  "failure_case_registry_sha256",
  "failure_cases",
  "matrix_digest",
  "matrix_id",
  "node_contract_registry_sha256",
  "provider_id",
  "scenario_registry_sha256",
  "scenarios",
  "semantic_manifest_sha256",
  "terminal_classifier_registry",
  "terminal_classifier_registry_sha256",
  "transport_pair_registry",
  "transport_pair_registry_sha256",
  "variant_failure_bindings",
  "version",
]);

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value != null && typeof value === "object") {
    const output = Object.create(null);
    for (const key of Object.keys(value).sort()) output[key] = canonicalize(value[key]);
    return output;
  }
  return value;
}

function canonicalJson(value) {
  return JSON.stringify(canonicalize(value));
}

function digest(value) {
  return crypto.createHash("sha256").update(canonicalJson(value), "utf8").digest("hex");
}

function deepFreeze(value, seen = new WeakSet()) {
  if (value == null || typeof value !== "object" || seen.has(value)) return value;
  seen.add(value);
  for (const child of Object.values(value)) deepFreeze(child, seen);
  return Object.freeze(value);
}

function assertExactFields(value, fields, label) {
  if (value == null || typeof value !== "object" || Array.isArray(value)
      || canonicalJson(Object.keys(value).sort()) !== canonicalJson([...fields].sort())) {
    throw new Error(`${label} has an open schema`);
  }
}

function assertPassiveValueGraph(value, label = "failure_matrix", active = new WeakSet(),
  visited = new WeakSet()) {
  if (value == null || ["string", "boolean"].includes(typeof value)) return;
  if (typeof value === "number" && Number.isFinite(value)) return;
  if (typeof value !== "object") throw new Error(`${label} is not a passive value graph`);
  if (isProxy(value)) throw new Error(`${label} contains a proxy`);
  if (active.has(value)) throw new Error(`${label} contains a cycle`);
  if (visited.has(value)) return;
  const prototype = Object.getPrototypeOf(value);
  if (!Array.isArray(value) && prototype !== Object.prototype && prototype !== null) {
    throw new Error(`${label} has an executable prototype`);
  }
  active.add(value);
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== "string") throw new Error(`${label} contains a symbol key`);
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (Array.isArray(value) && key === "length") continue;
    if (!descriptor || !("value" in descriptor) || descriptor.enumerable !== true) {
      throw new Error(`${label}.${key} is not passive data`);
    }
    assertPassiveValueGraph(descriptor.value, `${label}.${key}`, active, visited);
  }
  active.delete(value);
  visited.add(value);
}

function matrixBody(matrix) {
  return Object.fromEntries(MATRIX_FIELDS.filter((field) => field !== "matrix_digest")
    .map((field) => [field, matrix[field]]));
}

function validateReviewedMatrix(matrix) {
  assertPassiveValueGraph(matrix);
  assertExactFields(matrix, MATRIX_FIELDS, "failure_matrix");
  if (matrix.version !== EXPECTED_MATRIX_VERSION || matrix.matrix_id !== EXPECTED_MATRIX_ID
      || matrix.provider_id !== "chameleon_ultra") {
    throw new Error("engineering executor rejected the matrix identity");
  }
  const computedMatrixDigest = digest(matrixBody(matrix));
  if (matrix.matrix_digest !== computedMatrixDigest
      || computedMatrixDigest !== EXPECTED_MATRIX_DIGEST) {
    throw new Error("engineering executor rejected an unreviewed matrix digest");
  }
  assertExactFields(matrix.execution_policy, [
    "cli_is_plan_only",
    "hardware_access_authorized",
    "import_is_inert",
    "live_hil_evidence_present",
    "production_ready",
  ], "failure_matrix.execution_policy");
  if (matrix.execution_policy.import_is_inert !== true
      || matrix.execution_policy.cli_is_plan_only !== true
      || matrix.execution_policy.hardware_access_authorized !== false
      || matrix.execution_policy.production_ready !== false
      || matrix.execution_policy.live_hil_evidence_present !== false) {
    throw new Error("engineering executor cannot consume an authorizing matrix");
  }
  if (!Array.isArray(matrix.failure_cases)
      || matrix.failure_cases.length !== EXPECTED_CASE_COUNT
      || matrix.failure_case_count !== EXPECTED_CASE_COUNT
      || matrix.failure_case_registry_sha256 !== digest(matrix.failure_cases)) {
    throw new Error("engineering executor requires all 734 reviewed cases");
  }
  if (!Array.isArray(matrix.scenarios) || matrix.scenarios.length === 0
      || matrix.scenario_registry_sha256 !== digest(matrix.scenarios)) {
    throw new Error("engineering executor rejected the scenario registry");
  }
  if (matrix.terminal_classifier_registry == null
      || typeof matrix.terminal_classifier_registry !== "object"
      || matrix.terminal_classifier_registry_sha256
        !== digest(matrix.terminal_classifier_registry)) {
    throw new Error("engineering executor rejected the terminal classifier registry");
  }
  const scenarios = new Map();
  for (const scenario of matrix.scenarios) {
    if (typeof scenario.scenario_id !== "string" || scenarios.has(scenario.scenario_id)
        || !EXPECTED_STAGES.includes(scenario.stage)
        || scenario.status !== "pending_hil"
        || scenario.production_nonwaivable !== true
        || scenario.requires_zero_active_effects !== true
        || scenario.requires_residue_accounting !== true
        || scenario.requires_signed_evidence !== true
        || scenario.automatic_effect_retry !== false) {
      throw new Error("engineering executor rejected a weakened failure scenario");
    }
    const classifier = matrix.terminal_classifier_registry[scenario.terminal_classifier_id];
    if (!classifier || scenario.terminal_classifier_digest !== digest(classifier)
        || !Array.isArray(scenario.expected_terminal_states)
        || scenario.expected_terminal_states.some((state) => !TERMINAL_STATES.includes(state))) {
      throw new Error(`engineering executor rejected classifier ${scenario.scenario_id}`);
    }
    scenarios.set(scenario.scenario_id, scenario);
  }
  const ids = new Set();
  for (const failureCase of matrix.failure_cases) {
    const scenario = scenarios.get(failureCase.scenario_id);
    if (!scenario || typeof failureCase.case_id !== "string" || ids.has(failureCase.case_id)
        || failureCase.status !== "pending_hil"
        || failureCase.terminal_classifier_id !== scenario.terminal_classifier_id
        || !Array.isArray(failureCase.required_evidence_contract_refs)
        || failureCase.required_evidence_contract_refs.some((contract) => (
          contract.must_be_signed !== true || contract.status !== "pending_hil"
        ))) {
      throw new Error("engineering executor rejected an incomplete or duplicate failure case");
    }
    ids.add(failureCase.case_id);
  }
  return Object.freeze({ matrix, scenarios });
}

const OBSERVATIONS = deepFreeze({
  irreversible_authorized: {
    effect_started: "yes", active_effects: "zero",
    independent_effect_observation: "expected", baseline_restoration: "not_applicable",
    containment: "proven", irreversible_authorization: "current",
    residue_accounting: "complete", witness_separation: "proven",
  },
  quarantined: {
    effect_started: "yes", active_effects: "zero",
    independent_effect_observation: "unexpected", baseline_restoration: "failed",
    containment: "proven", irreversible_authorization: "absent",
    residue_accounting: "complete", witness_separation: "proven",
  },
  rejected_no_effect: {
    effect_started: "no", active_effects: "zero",
    independent_effect_observation: "none", baseline_restoration: "not_applicable",
    containment: "not_applicable", irreversible_authorization: "not_applicable",
    residue_accounting: "complete", witness_separation: "proven",
  },
  restored: {
    effect_started: "yes", active_effects: "zero",
    independent_effect_observation: "expected", baseline_restoration: "proven",
    containment: "proven", irreversible_authorization: "not_applicable",
    residue_accounting: "complete", witness_separation: "proven",
  },
  unknown_effect: {
    effect_started: "unknown", active_effects: "zero",
    independent_effect_observation: "unknown", baseline_restoration: "unknown",
    containment: "unknown", irreversible_authorization: "unknown",
    residue_accounting: "complete", witness_separation: "proven",
  },
});

function desiredTerminalState(failureCase, scenario) {
  if (scenario.terminal_classifier_id === "effectless_resolution_v1") {
    return "rejected_no_effect";
  }
  const destructive = scenario.terminal_classifier_id === "irreversible_authorized_v1";
  const candidates = destructive
    ? ["irreversible_authorized", "quarantined", "rejected_no_effect", "unknown_effect"]
    : ["restored", "quarantined", "rejected_no_effect", "unknown_effect"];
  return candidates[Number.parseInt(digest(failureCase).slice(0, 8), 16) % candidates.length];
}

function classify(matrix, scenario, observation) {
  const classifier = matrix.terminal_classifier_registry[scenario.terminal_classifier_id];
  assertExactFields(observation, OBSERVATION_FIELDS, "engineering_observation");
  for (const [field, values] of Object.entries(classifier.observation_schema)) {
    if (!values.includes(observation[field])) {
      throw new Error(`engineering_observation.${field} is outside the classifier vocabulary`);
    }
  }
  const matched = classifier.ordered_rules.find((rule) => Object.entries(rule.when_all)
    .every(([field, value]) => observation[field] === value));
  const terminalState = matched ? matched.terminal_state : classifier.default_terminal_state;
  const decision = {
    classifier_digest: digest(classifier),
    classifier_id: scenario.terminal_classifier_id,
    matched_priority: matched ? matched.priority : null,
    observation_digest: digest(observation),
    terminal_state: terminalState,
  };
  return Object.freeze({ ...decision, decision_digest: digest(decision) });
}

function cleanupProjection(failureCase, terminalState) {
  const dispositions = {
    irreversible_authorized: "quarantine_or_disposal_required",
    quarantined: "quarantine_required",
    rejected_no_effect: "no_effect_closed",
    restored: "restoration_simulated",
    unknown_effect: "quarantine_required",
  };
  return {
    active_effects: "zero",
    automatic_effect_retry: false,
    case_digest: digest(failureCase),
    disposition: dispositions[terminalState],
    residue_accounting: "complete",
    terminal_state: terminalState,
  };
}

function requiredContractKinds(failureCase) {
  return failureCase.required_evidence_contract_refs
    .map((contract) => contract.contract_kind).sort();
}

function transportParityProjection(matrix, failureCase, scenario, terminalState) {
  const parityRequired = failureCase.transport_pair_id != null
    || scenario.evidence_requirements.same_operation_transport_parity_required === true;
  if (!parityRequired) return null;
  const pair = matrix.transport_pair_registry[failureCase.transport_pair_id];
  const channels = pair?.endpoints?.map((endpoint) => endpoint.channel).sort();
  const contractKinds = requiredContractKinds(failureCase);
  if (!pair || canonicalJson(channels) !== canonicalJson(["ble", "usb"])
      || pair.same_request_or_compiled_command_required !== true
      || pair.same_effect_contract_required !== true
      || pair.attempt_receipt_per_endpoint_required !== true
      || pair.signed_pair_comparison_verdict_required !== true
      || !contractKinds.includes("transport_attempt_receipt_ble")
      || !contractKinds.includes("transport_attempt_receipt_usb")
      || !contractKinds.includes("transport_pair_comparison_verdict")) {
    throw new Error(`parity case ${failureCase.case_id} weakens USB/BLE symmetry`);
  }
  const effectContractDigest = digest({
    effect_profile_refs: failureCase.effect_profile_refs,
    operation_id: failureCase.operation_id,
  });
  return {
    ble_effect_contract_digest: effectContractDigest,
    ble_terminal_state: terminalState,
    live_attempt_receipts_materialized: false,
    live_comparison_verdict_materialized: false,
    pair_digest: pair.pair_digest,
    semantic_parity: "equal",
    usb_effect_contract_digest: effectContractDigest,
    usb_terminal_state: terminalState,
  };
}

function maintenanceProjection(failureCase, scenario, terminalState) {
  if (scenario.stage !== "owned_maintenance_fixture") return null;
  const kinds = requiredContractKinds(failureCase);
  if (canonicalJson(kinds) !== canonicalJson(MAINTENANCE_CONTRACT_KINDS)) {
    throw new Error(`maintenance case ${failureCase.case_id} omits invalidation custody`);
  }
  return {
    assurance_after: "invalidated_pending_live_inventory",
    assurance_invalidation_required: true,
    cleanup_authority_used: false,
    live_contracts_materialized: false,
    post_operation_inventory_required: true,
    recovery_or_quarantine_required: true,
    requalification_claimed: false,
    terminal_state: terminalState,
  };
}

function externalReaderProjection(failureCase, scenario) {
  if (scenario.evidence_requirements.external_reader_required !== true) return null;
  if (!requiredContractKinds(failureCase).includes("external_reader_verdict")) {
    throw new Error(`write-only case ${failureCase.case_id} omits its independent reader`);
  }
  return {
    independent_reader_required: true,
    instrument_ack_is_outcome_verdict: false,
    live_reader_verdict_materialized: false,
  };
}

function increment(registry, key) {
  registry[key] = (registry[key] || 0) + 1;
}

function buildLedger(validated) {
  const { matrix, scenarios } = validated;
  const entries = [];
  const terminalCounts = Object.create(null);
  const stageCounts = Object.create(null);
  const parityEffectFamilyCounts = Object.create(null);
  let parityCaseCount = 0;
  let maintenanceCaseCount = 0;
  let externalReaderCaseCount = 0;
  for (let index = 0; index < matrix.failure_cases.length; index += 1) {
    const failureCase = matrix.failure_cases[index];
    const scenario = scenarios.get(failureCase.scenario_id);
    const requestedTerminal = desiredTerminalState(failureCase, scenario);
    const observation = OBSERVATIONS[requestedTerminal];
    const decision = classify(matrix, scenario, observation);
    if (decision.terminal_state !== requestedTerminal
        || !scenario.expected_terminal_states.includes(decision.terminal_state)
        || observation.active_effects !== "zero") {
      throw new Error(`case ${failureCase.case_id} has no single safe terminal classification`);
    }
    const cleanup = cleanupProjection(failureCase, decision.terminal_state);
    const parity = transportParityProjection(matrix, failureCase, scenario, decision.terminal_state);
    const maintenance = maintenanceProjection(failureCase, scenario, decision.terminal_state);
    const externalReader = externalReaderProjection(failureCase, scenario);
    if (parity) {
      parityCaseCount += 1;
      for (const family of scenario.effect_families) increment(parityEffectFamilyCounts, family);
    }
    if (maintenance) maintenanceCaseCount += 1;
    if (externalReader) externalReaderCaseCount += 1;
    increment(terminalCounts, decision.terminal_state);
    increment(stageCounts, scenario.stage);
    entries.push(Object.freeze({
      case_digest: digest(failureCase),
      case_id: failureCase.case_id,
      cleanup_digest: digest(cleanup),
      decision_digest: decision.decision_digest,
      engineering_only: true,
      external_reader_requirement_digest: externalReader ? digest(externalReader) : null,
      live_hil_evidence_present: false,
      maintenance_invalidation_digest: maintenance ? digest(maintenance) : null,
      observation_digest: decision.observation_digest,
      production_ready: false,
      sequence: index + 1,
      terminal_classification_count: 1,
      terminal_state: decision.terminal_state,
      transport_parity_digest: parity ? digest(parity) : null,
      verified_success: false,
      zero_active_effects: true,
    }));
  }
  const parityFamilies = Object.keys(parityEffectFamilyCounts).sort();
  if (parityCaseCount !== EXPECTED_PARITY_CASE_COUNT
      || maintenanceCaseCount !== EXPECTED_MAINTENANCE_CASE_COUNT
      || externalReaderCaseCount !== EXPECTED_EXTERNAL_READER_CASE_COUNT
      || canonicalJson(Object.keys(stageCounts).sort()) !== canonicalJson(EXPECTED_STAGES)
      || canonicalJson(parityFamilies) !== canonicalJson(EXPECTED_PARITY_EFFECT_FAMILIES)) {
    throw new Error("engineering executor detected incomplete PH-X5 staged coverage");
  }
  const body = {
    case_count: entries.length,
    engineering_only: true,
    entries,
    entries_digest: digest(entries),
    evidence_authority: false,
    executor_version: EXECUTOR_VERSION,
    external_reader_case_count: externalReaderCaseCount,
    failure_case_registry_sha256: matrix.failure_case_registry_sha256,
    hardware_access_authorized: false,
    ledger_kind: LEDGER_KIND,
    live_hil_evidence_present: false,
    maintenance_case_count: maintenanceCaseCount,
    matrix_digest: matrix.matrix_digest,
    matrix_id: matrix.matrix_id,
    missing_case_count: 0,
    production_ready: false,
    stage_counts: stageCounts,
    terminal_classification_count: entries.length,
    terminal_counts: terminalCounts,
    transport_parity_case_count: parityCaseCount,
    transport_parity_effect_family_counts: parityEffectFamilyCounts,
    verified_success_count: 0,
    zero_active_effects_case_count: entries.length,
  };
  return deepFreeze({ ...body, ledger_digest: digest(body) });
}

function executeChameleonFailureMatrixEngineering(matrix) {
  return buildLedger(validateReviewedMatrix(matrix));
}

function verifyChameleonFailureMatrixEngineeringLedger(matrix, ledger) {
  assertPassiveValueGraph(ledger, "engineering_ledger");
  const expected = executeChameleonFailureMatrixEngineering(matrix);
  if (canonicalJson(ledger) !== canonicalJson(expected)) {
    throw new Error("engineering ledger is not the deterministic reviewed execution");
  }
  return ledger;
}

function projectChameleonFailureMatrixEngineeringSummary(matrix, ledger) {
  verifyChameleonFailureMatrixEngineeringLedger(matrix, ledger);
  if (ledger.ledger_kind !== LEDGER_KIND || ledger.ledger_digest == null
      || ledger.case_count !== EXPECTED_CASE_COUNT
      || ledger.terminal_classification_count !== EXPECTED_CASE_COUNT
      || ledger.zero_active_effects_case_count !== EXPECTED_CASE_COUNT
      || ledger.verified_success_count !== 0
      || ledger.hardware_access_authorized !== false
      || ledger.production_ready !== false
      || ledger.live_hil_evidence_present !== false
      || ledger.evidence_authority !== false) {
    throw new Error("digest-only summary rejected an incomplete engineering ledger");
  }
  const body = {
    case_count: ledger.case_count,
    engineering_gate_passed: true,
    engineering_only: true,
    entries_digest: ledger.entries_digest,
    evidence_authority: false,
    external_reader_coverage_digest: digest({ count: ledger.external_reader_case_count }),
    hardware_access_authorized: false,
    hil_gate_passed: false,
    ledger_digest: ledger.ledger_digest,
    live_hil_evidence_present: false,
    maintenance_coverage_digest: digest({
      count: ledger.maintenance_case_count,
      entries: ledger.entries.filter((entry) => entry.maintenance_invalidation_digest != null)
        .map((entry) => entry.maintenance_invalidation_digest),
    }),
    matrix_digest: ledger.matrix_digest,
    production_ready: false,
    stage_coverage_digest: digest(ledger.stage_counts),
    summary_kind: SUMMARY_KIND,
    terminal_coverage_digest: digest(ledger.terminal_counts),
    transport_parity_coverage_digest: digest({
      count: ledger.transport_parity_case_count,
      effect_families: ledger.transport_parity_effect_family_counts,
    }),
    verified_success_count: 0,
  };
  return deepFreeze({ ...body, summary_digest: digest(body) });
}

module.exports = Object.freeze({
  ENGINEERING_FAILURE_MATRIX_DIGEST: EXPECTED_MATRIX_DIGEST,
  ENGINEERING_FAILURE_MATRIX_EXPECTED_CASE_COUNT: EXPECTED_CASE_COUNT,
  ENGINEERING_FAILURE_MATRIX_EXPECTED_EXTERNAL_READER_CASE_COUNT:
    EXPECTED_EXTERNAL_READER_CASE_COUNT,
  ENGINEERING_FAILURE_MATRIX_EXPECTED_MAINTENANCE_CASE_COUNT:
    EXPECTED_MAINTENANCE_CASE_COUNT,
  ENGINEERING_FAILURE_MATRIX_EXPECTED_PARITY_CASE_COUNT: EXPECTED_PARITY_CASE_COUNT,
  executeChameleonFailureMatrixEngineering,
  projectChameleonFailureMatrixEngineeringSummary,
  verifyChameleonFailureMatrixEngineeringLedger,
});
