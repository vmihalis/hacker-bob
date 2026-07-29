#!/usr/bin/env node
"use strict";

// Plane-PH PH-X5 HIL plan contract. This file is deliberately inert: importing
// it or invoking its CLI validates/prints the reviewed matrix and never loads a
// provider transport/worker, enumerates USB/BLE, opens a device, or emits RF. A
// future HIL runner must consume this exact digest and return separately signed
// gate evidence.

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const {
  CHAMELEON_SEMANTIC_MANIFEST,
  getChameleonAvailabilityVariant,
  reviewedManifestSnapshot,
} = require("../../packages/bob-instrument-chameleon/lib/operations.js");

const MATRIX_VERSION = 5;
const MATRIX_ID = "chameleon_ultra_failure_and_recovery_v5";
const EXPECTED_AVAILABILITY_VARIANT_COUNT = 112;
const EXPECTED_NODE_CONTRACT_REGISTRY_SHA256 =
  "aba04a5376b5c3ba75b864166baf3d563e2cb69fdf406a113e530d41b070a99d";
const EXPECTED_EFFECT_PROFILE_REGISTRY_SHA256 =
  "c28e0ae355de1111217e63a3111c3ca369ad39aa3082b73d9d54ff5dc33fb369";
const EXPECTED_CAPABILITY_DEPENDENCY_REGISTRY_SHA256 =
  "62ae7c98a576cb3d19aeaefad5860216a89692e29ba443f94163e260fe6ecfca";
const EXPECTED_SEMANTIC_MANIFEST_SHA256 =
  "3a270fa758a365e9cb4d5fa1db9c5c2f051e4b2df9aa6dd75856826050f09c29";
const EXPECTED_CASE_ELIGIBILITY_REGISTRY_SHA256 =
  "4003aa7a56ca2683fee0f586417a06d7b992a1e8a5396d436c46aafdd511bf27";
const EXPECTED_TRANSPORT_PAIR_REGISTRY_SHA256 =
  "23353ee5ad4c324f56e2522b4f56c7b9d80160902b2ef681c0e64ca4e89cefd4";
const EXPECTED_FAILURE_CASE_COUNT = 734;
const EXPECTED_FAILURE_CASE_REGISTRY_SHA256 =
  "f0e53ee1d9f8934cc6783b400917f36f5207e94e7af32009bcf4a7600efff83a";
const EXPECTED_AVAILABILITY_VARIANT_FAILURE_REGISTRY_SHA256 =
  "90721c9619d29b7c650c97954a5b497416e0355d577e1130cc6faacdfb38e8cb";
const NODE_CONTRACT = JSON.parse(fs.readFileSync(
  path.join(__dirname, "..", "..", "docs", "plane-physical", "nodes.json"),
  "utf8",
));
const COVERAGE_CONTRACT = JSON.parse(fs.readFileSync(
  path.join(__dirname, "..", "..", "docs", "plane-physical", "coverage.json"),
  "utf8",
));
const REVIEWED_SEMANTIC_CONTRACT = reviewedManifestSnapshot();
if (!Array.isArray(NODE_CONTRACT.nodes)
    || NODE_CONTRACT.node_contract_registry_sha256
      !== EXPECTED_NODE_CONTRACT_REGISTRY_SHA256
    || reviewedDigest(canonicalNodeContracts(NODE_CONTRACT))
      !== EXPECTED_NODE_CONTRACT_REGISTRY_SHA256) {
  throw new Error("Plane-PH node contract registry drifted from the reviewed HIL matrix");
}
if (COVERAGE_CONTRACT.effect_profiles == null
    || typeof COVERAGE_CONTRACT.effect_profiles !== "object"
    || Array.isArray(COVERAGE_CONTRACT.effect_profiles)) {
  throw new Error("Plane-PH effect-profile registry is unavailable");
}
const KNOWN_NODE_IDS = new Set(NODE_CONTRACT.nodes.map((node) => node.id));
const EFFECT_PROFILE_REGISTRY = COVERAGE_CONTRACT.effect_profiles;
const EFFECT_PROFILE_IDS = Object.freeze(Object.keys(EFFECT_PROFILE_REGISTRY).sort());
const EFFECT_PROFILE_REGISTRY_SHA256 = digest(EFFECT_PROFILE_REGISTRY);
if (EFFECT_PROFILE_REGISTRY_SHA256 !== EXPECTED_EFFECT_PROFILE_REGISTRY_SHA256) {
  throw new Error("Plane-PH effect-profile registry drifted from the reviewed HIL matrix");
}
if (COVERAGE_CONTRACT.capability_dependency_registry_sha256
      !== EXPECTED_CAPABILITY_DEPENDENCY_REGISTRY_SHA256
    || reviewedDigest(canonicalCapabilityDependencies(
      COVERAGE_CONTRACT.capability_dependency_registry,
    )) !== EXPECTED_CAPABILITY_DEPENDENCY_REGISTRY_SHA256
    || canonicalJson(canonicalCapabilityDependencies(
      COVERAGE_CONTRACT.capability_dependency_registry,
    )) !== canonicalJson(canonicalCapabilityDependencies(
      REVIEWED_SEMANTIC_CONTRACT.capability_dependency_registry,
    ))
    || CHAMELEON_SEMANTIC_MANIFEST.manifest_digest !== EXPECTED_SEMANTIC_MANIFEST_SHA256) {
  throw new Error("Chameleon semantic availability registry drifted from the reviewed HIL matrix");
}
const EFFECT_FAMILY_VALUES = Object.freeze([
  "instrument.observe",
  "instrument.configure",
  "instrument.transmit",
  "target.observe",
  "target.transmit",
  "target.present",
  "target.mutate",
  "target.destroy",
  "environment.observe",
  "environment.transmit",
  "environment.actuate",
  "instrument.administer",
  "instrument.destroy",
]);
const DEFAULT_EFFECT_PROFILE_REFS = Object.freeze({
  "instrument.observe": Object.freeze(["EP-INSTRUMENT-OBSERVE-USB"]),
  "instrument.configure": Object.freeze(["EP-INSTRUMENT-CONFIGURE-USB"]),
  "instrument.transmit": Object.freeze([
    "EP-INSTRUMENT-TRANSMIT-BLE",
    "EP-INSTRUMENT-TRANSMIT-USB",
  ]),
  "target.transmit": Object.freeze(["EP-TARGET-TRANSMIT-RF"]),
  "target.present": Object.freeze(["EP-TARGET-PRESENT-RF"]),
  "target.mutate": Object.freeze(["EP-TARGET-MUTATE-RF"]),
  "target.destroy": Object.freeze(["EP-TARGET-DESTROY-RF"]),
  "environment.transmit": Object.freeze(["EP-ENVIRONMENT-TRANSMIT-RF"]),
  "instrument.administer": Object.freeze(["EP-INSTRUMENT-ADMINISTER-LOCAL"]),
  "instrument.destroy": Object.freeze(["EP-INSTRUMENT-DESTROY-USB"]),
});
const STAGES = Object.freeze([
  "rf_off",
  "shielded_active",
  "owned_media",
  "owned_maintenance_fixture",
  "cross_plane",
]);
const TERMINAL_STATES = Object.freeze([
  "rejected_no_effect",
  "restored",
  "quarantined",
  "irreversible_authorized",
  "unknown_effect",
]);
const STATUS = "pending_hil";
const IDENTIFIER_RE = /^[a-z][a-z0-9._-]{0,127}$/u;
const NODE_ID_RE = /^PH-(?:S|I|IP|P|C|X)[0-9]+$/u;
const REF_RE = /^[a-z][a-z0-9._-]{0,63}:[A-Za-z0-9][A-Za-z0-9._:-]{0,190}$/u;
const POLICY_FIELDS = Object.freeze([
  "import_is_inert",
  "cli_is_plan_only",
  "hardware_access_authorized",
  "production_ready",
  "live_hil_evidence_present",
]);
const SCENARIO_FIELDS = Object.freeze([
  "scenario_id",
  "stage",
  "case_binding_kind",
  "node_ids",
  "fault_class",
  "injection_point",
  "effect_families",
  "effect_profile_refs",
  "effectless_resolution_only",
  "terminal_classifier_id",
  "terminal_classifier_digest",
  "evidence_requirements",
  "scenario_evidence_key",
  "fixture_ref",
  "independent_witness_ref",
  "expected_terminal_states",
  "automatic_effect_retry",
  "requires_signed_evidence",
  "requires_zero_active_effects",
  "requires_residue_accounting",
  "production_nonwaivable",
  "status",
]);
const VARIANT_BINDING_FIELDS = Object.freeze([
  "capability_id",
  "variant_id",
  "availability_variant_digest",
  "disposition",
  "normalized_operations",
  "technique_bindings",
  "effect_profile_refs",
  "failure_scenario_ids",
  "failure_case_ids",
  "status",
]);
const EVIDENCE_REQUIREMENT_FIELDS = Object.freeze([
  "executor_principal_ref",
  "witness_principal_ref",
  "executor_witness_separation_required",
  "pre_state_snapshot_required",
  "backup_required",
  "exact_delta_required",
  "post_operation_inventory_required",
  "assurance_invalidation_required",
  "recovery_or_quarantine_required",
  "external_reader_required",
  "same_operation_transport_parity_required",
]);
const FAILURE_CASE_FIELDS = Object.freeze([
  "case_id",
  "case_kind",
  "capability_id",
  "variant_id",
  "availability_variant_digest",
  "operation_id",
  "technique_id",
  "effect_profile_refs",
  "transport_pair_id",
  "transport_pair_digest",
  "required_evidence_contract_refs",
  "scenario_id",
  "terminal_classifier_id",
  "evidence_key",
  "status",
]);
const EVIDENCE_CONTRACT_REF_FIELDS = Object.freeze([
  "contract_kind",
  "contract_ref",
  "must_be_signed",
  "status",
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

function reviewedDigest(value) {
  return crypto.createHash("sha256").update(JSON.stringify(value), "utf8").digest("hex");
}

function sortedStrings(value) {
  return Array.isArray(value)
    ? value.map(String).sort((left, right) => left.localeCompare(right))
    : [];
}

// These are intentionally local copies of the reviewed digest projections.
// Importing the broad design checker would make an inert HIL plan depend on a
// CLI surface; recomputing the canonical projections here catches stale digest
// fields while the focused tests keep both implementations coherent.
function canonicalNodeContracts(document) {
  return {
    version: document?.version,
    production_nonwaivable_hil_node_ids: sortedStrings(
      document?.production_nonwaivable_hil_node_ids,
    ),
    nodes: (Array.isArray(document?.nodes) ? document.nodes : [])
      .filter((node) => node != null && typeof node === "object" && !Array.isArray(node))
      .map((node) => ({
        id: node.id,
        kind: node.kind,
        title: node.title,
        action: node.action,
        phase: node.phase,
        intent: node.intent,
        anchors: sortedStrings(node.anchors),
        deliverables: sortedStrings(node.deliverables),
        predecessors: sortedStrings(node.predecessors),
        effect_surface: sortedStrings(node.effect_surface),
        engineering_gate: node.engineering_gate,
        hil_gate: node.hil_gate,
        findings: sortedStrings(node.findings),
      }))
      .sort((left, right) => String(left.id).localeCompare(String(right.id))),
  };
}

function canonicalCapabilityDependencies(registry) {
  if (registry == null || typeof registry !== "object" || Array.isArray(registry)) return [];
  const formula = (value) => ({
    all_of: sortedStrings(value?.all_of),
    any_of: (Array.isArray(value?.any_of) ? value.any_of : [])
      .map(sortedStrings)
      .sort((left, right) => JSON.stringify(left).localeCompare(JSON.stringify(right))),
  });
  return Object.entries(registry).map(([capabilityId, dependency]) => [capabilityId, {
    ...formula(dependency),
    variants: Object.entries(
      dependency?.variants != null && typeof dependency.variants === "object"
        && !Array.isArray(dependency.variants) ? dependency.variants : {},
    ).map(([variantId, variant]) => [variantId, {
      parameter_selector_id: variant?.parameter_selector_id,
      ...formula(variant),
      normalized_operations: sortedStrings(variant?.normalized_operations),
      technique_bindings: sortedStrings(variant?.technique_bindings),
      effect_profile_refs: sortedStrings(variant?.effect_profile_refs),
    }]).sort(([left], [right]) => left.localeCompare(right)),
  }]).sort(([left], [right]) => left.localeCompare(right));
}

function deepFreeze(value) {
  if (value == null || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

const TERMINAL_OBSERVATION_SCHEMA = deepFreeze({
  effect_started: ["yes", "no", "unknown"],
  active_effects: ["zero", "nonzero", "unknown"],
  independent_effect_observation: ["expected", "none", "unexpected", "unknown"],
  baseline_restoration: ["proven", "failed", "not_applicable", "unknown"],
  containment: ["proven", "failed", "not_applicable", "unknown"],
  irreversible_authorization: ["current", "absent", "not_applicable", "unknown"],
  residue_accounting: ["complete", "incomplete", "unknown"],
  witness_separation: ["proven", "failed", "unknown"],
});

function terminalClassifier(orderedRules, defaultTerminalState) {
  return deepFreeze({
    version: 1,
    evaluation: "first_matching_rule_then_default",
    observation_schema: TERMINAL_OBSERVATION_SCHEMA,
    ordered_rules: orderedRules.map((rule, index) => ({
      priority: index + 1,
      when_all: rule.when_all,
      terminal_state: rule.terminal_state,
    })),
    default_terminal_state: defaultTerminalState,
  });
}

const NO_EFFECT_RULE = deepFreeze({
  when_all: {
    effect_started: "no",
    active_effects: "zero",
    independent_effect_observation: "none",
    baseline_restoration: "not_applicable",
    containment: "not_applicable",
    irreversible_authorization: "not_applicable",
    residue_accounting: "complete",
    witness_separation: "proven",
  },
  terminal_state: "rejected_no_effect",
});
const QUARANTINE_RULE = deepFreeze({
  when_all: {
    active_effects: "zero",
    containment: "proven",
    residue_accounting: "complete",
    witness_separation: "proven",
  },
  terminal_state: "quarantined",
});
const TERMINAL_CLASSIFIER_REGISTRY = deepFreeze({
  effectless_resolution_v1: terminalClassifier([NO_EFFECT_RULE], "unknown_effect"),
  reversible_effect_v1: terminalClassifier([
    NO_EFFECT_RULE,
    {
      when_all: {
        effect_started: "yes",
        active_effects: "zero",
        independent_effect_observation: "expected",
        baseline_restoration: "proven",
        containment: "proven",
        irreversible_authorization: "not_applicable",
        residue_accounting: "complete",
        witness_separation: "proven",
      },
      terminal_state: "restored",
    },
    QUARANTINE_RULE,
  ], "unknown_effect"),
  irreversible_authorized_v1: terminalClassifier([
    NO_EFFECT_RULE,
    {
      when_all: {
        effect_started: "yes",
        active_effects: "zero",
        irreversible_authorization: "current",
        independent_effect_observation: "expected",
        baseline_restoration: "not_applicable",
        containment: "proven",
        residue_accounting: "complete",
        witness_separation: "proven",
      },
      terminal_state: "irreversible_authorized",
    },
    QUARANTINE_RULE,
  ], "unknown_effect"),
});

function terminalStatesForClassifier(classifierId) {
  const classifier = TERMINAL_CLASSIFIER_REGISTRY[classifierId];
  if (!classifier) throw new Error(`unknown terminal classifier ${classifierId}`);
  return [...new Set([
    ...classifier.ordered_rules.map((rule) => rule.terminal_state),
    classifier.default_terminal_state,
  ])].sort();
}

function classifyTerminalObservation(classifierId, observation) {
  const classifier = TERMINAL_CLASSIFIER_REGISTRY[classifierId];
  if (!classifier) throw new Error(`unknown terminal classifier ${classifierId}`);
  assertExactFields(
    observation,
    Object.keys(TERMINAL_OBSERVATION_SCHEMA),
    "terminal_observation",
  );
  for (const [field, values] of Object.entries(TERMINAL_OBSERVATION_SCHEMA)) {
    if (!values.includes(observation[field])) {
      throw new Error(`terminal_observation.${field} is outside the closed vocabulary`);
    }
  }
  const matched = classifier.ordered_rules.find((rule) => (
    Object.entries(rule.when_all).every(([field, expected]) => observation[field] === expected)
  ));
  const terminalState = matched ? matched.terminal_state : classifier.default_terminal_state;
  const body = {
    version: 1,
    classifier_id: classifierId,
    classifier_digest: digest(classifier),
    observation_digest: digest(observation),
    matched_priority: matched ? matched.priority : null,
    terminal_state: terminalState,
    execution_authority: false,
    evidence_authority: false,
  };
  return deepFreeze({ ...body, decision_digest: digest(body) });
}

function evidenceRequirementsForScenario(input, effectProfileRefs) {
  const effectful = effectProfileRefs.length > 0;
  const maintenance = input.stage === "owned_maintenance_fixture";
  const transportParity = input.fault_class === "transport_effect_semantic_drift";
  return deepFreeze({
    executor_principal_ref: input.executor_principal_ref
      || "hil-principal:enrolled-operation-executor",
    witness_principal_ref: input.witness_principal_ref
      || "hil-principal:independently-enrolled-observer",
    executor_witness_separation_required: true,
    pre_state_snapshot_required: effectful,
    backup_required: maintenance,
    exact_delta_required: effectful,
    post_operation_inventory_required: maintenance,
    assurance_invalidation_required: maintenance,
    recovery_or_quarantine_required: effectful,
    external_reader_required: input.scenario_id === "owned_media.t55xx_external_verification",
    same_operation_transport_parity_required: transportParity,
  });
}

function scenario(input) {
  const effectFamilies = [...(input.effect_families || [input.effect_family])].sort();
  const effectProfileRefs = input.effect_profile_refs || effectFamilies.flatMap((family) => {
    const refs = DEFAULT_EFFECT_PROFILE_REFS[family];
    if (!refs) throw new Error(`failure scenario has no default effect profile for ${family}`);
    return refs;
  });
  const normalizedProfileRefs = [...new Set(effectProfileRefs)].sort();
  const effectlessResolutionOnly = input.effectless_resolution_only === true;
  const destructive = normalizedProfileRefs.some((ref) => (
    EFFECT_PROFILE_REGISTRY[ref]?.action === "destroy"
  ));
  const terminalClassifierId = effectlessResolutionOnly
    ? "effectless_resolution_v1"
    : destructive
      ? "irreversible_authorized_v1"
      : "reversible_effect_v1";
  const evidenceRequirements = evidenceRequirementsForScenario(input, normalizedProfileRefs);
  if (evidenceRequirements.executor_principal_ref === evidenceRequirements.witness_principal_ref) {
    throw new Error(`failure scenario ${input.scenario_id} does not separate executor and witness`);
  }
  const body = {
    scenario_id: input.scenario_id,
    stage: input.stage,
    case_binding_kind: input.case_binding_kind || "availability_variant",
    node_ids: [...input.node_ids].sort(),
    fault_class: input.fault_class,
    injection_point: input.injection_point,
    effect_families: effectFamilies,
    effect_profile_refs: normalizedProfileRefs,
    effectless_resolution_only: effectlessResolutionOnly,
    terminal_classifier_id: terminalClassifierId,
    terminal_classifier_digest: digest(TERMINAL_CLASSIFIER_REGISTRY[terminalClassifierId]),
    evidence_requirements: evidenceRequirements,
    fixture_ref: input.fixture_ref,
    independent_witness_ref: input.independent_witness_ref,
    expected_terminal_states: terminalStatesForClassifier(terminalClassifierId),
    automatic_effect_retry: false,
    requires_signed_evidence: true,
    requires_zero_active_effects: true,
    requires_residue_accounting: true,
    production_nonwaivable: input.production_nonwaivable !== false,
    status: STATUS,
  };
  return deepFreeze({
    ...body,
    scenario_evidence_key: `hil-evidence-key:v1:${digest({
      domain: "hacker-bob/chameleon-hil-scenario-evidence/v1",
      ...body,
    })}`,
  });
}

const SCENARIOS = Object.freeze([
  scenario({
    scenario_id: "rf_off.availability_variant_formula_drift",
    stage: "rf_off",
    node_ids: ["PH-P4", "PH-X5", "PH-X6"],
    fault_class: "availability_formula_drift",
    injection_point: "before_availability_projection",
    effect_families: [],
    effect_profile_refs: [],
    effectless_resolution_only: true,
    fixture_ref: "hil-fixture:mutated-semantic-registry-copy",
    independent_witness_ref: "hil-witness:semantic-manifest-digest-verifier",
    expected_terminal_states: ["rejected_no_effect"],
  }),
  scenario({
    scenario_id: "rf_off.normalized_operation_binding_drift",
    stage: "rf_off",
    node_ids: ["PH-P4", "PH-S9", "PH-X5"],
    fault_class: "normalized_operation_binding_drift",
    injection_point: "before_semantic_selection",
    effect_families: [],
    effect_profile_refs: [],
    effectless_resolution_only: true,
    fixture_ref: "hil-fixture:mutated-operation-selector-copy",
    independent_witness_ref: "hil-witness:semantic-selection-digest-verifier",
    expected_terminal_states: ["rejected_no_effect"],
  }),
  scenario({
    scenario_id: "rf_off.technique_selector_binding_drift",
    stage: "rf_off",
    node_ids: ["PH-S9", "PH-X5", "PH-X6"],
    fault_class: "technique_selector_binding_drift",
    injection_point: "before_active_admission",
    effect_families: [],
    effect_profile_refs: [],
    effectless_resolution_only: true,
    fixture_ref: "hil-fixture:mutated-technique-selector-copy",
    independent_witness_ref: "hil-witness:capability-pack-selection-verifier",
    expected_terminal_states: ["rejected_no_effect"],
  }),
  scenario({
    scenario_id: "rf_off.agent_device_open_denied",
    stage: "rf_off",
    case_binding_kind: "infrastructure",
    node_ids: ["PH-S3", "PH-X6"],
    fault_class: "negative_principal_access",
    injection_point: "before_device_descriptor_delegation",
    effect_family: "instrument.observe",
    fixture_ref: "hil-fixture:dedicated-principal-matrix",
    independent_witness_ref: "hil-witness:kernel-device-acl-observer",
    expected_terminal_states: ["rejected_no_effect"],
  }),
  scenario({
    scenario_id: "rf_off.issuer_device_open_denied",
    stage: "rf_off",
    case_binding_kind: "infrastructure",
    node_ids: ["PH-S3", "PH-X6"],
    fault_class: "negative_principal_access",
    injection_point: "issuer_process_before_grant",
    effect_family: "instrument.observe",
    fixture_ref: "hil-fixture:dedicated-principal-matrix",
    independent_witness_ref: "hil-witness:kernel-device-acl-observer",
    expected_terminal_states: ["rejected_no_effect"],
  }),
  scenario({
    scenario_id: "rf_off.descriptor_substitution",
    stage: "rf_off",
    case_binding_kind: "infrastructure",
    node_ids: ["PH-P3", "PH-S3", "PH-X6"],
    fault_class: "descriptor_identity_drift",
    injection_point: "native_handoff_before_go",
    effect_family: "instrument.observe",
    fixture_ref: "hil-fixture:substituted-usb-descriptor",
    independent_witness_ref: "hil-witness:native-descriptor-identity",
    expected_terminal_states: ["rejected_no_effect", "quarantined"],
  }),
  scenario({
    scenario_id: "rf_off.worker_kill_before_go",
    stage: "rf_off",
    case_binding_kind: "infrastructure",
    node_ids: ["PH-S7", "PH-X7"],
    fault_class: "worker_process_death",
    injection_point: "after_durable_grant_before_commit_go",
    effect_family: "instrument.configure",
    fixture_ref: "hil-fixture:rf-off-worker-lifecycle",
    independent_witness_ref: "hil-witness:native-process-custodian",
    expected_terminal_states: ["rejected_no_effect", "quarantined"],
  }),
  scenario({
    scenario_id: "rf_off.partial_frame",
    stage: "rf_off",
    node_ids: ["PH-P2", "PH-P3", "PH-X5"],
    fault_class: "transport_partial_frame",
    injection_point: "provider_response_decoder",
    effect_family: "instrument.observe",
    fixture_ref: "hil-fixture:usb-cdc-partial-frame",
    independent_witness_ref: "hil-witness:transport-byte-recorder",
    expected_terminal_states: ["rejected_no_effect", "quarantined"],
  }),
  scenario({
    scenario_id: "rf_off.response_timeout",
    stage: "rf_off",
    node_ids: ["PH-P3", "PH-S7", "PH-X5"],
    fault_class: "transport_timeout",
    injection_point: "bootstrap_response_deadline",
    effect_family: "instrument.observe",
    fixture_ref: "hil-fixture:usb-cdc-timeout",
    independent_witness_ref: "hil-witness:trusted-monotonic-clock",
    expected_terminal_states: ["rejected_no_effect", "quarantined"],
  }),
  scenario({
    scenario_id: "rf_off.disconnect_during_inventory",
    stage: "rf_off",
    node_ids: ["PH-P7", "PH-S7", "PH-X5"],
    fault_class: "device_disconnect",
    injection_point: "between_bootstrap_commands",
    effect_family: "instrument.observe",
    fixture_ref: "hil-fixture:usb-disconnect-relay",
    independent_witness_ref: "hil-witness:usb-topology-observer",
    expected_terminal_states: ["rejected_no_effect", "quarantined"],
  }),
  scenario({
    scenario_id: "rf_off.lease_expiry_before_effect",
    stage: "rf_off",
    node_ids: ["PH-S7", "PH-S11", "PH-X6"],
    fault_class: "lease_expiry",
    injection_point: "final_provider_seam",
    effect_family: "instrument.configure",
    fixture_ref: "hil-fixture:trusted-clock-expiry",
    independent_witness_ref: "hil-witness:lease-journal-reader",
    expected_terminal_states: ["rejected_no_effect", "quarantined"],
  }),
  scenario({
    scenario_id: "rf_off.workspace_slot_drift",
    stage: "rf_off",
    node_ids: ["PH-P5", "PH-X6"],
    fault_class: "workspace_state_drift",
    injection_point: "post_snapshot_pre_dispatch",
    effect_family: "instrument.configure",
    fixture_ref: "hil-fixture:owned-chameleon-workspace",
    independent_witness_ref: "hil-witness:workspace-state-reader",
    expected_terminal_states: ["rejected_no_effect", "restored", "quarantined"],
  }),
  scenario({
    scenario_id: "rf_off.vault_quota_exhaustion",
    stage: "rf_off",
    case_binding_kind: "infrastructure",
    node_ids: ["PH-S5", "PH-X5"],
    fault_class: "evidence_sink_unavailable",
    injection_point: "pre_stimulus_artifact_reservation",
    effect_family: "instrument.observe",
    fixture_ref: "hil-fixture:bounded-vault-quota",
    independent_witness_ref: "hil-witness:vault-capacity-ledger",
    expected_terminal_states: ["rejected_no_effect"],
  }),
  scenario({
    scenario_id: "rf_off.vault_corruption",
    stage: "rf_off",
    case_binding_kind: "infrastructure",
    node_ids: ["PH-S5", "PH-X5"],
    fault_class: "evidence_store_corruption",
    injection_point: "artifact_readback_before_receipt",
    effect_family: "instrument.observe",
    fixture_ref: "hil-fixture:corrupt-ciphertext-copy",
    independent_witness_ref: "hil-witness:vault-anchor-reader",
    expected_terminal_states: ["quarantined"],
  }),
  scenario({
    scenario_id: "rf_off.usb_ble_transport_parity",
    stage: "rf_off",
    case_binding_kind: "transport_pair",
    node_ids: ["PH-P3", "PH-P6", "PH-X5"],
    fault_class: "transport_effect_semantic_drift",
    injection_point: "equivalent_inventory_operation_over_usb_and_ble",
    effect_family: "instrument.transmit",
    fixture_ref: "hil-fixture:rf-off-dual-transport-instrument",
    independent_witness_ref: "hil-witness:transport-byte-and-state-observer",
    expected_terminal_states: ["rejected_no_effect", "restored", "quarantined", "unknown_effect"],
  }),
  scenario({
    scenario_id: "shielded.worker_kill_after_go",
    stage: "shielded_active",
    node_ids: ["PH-S7", "PH-X5", "PH-X7"],
    fault_class: "worker_process_death",
    injection_point: "after_commit_go_during_rf_effect",
    effect_family: "target.transmit",
    fixture_ref: "hil-fixture:shielded-non-target-rf-load",
    independent_witness_ref: "hil-witness:external-rf-power-observer",
    expected_terminal_states: ["restored", "quarantined", "unknown_effect"],
  }),
  scenario({
    scenario_id: "shielded.observer_loss",
    stage: "shielded_active",
    node_ids: ["PH-C8", "PH-X5", "PH-X7"],
    fault_class: "independent_observer_loss",
    injection_point: "positive_observation_window",
    effect_family: "target.transmit",
    fixture_ref: "hil-fixture:shielded-non-target-rf-load",
    independent_witness_ref: "hil-witness:observer-heartbeat-recorder",
    expected_terminal_states: ["restored", "quarantined", "unknown_effect"],
  }),
  scenario({
    scenario_id: "shielded.lost_provider_acknowledgement",
    stage: "shielded_active",
    node_ids: ["PH-S3", "PH-S7", "PH-X5"],
    fault_class: "ambiguous_acknowledgement",
    injection_point: "after_durable_completion_before_broker_reply",
    effect_family: "target.transmit",
    fixture_ref: "hil-fixture:shielded-non-target-rf-load",
    independent_witness_ref: "hil-witness:durable-outbox-reader",
    expected_terminal_states: ["restored", "quarantined", "unknown_effect"],
  }),
  scenario({
    scenario_id: "shielded.usb_ble_target_transmit_parity",
    stage: "shielded_active",
    node_ids: ["PH-P6", "PH-X5"],
    fault_class: "transport_effect_semantic_drift",
    injection_point: "equivalent_discovery_operation_over_usb_and_ble",
    effect_family: "target.transmit",
    fixture_ref: "hil-fixture:shielded-dual-transport-rf-load",
    independent_witness_ref: "hil-witness:transport-independent-target-observer",
    expected_terminal_states: ["restored", "quarantined", "unknown_effect"],
  }),
  scenario({
    scenario_id: "shielded.environment_rf_containment",
    stage: "shielded_active",
    node_ids: ["PH-P5", "PH-X5"],
    fault_class: "environment_envelope_drift",
    injection_point: "rf_session_field_boundary",
    effect_family: "environment.transmit",
    fixture_ref: "hil-fixture:shielded-environment-rf-load",
    independent_witness_ref: "hil-witness:external-rf-zone-observer",
    expected_terminal_states: ["restored", "quarantined", "unknown_effect"],
  }),
  scenario({
    scenario_id: "shielded.manual_environment_transmit",
    stage: "shielded_active",
    node_ids: ["PH-P9", "PH-C6", "PH-X5"],
    fault_class: "manual_action_witness_drift",
    injection_point: "operator_field_generator_invocation",
    effect_family: "environment.transmit",
    effect_profile_refs: ["EP-ENVIRONMENT-TRANSMIT-RF-MANUAL"],
    fixture_ref: "hil-fixture:owned-manual-field-generator-load",
    independent_witness_ref: "hil-witness:operator-independent-rf-observer",
    expected_terminal_states: ["restored", "quarantined", "unknown_effect"],
  }),
  scenario({
    scenario_id: "owned_media.write_failure",
    stage: "owned_media",
    node_ids: ["PH-C5", "PH-S7", "PH-X5"],
    fault_class: "partial_persistent_write",
    injection_point: "owned_media_write_sequence",
    effect_family: "target.mutate",
    fixture_ref: "hil-fixture:owned-rewritable-rfid-media",
    independent_witness_ref: "hil-witness:independent-media-reader",
    expected_terminal_states: ["restored", "quarantined", "unknown_effect"],
  }),
  scenario({
    scenario_id: "owned_media.t55xx_external_verification",
    stage: "owned_media",
    node_ids: ["PH-C5", "PH-X5"],
    fault_class: "write_only_provider_ack",
    injection_point: "post_write_verification",
    effect_family: "target.mutate",
    fixture_ref: "hil-fixture:owned-t55xx-media",
    independent_witness_ref: "hil-witness:assurance-qualified-t55xx-reader",
    expected_terminal_states: ["restored", "quarantined", "unknown_effect"],
  }),
  scenario({
    scenario_id: "owned_media.usb_ble_effect_parity",
    stage: "owned_media",
    node_ids: ["PH-P6", "PH-X5"],
    fault_class: "transport_effect_semantic_drift",
    injection_point: "equivalent_closed_operation_over_usb_and_ble",
    effect_family: "target.present",
    fixture_ref: "hil-fixture:owned-dual-transport-media",
    independent_witness_ref: "hil-witness:transport-independent-target-observer",
    expected_terminal_states: ["restored", "quarantined", "unknown_effect"],
  }),
  scenario({
    scenario_id: "owned_media.usb_ble_target_mutate_parity",
    stage: "owned_media",
    node_ids: ["PH-P6", "PH-C5", "PH-X5"],
    fault_class: "transport_effect_semantic_drift",
    injection_point: "equivalent_reversible_write_over_usb_and_ble",
    effect_family: "target.mutate",
    fixture_ref: "hil-fixture:owned-dual-transport-rewritable-media",
    independent_witness_ref: "hil-witness:independent-media-reader",
    expected_terminal_states: ["restored", "quarantined", "unknown_effect"],
  }),
  scenario({
    scenario_id: "owned_media.usb_ble_stateful_mutate_parity",
    stage: "owned_media",
    node_ids: ["PH-P6", "PH-C5", "PH-X5"],
    fault_class: "transport_effect_semantic_drift",
    injection_point: "equivalent_bounded_counter_operation_over_usb_and_ble",
    effect_family: "target.mutate",
    effect_profile_refs: ["EP-TARGET-MUTATE-RF-STATEFUL"],
    fixture_ref: "hil-fixture:owned-stateful-counter-media",
    independent_witness_ref: "hil-witness:independent-counter-and-log-reader",
    expected_terminal_states: ["restored", "quarantined", "unknown_effect"],
  }),
  scenario({
    scenario_id: "owned_media.usb_ble_target_destroy_parity",
    stage: "owned_media",
    node_ids: ["PH-P6", "PH-C5", "PH-X5"],
    fault_class: "transport_effect_semantic_drift",
    injection_point: "equivalent_authorized_destroy_variant_over_usb_and_ble",
    effect_family: "target.destroy",
    fixture_ref: "hil-fixture:owned-disposable-dual-transport-media",
    independent_witness_ref: "hil-witness:independent-terminal-media-reader",
    expected_terminal_states: ["irreversible_authorized", "quarantined", "unknown_effect"],
  }),
  scenario({
    scenario_id: "owned_media.manual_target_transmit_and_configure",
    stage: "owned_media",
    node_ids: ["PH-P9", "PH-C2", "PH-X5"],
    fault_class: "manual_action_witness_drift",
    injection_point: "operator_clone_button_invocation",
    effect_families: ["instrument.configure", "target.transmit"],
    effect_profile_refs: [
      "EP-INSTRUMENT-CONFIGURE-MANUAL",
      "EP-TARGET-TRANSMIT-RF-MANUAL",
    ],
    fixture_ref: "hil-fixture:owned-manual-clone-source-and-workspace",
    independent_witness_ref: "hil-witness:operator-independent-source-and-state-reader",
    expected_terminal_states: ["restored", "quarantined", "unknown_effect"],
  }),
  scenario({
    scenario_id: "maintenance.settings_recovery",
    stage: "owned_maintenance_fixture",
    node_ids: ["PH-P9", "PH-X5"],
    fault_class: "maintenance_state_drift",
    injection_point: "post_settings_delta_inventory",
    effect_family: "instrument.administer",
    fixture_ref: "hil-fixture:owned-chameleon-maintenance-unit",
    independent_witness_ref: "hil-witness:maintenance-state-observer",
    expected_terminal_states: ["restored", "quarantined"],
  }),
  scenario({
    scenario_id: "maintenance.ble_pairing_recovery",
    stage: "owned_maintenance_fixture",
    node_ids: ["PH-P6", "PH-P9", "PH-X5"],
    fault_class: "maintenance_state_drift",
    injection_point: "post_ble_pairing_delta_inventory",
    effect_family: "instrument.administer",
    effect_profile_refs: ["EP-INSTRUMENT-ADMINISTER-BLE"],
    fixture_ref: "hil-fixture:owned-chameleon-ble-maintenance-unit",
    independent_witness_ref: "hil-witness:ble-bond-and-advertising-state-observer",
    expected_terminal_states: ["restored", "quarantined", "unknown_effect"],
  }),
  scenario({
    scenario_id: "maintenance.dfu_interruption",
    stage: "owned_maintenance_fixture",
    node_ids: ["PH-P9", "PH-X5"],
    fault_class: "firmware_update_interruption",
    injection_point: "dfu_transfer_before_terminal_inventory",
    effect_family: "instrument.administer",
    fixture_ref: "hil-fixture:owned-chameleon-maintenance-unit",
    independent_witness_ref: "hil-witness:maintenance-state-observer",
    expected_terminal_states: ["restored", "quarantined", "unknown_effect"],
  }),
  scenario({
    scenario_id: "maintenance.authorized_erase",
    stage: "owned_maintenance_fixture",
    node_ids: ["PH-P9", "PH-X5"],
    fault_class: "irreversible_fixture_erase",
    injection_point: "fds_erase_terminal_state",
    effect_family: "instrument.destroy",
    fixture_ref: "hil-fixture:owned-disposable-chameleon-maintenance-unit",
    independent_witness_ref: "hil-witness:independent-maintenance-terminal-state-reader",
    expected_terminal_states: ["irreversible_authorized", "quarantined", "unknown_effect"],
  }),
  scenario({
    scenario_id: "cross_plane.custody_drift_before_downstream_consumption",
    stage: "cross_plane",
    node_ids: ["PH-C9", "PH-I5", "PH-X5"],
    fault_class: "capability_custody_drift",
    injection_point: "after_physical_verdict_before_downstream_execution",
    effect_family: "target.present",
    fixture_ref: "hil-fixture:owned-physical-to-cyber-composition",
    independent_witness_ref: "hil-witness:downstream-consumption-verifier",
    expected_terminal_states: ["rejected_no_effect", "restored", "quarantined"],
  }),
]);

// This reviewed relation is deliberately narrower than the variant declarations.
// A variant can expose several normalized operations and effect profiles without
// every operation being capable of producing every effect. Failure cases are
// emitted only for the exact scenario/profile/operation tuples listed here.
const OBSERVE_USB_OPERATIONS = Object.freeze([
  "emulator.profile_observe",
  "instrument.capabilities",
  "instrument.enrollment_match",
  "instrument.health",
  "instrument.identity_observe",
  "instrument.inventory",
  "protocol.diagnostics_observe",
  "reader_profile.observe",
  "workspace.snapshot",
]);
const CONFIGURE_USB_OPERATIONS = Object.freeze([
  "emulator.configure",
  "emulator.profile_configure",
  "instrument.restore",
  "reader_profile.configure",
  "representation.stage",
  "response_profile.stage",
  "rf_session.acquire",
  "rf_session.release",
  "workspace.restore",
]);
const TARGET_TRANSMIT_OPERATIONS = Object.freeze([
  "protocol.apdu_exchange",
  "protocol.authenticate",
  "protocol.challenge_collect",
  "protocol.compiled_exchange",
  "protocol.discover",
  "protocol.discovery_probe",
  "protocol.transceive",
  "rf_session.acquire",
  "signal.capture",
]);
const TARGET_PRESENT_OPERATIONS = Object.freeze([
  "emulator.present",
  "protocol.compiled_responder",
  "protocol.respond",
  "rf_session.acquire",
]);
const TARGET_STATEFUL_MUTATE_OPERATIONS = Object.freeze([
  "protocol.apdu_exchange",
  "protocol.authenticate",
  "protocol.compiled_exchange",
  "protocol.transceive",
]);
const TARGET_DESTROY_OPERATIONS = Object.freeze([
  "protocol.apdu_exchange",
  "protocol.authenticate",
  "protocol.transceive",
  "representation.write",
]);
const SCENARIO_OPERATION_ELIGIBILITY = deepFreeze({
  "rf_off.partial_frame": {
    "EP-INSTRUMENT-OBSERVE-USB": OBSERVE_USB_OPERATIONS,
  },
  "rf_off.response_timeout": {
    "EP-INSTRUMENT-OBSERVE-USB": OBSERVE_USB_OPERATIONS,
  },
  "rf_off.disconnect_during_inventory": {
    "EP-INSTRUMENT-OBSERVE-USB": [
      "instrument.capabilities",
      "instrument.enrollment_match",
      "instrument.health",
      "instrument.identity_observe",
      "instrument.inventory",
    ],
  },
  "rf_off.lease_expiry_before_effect": {
    "EP-INSTRUMENT-CONFIGURE-USB": CONFIGURE_USB_OPERATIONS,
  },
  "rf_off.workspace_slot_drift": {
    "EP-INSTRUMENT-CONFIGURE-USB": ["workspace.restore"],
  },
  "rf_off.usb_ble_transport_parity": {
    "EP-INSTRUMENT-TRANSMIT-BLE": ["transport.exchange"],
    "EP-INSTRUMENT-TRANSMIT-USB": ["transport.exchange"],
  },
  "shielded.worker_kill_after_go": {
    "EP-TARGET-TRANSMIT-RF": TARGET_TRANSMIT_OPERATIONS,
  },
  "shielded.observer_loss": {
    "EP-TARGET-TRANSMIT-RF": TARGET_TRANSMIT_OPERATIONS,
  },
  "shielded.lost_provider_acknowledgement": {
    "EP-TARGET-TRANSMIT-RF": TARGET_TRANSMIT_OPERATIONS,
  },
  "shielded.usb_ble_target_transmit_parity": {
    "EP-TARGET-TRANSMIT-RF": TARGET_TRANSMIT_OPERATIONS,
  },
  "shielded.environment_rf_containment": {
    "EP-ENVIRONMENT-TRANSMIT-RF": ["rf_session.acquire"],
  },
  "shielded.manual_environment_transmit": {
    "EP-ENVIRONMENT-TRANSMIT-RF-MANUAL": ["instrument.manual_action"],
  },
  "owned_media.write_failure": {
    "EP-TARGET-MUTATE-RF": ["representation.write"],
  },
  "owned_media.t55xx_external_verification": {
    "EP-TARGET-MUTATE-RF": ["representation.write"],
  },
  "owned_media.usb_ble_effect_parity": {
    "EP-TARGET-PRESENT-RF": TARGET_PRESENT_OPERATIONS,
  },
  "owned_media.usb_ble_target_mutate_parity": {
    "EP-TARGET-MUTATE-RF": ["representation.write"],
  },
  "owned_media.usb_ble_stateful_mutate_parity": {
    "EP-TARGET-MUTATE-RF-STATEFUL": TARGET_STATEFUL_MUTATE_OPERATIONS,
  },
  "owned_media.usb_ble_target_destroy_parity": {
    "EP-TARGET-DESTROY-RF": TARGET_DESTROY_OPERATIONS,
  },
  "owned_media.manual_target_transmit_and_configure": {
    "EP-INSTRUMENT-CONFIGURE-MANUAL": ["instrument.manual_action"],
    "EP-TARGET-TRANSMIT-RF-MANUAL": ["instrument.manual_action"],
  },
  "maintenance.settings_recovery": {
    "EP-INSTRUMENT-ADMINISTER-LOCAL": ["instrument.admin_configure"],
  },
  "maintenance.ble_pairing_recovery": {
    "EP-INSTRUMENT-ADMINISTER-BLE": ["instrument.admin_configure"],
  },
  "maintenance.dfu_interruption": {
    "EP-INSTRUMENT-ADMINISTER-LOCAL": ["instrument.firmware_manage"],
  },
  "maintenance.authorized_erase": {
    "EP-INSTRUMENT-DESTROY-USB": ["instrument.erase"],
  },
  "cross_plane.custody_drift_before_downstream_consumption": {
    "EP-TARGET-PRESENT-RF": TARGET_PRESENT_OPERATIONS,
  },
});

function reviewedAvailabilityVariants() {
  const variants = [];
  const dependencies = COVERAGE_CONTRACT.capability_dependency_registry;
  for (const capabilityId of Object.keys(dependencies).sort()) {
    for (const variantId of Object.keys(dependencies[capabilityId].variants).sort()) {
      const variant = getChameleonAvailabilityVariant(capabilityId, variantId);
      if (!variant) {
        throw new Error(`reviewed availability variant ${capabilityId}/${variantId} is unresolved`);
      }
      variants.push(variant);
    }
  }
  if (variants.length !== EXPECTED_AVAILABILITY_VARIANT_COUNT) {
    throw new Error("reviewed availability variant count drifted from the PH-X5 plan");
  }
  return Object.freeze(variants);
}

const REVIEWED_AVAILABILITY_VARIANTS = reviewedAvailabilityVariants();

const SCENARIO_CAPABILITY_ELIGIBILITY = deepFreeze({
  "owned_media.t55xx_external_verification": ["CU-LF-T55XX-WRITE"],
});
const CASE_ELIGIBILITY_REGISTRY = deepFreeze({
  scenario_operation_eligibility: SCENARIO_OPERATION_ELIGIBILITY,
  scenario_capability_eligibility: SCENARIO_CAPABILITY_ELIGIBILITY,
});

function transportEndpoint(capabilityId, variantId, channel, effectProfileRef) {
  const variant = getChameleonAvailabilityVariant(capabilityId, variantId);
  if (!variant
      || !variant.normalized_operations.includes("transport.exchange")
      || !variant.effect_profile_refs.includes(effectProfileRef)) {
    throw new Error(`transport endpoint ${capabilityId}/${variantId} drifted`);
  }
  return deepFreeze({
    capability_id: capabilityId,
    variant_id: variantId,
    availability_variant_digest: variant.availability_variant_digest,
    channel,
    effect_profile_ref: effectProfileRef,
  });
}

function transportPair(input) {
  const body = {
    pair_id: input.pair_id,
    provider_id: "chameleon_ultra",
    operation_id: "transport.exchange",
    endpoints: [...input.endpoints].sort((left, right) => left.channel.localeCompare(right.channel)),
    same_request_or_compiled_command_required: true,
    same_effect_contract_required: true,
    attempt_receipt_per_endpoint_required: true,
    signed_pair_comparison_verdict_required: true,
    status: STATUS,
  };
  return deepFreeze({ ...body, pair_digest: digest(body) });
}

const TRANSPORT_PAIR_REGISTRY = deepFreeze({
  "transport-pair:chameleon-ultra.usb-ble.v1": transportPair({
    pair_id: "transport-pair:chameleon-ultra.usb-ble.v1",
    endpoints: [
      transportEndpoint(
        "CU-TRANSPORT-USB",
        "default",
        "usb",
        "EP-INSTRUMENT-TRANSMIT-USB",
      ),
      transportEndpoint(
        "CU-TRANSPORT-BLE",
        "default",
        "ble",
        "EP-INSTRUMENT-TRANSMIT-BLE",
      ),
    ],
  }),
});
const CHAMELEON_USB_BLE_PAIR =
  TRANSPORT_PAIR_REGISTRY["transport-pair:chameleon-ultra.usb-ble.v1"];

function exactOperationIdsForVariantScenario(variant, scenarioRow) {
  const relation = SCENARIO_OPERATION_ELIGIBILITY[scenarioRow.scenario_id];
  if (!relation) return [];
  const capabilityIds = SCENARIO_CAPABILITY_ELIGIBILITY[scenarioRow.scenario_id];
  if (capabilityIds && !capabilityIds.includes(variant.capability_id)) return [];
  if (!scenarioRow.effect_profile_refs.every((ref) => (
    variant.effect_profile_refs.includes(ref) && Array.isArray(relation[ref])
  ))) return [];
  return variant.normalized_operations.filter((operationId) => (
    scenarioRow.effect_profile_refs.every((ref) => relation[ref].includes(operationId))
  )).sort();
}

function pairBindsVariant(pair, variant) {
  return pair.endpoints.some((endpoint) => (
    endpoint.availability_variant_digest === variant.availability_variant_digest
  ));
}

function failureScenarioIdsForVariant(variant) {
  const scenarioIds = new Set([
    "rf_off.availability_variant_formula_drift",
    "rf_off.normalized_operation_binding_drift",
  ]);
  if (variant.technique_bindings.length > 0) {
    scenarioIds.add("rf_off.technique_selector_binding_drift");
  }
  for (const scenarioRow of SCENARIOS) {
    if (scenarioRow.case_binding_kind === "availability_variant"
        && exactOperationIdsForVariantScenario(variant, scenarioRow).length > 0) {
      scenarioIds.add(scenarioRow.scenario_id);
    }
    if (scenarioRow.case_binding_kind === "transport_pair"
        && pairBindsVariant(CHAMELEON_USB_BLE_PAIR, variant)) {
      scenarioIds.add(scenarioRow.scenario_id);
    }
  }
  return [...scenarioIds].sort();
}

const SCENARIO_BY_ID = new Map(SCENARIOS.map((row) => [row.scenario_id, row]));

function makeFailureCase(input) {
  const scenarioRow = SCENARIO_BY_ID.get(input.scenario_id);
  if (!scenarioRow) throw new Error(`failure case names unknown scenario ${input.scenario_id}`);
  const identitySeed = {
    case_kind: input.case_kind,
    capability_id: input.capability_id ?? null,
    variant_id: input.variant_id ?? null,
    availability_variant_digest: input.availability_variant_digest ?? null,
    operation_id: input.operation_id ?? null,
    technique_id: input.technique_id ?? null,
    effect_profile_refs: [...(input.effect_profile_refs || [])].sort(),
    transport_pair_id: input.transport_pair?.pair_id || null,
    transport_pair_digest: input.transport_pair?.pair_digest || null,
    scenario_id: input.scenario_id,
    terminal_classifier_id: scenarioRow.terminal_classifier_id,
    status: STATUS,
  };
  const contractKinds = [];
  const requirements = scenarioRow.evidence_requirements;
  if (requirements.pre_state_snapshot_required) contractKinds.push("pre_state_snapshot");
  if (requirements.backup_required) contractKinds.push("backup");
  if (requirements.exact_delta_required) contractKinds.push("exact_delta");
  if (requirements.post_operation_inventory_required) {
    contractKinds.push("post_operation_inventory");
  }
  if (requirements.assurance_invalidation_required) {
    contractKinds.push("assurance_invalidation");
  }
  if (requirements.recovery_or_quarantine_required) {
    contractKinds.push("recovery_or_quarantine");
  }
  if (requirements.external_reader_required) contractKinds.push("external_reader_verdict");
  if (input.transport_pair) {
    for (const endpoint of input.transport_pair.endpoints) {
      contractKinds.push(`transport_attempt_receipt_${endpoint.channel}`);
    }
    contractKinds.push("transport_pair_comparison_verdict");
  }
  const contractSeed = digest({
    domain: "hacker-bob/chameleon-hil-evidence-contract-seed/v1",
    identity_seed: identitySeed,
    scenario_evidence_key: scenarioRow.scenario_evidence_key,
  });
  const requiredEvidenceContractRefs = [...new Set(contractKinds)].sort().map((contractKind) => (
    deepFreeze({
      contract_kind: contractKind,
      contract_ref: `hil-contract:v1.${digest({ contract_seed: contractSeed, contract_kind: contractKind })}`,
      must_be_signed: true,
      status: STATUS,
    })
  ));
  const basis = {
    ...identitySeed,
    required_evidence_contract_refs: requiredEvidenceContractRefs,
  };
  const caseId = `hil-case:v2:${digest({
    domain: "hacker-bob/chameleon-hil-failure-case/v2",
    ...basis,
  })}`;
  return deepFreeze({
    case_id: caseId,
    ...basis,
    evidence_key: `hil-evidence-key:v2:${digest({
      domain: "hacker-bob/chameleon-hil-case-evidence/v2",
      case_id: caseId,
      scenario_evidence_key: scenarioRow.scenario_evidence_key,
    })}`,
  });
}

function buildFailureCases() {
  const casesByIdentity = new Map();
  const add = (input) => {
    const failureCase = makeFailureCase(input);
    if (casesByIdentity.has(failureCase.case_id)) {
      throw new Error(`duplicate exact failure case ${failureCase.case_id}`);
    }
    casesByIdentity.set(failureCase.case_id, failureCase);
  };
  for (const scenarioRow of SCENARIOS) {
    if (scenarioRow.case_binding_kind !== "infrastructure") continue;
    add({
      case_kind: "infrastructure_failure",
      capability_id: null,
      variant_id: null,
      availability_variant_digest: null,
      operation_id: null,
      technique_id: null,
      effect_profile_refs: [],
      scenario_id: scenarioRow.scenario_id,
    });
  }
  for (const scenarioRow of SCENARIOS.filter(
    (row) => row.case_binding_kind === "transport_pair",
  )) {
    add({
      case_kind: "paired_transport_parity",
      operation_id: CHAMELEON_USB_BLE_PAIR.operation_id,
      effect_profile_refs: scenarioRow.effect_profile_refs,
      transport_pair: CHAMELEON_USB_BLE_PAIR,
      scenario_id: scenarioRow.scenario_id,
    });
  }
  for (const variant of REVIEWED_AVAILABILITY_VARIANTS) {
    add({
      case_kind: "availability_formula",
      capability_id: variant.capability_id,
      variant_id: variant.variant_id,
      availability_variant_digest: variant.availability_variant_digest,
      operation_id: null,
      technique_id: null,
      effect_profile_refs: [],
      scenario_id: "rf_off.availability_variant_formula_drift",
    });
    for (const operationId of variant.normalized_operations) {
      add({
        case_kind: "operation_binding",
        capability_id: variant.capability_id,
        variant_id: variant.variant_id,
        availability_variant_digest: variant.availability_variant_digest,
        operation_id: operationId,
        technique_id: null,
        effect_profile_refs: [],
        scenario_id: "rf_off.normalized_operation_binding_drift",
      });
    }
    for (const techniqueId of variant.technique_bindings) {
      add({
        case_kind: "technique_binding",
        capability_id: variant.capability_id,
        variant_id: variant.variant_id,
        availability_variant_digest: variant.availability_variant_digest,
        operation_id: null,
        technique_id: techniqueId,
        effect_profile_refs: [],
        scenario_id: "rf_off.technique_selector_binding_drift",
      });
    }
    for (const scenarioRow of SCENARIOS.filter(
      (row) => row.case_binding_kind === "availability_variant"
        && row.effect_profile_refs.length > 0,
    )) {
      const operationIds = exactOperationIdsForVariantScenario(variant, scenarioRow);
      if (operationIds.length === 0) continue;
      const caseKind = scenarioRow.evidence_requirements.external_reader_required
        ? "external_reader_verification"
        : scenarioRow.evidence_requirements.same_operation_transport_parity_required
          ? "same_operation_transport_parity"
          : scenarioRow.stage === "owned_maintenance_fixture"
            ? "maintenance_failure"
            : "effect_failure";
      for (const operationId of operationIds) {
        add({
          case_kind: caseKind,
          capability_id: variant.capability_id,
          variant_id: variant.variant_id,
          availability_variant_digest: variant.availability_variant_digest,
          operation_id: operationId,
          technique_id: null,
          effect_profile_refs: scenarioRow.effect_profile_refs,
          transport_pair: scenarioRow.evidence_requirements.same_operation_transport_parity_required
            ? CHAMELEON_USB_BLE_PAIR
            : null,
          scenario_id: scenarioRow.scenario_id,
        });
      }
    }
  }
  return deepFreeze([...casesByIdentity.values()].sort(
    (left, right) => left.case_id.localeCompare(right.case_id),
  ));
}

function buildVariantFailureBindings(failureCases) {
  return deepFreeze(REVIEWED_AVAILABILITY_VARIANTS.map((variant) => ({
    capability_id: variant.capability_id,
    variant_id: variant.variant_id,
    availability_variant_digest: variant.availability_variant_digest,
    disposition: variant.disposition,
    normalized_operations: [...variant.normalized_operations],
    technique_bindings: [...variant.technique_bindings],
    effect_profile_refs: [...variant.effect_profile_refs],
    failure_scenario_ids: failureScenarioIdsForVariant(variant),
    failure_case_ids: failureCases.filter((failureCase) => (
      failureCase.availability_variant_digest === variant.availability_variant_digest
      || (failureCase.transport_pair_id != null
        && pairBindsVariant(CHAMELEON_USB_BLE_PAIR, variant))
    )).map((failureCase) => failureCase.case_id).sort(),
    status: STATUS,
  })));
}

function assertString(value, pattern, label) {
  if (typeof value !== "string" || !pattern.test(value)) throw new Error(`${label} is invalid`);
}

function assertExactFields(value, expected, label) {
  if (value == null || typeof value !== "object" || Array.isArray(value)
      || canonicalJson(Object.keys(value).sort()) !== canonicalJson([...expected].sort())) {
    throw new Error(`${label} has an open schema`);
  }
}

const FAILURE_MATRIX_BODY_FIELDS = Object.freeze([
  "version",
  "matrix_id",
  "provider_id",
  "node_contract_registry_sha256",
  "effect_profile_registry_sha256",
  "capability_dependency_registry_sha256",
  "semantic_manifest_sha256",
  "terminal_classifier_registry_sha256",
  "terminal_classifier_registry",
  "scenario_registry_sha256",
  "case_eligibility_registry_sha256",
  "case_eligibility_registry",
  "transport_pair_registry_sha256",
  "transport_pair_registry",
  "availability_variant_count",
  "failure_case_count",
  "failure_case_registry_sha256",
  "availability_variant_failure_registry_sha256",
  "execution_policy",
  "scenarios",
  "failure_cases",
  "variant_failure_bindings",
]);

function validateFailureMatrixBody(input) {
  if (input == null || typeof input !== "object" || Array.isArray(input)) {
    throw new Error("failure matrix must be an object");
  }
  if (canonicalJson(Object.keys(input).sort())
      !== canonicalJson([...FAILURE_MATRIX_BODY_FIELDS].sort())) {
    throw new Error("failure matrix has an open schema");
  }
  if (input.version !== MATRIX_VERSION || input.matrix_id !== MATRIX_ID
      || input.provider_id !== "chameleon_ultra") {
    throw new Error("failure matrix identity is invalid");
  }
  if (input.node_contract_registry_sha256 !== EXPECTED_NODE_CONTRACT_REGISTRY_SHA256
      || input.effect_profile_registry_sha256 !== EFFECT_PROFILE_REGISTRY_SHA256
      || input.capability_dependency_registry_sha256
        !== EXPECTED_CAPABILITY_DEPENDENCY_REGISTRY_SHA256
      || input.semantic_manifest_sha256 !== EXPECTED_SEMANTIC_MANIFEST_SHA256
      || input.availability_variant_count !== EXPECTED_AVAILABILITY_VARIANT_COUNT) {
    throw new Error("failure matrix registry binding is invalid");
  }
  if (canonicalJson(input.terminal_classifier_registry)
        !== canonicalJson(TERMINAL_CLASSIFIER_REGISTRY)
      || input.terminal_classifier_registry_sha256 !== digest(TERMINAL_CLASSIFIER_REGISTRY)) {
    throw new Error("failure matrix terminal classifier registry is invalid");
  }
  if (input.scenario_registry_sha256 !== digest(SCENARIOS)
      || canonicalJson(input.scenarios) !== canonicalJson(SCENARIOS)) {
    throw new Error("failure matrix scenarios drifted from the exact reviewed registry");
  }
  if (digest(CASE_ELIGIBILITY_REGISTRY) !== EXPECTED_CASE_ELIGIBILITY_REGISTRY_SHA256
      || input.case_eligibility_registry_sha256
        !== EXPECTED_CASE_ELIGIBILITY_REGISTRY_SHA256
      || canonicalJson(input.case_eligibility_registry)
        !== canonicalJson(CASE_ELIGIBILITY_REGISTRY)) {
    throw new Error("failure matrix case eligibility relation drifted");
  }
  if (digest(TRANSPORT_PAIR_REGISTRY) !== EXPECTED_TRANSPORT_PAIR_REGISTRY_SHA256
      || input.transport_pair_registry_sha256
        !== EXPECTED_TRANSPORT_PAIR_REGISTRY_SHA256
      || canonicalJson(input.transport_pair_registry)
        !== canonicalJson(TRANSPORT_PAIR_REGISTRY)) {
    throw new Error("failure matrix transport-pair registry drifted");
  }
  const policy = input.execution_policy;
  assertExactFields(policy, POLICY_FIELDS, "failure_matrix.execution_policy");
  if (policy.import_is_inert !== true || policy.cli_is_plan_only !== true
      || policy.hardware_access_authorized !== false || policy.production_ready !== false
      || policy.live_hil_evidence_present !== false) {
    throw new Error("failure matrix must remain inert and non-authorizing");
  }
  if (!Array.isArray(input.scenarios) || input.scenarios.length < 20) {
    throw new Error("failure matrix does not cover the required fault families");
  }
  const reviewedOperations = new Set(REVIEWED_AVAILABILITY_VARIANTS.flatMap(
    (variant) => variant.normalized_operations,
  ));
  for (const [scenarioId, relation] of Object.entries(SCENARIO_OPERATION_ELIGIBILITY)) {
    const scenarioRow = SCENARIOS.find((row) => row.scenario_id === scenarioId);
    if (!scenarioRow || scenarioRow.case_binding_kind === "infrastructure"
        || relation == null || typeof relation !== "object" || Array.isArray(relation)
        || canonicalJson(Object.keys(relation).sort())
          !== canonicalJson([...scenarioRow.effect_profile_refs].sort())) {
      throw new Error(`case eligibility for ${scenarioId} is not bound to exact profiles`);
    }
    for (const [profileRef, operationIds] of Object.entries(relation)) {
      if (!EFFECT_PROFILE_IDS.includes(profileRef) || !Array.isArray(operationIds)
          || operationIds.length < 1 || new Set(operationIds).size !== operationIds.length
          || canonicalJson(operationIds) !== canonicalJson([...operationIds].sort())
          || operationIds.some((operationId) => !reviewedOperations.has(operationId))) {
        throw new Error(`case eligibility for ${scenarioId}/${profileRef} is invalid`);
      }
    }
  }
  for (const scenarioRow of SCENARIOS.filter((row) => (
    row.case_binding_kind !== "infrastructure" && row.effect_profile_refs.length > 0
  ))) {
    if (!SCENARIO_OPERATION_ELIGIBILITY[scenarioRow.scenario_id]) {
      throw new Error(`failure scenario ${scenarioRow.scenario_id} lacks exact operation eligibility`);
    }
  }
  const ids = new Set();
  const seenStages = new Set();
  for (let index = 0; index < input.scenarios.length; index += 1) {
    const row = input.scenarios[index];
    const label = `failure_matrix.scenarios[${index}]`;
    if (row == null || typeof row !== "object" || Array.isArray(row)) {
      throw new Error(`${label} must be an object`);
    }
    assertExactFields(row, SCENARIO_FIELDS, label);
    assertString(row.scenario_id, /^[a-z][a-z0-9._-]{0,190}$/u, `${label}.scenario_id`);
    if (ids.has(row.scenario_id)) throw new Error(`${label}.scenario_id is duplicated`);
    ids.add(row.scenario_id);
    if (!STAGES.includes(row.stage)) throw new Error(`${label}.stage is invalid`);
    if (!["availability_variant", "infrastructure", "transport_pair"]
      .includes(row.case_binding_kind)) {
      throw new Error(`${label}.case_binding_kind is invalid`);
    }
    seenStages.add(row.stage);
    if (!Array.isArray(row.node_ids) || row.node_ids.length < 1
        || row.node_ids.some((id) => typeof id !== "string" || !NODE_ID_RE.test(id)
          || !KNOWN_NODE_IDS.has(id))
        || new Set(row.node_ids).size !== row.node_ids.length
        || canonicalJson(row.node_ids) !== canonicalJson([...row.node_ids].sort())) {
      throw new Error(`${label}.node_ids is invalid`);
    }
    assertString(row.fault_class, IDENTIFIER_RE, `${label}.fault_class`);
    assertString(row.injection_point, IDENTIFIER_RE, `${label}.injection_point`);
    if (!Array.isArray(row.effect_families)
        || row.effect_families.length > 4
        || row.effect_families.some((family) => !EFFECT_FAMILY_VALUES.includes(family))
        || new Set(row.effect_families).size !== row.effect_families.length
        || canonicalJson(row.effect_families)
          !== canonicalJson([...row.effect_families].sort())) {
      throw new Error(`${label}.effect_families is invalid`);
    }
    if (!Array.isArray(row.effect_profile_refs)
        || row.effect_profile_refs.length > 8
        || row.effect_profile_refs.some((ref) => !EFFECT_PROFILE_IDS.includes(ref))
        || new Set(row.effect_profile_refs).size !== row.effect_profile_refs.length
        || canonicalJson(row.effect_profile_refs)
          !== canonicalJson([...row.effect_profile_refs].sort())) {
      throw new Error(`${label}.effect_profile_refs is invalid`);
    }
    const profileFamilies = [...new Set(row.effect_profile_refs.map((ref) => {
      const profile = EFFECT_PROFILE_REGISTRY[ref];
      return `${profile.subject_kind}.${profile.action}`;
    }))].sort();
    if (canonicalJson(profileFamilies) !== canonicalJson(row.effect_families)) {
      throw new Error(`${label} effect families drift from the bound profiles`);
    }
    if (typeof row.effectless_resolution_only !== "boolean"
        || row.effectless_resolution_only !== (row.effect_profile_refs.length === 0)) {
      throw new Error(`${label}.effectless_resolution_only is invalid`);
    }
    const classifier = TERMINAL_CLASSIFIER_REGISTRY[row.terminal_classifier_id];
    if (!classifier || row.terminal_classifier_digest !== digest(classifier)
        || canonicalJson(row.expected_terminal_states)
          !== canonicalJson(terminalStatesForClassifier(row.terminal_classifier_id))) {
      throw new Error(`${label} has no exact deterministic terminal classifier`);
    }
    if (row.effectless_resolution_only
        !== (row.terminal_classifier_id === "effectless_resolution_v1")) {
      throw new Error(`${label} terminal classifier does not match its effect boundary`);
    }
    assertExactFields(row.evidence_requirements, EVIDENCE_REQUIREMENT_FIELDS, `${label}.evidence_requirements`);
    if (canonicalJson(row.evidence_requirements)
        !== canonicalJson(evidenceRequirementsForScenario(row, row.effect_profile_refs))) {
      throw new Error(`${label}.evidence_requirements drifted from the staged boundary`);
    }
    assertString(
      row.evidence_requirements.executor_principal_ref,
      REF_RE,
      `${label}.evidence_requirements.executor_principal_ref`,
    );
    assertString(
      row.evidence_requirements.witness_principal_ref,
      REF_RE,
      `${label}.evidence_requirements.witness_principal_ref`,
    );
    if (row.evidence_requirements.executor_principal_ref
        === row.evidence_requirements.witness_principal_ref) {
      throw new Error(`${label} does not independently separate executor and witness`);
    }
    const { scenario_evidence_key: scenarioEvidenceKey, ...scenarioBody } = row;
    const expectedScenarioEvidenceKey = `hil-evidence-key:v1:${digest({
      domain: "hacker-bob/chameleon-hil-scenario-evidence/v1",
      ...scenarioBody,
    })}`;
    if (scenarioEvidenceKey !== expectedScenarioEvidenceKey) {
      throw new Error(`${label}.scenario_evidence_key does not bind the exact scenario`);
    }
    assertString(row.fixture_ref, REF_RE, `${label}.fixture_ref`);
    assertString(row.independent_witness_ref, REF_RE, `${label}.independent_witness_ref`);
    if (!Array.isArray(row.expected_terminal_states)
        || row.expected_terminal_states.length < 1
        || row.expected_terminal_states.some((state) => !TERMINAL_STATES.includes(state))
        || new Set(row.expected_terminal_states).size !== row.expected_terminal_states.length
        || canonicalJson(row.expected_terminal_states)
          !== canonicalJson([...row.expected_terminal_states].sort())) {
      throw new Error(`${label}.expected_terminal_states is invalid`);
    }
    if (row.automatic_effect_retry !== false || row.requires_signed_evidence !== true
        || row.requires_zero_active_effects !== true
        || row.requires_residue_accounting !== true || row.production_nonwaivable !== true
        || row.status !== STATUS) {
      throw new Error(`${label} weakens a nonwaivable recovery invariant`);
    }
    if (row.effectless_resolution_only && row.stage !== "rf_off") {
      throw new Error(`${label} launders an effectless resolution failure`);
    }
    if (row.effect_families.some((family) => family.endsWith(".destroy"))
        && !row.expected_terminal_states.includes("irreversible_authorized")) {
      throw new Error(`${label} destructive work lacks an irreversible terminal`);
    }
  }
  if (STAGES.some((stage) => !seenStages.has(stage))) {
    throw new Error("failure matrix omits a required staged HIL boundary");
  }
  const expectedFailureCases = buildFailureCases();
  if (expectedFailureCases.length !== EXPECTED_FAILURE_CASE_COUNT
      || digest(expectedFailureCases) !== EXPECTED_FAILURE_CASE_REGISTRY_SHA256
      || !Array.isArray(input.failure_cases)
      || input.failure_case_count !== EXPECTED_FAILURE_CASE_COUNT
      || input.failure_cases.length !== EXPECTED_FAILURE_CASE_COUNT
      || input.failure_case_registry_sha256 !== EXPECTED_FAILURE_CASE_REGISTRY_SHA256
      || input.failure_case_registry_sha256 !== digest(input.failure_cases)) {
    throw new Error("failure matrix exact-case registry binding is invalid");
  }
  const caseIds = new Set();
  const evidenceKeys = new Set();
  const incomingCasesByScenario = new Map(input.scenarios.map((row) => [row.scenario_id, []]));
  for (let index = 0; index < expectedFailureCases.length; index += 1) {
    const row = input.failure_cases[index];
    const expected = expectedFailureCases[index];
    const label = `failure_matrix.failure_cases[${index}]`;
    assertExactFields(row, FAILURE_CASE_FIELDS, label);
    if (canonicalJson(row) !== canonicalJson(expected)) {
      throw new Error(`${label} drifted from its exact reviewed case identity`);
    }
    assertString(row.case_id, REF_RE, `${label}.case_id`);
    assertString(row.evidence_key, REF_RE, `${label}.evidence_key`);
    if (caseIds.has(row.case_id) || evidenceKeys.has(row.evidence_key)) {
      throw new Error(`${label} reuses a case or evidence identity`);
    }
    caseIds.add(row.case_id);
    evidenceKeys.add(row.evidence_key);
    incomingCasesByScenario.get(row.scenario_id)?.push(row);
    const scenarioRow = input.scenarios.find((entry) => entry.scenario_id === row.scenario_id);
    if (!scenarioRow || row.terminal_classifier_id !== scenarioRow.terminal_classifier_id) {
      throw new Error(`${label} is not bound to its scenario terminal classifier`);
    }
    if (!Array.isArray(row.effect_profile_refs)
        || new Set(row.effect_profile_refs).size !== row.effect_profile_refs.length
        || canonicalJson(row.effect_profile_refs)
          !== canonicalJson([...row.effect_profile_refs].sort())
        || row.effect_profile_refs.some((ref) => !scenarioRow.effect_profile_refs.includes(ref))) {
      throw new Error(`${label}.effect_profile_refs is invalid`);
    }
    if (!Array.isArray(row.required_evidence_contract_refs)
        || new Set(row.required_evidence_contract_refs.map((entry) => entry.contract_kind)).size
          !== row.required_evidence_contract_refs.length) {
      throw new Error(`${label}.required_evidence_contract_refs is invalid`);
    }
    for (const contractRef of row.required_evidence_contract_refs) {
      assertExactFields(contractRef, EVIDENCE_CONTRACT_REF_FIELDS, `${label}.evidence_contract`);
      assertString(contractRef.contract_kind, IDENTIFIER_RE, `${label}.contract_kind`);
      assertString(contractRef.contract_ref, REF_RE, `${label}.contract_ref`);
      if (contractRef.must_be_signed !== true || contractRef.status !== STATUS) {
        throw new Error(`${label}.evidence_contract weakens signed pending evidence`);
      }
    }
    const pair = row.transport_pair_id == null
      ? null
      : TRANSPORT_PAIR_REGISTRY[row.transport_pair_id];
    if ((row.transport_pair_id == null) !== (row.transport_pair_digest == null)
        || (pair && pair.pair_digest !== row.transport_pair_digest)
        || (row.transport_pair_id != null && !pair)) {
      throw new Error(`${label} has an invalid transport-pair binding`);
    }
    if (row.case_kind === "infrastructure_failure") {
      if (scenarioRow.case_binding_kind !== "infrastructure"
          || [row.capability_id, row.variant_id, row.availability_variant_digest,
            row.operation_id, row.technique_id, row.transport_pair_id,
            row.transport_pair_digest].some((value) => value !== null)
          || row.effect_profile_refs.length !== 0) {
        throw new Error(`${label} launders an infrastructure-only case`);
      }
    } else if (scenarioRow.case_binding_kind === "transport_pair") {
      if (row.case_kind !== "paired_transport_parity" || pair == null
          || row.availability_variant_digest !== null
          || row.operation_id !== pair.operation_id
          || canonicalJson(row.effect_profile_refs)
            !== canonicalJson(scenarioRow.effect_profile_refs)) {
        throw new Error(`${label} omits its composite transport-pair binding`);
      }
    } else if (scenarioRow.case_binding_kind !== "availability_variant"
        || row.availability_variant_digest == null
        || (scenarioRow.evidence_requirements.same_operation_transport_parity_required
          !== (pair != null))) {
      throw new Error(`${label} omits its reviewed availability-variant binding`);
    }
  }
  for (const variant of REVIEWED_AVAILABILITY_VARIANTS) {
    for (const scenarioRow of SCENARIOS.filter(
      (row) => row.case_binding_kind === "availability_variant"
        && row.effect_profile_refs.length > 0,
    )) {
      const expectedOperationIds = exactOperationIdsForVariantScenario(variant, scenarioRow);
      const actual = input.failure_cases.filter((failureCase) => (
        failureCase.availability_variant_digest === variant.availability_variant_digest
        && failureCase.scenario_id === scenarioRow.scenario_id
      ));
      if (canonicalJson(actual.map((failureCase) => failureCase.operation_id).sort())
          !== canonicalJson(expectedOperationIds)
          || actual.some((failureCase) => failureCase.technique_id !== null
            || canonicalJson(failureCase.effect_profile_refs)
              !== canonicalJson(scenarioRow.effect_profile_refs))) {
        throw new Error(
          `failure relation drifted for ${variant.capability_id}/${variant.variant_id}/${scenarioRow.scenario_id}`,
        );
      }
    }
  }
  for (const scenarioRow of input.scenarios) {
    const incoming = incomingCasesByScenario.get(scenarioRow.scenario_id) || [];
    if (incoming.length < 1) {
      throw new Error(`failure scenario ${scenarioRow.scenario_id} has no exact execution case`);
    }
    if (scenarioRow.case_binding_kind === "availability_variant"
        && incoming.every((failureCase) => failureCase.availability_variant_digest == null)) {
      throw new Error(`failure scenario ${scenarioRow.scenario_id} has no variant-bound execution case`);
    }
    if (scenarioRow.case_binding_kind === "transport_pair"
        && incoming.some((failureCase) => failureCase.transport_pair_id == null)) {
      throw new Error(`failure scenario ${scenarioRow.scenario_id} has an unpaired execution case`);
    }
  }
  const expectedBindings = buildVariantFailureBindings(expectedFailureCases);
  if (digest(expectedBindings) !== EXPECTED_AVAILABILITY_VARIANT_FAILURE_REGISTRY_SHA256
      || !Array.isArray(input.variant_failure_bindings)
      || input.variant_failure_bindings.length !== EXPECTED_AVAILABILITY_VARIANT_COUNT
      || input.availability_variant_failure_registry_sha256
        !== EXPECTED_AVAILABILITY_VARIANT_FAILURE_REGISTRY_SHA256
      || input.availability_variant_failure_registry_sha256
        !== digest(input.variant_failure_bindings)) {
    throw new Error("failure matrix availability-variant registry binding is invalid");
  }
  for (let index = 0; index < expectedBindings.length; index += 1) {
    const row = input.variant_failure_bindings[index];
    const expected = expectedBindings[index];
    const label = `failure_matrix.variant_failure_bindings[${index}]`;
    assertExactFields(row, VARIANT_BINDING_FIELDS, label);
    if (canonicalJson(row) !== canonicalJson(expected)) {
      throw new Error(`${label} drifted from the reviewed availability variant`);
    }
    if (row.failure_scenario_ids.some((scenarioId) => !ids.has(scenarioId))) {
      throw new Error(`${label} names an unknown failure scenario`);
    }
    if (row.failure_case_ids.length < 1
        || row.failure_case_ids.some((caseId) => !caseIds.has(caseId))) {
      throw new Error(`${label} omits an exact case identity`);
    }
    for (const profileRef of row.effect_profile_refs) {
      if (!row.failure_scenario_ids.some((scenarioId) => {
        const failureScenario = input.scenarios.find((entry) => entry.scenario_id === scenarioId);
        return failureScenario.effect_profile_refs.includes(profileRef);
      })) {
        throw new Error(`${label} omits a physical failure for ${profileRef}`);
      }
    }
  }
  for (const failureCase of input.failure_cases) {
    const expectedVariantDigests = new Set();
    if (failureCase.availability_variant_digest != null) {
      expectedVariantDigests.add(failureCase.availability_variant_digest);
    }
    if (failureCase.transport_pair_id != null) {
      for (const endpoint of TRANSPORT_PAIR_REGISTRY[failureCase.transport_pair_id].endpoints) {
        expectedVariantDigests.add(endpoint.availability_variant_digest);
      }
    }
    const actualVariantDigests = input.variant_failure_bindings.filter((binding) => (
      binding.failure_case_ids.includes(failureCase.case_id)
    )).map((binding) => binding.availability_variant_digest).sort();
    if (canonicalJson(actualVariantDigests)
        !== canonicalJson([...expectedVariantDigests].sort())) {
      throw new Error(`failure case ${failureCase.case_id} has asymmetric variant bindings`);
    }
  }
  return input;
}

function validateFailureMatrix(input) {
  if (input == null || typeof input !== "object" || Array.isArray(input)) {
    throw new Error("failure matrix must be an object");
  }
  assertExactFields(
    input,
    [...FAILURE_MATRIX_BODY_FIELDS, "matrix_digest"],
    "failure_matrix",
  );
  const body = Object.fromEntries(
    FAILURE_MATRIX_BODY_FIELDS.map((field) => [field, input[field]]),
  );
  if (typeof input.matrix_digest !== "string" || input.matrix_digest !== digest(body)) {
    throw new Error("failure matrix digest does not authenticate the exact printed plan");
  }
  validateFailureMatrixBody(body);
  return input;
}

function buildFailureMatrix() {
  const failureCases = buildFailureCases();
  const variantFailureBindings = buildVariantFailureBindings(failureCases);
  const body = deepFreeze({
    version: MATRIX_VERSION,
    matrix_id: MATRIX_ID,
    provider_id: "chameleon_ultra",
    node_contract_registry_sha256: EXPECTED_NODE_CONTRACT_REGISTRY_SHA256,
    effect_profile_registry_sha256: EFFECT_PROFILE_REGISTRY_SHA256,
    capability_dependency_registry_sha256: EXPECTED_CAPABILITY_DEPENDENCY_REGISTRY_SHA256,
    semantic_manifest_sha256: EXPECTED_SEMANTIC_MANIFEST_SHA256,
    terminal_classifier_registry_sha256: digest(TERMINAL_CLASSIFIER_REGISTRY),
    terminal_classifier_registry: TERMINAL_CLASSIFIER_REGISTRY,
    scenario_registry_sha256: digest(SCENARIOS),
    case_eligibility_registry_sha256: EXPECTED_CASE_ELIGIBILITY_REGISTRY_SHA256,
    case_eligibility_registry: CASE_ELIGIBILITY_REGISTRY,
    transport_pair_registry_sha256: EXPECTED_TRANSPORT_PAIR_REGISTRY_SHA256,
    transport_pair_registry: TRANSPORT_PAIR_REGISTRY,
    availability_variant_count: EXPECTED_AVAILABILITY_VARIANT_COUNT,
    failure_case_count: EXPECTED_FAILURE_CASE_COUNT,
    failure_case_registry_sha256: EXPECTED_FAILURE_CASE_REGISTRY_SHA256,
    availability_variant_failure_registry_sha256:
      EXPECTED_AVAILABILITY_VARIANT_FAILURE_REGISTRY_SHA256,
    execution_policy: deepFreeze({
      import_is_inert: true,
      cli_is_plan_only: true,
      hardware_access_authorized: false,
      production_ready: false,
      live_hil_evidence_present: false,
    }),
    scenarios: SCENARIOS,
    failure_cases: failureCases,
    variant_failure_bindings: variantFailureBindings,
  });
  validateFailureMatrixBody(body);
  const matrix = deepFreeze({ ...body, matrix_digest: digest(body) });
  validateFailureMatrix(matrix);
  return matrix;
}

if (require.main === module) {
  if (process.argv.length !== 3 || process.argv[2] !== "--print-plan") {
    process.stderr.write(
      "This command is inert. Use --print-plan to emit the pending HIL matrix; no execution mode exists.\n",
    );
    process.exitCode = 2;
  } else {
    process.stdout.write(`${JSON.stringify(buildFailureMatrix(), null, 2)}\n`);
  }
}

module.exports = Object.freeze({
  AVAILABILITY_VARIANT_COUNT: EXPECTED_AVAILABILITY_VARIANT_COUNT,
  EFFECT_PROFILE_IDS,
  EFFECT_PROFILE_REGISTRY_SHA256,
  MATRIX_ID,
  MATRIX_VERSION,
  STAGES,
  TERMINAL_STATES,
  buildFailureCases,
  buildFailureMatrix,
  canonicalCapabilityDependencies,
  canonicalNodeContracts,
  classifyTerminalObservation,
  reviewedDigest,
  validateFailureMatrix,
});
