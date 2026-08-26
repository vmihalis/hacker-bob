#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const {
  assertPackageSafePhysicalDesignDocument,
} = require("../mcp/core/physical-sensitive-material-contracts.js");
const {
  canonicalPlanePhysicalHyperedgeRegistry,
  canonicalPlanePhysicalNodeContractRegistry,
} = require("../mcp/domains/physical/plane-physical-release-contracts.js");

const ROOT = path.join(__dirname, "..");
const DOCUMENTS = Object.freeze({
  nodes: "docs/plane-physical/nodes.json",
  hyperedges: "docs/plane-physical/hyperedges.json",
  coverage: "docs/plane-physical/coverage.json",
});
const CHAMELEON_OPERATIONS_MODULE =
  "packages/bob-instrument-chameleon/lib/operations.js";

const GRAPH_ID = "plane-physical-security";
const NODE_KINDS = new Set(["S", "I", "IP", "P", "C", "X"]);
const NODE_STATUSES = new Set(["blocked", "ready", "in_progress", "in_review", "done"]);
const NODE_ACTIONS = new Set(["build_new", "extend_existing", "adopt", "harden", "register"]);
const NODE_PHASES = new Set([
  "PH0_contracts",
  "PH1_broker",
  "PH2_trusted_loop",
  "PH3_full_hardware",
  "PH4_composition",
]);
const NODE_PHASE_RANK = new Map([...NODE_PHASES].map((phase, index) => [phase, index]));
const NODES_DOCUMENT_FIELDS = new Set([
  "schema_version",
  "graph_id",
  "graph",
  "version",
  "source_doc",
  "tracking",
  "status_values",
  "ready_rule",
  "phase_order",
  "vocabulary",
  "gate_status_values",
  "production_nonwaivable_hil_node_ids",
  "node_contract_registry_sha256",
  "gate_tracking",
  "nodes",
  "excluded_by_doctrine",
]);
const NODE_FIELDS = new Set([
  "id",
  "kind",
  "title",
  "action",
  "phase",
  "status",
  "intent",
  "anchors",
  "deliverables",
  "predecessors",
  "effect_surface",
  "engineering_gate",
  "hil_gate",
  "findings",
  "review_evidence",
]);
const HYPEREDGES_DOCUMENT_FIELDS = new Set([
  "schema_version",
  "graph_id",
  "version",
  "note",
  "hyperedge_registry_sha256",
  "hyperedges",
]);
const HYPEREDGE_REQUIRED_FIELDS = new Set(["id", "predecessors", "unlocks", "kind"]);
const HYPEREDGE_OPTIONAL_FIELDS = new Set(["note"]);
const EXPECTED_PRODUCTION_NONWAIVABLE_HIL_NODE_IDS = Object.freeze([
  "PH-C1", "PH-C10", "PH-C2", "PH-C3", "PH-C4", "PH-C5", "PH-C6", "PH-C7", "PH-C8", "PH-C9",
  "PH-P5", "PH-P6", "PH-P7", "PH-P9", "PH-S3", "PH-S5", "PH-S7", "PH-X4", "PH-X5", "PH-X6", "PH-X7", "PH-X8",
]);
const EXPECTED_NODE_CONTRACT_REGISTRY_SHA256 = "aba04a5376b5c3ba75b864166baf3d563e2cb69fdf406a113e530d41b070a99d";
const EXPECTED_HYPEREDGE_REGISTRY_SHA256 = "bc71611c7512463d2462434f5633a966fd4f42257117f41d732853371aadc755";
const EFFECT_SURFACES = new Set([
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
const EFFECT_SUBJECT_KINDS = new Set(["instrument", "target", "environment"]);
const EFFECT_ACTIONS = new Set([
  "observe",
  "configure",
  "transmit",
  "present",
  "mutate",
  "actuate",
  "administer",
  "destroy",
]);
const EFFECT_CHANNELS = new Set([
  "instrument_local",
  "rf",
  "contact",
  "usb",
  "ble",
  "network",
  "gpio",
  "optical",
  "acoustic",
  "manual",
  "other",
]);
const EFFECT_PERSISTENCE = new Set(["none", "ephemeral", "persistent", "irreversible"]);
const EFFECT_PROFILE_FIELDS = new Set([
  "subject_kind",
  "action",
  "channel",
  "persistence",
  "required_bounds",
]);
const NORMALIZED_OPERATION_EXPOSURES = new Set([
  "provider_private",
  "technique_compiled",
  "operator_only",
  "unsupported",
]);
const NORMALIZED_OPERATION_FIELDS = new Set([
  "exposure",
  "minimum_assurance_profile_id",
]);
const ASSURANCE_PROFILE_FIELDS = new Set([
  "identity_enrollment",
  "firmware_provenance",
  "command_surface_conformance",
  "transport_trust",
]);
const ASSURANCE_AXIS_VALUES = Object.freeze({
  identity_enrollment: new Set(["not_required", "unverified", "operator_enrolled", "hardware_bound", "not_applicable"]),
  firmware_provenance: new Set(["not_required", "self_reported", "operator_pinned", "hardware_attested", "not_applicable"]),
  command_surface_conformance: new Set(["not_required", "bootstrap_allowlisted", "manifest_intersected", "conformance_tested", "not_applicable"]),
  transport_trust: new Set(["not_required", "local_observed", "operator_provisioned", "hardware_attested", "not_applicable"]),
});
const ASSURANCE_AXIS_ORDER = Object.freeze({
  identity_enrollment: Object.freeze(["unverified", "operator_enrolled", "hardware_bound"]),
  firmware_provenance: Object.freeze(["self_reported", "operator_pinned", "hardware_attested"]),
  command_surface_conformance: Object.freeze(["bootstrap_allowlisted", "manifest_intersected", "conformance_tested"]),
  transport_trust: Object.freeze(["local_observed", "operator_provisioned", "hardware_attested"]),
});
const CAPABILITY_DEPENDENCY_FIELDS = new Set(["all_of", "any_of", "variants"]);
const CAPABILITY_VARIANT_FIELDS = new Set([
  "parameter_selector_id",
  "all_of",
  "any_of",
  "normalized_operations",
  "technique_bindings",
  "effect_profile_refs",
]);
const DEPENDENCY_PROOF_PROVIDER_FIELDS = new Set([
  "provider_kind",
  "owner_principal",
  "artifact_digest_binding",
  "signed_verdict_type",
  "trust_epoch_binding",
  "freshness_policy",
  "revocation_policy",
]);
const DEPENDENCY_PROOF_PROVIDER_KINDS = new Set(["compiler", "conformance", "observer", "transport", "vault_tool"]);
const DEPENDENCY_REF_PATTERN = /^(?:command:[1-9]\d*|capability_variant:[A-Za-z0-9][A-Za-z0-9._:-]*\/[a-z][a-z0-9._-]*|(?:compiler|conformance|manual_procedure|observer|transport|vault_tool):[a-z][a-z0-9._-]*)$/;
const VAULT_BACKED_RECOVERY_TOOLS = new Map([
  ["secret.recover_from_trace", "vault_tool:classic_trace_recovery_v1"],
  ["secret.recover.autopwn", "vault_tool:classic_autopwn_v1"],
  ["secret.recover.darkside", "vault_tool:classic_darkside_recovery_v1"],
  ["secret.recover.destructive_clone_variant", "vault_tool:mfu_secret_transform_v1"],
  ["secret.recover.encrypted_nested", "vault_tool:classic_encrypted_nested_recovery_v1"],
  ["secret.recover.hardnested", "vault_tool:classic_hardnested_recovery_v1"],
  ["secret.recover.nested", "vault_tool:classic_nested_recovery_v1"],
  ["secret.recover.static_nested", "vault_tool:classic_static_nested_recovery_v1"],
]);
const HF14A_CLOSED_PROBE_PROFILE_ID = "enrolled_conformance_tested";
const HF14A_CLOSED_PROBE_OPERATION_ID = "protocol.discovery_probe";
const HF14A_CLOSED_PROBE_CAPABILITY_ID = "CU-HF-14A-COMPILED-PROBE";
const HF14A_CLOSED_PROBE_CONFORMANCE_REF =
  "conformance:chameleon_hf14a_closed_probe_v1";
const HF14A_CLOSED_PROBE_COMMON_REFS = Object.freeze([
  "capability_variant:CU-HF-14A-RAW/default",
  "compiler:iso14443a_closed_probe_v1",
  HF14A_CLOSED_PROBE_CONFORMANCE_REF,
]);
const HF14A_CLOSED_PROBE_SCHEMA_BINDINGS = Object.freeze([
  Object.freeze({
    schema_id: "iso14443a.requa_atqa_v1",
    variant_id: "requa_atqa_v1",
    parameter_selector_id: "requa_atqa_v1",
  }),
  Object.freeze({
    schema_id: "iso14443a.wupa_atqa_v1",
    variant_id: "wupa_atqa_v1",
    parameter_selector_id: "wupa_atqa_v1",
  }),
]);
const HF14A_CLOSED_PROBE_PROOF_CONTRACT = Object.freeze({
  provider_kind: "conformance",
  owner_principal: "provider_hil_conformance_runner",
  artifact_digest_binding:
    "provider_binary_compiler_registry_source_firmware_transport_and_hil_fixture_digests",
  signed_verdict_type: "bob-proof:provider-hil-conformance:v1",
  trust_epoch_binding: "provider_registry_and_hil_fixture_epoch",
  freshness_policy: "provider_build_firmware_transport_compiler_and_owned_hil_run",
  revocation_policy: "deny_on_provider_firmware_transport_compiler_fixture_or_epoch_drift",
});
const PROVIDER_VARIANT_SAFETY_GUARDS = new Map([
  ["CU-HF-14A-COMPILED-PROBE/requa_atqa_v1", Object.freeze({
    mandatory_refs: Object.freeze([
      "capability_variant:CU-HF-14A-RAW/default",
      "compiler:iso14443a_closed_probe_v1",
      "conformance:chameleon_hf14a_closed_probe_v1",
    ]),
    normalized_operations: Object.freeze(["protocol.discovery_probe"]),
    technique_bindings: Object.freeze(["protocol.probe"]),
    effect_profile_refs: Object.freeze(["EP-TARGET-TRANSMIT-RF"]),
  })],
  ["CU-HF-14A-COMPILED-PROBE/wupa_atqa_v1", Object.freeze({
    mandatory_refs: Object.freeze([
      "capability_variant:CU-HF-14A-RAW/default",
      "compiler:iso14443a_closed_probe_v1",
      "conformance:chameleon_hf14a_closed_probe_v1",
    ]),
    normalized_operations: Object.freeze(["protocol.discovery_probe"]),
    technique_bindings: Object.freeze(["protocol.probe"]),
    effect_profile_refs: Object.freeze(["EP-TARGET-TRANSMIT-RF"]),
  })],
  ["CU-HF-MFU-ACQUIRE/plain_read", Object.freeze({
    mandatory_refs: Object.freeze([
      "capability_variant:CU-HF-14A-RAW/default",
      "compiler:mfu_acquire_v1",
      "vault_tool:mfu_secret_transform_v1",
    ]),
    normalized_operations: Object.freeze(["protocol.discover", "representation.read"]),
    technique_bindings: Object.freeze(["credential.acquire", "credential.classify"]),
    effect_profile_refs: Object.freeze(["EP-TARGET-TRANSMIT-RF"]),
  })],
  ["CU-HF-MFU-ACQUIRE/authenticated_read", Object.freeze({
    mandatory_refs: Object.freeze([
      "capability_variant:CU-HF-14A-RAW/default",
      "compiler:mfu_acquire_v1",
      "vault_tool:mfu_secret_transform_v1",
    ]),
    normalized_operations: Object.freeze(["protocol.authenticate", "protocol.discover", "representation.read"]),
    technique_bindings: Object.freeze(["credential.acquire", "credential.classify"]),
    effect_profile_refs: Object.freeze(["EP-TARGET-MUTATE-RF-STATEFUL", "EP-TARGET-TRANSMIT-RF"]),
  })],
  ["CU-HF-MFU-ACQUIRE/terminal_risk_authenticated_read", Object.freeze({
    mandatory_refs: Object.freeze([
      "capability_variant:CU-HF-14A-RAW/default",
      "compiler:mfu_acquire_v1",
      "vault_tool:mfu_secret_transform_v1",
    ]),
    normalized_operations: Object.freeze(["protocol.authenticate", "protocol.discover", "representation.read"]),
    technique_bindings: Object.freeze(["credential.acquire", "credential.classify"]),
    effect_profile_refs: Object.freeze([
      "EP-TARGET-DESTROY-RF",
      "EP-TARGET-MUTATE-RF-STATEFUL",
      "EP-TARGET-TRANSMIT-RF",
    ]),
  })],
]);
const MANUAL_ACTION_FIELDS = new Set([
  "source_url",
  "source_sha256",
  "source_symbol",
  "source_case",
  "procedure_id",
  "effect_profile_refs",
  "required_receipts",
  "rf_off_deadline_required",
]);
const MANUAL_ACTION_SOURCE = Object.freeze({
  url: "https://raw.githubusercontent.com/RfidResearchGroup/ChameleonUltra/v2.2.0/firmware/application/src/app_main.c",
  sha256: "95a62be3fffe6b66b635216523d7beb5d74692db14747549da37b29aea8828bd",
  symbol: "run_button_function_by_settings",
});
const EXPECTED_MANUAL_ACTIONS = Object.freeze({
  "CU-ADMIN-BUTTON-CLONE-INVOKE": Object.freeze({
    source_case: "SettingsButtonCloneIcUid",
    procedure_id: "manual.chameleon_ultra.clone_ic_uid.v1",
  }),
  "CU-ADMIN-FIELD-GENERATOR-INVOKE": Object.freeze({
    source_case: "SettingsButtonNfcFieldGenerator",
    procedure_id: "manual.chameleon_ultra.nfc_field_generator.v1",
  }),
});
// Graph-tracked engineering/HIL/review evidence must reference the production
// gate-evidence scheme. This is the only scheme bound to an independently
// signed issue transaction and accepted by the runtime release evaluator
// (plane-physical-release-readiness.js); a versioned reference is rejected as
// an invalid evidence ref. This is a syntactic scheme check only; the
// anti-fabrication / signature / binding guarantees live in the runtime
// resolver, never in this package-safe checker.
const EVIDENCE_REF_PATTERN = /^bob-evidence:sha256:[a-f0-9]{64}$/;
const WAIVER_REF_PATTERN = /^bob-waiver:v1:sha256:[a-f0-9]{64}$/;
const RF_REQUIRED_BOUNDS = Object.freeze([
  "instrument_ref",
  "duration_ms",
  "attempt_limit",
  "frequency_band",
  "power_ceiling",
  "duty_cycle",
  "zone_ref",
  "containment_plan_ref",
  "execution_deadline",
  "spatial_envelope_ref",
  "stimulus_sequence_ref",
]);
const INSTRUMENT_MAINTENANCE_REQUIRED_BOUNDS = Object.freeze([
  "instrument_ref",
  "pre_state_snapshot_ref",
  "backup_artifact_ref",
  "state_delta_plan_ref",
  "post_operation_inventory_plan_ref",
  "assurance_invalidation_plan_ref",
  "owned_fixture_ref",
  "hil_evidence_plan_ref",
  "operator_receipt_ref",
]);
const GATE_TRACKING_FIELDS = new Set([
  "engineering_state",
  "engineering_evidence_refs",
  "hil_state",
  "hil_evidence_refs",
  "hil_waiver_ref",
]);
const ENGINEERING_GATE_STATES = new Set(["pending", "passed", "failed"]);
const HIL_GATE_STATES = new Set(["not_required", "pending", "passed", "failed", "waived"]);
const UPSTREAM_COMMAND_REGISTRY_FIELDS = new Set([
  "version",
  "source_commit",
  "declaration_source",
  "declaration_source_sha256",
  "registry_source",
  "registry_source_sha256",
  "declared_command_ids",
  "declared_unregistered_ids",
  "registry_private_ids",
  "command_ownership_sha256",
  "coverage_semantics_sha256",
  "expected_ultra_capabilities_rule",
]);
const EXPECTED_ULTRA_CAPABILITIES_RULE =
  "declared_command_ids - declared_unregistered_ids + registry_private_ids";
const EXPECTED_ULTRA_RUNTIME_COMMAND_COUNT = 144;
const EXPECTED_UPSTREAM_COMMAND_REGISTRY = Object.freeze({
  version: "v2.2.0",
  source_commit: "f349dbeeaa315776b272ae8fb851cc4042d55f07",
  declaration_source: "https://github.com/RfidResearchGroup/ChameleonUltra/blob/v2.2.0/firmware/application/src/data_cmd.h",
  declaration_source_sha256: "12c17b902e413984b688cfb06d6822b4581a3c2efaf2fbdf2fcc1fe67a640a68",
  registry_source: "https://github.com/RfidResearchGroup/ChameleonUltra/blob/v2.2.0/firmware/application/src/app_cmd.c",
  registry_source_sha256: "3d79043158be47c12ba3f706a8e673c845fd73c5c0ef6e310c924bcdfe99177c",
  declared_command_ids_sha256: "cfe13141d3e196c456546a678ff9c1a0a0bdd296bbaef9ffec0805e6f20a23e4",
  declared_unregistered_ids: Object.freeze([3007, 3008, 3032]),
  registry_private_ids: Object.freeze([6010]),
  command_ownership_sha256: "f92a84341f8d79b0340071fe90eb00beafab1cc3b099f2e6252299e744aab2f7",
  coverage_semantics_sha256: "5e197912d21dafc7c99c9ece6cdca645913ddc23a74151436b71ea5ff2b78e12",
});
const COMMAND_SOURCE_ENTRY_FIELDS = new Set([
  "command_id",
  "declaration_symbol",
  "runtime_handler_symbol",
  "hook_symbols",
  "provider_capability_id",
  "disposition",
  "source_profile_id",
  "source_profile_digest",
  "declaration_source_sha256",
  "registry_source_sha256",
  "entry_digest",
]);
const COMMAND_SOURCE_PROFILE_ID = "chameleon_ultra_v2_2_0_source_pinned_v1";
const EXPECTED_COMMAND_SOURCE_REGISTRY_SHA256 =
  "464bcd9c4ef1045a48d052832b8ad2e67aa240c4375b6ce51298b29abeb617c5";
const DECLARATION_SYMBOL_PATTERN = /^DATA_CMD_[A-Z0-9_]+$/;
const RUNTIME_SYMBOL_PATTERN = /^[a-z][a-z0-9_]*$/;
const EXPECTED_NORMALIZED_OPERATION_REGISTRY_SHA256 =
  "2d048b7a95212ebf3dab3880465c5a920fb2236ac591334a3c940dab606ce8f1";
const EXPECTED_ASSURANCE_PROFILE_REGISTRY_SHA256 =
  "6ca848e291e9630560fef47875e4f111b24f418804d5b271f517d3243d3e9c55";
const EXPECTED_ASSURANCE_SATISFACTION_REGISTRY_SHA256 = "3da45ca0dd100715317e704bbb0e7a603e490f4398f3e0b15ac1f17563f808df";
const EXPECTED_CAPABILITY_DEPENDENCY_REGISTRY_SHA256 =
  "62ae7c98a576cb3d19aeaefad5860216a89692e29ba443f94163e260fe6ecfca";
const EXPECTED_DEPENDENCY_PROOF_PROVIDER_REGISTRY_SHA256 = "67e4b6a4c2545e836c6680dd102e12017fa3706a692f45bc96612f17abd49f42";
const EXPECTED_MANUAL_ACTION_REGISTRY_SHA256 =
  "fce6a16f56c002d9e6259762b7887461d1be145aa0c1cd059790f8955c2dd9c7";
const EXPECTED_TECHNIQUE_REGISTRY_SHA256 =
  "94f7d1f1b313d4b4a33c2c476c9676e2d9668a7d83b41252e89ada5ffbc65726";
const EDGE_KINDS = new Set(["blocking", "augment", "advisory"]);
const COVERAGE_DISPOSITIONS = new Set([
  "planned",
  "optional",
  "provider_internal",
  "operator_only",
  "unsupported",
]);
const COVERAGE_TOP_LEVEL_FIELDS = new Set([
  "schema_version",
  "graph_id",
  "provider",
  "provider_baseline",
  "coverage_contract",
  "runtime_rule",
  "assurance_profile_registry",
  "assurance_profile_registry_sha256",
  "assurance_satisfaction_registry",
  "assurance_satisfaction_registry_sha256",
  "normalized_operation_registry",
  "normalized_operation_registry_sha256",
  "capability_dependency_registry",
  "capability_dependency_registry_sha256",
  "dependency_proof_provider_registry",
  "dependency_proof_provider_registry_sha256",
  "technique_registry",
  "technique_registry_sha256",
  "upstream_command_registry",
  "command_source_registry",
  "command_source_registry_sha256",
  "version",
  "effect_profiles",
  "manual_action_registry",
  "manual_action_registry_sha256",
  "data_classes",
  "dispositions",
  "coverage",
]);
const COVERAGE_ROW_FIELDS = new Set([
  "provider_capability_id",
  "provider",
  "protocol_family",
  "device_surface",
  "upstream_command_ids",
  "normalized_operations",
  "technique_bindings",
  "effect_profile_refs",
  "data_class",
  "node_refs",
  "disposition",
  "reason",
]);
const DATA_CLASSES = new Set(["metadata", "linkable", "credential_secret", "regulated"]);
const PROVIDER_COVERAGE_EXEMPTIONS = new Set(["PH-P0", "PH-P1"]);

const GENERIC_CAPABILITY_LEAKS = [
  ["Chameleon product name", /\bchameleon(?:\s+ultra)?\b/i],
  ["Proxgrind vendor name", /\bproxgrind\b/i],
  ["local USB identifier", /\b(?:6868|8686)\b/i],
  ["local firmware identifier", /\bfw_v\d+\b/i],
  ["local USB device path", /\busbmodem\w*\b/i],
  ["hotel-specific context", /\b(?:hotel|marina\s+hotel)\b/i],
  ["Network School context", /\bnetwork\s+school\b/i],
  ["Forest City context", /\bforest\s+city\b/i],
  ["UniFi product name", /\bunifi\b/i],
];

function sorted(values) {
  return [...values].sort((a, b) => a.localeCompare(b));
}

function sameStrings(left, right) {
  if (left.length !== right.length) return false;
  return left.every((value, index) => value === right[index]);
}

function sha256Json(value) {
  return crypto.createHash("sha256").update(JSON.stringify(value)).digest("hex");
}

function readJson(relativePath, errors) {
  const absolutePath = path.join(ROOT, relativePath);
  let source;
  try {
    source = fs.readFileSync(absolutePath, "utf8");
  } catch (error) {
    errors.push(`${relativePath}: cannot read file (${error.code || error.message})`);
    return null;
  }
  try {
    return JSON.parse(source);
  } catch (error) {
    errors.push(`${relativePath}: invalid JSON (${error.message})`);
    return null;
  }
}

function validateChameleonRuntimeManifest(document, errors) {
  const label = CHAMELEON_OPERATIONS_MODULE;
  let runtime;
  try {
    runtime = require(path.join(ROOT, CHAMELEON_OPERATIONS_MODULE));
  } catch (error) {
    errors.push(`${label}: cannot load immutable semantic manifest (${error.message})`);
    return;
  }
  let snapshot;
  try {
    snapshot = runtime.reviewedManifestSnapshot();
  } catch (error) {
    errors.push(`${label}: cannot read reviewed manifest snapshot (${error.message})`);
    return;
  }
  const compare = (name, runtimeValue, documentValue) => {
    if (sha256Json(runtimeValue) !== sha256Json(documentValue)) {
      errors.push(`${label}: ${name} drifted from ${DOCUMENTS.coverage}`);
    }
  };
  compare(
    "coverage semantics",
    canonicalCoverageSemantics(snapshot, snapshot.coverage),
    canonicalCoverageSemantics(
      document,
      Array.isArray(document?.coverage) ? document.coverage : [],
    ),
  );
  compare(
    "normalized operation registry",
    canonicalOperationRegistry(snapshot.normalized_operation_registry),
    canonicalOperationRegistry(document?.normalized_operation_registry),
  );
  compare(
    "assurance profile registry",
    canonicalAssuranceProfiles(snapshot.assurance_profile_registry),
    canonicalAssuranceProfiles(document?.assurance_profile_registry),
  );
  compare(
    "assurance satisfaction registry",
    canonicalAssuranceSatisfaction(snapshot.assurance_satisfaction_registry),
    canonicalAssuranceSatisfaction(document?.assurance_satisfaction_registry),
  );
  compare(
    "capability dependency registry",
    canonicalCapabilityDependencies(snapshot.capability_dependency_registry),
    canonicalCapabilityDependencies(document?.capability_dependency_registry),
  );
  compare(
    "dependency proof provider registry",
    canonicalDependencyProofProviders(snapshot.dependency_proof_provider_registry),
    canonicalDependencyProofProviders(document?.dependency_proof_provider_registry),
  );
  compare(
    "effect profiles",
    canonicalEffectProfiles(snapshot.effect_profiles),
    canonicalEffectProfiles(document?.effect_profiles),
  );
  compare(
    "manual action registry",
    canonicalManualActions(snapshot.manual_action_registry),
    canonicalManualActions(document?.manual_action_registry),
  );
  compare(
    "command source registry",
    canonicalCommandSourceRegistry(snapshot.command_source_registry),
    canonicalCommandSourceRegistry(document?.command_source_registry),
  );

  const digestFields = [
    "assurance_profile_registry_sha256",
    "assurance_satisfaction_registry_sha256",
    "capability_dependency_registry_sha256",
    "command_source_registry_sha256",
    "dependency_proof_provider_registry_sha256",
    "manual_action_registry_sha256",
    "normalized_operation_registry_sha256",
    "technique_registry_sha256",
  ];
  for (const field of digestFields) {
    if (snapshot[field] !== document?.[field]) {
      errors.push(`${label}: ${field} drifted from ${DOCUMENTS.coverage}`);
    }
  }
  for (const field of [
    "source_commit",
    "declaration_source_sha256",
    "registry_source_sha256",
    "command_ownership_sha256",
    "coverage_semantics_sha256",
  ]) {
    if (snapshot.upstream_command_registry?.[field]
        !== document?.upstream_command_registry?.[field]) {
      errors.push(`${label}: upstream ${field} drifted from ${DOCUMENTS.coverage}`);
    }
  }
  if (runtime.CHAMELEON_SEMANTIC_MANIFEST?.counts?.normalized_operations !== 50
      || runtime.CHAMELEON_SEMANTIC_MANIFEST?.counts?.coverage_rows !== 51
      || runtime.CHAMELEON_SEMANTIC_MANIFEST?.counts?.availability_variants !== 112
      || runtime.CHAMELEON_SEMANTIC_MANIFEST?.counts?.dependency_proof_providers !== 22
      || runtime.CHAMELEON_SEMANTIC_MANIFEST?.counts?.compiled_commands !== 37
      || runtime.CHAMELEON_SEMANTIC_MANIFEST?.counts?.command_owners !== 147
      || runtime.CHAMELEON_SEMANTIC_MANIFEST?.counts?.command_source_entries !== 147) {
    errors.push(`${label}: runtime manifest completeness counts drifted`);
  }
  if (runtime.CHAMELEON_SEMANTIC_MANIFEST?.command_source_metadata_authority
      !== "provenance_only") {
    errors.push(`${label}: command source names must remain provenance-only metadata`);
  }

  try {
    const codec = require(path.join(
      ROOT,
      "packages/bob-instrument-chameleon/lib/codec.js",
    ));
    const profile = codec.v220CodecProfileSnapshot();
    const runtimeProfile = runtime.CHAMELEON_V220_CODEC_PROFILE;
    compare(
      "immutable codec command IDs",
      runtimeProfile.command_ids,
      Object.keys(codec.V2_2_0_COMMAND_DATA_LIMITS).map(Number).sort((a, b) => a - b),
    );
    for (const field of [
      "profile_id",
      "assurance",
      "release_tag",
      "tag_commit",
      "declaration_source_sha256",
      "registry_source_sha256",
      "command_data_limits_digest",
    ]) {
      if (runtimeProfile[field] !== profile[field]) {
        errors.push(`${label}: immutable codec profile ${field} drifted`);
      }
    }
  } catch (error) {
    errors.push(`${label}: cannot verify immutable codec profile (${error.message})`);
  }

  try {
    const bootstrap = require(path.join(
      ROOT,
      "packages/bob-instrument-chameleon/lib/bootstrap-operations.js",
    ));
    const subset = runtime.CHAMELEON_BOOTSTRAP_SUBSET;
    compare(
      "bootstrap operation subset",
      subset.operation_ids,
      bootstrap.CHAMELEON_BOOTSTRAP_OPERATION_REGISTRY.ids(),
    );
    compare(
      "bootstrap command subset",
      subset.command_ids,
      bootstrap.CHAMELEON_BOOTSTRAP_COMMAND_ALLOWLIST,
    );
  } catch (error) {
    errors.push(`${label}: cannot verify bootstrap strict subset (${error.message})`);
  }
}

function validateClosedTopLevelSet(document, field, allowed, label, errors) {
  const value = document[field];
  if (!Array.isArray(value)) {
    errors.push(`${label}.${field}: expected an array`);
    return;
  }
  const actual = sorted(value);
  const expected = sorted(allowed);
  if (!sameStrings(actual, expected)) {
    errors.push(`${label}.${field}: expected exactly ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
  }
}

function validateObjectFields(value, label, required, optional, errors) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    errors.push(`${label}: expected an object`);
    return false;
  }
  const actual = sorted(Object.keys(value));
  const allowed = new Set([...required, ...optional]);
  const missing = sorted([...required].filter((field) => !Object.hasOwn(value, field)));
  const extra = actual.filter((field) => !allowed.has(field));
  if (missing.length > 0 || extra.length > 0) {
    errors.push(`${label}: object fields are closed; missing=${JSON.stringify(missing)}, extra=${JSON.stringify(extra)}`);
  }
  return missing.length === 0 && extra.length === 0;
}

function validateString(value, label, errors, { optional = false } = {}) {
  if (optional && value === undefined) return false;
  if (typeof value !== "string" || value.trim() === "") {
    errors.push(`${label}: expected a non-empty string`);
    return false;
  }
  return true;
}

function validateStringArray(value, label, errors, { nonEmpty = false } = {}) {
  if (!Array.isArray(value)) {
    errors.push(`${label}: expected an array`);
    return [];
  }
  if (nonEmpty && value.length === 0) {
    errors.push(`${label}: must not be empty`);
  }
  const seen = new Set();
  for (let index = 0; index < value.length; index += 1) {
    const item = value[index];
    if (typeof item !== "string" || item.trim() === "") {
      errors.push(`${label}[${index}]: expected a non-empty string`);
      continue;
    }
    if (seen.has(item)) errors.push(`${label}: duplicate value ${JSON.stringify(item)}`);
    seen.add(item);
  }
  return value;
}

function validateTypedRef(value, label, pattern, expectedScheme, errors) {
  if (!validateString(value, label, errors)) return false;
  if (!pattern.test(value)) {
    errors.push(`${label}: expected ${expectedScheme}`);
    return false;
  }
  return true;
}

function validateTypedRefArray(value, label, pattern, expectedScheme, errors) {
  const refs = validateStringArray(value, label, errors);
  for (let index = 0; index < refs.length; index += 1) {
    if (typeof refs[index] !== "string") continue;
    if (!pattern.test(refs[index])) {
      errors.push(`${label}[${index}]: expected ${expectedScheme}`);
    }
  }
  return refs;
}

function validatePositiveIntegerArray(value, label, errors) {
  if (!Array.isArray(value)) {
    errors.push(`${label}: expected an array`);
    return [];
  }
  const seen = new Set();
  for (let index = 0; index < value.length; index += 1) {
    const item = value[index];
    if (!Number.isSafeInteger(item) || item <= 0) {
      errors.push(`${label}[${index}]: expected a positive safe integer`);
      continue;
    }
    if (seen.has(item)) errors.push(`${label}: duplicate command ID ${item}`);
    seen.add(item);
  }
  return value;
}

function validateGraphHeader(document, label, errors) {
  if (!document || typeof document !== "object" || Array.isArray(document)) {
    errors.push(`${label}: expected a JSON object`);
    return;
  }
  if (document.schema_version !== 1) {
    errors.push(`${label}.schema_version: expected 1`);
  }
  if (document.graph_id !== GRAPH_ID) {
    errors.push(`${label}.graph_id: expected ${JSON.stringify(GRAPH_ID)}`);
  }
}

function canonicalNodeContracts(document) {
  return canonicalPlanePhysicalNodeContractRegistry(document);
}

function canonicalHyperedgeRegistry(document) {
  return canonicalPlanePhysicalHyperedgeRegistry(document);
}

function validateReviewedDigest(actual, canonicalValue, expected, label, errors) {
  const digest = sha256Json(canonicalValue);
  if (validateString(actual, label, errors) && !/^[a-f0-9]{64}$/.test(actual)) {
    errors.push(`${label}: expected a lowercase SHA-256 digest`);
  }
  if (actual !== digest) {
    errors.push(`${label}: does not match canonical reviewed semantics`);
  }
  if (digest !== expected) {
    errors.push(`${label}: reviewed semantic pin drifted`);
  }
}

function validateGateTracking(document, nodes, nodeById, errors) {
  const label = `${DOCUMENTS.nodes}.gate_tracking`;
  const nonwaivableLabel = `${DOCUMENTS.nodes}.production_nonwaivable_hil_node_ids`;
  const nonwaivableValues = validateStringArray(
    document.production_nonwaivable_hil_node_ids,
    nonwaivableLabel,
    errors,
    { nonEmpty: true },
  );
  const nonwaivable = new Set(nonwaivableValues.filter((value) => typeof value === "string"));
  const reviewedNonwaivable = sorted(EXPECTED_PRODUCTION_NONWAIVABLE_HIL_NODE_IDS);
  if (!sameStrings(sorted(nonwaivable), reviewedNonwaivable)
      || nonwaivable.size !== nonwaivableValues.length) {
    errors.push(`${nonwaivableLabel}: must exactly match the independently reviewed production HIL set; expected=${JSON.stringify(reviewedNonwaivable)}`);
  }
  const hilGateNodes = sorted(nodes
    .filter((node) => node && typeof node.id === "string" && node.hil_gate !== null)
    .map((node) => node.id));
  if (!sameStrings(hilGateNodes, reviewedNonwaivable)) {
    errors.push(`${nonwaivableLabel}: node HIL gates must exactly match the independently reviewed production set; got=${JSON.stringify(hilGateNodes)}`);
  }
  const tracking = document.gate_tracking;
  if (!tracking || typeof tracking !== "object" || Array.isArray(tracking)) {
    errors.push(`${label}: expected an object keyed by every node ID`);
    return;
  }

  const actualIds = sorted(Object.keys(tracking));
  const expectedIds = sorted(nodeById.keys());
  if (!sameStrings(actualIds, expectedIds)) {
    const missing = expectedIds.filter((id) => !Object.hasOwn(tracking, id));
    const extra = actualIds.filter((id) => !nodeById.has(id));
    errors.push(`${label}: keys must exactly cover node IDs; missing=${JSON.stringify(missing)}, extra=${JSON.stringify(extra)}`);
  }

  for (const node of nodes) {
    if (!node || typeof node.id !== "string") continue;
    const entry = tracking[node.id];
    const at = `${label}.${node.id}`;
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
      errors.push(`${at}: expected an object`);
      continue;
    }

    const actualFields = sorted(Object.keys(entry));
    const expectedFields = sorted(GATE_TRACKING_FIELDS);
    if (!sameStrings(actualFields, expectedFields)) {
      errors.push(`${at}: expected exactly fields ${JSON.stringify(expectedFields)}, got ${JSON.stringify(actualFields)}`);
    }
    if (!ENGINEERING_GATE_STATES.has(entry.engineering_state)) {
      errors.push(`${at}.engineering_state: unknown state ${JSON.stringify(entry.engineering_state)}`);
    }
    if (!HIL_GATE_STATES.has(entry.hil_state)) {
      errors.push(`${at}.hil_state: unknown state ${JSON.stringify(entry.hil_state)}`);
    }
    const engineeringRefs = validateTypedRefArray(
      entry.engineering_evidence_refs,
      `${at}.engineering_evidence_refs`,
      EVIDENCE_REF_PATTERN,
      "bob-evidence:sha256:<64 lowercase hex>",
      errors,
    );
    const hilRefs = validateTypedRefArray(
      entry.hil_evidence_refs,
      `${at}.hil_evidence_refs`,
      EVIDENCE_REF_PATTERN,
      "bob-evidence:sha256:<64 lowercase hex>",
      errors,
    );
    if (entry.hil_waiver_ref !== null) {
      validateTypedRef(
        entry.hil_waiver_ref,
        `${at}.hil_waiver_ref`,
        WAIVER_REF_PATTERN,
        "bob-waiver:v1:sha256:<64 lowercase hex>",
        errors,
      );
    }

    if (entry.engineering_state === "passed" && engineeringRefs.length === 0) {
      errors.push(`${at}: passed engineering gate requires engineering_evidence_refs`);
    }
    if (entry.hil_state === "passed" && hilRefs.length === 0) {
      errors.push(`${at}: passed HIL gate requires hil_evidence_refs`);
    }
    if (entry.hil_state === "waived"
        && (typeof entry.hil_waiver_ref !== "string" || entry.hil_waiver_ref.trim() === "")) {
      errors.push(`${at}: waived HIL gate requires a non-empty typed hil_waiver_ref`);
    }
    if (entry.hil_state !== "waived" && entry.hil_waiver_ref !== null) {
      errors.push(`${at}: hil_waiver_ref must be null unless hil_state is waived`);
    }
    if (entry.hil_state === "not_required" && hilRefs.length !== 0) {
      errors.push(`${at}: not_required HIL gate must not carry hil_evidence_refs`);
    }

    const hilGateIsNull = node.hil_gate === null;
    const hilNotRequired = entry.hil_state === "not_required";
    if (hilGateIsNull !== hilNotRequired) {
      errors.push(`${at}: hil_gate is null iff hil_state is not_required`);
    }

    if (node.status === "done") {
      if (entry.engineering_state !== "passed" || engineeringRefs.length === 0) {
        errors.push(`${at}: done node requires a passed engineering gate with evidence`);
      }
      if (hilGateIsNull) {
        if (entry.hil_state !== "not_required") {
          errors.push(`${at}: done node without a HIL gate requires hil_state not_required`);
        }
      } else {
        const passedWithEvidence = entry.hil_state === "passed" && hilRefs.length > 0;
        const waivedWithTypedRef = entry.hil_state === "waived"
          && typeof entry.hil_waiver_ref === "string"
          && entry.hil_waiver_ref.trim() !== "";
        if (nonwaivable.has(node.id) && !passedWithEvidence) {
          errors.push(`${at}: production-nonwaivable HIL gate requires passed evidence; a waiver cannot close this node`);
        } else if (!passedWithEvidence && !waivedWithTypedRef) {
          errors.push(`${at}: done node requires HIL evidence or a typed HIL waiver reference`);
        }
      }
    }
  }

  const releaseNode = nodeById.get("PH-X8");
  if (releaseNode?.status === "done") {
    for (const nodeId of nonwaivable) {
      const entry = tracking[nodeId];
      if (!entry || entry.hil_state !== "passed"
          || !Array.isArray(entry.hil_evidence_refs) || entry.hil_evidence_refs.length === 0) {
        errors.push(`${label}.PH-X8: production release requires passed HIL evidence for ${nodeId}`);
      }
    }
  }
}

function validateNodes(document, errors) {
  const label = DOCUMENTS.nodes;
  validateGraphHeader(document, label, errors);
  if (!document || typeof document !== "object") return { nodes: [], nodeById: new Map() };
  validateObjectFields(document, label, NODES_DOCUMENT_FIELDS, new Set(), errors);

  validateClosedTopLevelSet(document, "status_values", NODE_STATUSES, label, errors);
  validateClosedTopLevelSet(document, "phase_order", NODE_PHASES, label, errors);
  if (!Array.isArray(document.nodes)) {
    errors.push(`${label}.nodes: expected an array`);
    return { nodes: [], nodeById: new Map() };
  }
  if (document.nodes.length === 0) errors.push(`${label}.nodes: must not be empty`);

  const nodeById = new Map();
  for (let index = 0; index < document.nodes.length; index += 1) {
    const node = document.nodes[index];
    const at = `${label}.nodes[${index}]`;
    if (!node || typeof node !== "object" || Array.isArray(node)) {
      errors.push(`${at}: expected an object`);
      continue;
    }
    validateObjectFields(node, at, NODE_FIELDS, new Set(), errors);
    if (!validateString(node.id, `${at}.id`, errors)) continue;
    if (!/^PH-(?:IP|S|I|P|C|X)\d+$/.test(node.id)) {
      errors.push(`${at}.id: ${JSON.stringify(node.id)} does not match the Plane-PH node ID grammar`);
    }
    if (nodeById.has(node.id)) {
      errors.push(`${at}.id: duplicate node ID ${JSON.stringify(node.id)}`);
    } else {
      nodeById.set(node.id, node);
    }

    if (!NODE_KINDS.has(node.kind)) {
      errors.push(`${at}.kind: unknown node kind ${JSON.stringify(node.kind)}`);
    } else {
      const match = node.id.match(/^PH-(IP|S|I|P|C|X)\d+$/);
      if (match && match[1] !== node.kind) {
        errors.push(`${at}.kind: ${JSON.stringify(node.kind)} does not match ID ${JSON.stringify(node.id)}`);
      }
    }
    if (!NODE_STATUSES.has(node.status)) {
      errors.push(`${at}.status: unknown status ${JSON.stringify(node.status)}`);
    }
    if (!NODE_ACTIONS.has(node.action)) {
      errors.push(`${at}.action: unknown action ${JSON.stringify(node.action)}`);
    }
    if (!NODE_PHASES.has(node.phase)) {
      errors.push(`${at}.phase: unknown phase ${JSON.stringify(node.phase)}`);
    }

    validateString(node.title, `${at}.title`, errors);
    validateString(node.intent, `${at}.intent`, errors);
    validateString(node.engineering_gate, `${at}.engineering_gate`, errors);
    if (node.hil_gate !== null) validateString(node.hil_gate, `${at}.hil_gate`, errors);
    validateStringArray(node.anchors, `${at}.anchors`, errors, { nonEmpty: true });
    validateStringArray(node.deliverables, `${at}.deliverables`, errors, { nonEmpty: true });
    validateStringArray(node.predecessors, `${at}.predecessors`, errors);
    validateStringArray(node.effect_surface, `${at}.effect_surface`, errors);
    validateStringArray(node.findings, `${at}.findings`, errors);
    validateTypedRefArray(
      node.review_evidence,
      `${at}.review_evidence`,
      EVIDENCE_REF_PATTERN,
      "bob-evidence:sha256:<64 lowercase hex>",
      errors,
    );

    for (const effect of Array.isArray(node.effect_surface) ? node.effect_surface : []) {
      if (!EFFECT_SURFACES.has(effect)) {
        errors.push(`${at}.effect_surface: unknown effect surface ${JSON.stringify(effect)}`);
      }
    }
    if (Object.hasOwn(node, "effect_classes")) {
      errors.push(`${at}.effect_classes: legacy v0.1 field is forbidden; use effect_surface`);
    }
    if (Array.isArray(node.predecessors) && node.predecessors.includes(node.id)) {
      errors.push(`${at}.predecessors: node cannot depend on itself`);
    }
    if (node.status === "done" && (!Array.isArray(node.review_evidence) || node.review_evidence.length === 0)) {
      errors.push(`${at}: done nodes require review_evidence`);
    }

    if (node.kind === "C") {
      const genericSurface = JSON.stringify({
        title: node.title,
        intent: node.intent,
        anchors: node.anchors,
        deliverables: node.deliverables,
      });
      for (const [description, pattern] of GENERIC_CAPABILITY_LEAKS) {
        if (pattern.test(genericSurface)) {
          errors.push(`${at}: generic capability leaks ${description}; put provider-specific detail in coverage.json`);
        }
      }
    }
  }

  for (const node of nodeById.values()) {
    for (const predecessor of Array.isArray(node.predecessors) ? node.predecessors : []) {
      if (!nodeById.has(predecessor)) {
        errors.push(`${label}: ${node.id} references unknown predecessor ${JSON.stringify(predecessor)}`);
      }
    }
  }

  validateReviewedDigest(
    document.node_contract_registry_sha256,
    canonicalNodeContracts(document),
    EXPECTED_NODE_CONTRACT_REGISTRY_SHA256,
    `${label}.node_contract_registry_sha256`,
    errors,
  );

  validateGateTracking(document, document.nodes, nodeById, errors);

  return { nodes: document.nodes, nodeById };
}

function validateHyperedges(document, nodeById, errors) {
  const label = DOCUMENTS.hyperedges;
  validateGraphHeader(document, label, errors);
  if (document && typeof document === "object" && !Array.isArray(document)) {
    validateObjectFields(document, label, HYPEREDGES_DOCUMENT_FIELDS, new Set(), errors);
  }
  if (!document || !Array.isArray(document.hyperedges)) {
    errors.push(`${label}.hyperedges: expected an array`);
    return { hyperedges: [], projection: new Map(), blockingCount: 0 };
  }
  if (document.hyperedges.length === 0) errors.push(`${label}.hyperedges: must not be empty`);

  const edgeIds = new Set();
  const projection = new Map([...nodeById.keys()].map((id) => [id, new Set()]));
  const blockingClauseCounts = new Map([...nodeById.keys()].map((id) => [id, 0]));
  let blockingCount = 0;

  for (let index = 0; index < document.hyperedges.length; index += 1) {
    const edge = document.hyperedges[index];
    const at = `${label}.hyperedges[${index}]`;
    if (!edge || typeof edge !== "object" || Array.isArray(edge)) {
      errors.push(`${at}: expected an object`);
      continue;
    }
    validateObjectFields(edge, at, HYPEREDGE_REQUIRED_FIELDS, HYPEREDGE_OPTIONAL_FIELDS, errors);
    if (validateString(edge.id, `${at}.id`, errors)) {
      if (!/^PH-H(?:0|[1-9]\d*)$/.test(edge.id)) {
        errors.push(`${at}.id: ${JSON.stringify(edge.id)} does not match the Plane-PH hyperedge ID grammar`);
      }
      if (edgeIds.has(edge.id)) errors.push(`${at}.id: duplicate hyperedge ID ${JSON.stringify(edge.id)}`);
      edgeIds.add(edge.id);
    }
    if (!EDGE_KINDS.has(edge.kind)) {
      errors.push(`${at}.kind: unknown edge kind ${JSON.stringify(edge.kind)}`);
    }
    const predecessors = validateStringArray(edge.predecessors, `${at}.predecessors`, errors, { nonEmpty: true });
    const unlocks = validateStringArray(edge.unlocks, `${at}.unlocks`, errors, { nonEmpty: true });
    const predecessorSet = new Set(predecessors);

    for (const ref of [...predecessors, ...unlocks]) {
      if (!nodeById.has(ref)) errors.push(`${at}: references unknown node ${JSON.stringify(ref)}`);
    }
    for (const unlocked of unlocks) {
      if (predecessorSet.has(unlocked)) {
        errors.push(`${at}: node ${JSON.stringify(unlocked)} appears on both sides of the edge`);
      }
    }
    if (edge.note !== undefined) validateString(edge.note, `${at}.note`, errors);

    if (edge.kind === "blocking") {
      blockingCount += 1;
      for (const unlocked of unlocks) {
        if (!projection.has(unlocked)) continue;
        blockingClauseCounts.set(unlocked, blockingClauseCounts.get(unlocked) + 1);
        for (const predecessor of predecessors) {
          if (!nodeById.has(predecessor)) continue;
          projection.get(unlocked).add(predecessor);
          const predecessorNode = nodeById.get(predecessor);
          const unlockedNode = nodeById.get(unlocked);
          const predecessorPhase = NODE_PHASE_RANK.get(predecessorNode.phase);
          const unlockedPhase = NODE_PHASE_RANK.get(unlockedNode?.phase);
          if (predecessorPhase !== undefined && unlockedPhase !== undefined && predecessorPhase > unlockedPhase) {
            errors.push(`${at}: blocking dependency ${predecessor} (${predecessorNode.phase}) cannot unlock earlier-phase ${unlocked} (${unlockedNode.phase})`);
          }
        }
      }
    }
  }

  for (const [nodeId, node] of nodeById) {
    const expected = Array.isArray(node.predecessors) && node.predecessors.length > 0 ? 1 : 0;
    const actual = blockingClauseCounts.get(nodeId) || 0;
    if (actual !== expected) {
      errors.push(`${label}: conjunctive dependency semantics require ${nodeId} to have ${expected} incoming blocking clause(s); got ${actual}`);
    }
  }

  validateReviewedDigest(
    document?.hyperedge_registry_sha256,
    canonicalHyperedgeRegistry(document),
    EXPECTED_HYPEREDGE_REGISTRY_SHA256,
    `${label}.hyperedge_registry_sha256`,
    errors,
  );

  return { hyperedges: document.hyperedges, projection, blockingCount };
}

function validatePredecessorProjection(nodes, projection, errors) {
  for (const node of nodes) {
    if (!node || typeof node.id !== "string" || !projection.has(node.id)) continue;
    const declared = sorted(new Set(Array.isArray(node.predecessors) ? node.predecessors : []));
    const projected = sorted(projection.get(node.id));
    if (!sameStrings(declared, projected)) {
      errors.push(`${DOCUMENTS.nodes}: ${node.id}.predecessors is ${JSON.stringify(declared)}; blocking hyperedges project ${JSON.stringify(projected)}`);
    }
  }
}

function validateAcyclic(nodeById, projection, errors) {
  const adjacency = new Map([...nodeById.keys()].map((id) => [id, new Set()]));
  const indegree = new Map([...nodeById.keys()].map((id) => [id, 0]));

  for (const [unlocked, predecessors] of projection) {
    for (const predecessor of predecessors) {
      if (!adjacency.has(predecessor) || !indegree.has(unlocked)) continue;
      if (!adjacency.get(predecessor).has(unlocked)) {
        adjacency.get(predecessor).add(unlocked);
        indegree.set(unlocked, indegree.get(unlocked) + 1);
      }
    }
  }

  const queue = sorted([...indegree].filter(([, degree]) => degree === 0).map(([id]) => id));
  let visited = 0;
  while (queue.length > 0) {
    const id = queue.shift();
    visited += 1;
    for (const successor of adjacency.get(id)) {
      const degree = indegree.get(successor) - 1;
      indegree.set(successor, degree);
      if (degree === 0) queue.push(successor);
    }
    queue.sort((a, b) => a.localeCompare(b));
  }

  if (visited !== nodeById.size) {
    const cyclic = sorted([...indegree].filter(([, degree]) => degree > 0).map(([id]) => id));
    errors.push(`${DOCUMENTS.hyperedges}: blocking dependency graph contains a cycle involving ${cyclic.join(", ")}`);
  }
}

function validateReadiness(nodes, nodeById, errors) {
  for (const node of nodes) {
    if (!node || typeof node.id !== "string" || !NODE_STATUSES.has(node.status)) continue;
    const predecessors = Array.isArray(node.predecessors) ? node.predecessors : [];
    const allDone = predecessors.every((id) => nodeById.get(id)?.status === "done");
    if (allDone && node.status === "blocked") {
      errors.push(`${DOCUMENTS.nodes}: ${node.id} is blocked although every predecessor is done`);
    }
    if (!allDone && node.status !== "blocked") {
      const unfinished = predecessors.filter((id) => nodeById.get(id)?.status !== "done");
      errors.push(`${DOCUMENTS.nodes}: ${node.id} is ${node.status} but unfinished predecessors require blocked: ${unfinished.join(", ")}`);
    }
  }
}

function coverageRows(document, errors) {
  if (!document || typeof document !== "object") return [];
  if (!Array.isArray(document.coverage)) {
    errors.push(`${DOCUMENTS.coverage}.coverage: expected an array`);
    return [];
  }
  return document.coverage;
}

function validateUpstreamCommandRegistry(document, errors) {
  const label = `${DOCUMENTS.coverage}.upstream_command_registry`;
  const registry = document?.upstream_command_registry;
  if (!registry || typeof registry !== "object" || Array.isArray(registry)) {
    errors.push(`${label}: expected an object`);
    return {
      declaredIds: new Set(),
      declaredUnregisteredIds: new Set(),
      registryPrivateIds: new Set(),
      commandUniverse: new Set(),
      expectedRuntimeCount: 0,
    };
  }

  const actualFields = sorted(Object.keys(registry));
  const expectedFields = sorted(UPSTREAM_COMMAND_REGISTRY_FIELDS);
  if (!sameStrings(actualFields, expectedFields)) {
    errors.push(`${label}: expected exactly fields ${JSON.stringify(expectedFields)}, got ${JSON.stringify(actualFields)}`);
  }

  if (validateString(registry.version, `${label}.version`, errors)
      && !/^v\d+\.\d+\.\d+$/.test(registry.version)) {
    errors.push(`${label}.version: expected a vMAJOR.MINOR.PATCH version`);
  }
  if (validateString(registry.source_commit, `${label}.source_commit`, errors)
      && !/^[a-f0-9]{40}$/.test(registry.source_commit)) {
    errors.push(`${label}.source_commit: expected a lowercase 40-hex Git object ID`);
  }
  for (const field of ["declaration_source", "registry_source"]) {
    if (!validateString(registry[field], `${label}.${field}`, errors)) continue;
    try {
      const sourceUrl = new URL(registry[field]);
      if (sourceUrl.protocol !== "https:") errors.push(`${label}.${field}: expected an HTTPS URL`);
    } catch {
      errors.push(`${label}.${field}: expected a valid URL`);
    }
    if (typeof registry.version === "string" && !registry[field].includes(`/${registry.version}/`)) {
      errors.push(`${label}.${field}: source URL must be pinned to ${JSON.stringify(registry.version)}`);
    }
  }
  for (const field of [
    "declaration_source_sha256",
    "registry_source_sha256",
    "command_ownership_sha256",
    "coverage_semantics_sha256",
  ]) {
    if (validateString(registry[field], `${label}.${field}`, errors)
        && !/^[a-f0-9]{64}$/.test(registry[field])) {
      errors.push(`${label}.${field}: expected a lowercase SHA-256 digest`);
    }
  }

  const declaredValues = validatePositiveIntegerArray(
    registry.declared_command_ids,
    `${label}.declared_command_ids`,
    errors,
  );
  const unregisteredValues = validatePositiveIntegerArray(
    registry.declared_unregistered_ids,
    `${label}.declared_unregistered_ids`,
    errors,
  );
  const privateValues = validatePositiveIntegerArray(
    registry.registry_private_ids,
    `${label}.registry_private_ids`,
    errors,
  );
  const positiveIds = (values) => values.filter((id) => Number.isSafeInteger(id) && id > 0);
  const declaredIds = new Set(positiveIds(declaredValues));
  const declaredUnregisteredIds = new Set(positiveIds(unregisteredValues));
  const registryPrivateIds = new Set(positiveIds(privateValues));

  for (const id of declaredUnregisteredIds) {
    if (!declaredIds.has(id)) {
      errors.push(`${label}.declared_unregistered_ids: ${id} is not in declared_command_ids`);
    }
  }
  for (const id of registryPrivateIds) {
    if (declaredIds.has(id)) {
      errors.push(`${label}.registry_private_ids: ${id} must be disjoint from declared_command_ids`);
    }
  }

  if (registry.expected_ultra_capabilities_rule !== EXPECTED_ULTRA_CAPABILITIES_RULE) {
    errors.push(`${label}.expected_ultra_capabilities_rule: expected ${JSON.stringify(EXPECTED_ULTRA_CAPABILITIES_RULE)}`);
  }
  for (const field of [
    "version",
    "source_commit",
    "declaration_source",
    "declaration_source_sha256",
    "registry_source",
    "registry_source_sha256",
    "command_ownership_sha256",
    "coverage_semantics_sha256",
  ]) {
    if (registry[field] !== EXPECTED_UPSTREAM_COMMAND_REGISTRY[field]) {
      errors.push(`${label}.${field}: pinned value drifted from the reviewed v2.2.0 source`);
    }
  }
  if (sha256Json(declaredValues)
      !== EXPECTED_UPSTREAM_COMMAND_REGISTRY.declared_command_ids_sha256) {
    errors.push(`${label}.declared_command_ids: exact ordered ID set drifted from the reviewed v2.2.0 declaration source`);
  }
  if (!sameStrings(
    positiveIds(unregisteredValues).map(String),
    EXPECTED_UPSTREAM_COMMAND_REGISTRY.declared_unregistered_ids.map(String),
  )) {
    errors.push(`${label}.declared_unregistered_ids: expected exactly ${JSON.stringify(EXPECTED_UPSTREAM_COMMAND_REGISTRY.declared_unregistered_ids)}`);
  }
  if (!sameStrings(
    positiveIds(privateValues).map(String),
    EXPECTED_UPSTREAM_COMMAND_REGISTRY.registry_private_ids.map(String),
  )) {
    errors.push(`${label}.registry_private_ids: expected exactly ${JSON.stringify(EXPECTED_UPSTREAM_COMMAND_REGISTRY.registry_private_ids)}`);
  }
  const expectedRuntimeCount = declaredIds.size - declaredUnregisteredIds.size + registryPrivateIds.size;
  if (expectedRuntimeCount !== EXPECTED_ULTRA_RUNTIME_COMMAND_COUNT) {
    errors.push(`${label}: Ultra runtime formula yields ${expectedRuntimeCount}; expected ${EXPECTED_ULTRA_RUNTIME_COMMAND_COUNT}`);
  }

  return {
    declaredIds,
    declaredUnregisteredIds,
    registryPrivateIds,
    commandUniverse: new Set([...declaredIds, ...registryPrivateIds]),
    expectedRuntimeCount,
  };
}

function validateCommandSourceRegistry(document, upstreamRegistry, commandOwners, errors) {
  const label = `${DOCUMENTS.coverage}.command_source_registry`;
  const registry = document?.command_source_registry;
  if (!Array.isArray(registry)) {
    errors.push(`${label}: expected an array of provenance-only command metadata`);
    return [];
  }
  const expectedIds = [...upstreamRegistry.commandUniverse].sort((left, right) => left - right);
  const sourceProfileDigest = sha256Json(canonicalUpstreamSourceProfile(
    document?.upstream_command_registry,
  ));
  const seen = new Set();
  const actualIds = [];

  for (let index = 0; index < registry.length; index += 1) {
    const entry = registry[index];
    const at = `${label}[${index}]`;
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
      errors.push(`${at}: expected an object`);
      continue;
    }
    const actualFields = sorted(Object.keys(entry));
    const expectedFields = sorted(COMMAND_SOURCE_ENTRY_FIELDS);
    if (!sameStrings(actualFields, expectedFields)) {
      errors.push(`${at}: expected exactly fields ${JSON.stringify(expectedFields)}, got ${JSON.stringify(actualFields)}`);
    }
    const commandId = entry.command_id;
    if (!Number.isSafeInteger(commandId) || commandId <= 0 || commandId > 0xffff) {
      errors.push(`${at}.command_id: expected a positive unsigned 16-bit integer`);
      continue;
    }
    actualIds.push(commandId);
    if (seen.has(commandId)) errors.push(`${label}: duplicate command ID ${commandId}`);
    seen.add(commandId);
    if (index > 0 && Number(registry[index - 1]?.command_id) >= commandId) {
      errors.push(`${label}: entries must be strictly ordered by command_id`);
    }
    if (!upstreamRegistry.commandUniverse.has(commandId)) {
      errors.push(`${at}.command_id: absent from the pinned command universe`);
    }

    const registryPrivate = upstreamRegistry.registryPrivateIds.has(commandId);
    const declaredUnregistered = upstreamRegistry.declaredUnregisteredIds.has(commandId);
    if (registryPrivate) {
      if (entry.declaration_symbol !== null) {
        errors.push(`${at}.declaration_symbol: registry-private command must be null`);
      }
    } else if (typeof entry.declaration_symbol !== "string"
        || !DECLARATION_SYMBOL_PATTERN.test(entry.declaration_symbol)) {
      errors.push(`${at}.declaration_symbol: expected a DATA_CMD_* declaration symbol`);
    }
    if (declaredUnregistered) {
      if (entry.runtime_handler_symbol !== null) {
        errors.push(`${at}.runtime_handler_symbol: declared-unregistered command must be null`);
      }
    } else if (typeof entry.runtime_handler_symbol !== "string"
        || !RUNTIME_SYMBOL_PATTERN.test(entry.runtime_handler_symbol)) {
      errors.push(`${at}.runtime_handler_symbol: expected a runtime handler symbol`);
    }

    const hooks = validateStringArray(entry.hook_symbols, `${at}.hook_symbols`, errors);
    const stringHooks = hooks.filter((value) => typeof value === "string");
    if (!sameStrings(stringHooks, sorted(new Set(stringHooks)))) {
      errors.push(`${at}.hook_symbols: entries must be unique and lexicographically sorted`);
    }
    for (const hook of stringHooks) {
      if (!RUNTIME_SYMBOL_PATTERN.test(hook) || hook === "NULL") {
        errors.push(`${at}.hook_symbols: invalid hook symbol ${JSON.stringify(hook)}`);
      }
    }
    if (entry.runtime_handler_symbol === null && stringHooks.length > 0) {
      errors.push(`${at}.hook_symbols: a command without a runtime row cannot have hooks`);
    }

    const owners = commandOwners.get(commandId) || [];
    if (owners.length === 1) {
      if (entry.provider_capability_id !== owners[0].capabilityId) {
        errors.push(`${at}.provider_capability_id: drifted from the unique command owner`);
      }
      if (entry.disposition !== owners[0].disposition) {
        errors.push(`${at}.disposition: drifted from the unique command owner`);
      }
    } else {
      errors.push(`${at}: command must have exactly one coverage owner before source binding`);
    }
    if (entry.source_profile_id !== COMMAND_SOURCE_PROFILE_ID) {
      errors.push(`${at}.source_profile_id: expected ${JSON.stringify(COMMAND_SOURCE_PROFILE_ID)}`);
    }
    if (entry.source_profile_digest !== sourceProfileDigest) {
      errors.push(`${at}.source_profile_digest: drifted from the pinned upstream source profile`);
    }
    if (entry.declaration_source_sha256
        !== document?.upstream_command_registry?.declaration_source_sha256) {
      errors.push(`${at}.declaration_source_sha256: drifted from the pinned declaration source`);
    }
    if (entry.registry_source_sha256
        !== document?.upstream_command_registry?.registry_source_sha256) {
      errors.push(`${at}.registry_source_sha256: drifted from the pinned runtime registry source`);
    }
    if (typeof entry.entry_digest !== "string" || !/^[a-f0-9]{64}$/.test(entry.entry_digest)) {
      errors.push(`${at}.entry_digest: expected a lowercase SHA-256 digest`);
    }
    const entryDigest = sha256Json(canonicalCommandSourceEntryBasis(entry));
    if (entry.entry_digest !== entryDigest) {
      errors.push(`${at}.entry_digest: does not bind the exact source/owner metadata`);
    }
  }

  if (!sameStrings(actualIds.map(String), expectedIds.map(String))) {
    errors.push(`${label}: command IDs must exactly cover the 147-ID declared/private ceiling`);
  }
  const digest = sha256Json(canonicalCommandSourceRegistry(registry));
  const digestLabel = `${DOCUMENTS.coverage}.command_source_registry_sha256`;
  if (typeof document?.command_source_registry_sha256 !== "string"
      || !/^[a-f0-9]{64}$/.test(document.command_source_registry_sha256)) {
    errors.push(`${digestLabel}: expected a lowercase SHA-256 digest`);
  }
  if (document?.command_source_registry_sha256 !== digest) {
    errors.push(`${digestLabel}: does not match the canonical command-source registry`);
  }
  if (digest !== EXPECTED_COMMAND_SOURCE_REGISTRY_SHA256) {
    errors.push(`${label}: declaration/handler/hook metadata drifted from reviewed v2.2.0 sources`);
  }
  return registry;
}

function validateAssuranceProfiles(document, errors) {
  const label = `${DOCUMENTS.coverage}.assurance_profile_registry`;
  const registry = document?.assurance_profile_registry;
  const profiles = new Map();
  if (!registry || typeof registry !== "object" || Array.isArray(registry)) {
    errors.push(`${label}: expected an object keyed by assurance profile ID`);
    return profiles;
  }
  for (const [profileId, profile] of Object.entries(registry)) {
    const at = `${label}.${profileId}`;
    if (!/^[a-z][a-z0-9_]*$/.test(profileId)) {
      errors.push(`${at}: invalid assurance profile ID`);
    }
    if (!profile || typeof profile !== "object" || Array.isArray(profile)) {
      errors.push(`${at}: expected an object`);
      continue;
    }
    profiles.set(profileId, profile);
    const actualFields = sorted(Object.keys(profile));
    const expectedFields = sorted(ASSURANCE_PROFILE_FIELDS);
    if (!sameStrings(actualFields, expectedFields)) {
      errors.push(`${at}: expected exactly fields ${JSON.stringify(expectedFields)}, got ${JSON.stringify(actualFields)}`);
    }
    for (const field of ASSURANCE_PROFILE_FIELDS) {
      if (!ASSURANCE_AXIS_VALUES[field].has(profile[field])) {
        errors.push(`${at}.${field}: unknown assurance claim ${JSON.stringify(profile[field])}`);
      }
    }
  }
  if (profiles.size === 0) errors.push(`${label}: must not be empty`);

  const digest = sha256Json(canonicalAssuranceProfiles(registry));
  const digestLabel = `${DOCUMENTS.coverage}.assurance_profile_registry_sha256`;
  if (validateString(document?.assurance_profile_registry_sha256, digestLabel, errors)
      && !/^[a-f0-9]{64}$/.test(document.assurance_profile_registry_sha256)) {
    errors.push(`${digestLabel}: expected a lowercase SHA-256 digest`);
  }
  if (document?.assurance_profile_registry_sha256 !== digest) {
    errors.push(`${digestLabel}: does not match the canonical assurance-profile registry`);
  }
  if (digest !== EXPECTED_ASSURANCE_PROFILE_REGISTRY_SHA256) {
    errors.push(`${label}: claim-specific assurance registry drifted from the reviewed v0.3 map`);
  }
  return profiles;
}

function validateAssuranceSatisfactionRegistry(document, errors) {
  const label = `${DOCUMENTS.coverage}.assurance_satisfaction_registry`;
  const registry = document?.assurance_satisfaction_registry;
  if (!registry || typeof registry !== "object" || Array.isArray(registry)) {
    errors.push(`${label}: expected an object keyed by assurance axis`);
    return new Map();
  }
  const actualAxes = sorted(Object.keys(registry));
  const expectedAxes = sorted(Object.keys(ASSURANCE_AXIS_VALUES));
  if (!sameStrings(actualAxes, expectedAxes)) {
    errors.push(`${label}: expected exactly axes ${JSON.stringify(expectedAxes)}, got ${JSON.stringify(actualAxes)}`);
  }
  const result = new Map();
  for (const axis of expectedAxes) {
    const axisRegistry = registry[axis];
    const at = `${label}.${axis}`;
    if (!axisRegistry || typeof axisRegistry !== "object" || Array.isArray(axisRegistry)) {
      errors.push(`${at}: expected an object keyed by actual assurance claim`);
      continue;
    }
    const expectedActualClaims = sorted(ASSURANCE_AXIS_VALUES[axis]);
    const actualClaims = sorted(Object.keys(axisRegistry));
    if (!sameStrings(actualClaims, expectedActualClaims)) {
      errors.push(`${at}: expected exactly actual claims ${JSON.stringify(expectedActualClaims)}, got ${JSON.stringify(actualClaims)}`);
    }
    const axisMap = new Map();
    result.set(axis, axisMap);
    const ordered = ASSURANCE_AXIS_ORDER[axis];
    const expectedSatisfaction = new Map([
      ["not_required", ["not_required"]],
      ["not_applicable", ["not_required", "not_applicable"]],
      ...ordered.map((actual, index) => [actual, ["not_required", ...ordered.slice(0, index + 1)]]),
    ]);
    for (const actual of expectedActualClaims) {
      const minima = validateStringArray(axisRegistry[actual], `${at}.${actual}`, errors, { nonEmpty: true });
      const validMinima = minima.filter((minimum) => typeof minimum === "string");
      for (const minimum of validMinima) {
        if (!ASSURANCE_AXIS_VALUES[axis].has(minimum)) {
          errors.push(`${at}.${actual}: unknown minimum claim ${JSON.stringify(minimum)}`);
        }
      }
      const canonicalActual = sorted(new Set(validMinima));
      const canonicalExpected = sorted(expectedSatisfaction.get(actual) || []);
      if (!sameStrings(canonicalActual, canonicalExpected)
          || canonicalActual.length !== validMinima.length) {
        errors.push(`${at}.${actual}: satisfaction relation must equal ${JSON.stringify(canonicalExpected)}`);
      }
      axisMap.set(actual, new Set(canonicalActual));
    }
  }
  const digest = sha256Json(canonicalAssuranceSatisfaction(registry));
  const digestLabel = `${DOCUMENTS.coverage}.assurance_satisfaction_registry_sha256`;
  if (validateString(document?.assurance_satisfaction_registry_sha256, digestLabel, errors)
      && !/^[a-f0-9]{64}$/.test(document.assurance_satisfaction_registry_sha256)) {
    errors.push(`${digestLabel}: expected a lowercase SHA-256 digest`);
  }
  if (document?.assurance_satisfaction_registry_sha256 !== digest) {
    errors.push(`${digestLabel}: does not match the canonical assurance-satisfaction registry`);
  }
  if (digest !== EXPECTED_ASSURANCE_SATISFACTION_REGISTRY_SHA256) {
    errors.push(`${label}: satisfaction relation drifted from the reviewed v0.3 map`);
  }
  return result;
}

function validateDependencyProofProviders(document, errors) {
  const label = `${DOCUMENTS.coverage}.dependency_proof_provider_registry`;
  const registry = document?.dependency_proof_provider_registry;
  const providers = new Map();
  if (!registry || typeof registry !== "object" || Array.isArray(registry)) {
    errors.push(`${label}: expected an object keyed by typed proof-provider ref`);
    return providers;
  }
  for (const [ref, provider] of Object.entries(registry)) {
    const at = `${label}.${ref}`;
    if (!/^(?:compiler|conformance|observer|transport|vault_tool):[a-z][a-z0-9._-]*$/.test(ref)) {
      errors.push(`${at}: invalid proof-provider ref`);
    }
    if (!provider || typeof provider !== "object" || Array.isArray(provider)) {
      errors.push(`${at}: expected an object`);
      continue;
    }
    providers.set(ref, provider);
    const actualFields = sorted(Object.keys(provider));
    const expectedFields = sorted(DEPENDENCY_PROOF_PROVIDER_FIELDS);
    if (!sameStrings(actualFields, expectedFields)) {
      errors.push(`${at}: expected exactly fields ${JSON.stringify(expectedFields)}, got ${JSON.stringify(actualFields)}`);
    }
    for (const field of DEPENDENCY_PROOF_PROVIDER_FIELDS) {
      validateString(provider[field], `${at}.${field}`, errors);
    }
    const refKind = ref.split(":", 1)[0];
    if (!DEPENDENCY_PROOF_PROVIDER_KINDS.has(provider.provider_kind)
        || provider.provider_kind !== refKind) {
      errors.push(`${at}.provider_kind: must match typed ref prefix ${JSON.stringify(refKind)}`);
    }
  }
  if (providers.size === 0) errors.push(`${label}: must not be empty`);
  const digest = sha256Json(canonicalDependencyProofProviders(registry));
  const digestLabel = `${DOCUMENTS.coverage}.dependency_proof_provider_registry_sha256`;
  if (validateString(document?.dependency_proof_provider_registry_sha256, digestLabel, errors)
      && !/^[a-f0-9]{64}$/.test(document.dependency_proof_provider_registry_sha256)) {
    errors.push(`${digestLabel}: expected a lowercase SHA-256 digest`);
  }
  if (document?.dependency_proof_provider_registry_sha256 !== digest) {
    errors.push(`${digestLabel}: does not match the canonical dependency-proof-provider registry`);
  }
  if (digest !== EXPECTED_DEPENDENCY_PROOF_PROVIDER_REGISTRY_SHA256) {
    errors.push(`${label}: proof-provider registry drifted from the reviewed v0.3 map`);
  }
  return providers;
}

function validateHf14aClosedProbeContract(document, compilerManifest, errors) {
  const label = `${DOCUMENTS.coverage}.hf14a_closed_probe_contract`;
  const exactStrings = (actual, expected) => Array.isArray(actual)
    && sameStrings(sorted(actual), sorted(expected))
    && actual.length === expected.length;
  const exactRecord = (actual, expected) => actual != null
    && typeof actual === "object"
    && !Array.isArray(actual)
    && sameStrings(sorted(Object.keys(actual)), sorted(Object.keys(expected)))
    && Object.entries(expected).every(([field, value]) => actual[field] === value);

  const expectedProfile = {
    identity_enrollment: "operator_enrolled",
    firmware_provenance: "operator_pinned",
    command_surface_conformance: "conformance_tested",
    transport_trust: "operator_provisioned",
  };
  const profile = document?.assurance_profile_registry?.[HF14A_CLOSED_PROBE_PROFILE_ID];
  if (!exactRecord(profile, expectedProfile)) {
    errors.push(`${label}: ${HF14A_CLOSED_PROBE_PROFILE_ID} must remain the exact enrolled HIL-conformance profile`);
  }
  const profileUsers = Object.entries(document?.normalized_operation_registry || {})
    .filter(([, contract]) => contract?.minimum_assurance_profile_id
      === HF14A_CLOSED_PROBE_PROFILE_ID)
    .map(([operationId]) => operationId);
  if (!exactStrings(profileUsers, [HF14A_CLOSED_PROBE_OPERATION_ID])) {
    errors.push(`${label}: the HIL-conformance assurance profile must bind only protocol.discovery_probe`);
  }
  if (!exactRecord(document?.normalized_operation_registry?.[HF14A_CLOSED_PROBE_OPERATION_ID], {
    exposure: "technique_compiled",
    minimum_assurance_profile_id: HF14A_CLOSED_PROBE_PROFILE_ID,
  })) {
    errors.push(`${label}: protocol.discovery_probe must remain the sole conformance-tested technique operation`);
  }
  if (document?.normalized_operation_registry?.["protocol.compiled_exchange"]
    ?.minimum_assurance_profile_id !== "enrolled_source_pinned") {
    errors.push(`${label}: shared protocol.compiled_exchange assurance must not widen`);
  }

  const dependency = document?.capability_dependency_registry?.[
    HF14A_CLOSED_PROBE_CAPABILITY_ID
  ];
  if (!dependency || !exactStrings(dependency.all_of, HF14A_CLOSED_PROBE_COMMON_REFS)
      || !exactStrings(dependency.any_of, [])) {
    errors.push(`${label}: compiled probes require the exact raw, compiler, and distinct HIL-conformance dependencies`);
  }
  const variants = dependency?.variants;
  const expectedVariantIds = HF14A_CLOSED_PROBE_SCHEMA_BINDINGS.map(
    (binding) => binding.variant_id,
  );
  if (!variants || !exactStrings(Object.keys(variants), expectedVariantIds)) {
    errors.push(`${label}: compiled probes must expose exactly the REQA and WUPA variants`);
  }
  for (const binding of HF14A_CLOSED_PROBE_SCHEMA_BINDINGS) {
    const variant = variants?.[binding.variant_id];
    if (!variant
        || variant.parameter_selector_id !== binding.parameter_selector_id
        || !exactStrings(variant.all_of, [])
        || !exactStrings(variant.any_of, [])
        || !exactStrings(variant.normalized_operations, [HF14A_CLOSED_PROBE_OPERATION_ID])
        || !exactStrings(variant.technique_bindings, ["protocol.probe"])
        || !exactStrings(variant.effect_profile_refs, ["EP-TARGET-TRANSMIT-RF"])) {
      errors.push(`${label}: ${binding.schema_id} must map bijectively to ${binding.variant_id}`);
    }
  }

  const proofContract = document?.dependency_proof_provider_registry?.[
    HF14A_CLOSED_PROBE_CONFORMANCE_REF
  ];
  if (!exactRecord(proofContract, HF14A_CLOSED_PROBE_PROOF_CONTRACT)) {
    errors.push(`${label}: the HF14A proof must remain owned-HIL-, source-, firmware-, transport-, compiler-, and fixture-bound`);
  }
  const proofRefLocations = [];
  for (const [capabilityId, formula] of Object.entries(
    document?.capability_dependency_registry || {},
  )) {
    const commonRefs = [
      ...(Array.isArray(formula?.all_of) ? formula.all_of : []),
      ...(Array.isArray(formula?.any_of) ? formula.any_of.flat() : []),
    ];
    if (commonRefs.includes(HF14A_CLOSED_PROBE_CONFORMANCE_REF)) {
      proofRefLocations.push(`${capabilityId}/common`);
    }
    for (const [variantId, variant] of Object.entries(formula?.variants || {})) {
      const variantRefs = [
        ...(Array.isArray(variant?.all_of) ? variant.all_of : []),
        ...(Array.isArray(variant?.any_of) ? variant.any_of.flat() : []),
      ];
      if (variantRefs.includes(HF14A_CLOSED_PROBE_CONFORMANCE_REF)) {
        proofRefLocations.push(`${capabilityId}/${variantId}`);
      }
    }
  }
  if (!exactStrings(proofRefLocations, [`${HF14A_CLOSED_PROBE_CAPABILITY_ID}/common`])) {
    errors.push(`${label}: the HF14A HIL proof must not satisfy or gate any other capability`);
  }

  const compiledRows = (document?.coverage || []).filter(
    (row) => row?.provider_capability_id === HF14A_CLOSED_PROBE_CAPABILITY_ID,
  );
  const compiledRow = compiledRows[0];
  if (compiledRows.length !== 1
      || !exactStrings(compiledRow?.upstream_command_ids, [])
      || !exactStrings(compiledRow?.normalized_operations, [HF14A_CLOSED_PROBE_OPERATION_ID])
      || !exactStrings(compiledRow?.technique_bindings, ["protocol.probe"])
      || !exactStrings(compiledRow?.effect_profile_refs, ["EP-TARGET-TRANSMIT-RF"])
      || compiledRow?.disposition !== "planned") {
    errors.push(`${label}: compiled-probe coverage must remain byte-free, transmit-only, and planned`);
  }
  const operationVariantUsers = [];
  for (const [capabilityId, formula] of Object.entries(
    document?.capability_dependency_registry || {},
  )) {
    for (const [variantId, variant] of Object.entries(formula?.variants || {})) {
      if (variant?.normalized_operations?.includes(HF14A_CLOSED_PROBE_OPERATION_ID)) {
        operationVariantUsers.push(`${capabilityId}/${variantId}`);
      }
    }
  }
  if (!exactStrings(operationVariantUsers, expectedVariantIds.map(
    (variantId) => `${HF14A_CLOSED_PROBE_CAPABILITY_ID}/${variantId}`,
  ))) {
    errors.push(`${label}: protocol.discovery_probe must bind only the two closed HF14A variants`);
  }

  const raw = document?.capability_dependency_registry?.["CU-HF-14A-RAW"];
  const rawVariant = raw?.variants?.default;
  const rawEffects = [
    "EP-TARGET-DESTROY-RF",
    "EP-TARGET-MUTATE-RF-STATEFUL",
    "EP-TARGET-TRANSMIT-RF",
  ];
  if (!raw || !exactStrings(raw.all_of, []) || !exactStrings(raw.any_of, [])
      || !exactStrings(Object.keys(raw.variants || {}), ["default"])
      || !rawVariant || rawVariant.parameter_selector_id !== "default"
      || !exactStrings(rawVariant.all_of, ["command:2010"])
      || !exactStrings(rawVariant.any_of, [])
      || !exactStrings(rawVariant.normalized_operations, ["protocol.transceive"])
      || !exactStrings(rawVariant.technique_bindings, [])
      || !exactStrings(rawVariant.effect_profile_refs, rawEffects)) {
    errors.push(`${label}: command 2010 must remain the broad provider-private raw primitive`);
  }
  if ((document?.codec_profile?.command_ids || []).includes(2010)) {
    errors.push(`${label}: command 2010 must remain absent from the compiled codec profile`);
  }

  const canonicalBindings = (value) => Array.isArray(value)
    ? value.map((binding) => ({
      schema_id: binding?.schema_id,
      variant_id: binding?.variant_id,
      parameter_selector_id: binding?.parameter_selector_id,
    })).sort((left, right) => String(left.schema_id).localeCompare(String(right.schema_id)))
    : [];
  if (!compilerManifest
      || compilerManifest.capability_id !== HF14A_CLOSED_PROBE_CAPABILITY_ID
      || compilerManifest.operation_id !== HF14A_CLOSED_PROBE_OPERATION_ID
      || compilerManifest.minimum_assurance_profile_id !== HF14A_CLOSED_PROBE_PROFILE_ID
      || compilerManifest.required_conformance_dependency_ref
        !== HF14A_CLOSED_PROBE_CONFORMANCE_REF
      || compilerManifest.runtime_availability !== "unavailable_pending_hil_conformance"
      || compilerManifest.execution_authority !== false
      || compilerManifest.schema_count !== HF14A_CLOSED_PROBE_SCHEMA_BINDINGS.length
      || !exactStrings(
        compilerManifest.schema_ids,
        HF14A_CLOSED_PROBE_SCHEMA_BINDINGS.map((binding) => binding.schema_id),
      )
      || JSON.stringify(canonicalBindings(compilerManifest.schema_variant_bindings))
        !== JSON.stringify(canonicalBindings(HF14A_CLOSED_PROBE_SCHEMA_BINDINGS))) {
    errors.push(`${label}: compiler schemas and availability variants must remain an exact authority-free bijection`);
  }
}

function validateSemanticRegistries(document, assuranceProfiles, errors) {
  const operationLabel = `${DOCUMENTS.coverage}.normalized_operation_registry`;
  const operationRegistry = document?.normalized_operation_registry;
  const operations = new Map();
  if (!operationRegistry || typeof operationRegistry !== "object" || Array.isArray(operationRegistry)) {
    errors.push(`${operationLabel}: expected an object keyed by normalized operation ID`);
  } else {
    for (const [operationId, contract] of Object.entries(operationRegistry)) {
      if (!/^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+$/.test(operationId)) {
        errors.push(`${operationLabel}: invalid operation ID ${JSON.stringify(operationId)}`);
      }
      const at = `${operationLabel}.${operationId}`;
      if (!contract || typeof contract !== "object" || Array.isArray(contract)) {
        errors.push(`${at}: expected an operation contract object`);
        continue;
      }
      const actualFields = sorted(Object.keys(contract));
      const expectedFields = sorted(NORMALIZED_OPERATION_FIELDS);
      if (!sameStrings(actualFields, expectedFields)) {
        errors.push(`${at}: expected exactly fields ${JSON.stringify(expectedFields)}, got ${JSON.stringify(actualFields)}`);
      }
      if (!NORMALIZED_OPERATION_EXPOSURES.has(contract.exposure)) {
        errors.push(`${at}.exposure: unknown exposure ${JSON.stringify(contract.exposure)}`);
      }
      if (!validateString(contract.minimum_assurance_profile_id, `${at}.minimum_assurance_profile_id`, errors)
          || !assuranceProfiles.has(contract.minimum_assurance_profile_id)) {
        errors.push(`${at}.minimum_assurance_profile_id: references an unknown assurance profile`);
      }
      operations.set(operationId, contract);
    }
    if (operations.size === 0) errors.push(`${operationLabel}: must not be empty`);
  }

  const canonicalOperations = canonicalOperationRegistry(operationRegistry);
  const operationDigest = sha256Json(canonicalOperations);
  if (validateString(
    document?.normalized_operation_registry_sha256,
    `${DOCUMENTS.coverage}.normalized_operation_registry_sha256`,
    errors,
  ) && !/^[a-f0-9]{64}$/.test(document.normalized_operation_registry_sha256)) {
    errors.push(`${DOCUMENTS.coverage}.normalized_operation_registry_sha256: expected a lowercase SHA-256 digest`);
  }
  if (document?.normalized_operation_registry_sha256 !== operationDigest) {
    errors.push(`${DOCUMENTS.coverage}.normalized_operation_registry_sha256: does not match the canonical operation registry`);
  }
  if (operationDigest !== EXPECTED_NORMALIZED_OPERATION_REGISTRY_SHA256) {
    errors.push(`${operationLabel}: semantic registry drifted from the reviewed v0.3 map`);
  }

  const techniqueLabel = `${DOCUMENTS.coverage}.technique_registry`;
  const techniqueValues = validateStringArray(document?.technique_registry, techniqueLabel, errors, { nonEmpty: true });
  for (const techniqueId of techniqueValues) {
    if (typeof techniqueId === "string"
        && !/^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+$/.test(techniqueId)) {
      errors.push(`${techniqueLabel}: invalid technique ID ${JSON.stringify(techniqueId)}`);
    }
  }
  const stringTechniqueValues = techniqueValues.filter((value) => typeof value === "string");
  const canonicalTechniques = sorted(new Set(stringTechniqueValues));
  if (!sameStrings(stringTechniqueValues, canonicalTechniques)
      || stringTechniqueValues.length !== techniqueValues.length) {
    errors.push(`${techniqueLabel}: entries must be unique and lexicographically sorted`);
  }
  const techniqueDigest = sha256Json(canonicalTechniques);
  if (validateString(
    document?.technique_registry_sha256,
    `${DOCUMENTS.coverage}.technique_registry_sha256`,
    errors,
  ) && !/^[a-f0-9]{64}$/.test(document.technique_registry_sha256)) {
    errors.push(`${DOCUMENTS.coverage}.technique_registry_sha256: expected a lowercase SHA-256 digest`);
  }
  if (document?.technique_registry_sha256 !== techniqueDigest) {
    errors.push(`${DOCUMENTS.coverage}.technique_registry_sha256: does not match the canonical technique registry`);
  }
  if (techniqueDigest !== EXPECTED_TECHNIQUE_REGISTRY_SHA256) {
    errors.push(`${techniqueLabel}: semantic registry drifted from the reviewed v0.3 map`);
  }
  const registeredRecoveryTechniques = canonicalTechniques
    .filter((techniqueId) => /^secret\.recover(?:\.|_)/.test(techniqueId));
  const mappedRecoveryTechniques = sorted(VAULT_BACKED_RECOVERY_TOOLS.keys());
  if (!sameStrings(registeredRecoveryTechniques, mappedRecoveryTechniques)) {
    errors.push(
      `${techniqueLabel}: vault recovery-tool map must exactly cover recovery techniques; `
        + `registered=${JSON.stringify(registeredRecoveryTechniques)}, mapped=${JSON.stringify(mappedRecoveryTechniques)}`,
    );
  }

  return { operations, techniques: new Set(canonicalTechniques) };
}

function canonicalOperationRegistry(registry) {
  if (!registry || typeof registry !== "object" || Array.isArray(registry)) return [];
  return Object.entries(registry)
    .map(([operationId, contract]) => [operationId, {
      exposure: contract?.exposure,
      minimum_assurance_profile_id: contract?.minimum_assurance_profile_id,
    }])
    .sort(([left], [right]) => left.localeCompare(right));
}

function canonicalAssuranceProfiles(registry) {
  if (!registry || typeof registry !== "object" || Array.isArray(registry)) return [];
  return Object.entries(registry)
    .map(([profileId, profile]) => [profileId, {
      identity_enrollment: profile?.identity_enrollment,
      firmware_provenance: profile?.firmware_provenance,
      command_surface_conformance: profile?.command_surface_conformance,
      transport_trust: profile?.transport_trust,
    }])
    .sort(([left], [right]) => left.localeCompare(right));
}

function canonicalAssuranceSatisfaction(registry) {
  if (!registry || typeof registry !== "object" || Array.isArray(registry)) return [];
  const array = (value) => Array.isArray(value) ? value : [];
  return Object.entries(registry)
    .map(([axis, actualClaims]) => [axis, Object.entries(
      actualClaims && typeof actualClaims === "object" && !Array.isArray(actualClaims)
        ? actualClaims
        : {},
    )
      .map(([actual, minima]) => [actual, sorted(array(minima).map(String))])
      .sort(([left], [right]) => left.localeCompare(right))])
    .sort(([left], [right]) => left.localeCompare(right));
}

function canonicalCapabilityDependencies(registry) {
  if (!registry || typeof registry !== "object" || Array.isArray(registry)) return [];
  const array = (value) => Array.isArray(value) ? value : [];
  const canonicalFormula = (formula) => ({
    all_of: sorted(array(formula?.all_of).map(String)),
    any_of: array(formula?.any_of)
      .map((group) => sorted(array(group).map(String)))
      .sort((left, right) => JSON.stringify(left).localeCompare(JSON.stringify(right))),
  });
  return Object.entries(registry)
    .map(([capabilityId, dependency]) => [capabilityId, {
      ...canonicalFormula(dependency),
      variants: Object.entries(
        dependency?.variants && typeof dependency.variants === "object" && !Array.isArray(dependency.variants)
          ? dependency.variants
          : {},
      )
        .map(([variantId, variant]) => [variantId, {
          parameter_selector_id: variant?.parameter_selector_id,
          ...canonicalFormula(variant),
          normalized_operations: sorted(array(variant?.normalized_operations).map(String)),
          technique_bindings: sorted(array(variant?.technique_bindings).map(String)),
          effect_profile_refs: sorted(array(variant?.effect_profile_refs).map(String)),
        }])
        .sort(([left], [right]) => left.localeCompare(right)),
    }])
    .sort(([left], [right]) => left.localeCompare(right));
}

function canonicalDependencyProofProviders(registry) {
  if (!registry || typeof registry !== "object" || Array.isArray(registry)) return [];
  return Object.entries(registry)
    .map(([ref, provider]) => [ref, {
      provider_kind: provider?.provider_kind,
      owner_principal: provider?.owner_principal,
      artifact_digest_binding: provider?.artifact_digest_binding,
      signed_verdict_type: provider?.signed_verdict_type,
      trust_epoch_binding: provider?.trust_epoch_binding,
      freshness_policy: provider?.freshness_policy,
      revocation_policy: provider?.revocation_policy,
    }])
    .sort(([left], [right]) => left.localeCompare(right));
}

function canonicalEffectProfiles(profiles) {
  if (!profiles || typeof profiles !== "object" || Array.isArray(profiles)) return [];
  const array = (value) => Array.isArray(value) ? value : [];
  return Object.entries(profiles)
    .map(([profileId, profile]) => [profileId, {
      subject_kind: profile?.subject_kind,
      action: profile?.action,
      channel: profile?.channel,
      persistence: profile?.persistence,
      required_bounds: sorted(array(profile?.required_bounds).map(String)),
    }])
    .sort(([left], [right]) => left.localeCompare(right));
}

function canonicalManualActions(registry) {
  if (!registry || typeof registry !== "object" || Array.isArray(registry)) return [];
  const array = (value) => Array.isArray(value) ? value : [];
  return Object.entries(registry)
    .map(([capabilityId, action]) => [capabilityId, {
      source_url: action?.source_url,
      source_sha256: action?.source_sha256,
      source_symbol: action?.source_symbol,
      source_case: action?.source_case,
      procedure_id: action?.procedure_id,
      effect_profile_refs: sorted(array(action?.effect_profile_refs).map(String)),
      required_receipts: sorted(array(action?.required_receipts).map(String)),
      rf_off_deadline_required: action?.rf_off_deadline_required,
    }])
    .sort(([left], [right]) => left.localeCompare(right));
}

function canonicalCommandSourceEntryBasis(entry) {
  const array = (value) => Array.isArray(value) ? value : [];
  return {
    command_id: entry?.command_id,
    declaration_symbol: entry?.declaration_symbol,
    runtime_handler_symbol: entry?.runtime_handler_symbol,
    hook_symbols: sorted(array(entry?.hook_symbols).map(String)),
    provider_capability_id: entry?.provider_capability_id,
    disposition: entry?.disposition,
    source_profile_id: entry?.source_profile_id,
    source_profile_digest: entry?.source_profile_digest,
    declaration_source_sha256: entry?.declaration_source_sha256,
    registry_source_sha256: entry?.registry_source_sha256,
  };
}

function canonicalCommandSourceRegistry(registry) {
  if (!Array.isArray(registry)) return [];
  return registry.map((entry) => ({
    ...canonicalCommandSourceEntryBasis(entry),
    entry_digest: entry?.entry_digest,
  })).sort((left, right) => Number(left.command_id) - Number(right.command_id));
}

function canonicalUpstreamSourceProfile(registry) {
  const array = (value) => Array.isArray(value) ? value : [];
  return {
    version: registry?.version,
    declaration_source: registry?.declaration_source,
    declaration_source_sha256: registry?.declaration_source_sha256,
    registry_source: registry?.registry_source,
    registry_source_sha256: registry?.registry_source_sha256,
    expected_ultra_capabilities_rule: registry?.expected_ultra_capabilities_rule,
    declared_command_ids: [...array(registry?.declared_command_ids)],
    declared_unregistered_ids: [...array(registry?.declared_unregistered_ids)],
    registry_private_ids: [...array(registry?.registry_private_ids)],
  };
}

function canonicalCoverageSemantics(document, rows) {
  const array = (value) => Array.isArray(value) ? value : [];
  const canonicalValues = (value) => [...array(value)]
    .sort((left, right) => String(left).localeCompare(String(right)));
  const registry = document?.upstream_command_registry || {};
  const coverage = rows
    .filter((row) => row && typeof row === "object" && !Array.isArray(row))
    .map((row) => ({
      provider_capability_id: row.provider_capability_id,
      provider: row.provider,
      protocol_family: row.protocol_family,
      device_surface: row.device_surface,
      upstream_command_ids: [...array(row.upstream_command_ids)].sort((left, right) => left - right),
      normalized_operations: canonicalValues(row.normalized_operations),
      technique_bindings: canonicalValues(row.technique_bindings),
      effect_profile_refs: canonicalValues(row.effect_profile_refs),
      data_class: row.data_class,
      node_refs: canonicalValues(row.node_refs),
      disposition: row.disposition,
      reason: row.reason,
    }))
    .sort((left, right) => String(left.provider_capability_id).localeCompare(String(right.provider_capability_id)));
  return {
    version: document?.version,
    provider: document?.provider,
    provider_baseline: document?.provider_baseline,
    coverage_contract: document?.coverage_contract,
    runtime_rule: document?.runtime_rule,
    upstream_source: {
      version: registry.version,
      declaration_source: registry.declaration_source,
      declaration_source_sha256: registry.declaration_source_sha256,
      registry_source: registry.registry_source,
      registry_source_sha256: registry.registry_source_sha256,
      declared_command_ids: [...array(registry.declared_command_ids)].sort((left, right) => left - right),
      declared_unregistered_ids: [...array(registry.declared_unregistered_ids)].sort((left, right) => left - right),
      registry_private_ids: [...array(registry.registry_private_ids)].sort((left, right) => left - right),
      expected_ultra_capabilities_rule: registry.expected_ultra_capabilities_rule,
    },
    command_source_registry: canonicalCommandSourceRegistry(
      document?.command_source_registry,
    ),
    normalized_operation_registry: canonicalOperationRegistry(document?.normalized_operation_registry),
    assurance_profile_registry: canonicalAssuranceProfiles(document?.assurance_profile_registry),
    assurance_satisfaction_registry: canonicalAssuranceSatisfaction(document?.assurance_satisfaction_registry),
    capability_dependency_registry: canonicalCapabilityDependencies(document?.capability_dependency_registry),
    dependency_proof_provider_registry: canonicalDependencyProofProviders(document?.dependency_proof_provider_registry),
    technique_registry: canonicalValues(document?.technique_registry),
    effect_profiles: canonicalEffectProfiles(document?.effect_profiles),
    manual_action_registry: canonicalManualActions(document?.manual_action_registry),
    coverage,
  };
}

function validateEffectProfiles(document, errors) {
  const label = `${DOCUMENTS.coverage}.effect_profiles`;
  if (!document || !document.effect_profiles || typeof document.effect_profiles !== "object"
      || Array.isArray(document.effect_profiles)) {
    errors.push(`${label}: expected an object keyed by effect profile ID`);
    return new Map();
  }

  const entries = Object.entries(document.effect_profiles);
  if (entries.length === 0) errors.push(`${label}: must not be empty`);
  const profiles = new Map();

  for (const [profileId, profile] of entries) {
    const at = `${label}.${profileId}`;
    if (!/^EP-[A-Z0-9]+(?:-[A-Z0-9]+)*$/.test(profileId)) {
      errors.push(`${at}: profile ID does not match the EP-* grammar`);
    }
    if (!profile || typeof profile !== "object" || Array.isArray(profile)) {
      errors.push(`${at}: expected an object`);
      continue;
    }
    profiles.set(profileId, profile);

    const actualFields = sorted(Object.keys(profile));
    const expectedFields = sorted(EFFECT_PROFILE_FIELDS);
    if (!sameStrings(actualFields, expectedFields)) {
      errors.push(`${at}: expected exactly fields ${JSON.stringify(expectedFields)}, got ${JSON.stringify(actualFields)}`);
    }
    if (!EFFECT_SUBJECT_KINDS.has(profile.subject_kind)) {
      errors.push(`${at}.subject_kind: unknown subject kind ${JSON.stringify(profile.subject_kind)}`);
    }
    if (!EFFECT_ACTIONS.has(profile.action)) {
      errors.push(`${at}.action: unknown action ${JSON.stringify(profile.action)}`);
    }
    if (!EFFECT_CHANNELS.has(profile.channel)) {
      errors.push(`${at}.channel: unknown channel ${JSON.stringify(profile.channel)}`);
    }
    if (!EFFECT_PERSISTENCE.has(profile.persistence)) {
      errors.push(`${at}.persistence: unknown persistence ${JSON.stringify(profile.persistence)}`);
    }
    const bounds = validateStringArray(profile.required_bounds, `${at}.required_bounds`, errors);
    for (const bound of bounds) {
      if (typeof bound === "string" && !/^[a-z][a-z0-9_]*$/.test(bound)) {
        errors.push(`${at}.required_bounds: invalid bound name ${JSON.stringify(bound)}`);
      }
    }

    if (typeof profile.subject_kind === "string" && typeof profile.action === "string") {
      const surface = `${profile.subject_kind}.${profile.action}`;
      if (!EFFECT_SURFACES.has(surface)) {
        errors.push(`${at}: subject/action pair ${JSON.stringify(surface)} is not a registered effect surface`);
      }
    }

    const boundSet = new Set(bounds);
    const requireBound = (bound, reason) => {
      if (!boundSet.has(bound)) errors.push(`${at}.required_bounds: ${reason} requires ${bound}`);
    };
    requireBound("instrument_ref", "every provider effect");
    if (profile.action === "transmit" || profile.action === "present") {
      requireBound("duration_ms", `${profile.action} action`);
    }
    if (profile.channel === "rf") {
      for (const bound of RF_REQUIRED_BOUNDS) requireBound(bound, "RF effect");
    }
    if (profile.subject_kind === "target") {
      requireBound("target_ref", "target effect");
    }
    if ((profile.action === "mutate" || profile.action === "destroy") && profile.channel === "rf") {
      requireBound("state_delta_plan_ref", `${profile.action} RF action`);
      requireBound("byte_limit", `${profile.action} RF action`);
    }
    if (profile.action === "configure" && profile.persistence === "persistent") {
      requireBound("cleanup_plan_digest", "persistent configure action");
    }
    if (profile.action === "mutate" && profile.persistence === "persistent"
        && !boundSet.has("cleanup_plan_digest") && !boundSet.has("residual_state_plan_ref")) {
      errors.push(`${at}.required_bounds: persistent mutate action requires cleanup_plan_digest or residual_state_plan_ref`);
    }
    if (profile.action === "destroy") {
      requireBound("operator_receipt_ref", "destroy action");
      if (profile.subject_kind === "target") {
        requireBound("terminal_state_plan_ref", "target destroy action");
      }
    }
    if (profile.subject_kind === "instrument"
        && (profile.action === "administer" || profile.action === "destroy")) {
      for (const bound of INSTRUMENT_MAINTENANCE_REQUIRED_BOUNDS) {
        requireBound(bound, "instrument maintenance action");
      }
      if (profile.action === "administer") {
        requireBound("expected_terminal_state_ref", "persistent instrument administration");
        requireBound("recovery_or_quarantine_plan_ref", "persistent instrument administration");
      } else {
        requireBound("terminal_state_plan_ref", "irreversible instrument destruction");
        requireBound("quarantine_or_disposal_plan_ref", "irreversible instrument destruction");
      }
    }
    if (profileId.endsWith("-MANUAL")) {
      requireBound("operator_receipt_ref", "manual action");
      requireBound("witness_receipt_ref", "manual action");
    }
    if (profileId === "EP-TARGET-MUTATE-RF-STATEFUL") {
      for (const bound of [
        "auth_attempt_limit",
        "counter_delta_limit",
        "lockout_headroom_ref",
        "log_event_limit",
      ]) {
        requireBound(bound, "stateful authentication effect");
      }
    }
  }

  return profiles;
}

function validateManualActionRegistry(document, rows, effectProfiles, errors) {
  const label = `${DOCUMENTS.coverage}.manual_action_registry`;
  const registry = document?.manual_action_registry;
  if (!registry || typeof registry !== "object" || Array.isArray(registry)) {
    errors.push(`${label}: expected an object keyed by operator-only capability ID`);
    return new Map();
  }

  const actualIds = sorted(Object.keys(registry));
  const expectedIds = sorted(Object.keys(EXPECTED_MANUAL_ACTIONS));
  if (!sameStrings(actualIds, expectedIds)) {
    errors.push(`${label}: expected exactly action IDs ${JSON.stringify(expectedIds)}, got ${JSON.stringify(actualIds)}`);
  }

  const digest = sha256Json(canonicalManualActions(registry));
  const digestLabel = `${DOCUMENTS.coverage}.manual_action_registry_sha256`;
  if (validateString(document?.manual_action_registry_sha256, digestLabel, errors)
      && !/^[a-f0-9]{64}$/.test(document.manual_action_registry_sha256)) {
    errors.push(`${digestLabel}: expected a lowercase SHA-256 digest`);
  }
  if (document?.manual_action_registry_sha256 !== digest) {
    errors.push(`${digestLabel}: does not match the canonical manual-action registry`);
  }
  if (digest !== EXPECTED_MANUAL_ACTION_REGISTRY_SHA256) {
    errors.push(`${label}: source/procedure registry drifted from the reviewed v0.3 map`);
  }

  const rowsByCapability = new Map(rows
    .filter((row) => row && typeof row.provider_capability_id === "string")
    .map((row) => [row.provider_capability_id, row]));
  const result = new Map();
  for (const [capabilityId, action] of Object.entries(registry)) {
    const at = `${label}.${capabilityId}`;
    if (!action || typeof action !== "object" || Array.isArray(action)) {
      errors.push(`${at}: expected an object`);
      continue;
    }
    result.set(capabilityId, action);
    const actualFields = sorted(Object.keys(action));
    const expectedFields = sorted(MANUAL_ACTION_FIELDS);
    if (!sameStrings(actualFields, expectedFields)) {
      errors.push(`${at}: expected exactly fields ${JSON.stringify(expectedFields)}, got ${JSON.stringify(actualFields)}`);
    }
    for (const field of ["source_url", "source_sha256", "source_symbol", "source_case", "procedure_id"]) {
      validateString(action[field], `${at}.${field}`, errors);
    }
    if (action.source_url !== MANUAL_ACTION_SOURCE.url) {
      errors.push(`${at}.source_url: expected the reviewed v2.2.0 app_main.c source`);
    }
    if (action.source_sha256 !== MANUAL_ACTION_SOURCE.sha256) {
      errors.push(`${at}.source_sha256: source hash drifted from reviewed v2.2.0 app_main.c`);
    }
    if (action.source_symbol !== MANUAL_ACTION_SOURCE.symbol) {
      errors.push(`${at}.source_symbol: expected ${JSON.stringify(MANUAL_ACTION_SOURCE.symbol)}`);
    }
    const expectedAction = EXPECTED_MANUAL_ACTIONS[capabilityId];
    if (expectedAction) {
      if (action.source_case !== expectedAction.source_case) {
        errors.push(`${at}.source_case: expected ${JSON.stringify(expectedAction.source_case)}`);
      }
      if (action.procedure_id !== expectedAction.procedure_id) {
        errors.push(`${at}.procedure_id: expected ${JSON.stringify(expectedAction.procedure_id)}`);
      }
    }

    const effects = validateStringArray(action.effect_profile_refs, `${at}.effect_profile_refs`, errors, { nonEmpty: true });
    const receipts = validateStringArray(action.required_receipts, `${at}.required_receipts`, errors, { nonEmpty: true });
    const expectedReceipts = ["operator_receipt_ref", "witness_receipt_ref"];
    const validReceipts = receipts.filter((receipt) => typeof receipt === "string");
    if (!sameStrings(sorted(validReceipts), expectedReceipts)
        || validReceipts.length !== receipts.length) {
      errors.push(`${at}.required_receipts: expected exactly ${JSON.stringify(expectedReceipts)}`);
    }
    if (action.rf_off_deadline_required !== true) {
      errors.push(`${at}.rf_off_deadline_required: expected true`);
    }

    const row = rowsByCapability.get(capabilityId);
    if (!row) {
      errors.push(`${at}: no matching coverage row`);
      continue;
    }
    if (row.disposition !== "operator_only") {
      errors.push(`${at}: matching coverage row must be operator_only`);
    }
    if (!Array.isArray(row.normalized_operations)
        || !row.normalized_operations.includes("instrument.manual_action")) {
      errors.push(`${at}: matching coverage row must include instrument.manual_action`);
    }
    const rowEffects = Array.isArray(row.effect_profile_refs)
      ? row.effect_profile_refs.filter((effect) => typeof effect === "string")
      : [];
    const validEffects = effects.filter((effect) => typeof effect === "string");
    if (!sameStrings(sorted(rowEffects), sorted(validEffects))
        || validEffects.length !== effects.length) {
      errors.push(`${at}: effect_profile_refs must exactly match the coverage row`);
    }
    let hasRfEffect = false;
    for (const effectRef of validEffects) {
      const profile = effectProfiles.get(effectRef);
      if (!profile) {
        errors.push(`${at}.effect_profile_refs: unknown effect profile ${JSON.stringify(effectRef)}`);
        continue;
      }
      const bounds = new Set(Array.isArray(profile.required_bounds) ? profile.required_bounds : []);
      for (const receipt of expectedReceipts) {
        if (!bounds.has(receipt)) {
          errors.push(`${at}: effect profile ${effectRef} does not bind ${receipt}`);
        }
      }
      if (profile.channel === "rf") {
        hasRfEffect = true;
        if (!bounds.has("execution_deadline")) {
          errors.push(`${at}: RF effect profile ${effectRef} lacks an RF-off execution deadline`);
        }
      }
    }
    if (!hasRfEffect) errors.push(`${at}: manual target-facing action requires an RF effect profile`);
  }

  return result;
}

function validateCapabilityDependencies(
  document,
  rows,
  operations,
  techniques,
  effectProfiles,
  proofProviders,
  errors,
) {
  const label = `${DOCUMENTS.coverage}.capability_dependency_registry`;
  const registry = document?.capability_dependency_registry;
  if (!registry || typeof registry !== "object" || Array.isArray(registry)) {
    errors.push(`${label}: expected an object keyed by provider capability ID`);
    return new Map();
  }

  const rowsByCapability = new Map(rows
    .filter((row) => row && typeof row.provider_capability_id === "string")
    .map((row) => [row.provider_capability_id, row]));
  const requiredIds = sorted(rows
    .filter((row) => row && row.disposition !== "unsupported")
    .map((row) => row.provider_capability_id)
    .filter((value) => typeof value === "string"));
  const actualIds = sorted(Object.keys(registry));
  const missingRequired = requiredIds.filter((capabilityId) => !Object.hasOwn(registry, capabilityId));
  const unexpected = actualIds.filter((capabilityId) => !requiredIds.includes(capabilityId));
  if (missingRequired.length > 0 || unexpected.length > 0) {
    errors.push(`${label}: formulas must exactly cover supported rows; missing=${JSON.stringify(missingRequired)}, extra=${JSON.stringify(unexpected)}`);
  }

  const manualProcedures = new Set(Object.values(document?.manual_action_registry || {})
    .map((action) => action?.procedure_id)
    .filter((value) => typeof value === "string"));
  const proofRefsUsed = new Set();
  const dependencyMap = new Map();
  const variantMap = new Map();
  const formulaRefsByVariant = new Map();

  const validateFormula = (formula, at, row, mentionedCommands) => {
    const allOf = validateStringArray(formula?.all_of, `${at}.all_of`, errors);
    if (!Array.isArray(formula?.any_of)) {
      errors.push(`${at}.any_of: expected an array of non-empty alternative groups`);
    }
    const anyOf = Array.isArray(formula?.any_of) ? formula.any_of : [];
    const groups = [];
    for (let groupIndex = 0; groupIndex < anyOf.length; groupIndex += 1) {
      groups.push(validateStringArray(
        anyOf[groupIndex],
        `${at}.any_of[${groupIndex}]`,
        errors,
        { nonEmpty: true },
      ));
    }
    const refs = [...allOf, ...groups.flat()].filter((ref) => typeof ref === "string");
    const ownedCommands = new Set(Array.isArray(row?.upstream_command_ids) ? row.upstream_command_ids : []);
    for (const ref of refs) {
      if (ref.startsWith("capability:")) {
        errors.push(`${at}: generic capability refs are forbidden; bind exact capability_variant refs`);
        continue;
      }
      if (!DEPENDENCY_REF_PATTERN.test(ref)) {
        errors.push(`${at}: invalid typed dependency ref ${JSON.stringify(ref)}`);
        continue;
      }
      if (ref.startsWith("command:")) {
        const commandId = Number(ref.slice("command:".length));
        mentionedCommands.add(commandId);
        if (!ownedCommands.has(commandId)) {
          errors.push(`${at}: command ref ${commandId} is not owned by ${row?.provider_capability_id}`);
        }
        continue;
      }
      if (ref.startsWith("manual_procedure:")) {
        if (!manualProcedures.has(ref.slice("manual_procedure:".length))) {
          errors.push(`${at}: unknown manual procedure dependency ${JSON.stringify(ref)}`);
        }
        continue;
      }
      if (/^(?:compiler|conformance|observer|transport|vault_tool):/.test(ref)) {
        proofRefsUsed.add(ref);
        if (!proofProviders.has(ref)) {
          errors.push(`${at}: unresolved proof-provider dependency ${JSON.stringify(ref)}`);
        }
        continue;
      }
    }
    return refs;
  };

  for (const capabilityId of actualIds) {
    const dependency = registry[capabilityId];
    const at = `${label}.${capabilityId}`;
    const row = rowsByCapability.get(capabilityId);
    if (!row) {
      errors.push(`${at}: no matching coverage row`);
    } else if (row.disposition === "unsupported") {
      errors.push(`${at}: unsupported capabilities cannot declare availability variants`);
    }
    if (!dependency || typeof dependency !== "object" || Array.isArray(dependency)) {
      errors.push(`${at}: expected an object`);
      continue;
    }
    dependencyMap.set(capabilityId, dependency);
    const actualFields = sorted(Object.keys(dependency));
    const expectedFields = sorted(CAPABILITY_DEPENDENCY_FIELDS);
    if (!sameStrings(actualFields, expectedFields)) {
      errors.push(`${at}: expected exactly fields ${JSON.stringify(expectedFields)}, got ${JSON.stringify(actualFields)}`);
    }

    const mentionedCommands = new Set();
    const commonRefs = validateFormula(dependency, at, row, mentionedCommands);
    const variants = dependency.variants;
    if (!variants || typeof variants !== "object" || Array.isArray(variants)) {
      errors.push(`${at}.variants: expected a non-empty object keyed by schedulable variant ID`);
      continue;
    }
    const variantEntries = Object.entries(variants);
    if (variantEntries.length === 0) {
      errors.push(`${at}.variants: must not be empty`);
    }
    const unionOperations = new Set();
    const unionTechniques = new Set();
    const unionEffects = new Set();
    const rowOperations = new Set(Array.isArray(row?.normalized_operations) ? row.normalized_operations : []);
    const rowTechniques = new Set(Array.isArray(row?.technique_bindings) ? row.technique_bindings : []);
    const rowEffects = new Set(Array.isArray(row?.effect_profile_refs) ? row.effect_profile_refs : []);

    for (const [variantId, variant] of variantEntries) {
      const variantAt = `${at}.variants.${variantId}`;
      const variantKey = `${capabilityId}/${variantId}`;
      if (!/^[a-z][a-z0-9._-]*$/.test(variantId)) {
        errors.push(`${variantAt}: invalid variant ID`);
      }
      if (!variant || typeof variant !== "object" || Array.isArray(variant)) {
        errors.push(`${variantAt}: expected an object`);
        continue;
      }
      variantMap.set(variantKey, variant);
      const variantFields = sorted(Object.keys(variant));
      const expectedVariantFields = sorted(CAPABILITY_VARIANT_FIELDS);
      if (!sameStrings(variantFields, expectedVariantFields)) {
        errors.push(`${variantAt}: expected exactly fields ${JSON.stringify(expectedVariantFields)}, got ${JSON.stringify(variantFields)}`);
      }
      if (variant.parameter_selector_id !== variantId) {
        errors.push(`${variantAt}.parameter_selector_id: must equal the variant ID`);
      }
      const variantRefs = validateFormula(variant, variantAt, row, mentionedCommands);
      if (commonRefs.length === 0 && variantRefs.length === 0) {
        errors.push(`${variantAt}: common plus variant formula must contain at least one dependency ref`);
      }
      const formulaRefs = [...commonRefs, ...variantRefs];
      const mandatoryRefs = [
        ...(Array.isArray(dependency.all_of) ? dependency.all_of : []),
        ...(Array.isArray(variant.all_of) ? variant.all_of : []),
      ];
      formulaRefsByVariant.set(variantKey, formulaRefs);

      const variantOperations = validateStringArray(
        variant.normalized_operations,
        `${variantAt}.normalized_operations`,
        errors,
      );
      const variantTechniques = validateStringArray(
        variant.technique_bindings,
        `${variantAt}.technique_bindings`,
        errors,
      );
      const variantEffects = validateStringArray(
        variant.effect_profile_refs,
        `${variantAt}.effect_profile_refs`,
        errors,
      );
      if (variantOperations.length === 0 && variantTechniques.length === 0) {
        errors.push(`${variantAt}: variant must bind at least one operation or technique`);
      }
      for (const technique of variantTechniques) {
        const requiredVaultTool = VAULT_BACKED_RECOVERY_TOOLS.get(technique);
        if (requiredVaultTool && !mandatoryRefs.includes(requiredVaultTool)) {
          errors.push(`${variantAt}: recovery technique ${JSON.stringify(technique)} requires mandatory all_of dependency ${JSON.stringify(requiredVaultTool)}`);
        }
      }
      const safetyGuard = PROVIDER_VARIANT_SAFETY_GUARDS.get(variantKey);
      if (safetyGuard) {
        const missingMandatoryRefs = safetyGuard.mandatory_refs
          .filter((ref) => !mandatoryRefs.includes(ref));
        if (missingMandatoryRefs.length > 0) {
          errors.push(`${variantAt}: provider safety guard lacks mandatory refs ${JSON.stringify(missingMandatoryRefs)}`);
        }
        for (const [field, actual, expected] of [
          ["normalized_operations", variantOperations, safetyGuard.normalized_operations],
          ["technique_bindings", variantTechniques, safetyGuard.technique_bindings],
          ["effect_profile_refs", variantEffects, safetyGuard.effect_profile_refs],
        ]) {
          if (!sameStrings(sorted(actual), sorted(expected))) {
            errors.push(
              `${variantAt}: provider safety guard requires exact ${field}; `
                + `expected=${JSON.stringify(sorted(expected))}, got=${JSON.stringify(sorted(actual))}`,
            );
          }
        }
      }
      for (const operation of variantOperations) {
        unionOperations.add(operation);
        if (!rowOperations.has(operation)) {
          errors.push(`${variantAt}: operation ${JSON.stringify(operation)} is absent from the owning coverage row`);
        }
        if (!operations.has(operation)) {
          errors.push(`${variantAt}: unknown normalized operation ${JSON.stringify(operation)}`);
        }
      }
      for (const technique of variantTechniques) {
        unionTechniques.add(technique);
        if (!rowTechniques.has(technique)) {
          errors.push(`${variantAt}: technique ${JSON.stringify(technique)} is absent from the owning coverage row`);
        }
        if (!techniques.has(technique)) {
          errors.push(`${variantAt}: unknown technique ${JSON.stringify(technique)}`);
        }
      }
      for (const effectRef of variantEffects) {
        unionEffects.add(effectRef);
        if (!rowEffects.has(effectRef)) {
          errors.push(`${variantAt}: effect profile ${JSON.stringify(effectRef)} is absent from the owning coverage row`);
        }
        if (!effectProfiles.has(effectRef)) {
          errors.push(`${variantAt}: unknown effect profile ${JSON.stringify(effectRef)}`);
        }
      }
    }

    for (const [field, actualSet, expectedSet] of [
      ["normalized_operations", unionOperations, rowOperations],
      ["technique_bindings", unionTechniques, rowTechniques],
      ["effect_profile_refs", unionEffects, rowEffects],
    ]) {
      const actual = sorted(actualSet);
      const expected = sorted(expectedSet);
      if (!sameStrings(actual, expected)) {
        errors.push(`${at}.variants: ${field} union must exactly equal the coverage row; expected=${JSON.stringify(expected)}, got=${JSON.stringify(actual)}`);
      }
    }
    const ownedCommands = Array.isArray(row?.upstream_command_ids) ? row.upstream_command_ids : [];
    const missingCommands = ownedCommands.filter((commandId) => !mentionedCommands.has(commandId));
    if (missingCommands.length > 0) {
      errors.push(`${at}.variants: every owned command needs an exact variant predicate; missing=${JSON.stringify(missingCommands)}`);
    }
  }

  const registeredProofRefs = sorted(proofProviders.keys());
  const usedProofRefs = sorted(proofRefsUsed);
  if (!sameStrings(registeredProofRefs, usedProofRefs)) {
    const unreferenced = registeredProofRefs.filter((ref) => !proofRefsUsed.has(ref));
    const unresolved = usedProofRefs.filter((ref) => !proofProviders.has(ref));
    errors.push(`${label}: proof-provider registry must exactly cover typed proof dependencies; unreferenced=${JSON.stringify(unreferenced)}, unresolved=${JSON.stringify(unresolved)}`);
  }

  for (const guardedVariantKey of PROVIDER_VARIANT_SAFETY_GUARDS.keys()) {
    if (!variantMap.has(guardedVariantKey)) {
      errors.push(`${label}: required provider safety-guard variant is missing ${JSON.stringify(guardedVariantKey)}`);
    }
  }

  for (const [variantKey, refs] of formulaRefsByVariant) {
    for (const ref of refs) {
      if (!ref.startsWith("capability_variant:")) continue;
      const referencedVariant = ref.slice("capability_variant:".length);
      if (!variantMap.has(referencedVariant)) {
        errors.push(`${label}.${variantKey}: unknown capability variant dependency ${JSON.stringify(referencedVariant)}`);
      }
      if (referencedVariant === variantKey) {
        errors.push(`${label}.${variantKey}: variant cannot depend on itself`);
      }
    }
  }

  const variantGraph = new Map([...variantMap.keys()].map((key) => [key, new Set()]));
  for (const [variantKey, refs] of formulaRefsByVariant) {
    const edges = variantGraph.get(variantKey);
    for (const ref of refs) {
      if (ref.startsWith("capability_variant:")) {
        const target = ref.slice("capability_variant:".length);
        if (variantMap.has(target)) edges.add(target);
      }
    }
  }
  const visiting = new Set();
  const visited = new Set();
  const visit = (variantKey) => {
    if (visiting.has(variantKey)) {
      errors.push(`${label}: availability-variant dependency cycle contains ${variantKey}`);
      return;
    }
    if (visited.has(variantKey)) return;
    visiting.add(variantKey);
    for (const child of variantGraph.get(variantKey) || []) visit(child);
    visiting.delete(variantKey);
    visited.add(variantKey);
  };
  for (const variantKey of variantGraph.keys()) visit(variantKey);

  const digest = sha256Json(canonicalCapabilityDependencies(registry));
  const digestLabel = `${DOCUMENTS.coverage}.capability_dependency_registry_sha256`;
  if (validateString(document?.capability_dependency_registry_sha256, digestLabel, errors)
      && !/^[a-f0-9]{64}$/.test(document.capability_dependency_registry_sha256)) {
    errors.push(`${digestLabel}: expected a lowercase SHA-256 digest`);
  }
  if (document?.capability_dependency_registry_sha256 !== digest) {
    errors.push(`${digestLabel}: does not match the canonical capability-dependency registry`);
  }
  if (digest !== EXPECTED_CAPABILITY_DEPENDENCY_REGISTRY_SHA256) {
    errors.push(`${label}: dependency formulas drifted from the reviewed v0.3 map`);
  }

  return dependencyMap;
}

function validateCoverage(document, nodeById, errors) {
  const label = DOCUMENTS.coverage;
  validateGraphHeader(document, label, errors);
  if (document && typeof document === "object") {
    const actualFields = sorted(Object.keys(document));
    const expectedFields = sorted(COVERAGE_TOP_LEVEL_FIELDS);
    if (!sameStrings(actualFields, expectedFields)) {
      errors.push(`${label}: expected exactly top-level fields ${JSON.stringify(expectedFields)}, got ${JSON.stringify(actualFields)}`);
    }
    validateString(document.provider, `${label}.provider`, errors);
    validateClosedTopLevelSet(document, "data_classes", DATA_CLASSES, label, errors);
    validateClosedTopLevelSet(document, "dispositions", COVERAGE_DISPOSITIONS, label, errors);
    if (Object.hasOwn(document, "effect_classes")) {
      errors.push(`${label}.effect_classes: legacy v0.1 field is forbidden; use effect_profiles`);
    }
  }
  const assuranceProfiles = validateAssuranceProfiles(document, errors);
  validateAssuranceSatisfactionRegistry(document, errors);
  const semanticRegistries = validateSemanticRegistries(document, assuranceProfiles, errors);
  const effectProfiles = validateEffectProfiles(document, errors);
  const upstreamRegistry = validateUpstreamCommandRegistry(document, errors);
  const rows = coverageRows(document, errors);
  validateManualActionRegistry(document, rows, effectProfiles, errors);
  const proofProviders = validateDependencyProofProviders(document, errors);
  let hf14aCompilerManifest = null;
  try {
    ({ HF14A_PROBE_COMPILER_MANIFEST: hf14aCompilerManifest } = require(path.join(
      ROOT,
      "packages/bob-instrument-chameleon/lib/hf14a-probe-compiler.js",
    )));
  } catch (error) {
    errors.push(`${DOCUMENTS.coverage}.hf14a_closed_probe_contract: cannot load compiler manifest (${error.message})`);
  }
  validateHf14aClosedProbeContract(document, hf14aCompilerManifest, errors);
  const capabilityDependencies = validateCapabilityDependencies(
    document,
    rows,
    semanticRegistries.operations,
    semanticRegistries.techniques,
    effectProfiles,
    proofProviders,
    errors,
  );
  if (rows.length === 0) errors.push(`${label}.coverage: must not be empty`);
  const capabilityIds = new Set();
  const coveredProviderNodes = new Set();
  const referencedEffectProfiles = new Set();
  const commandOwners = new Map();
  const usedOperations = new Set();
  const usedTechniques = new Set();

  for (let index = 0; index < rows.length; index += 1) {
    const row = rows[index];
    const at = `${label}.coverage[${index}]`;
    if (!row || typeof row !== "object" || Array.isArray(row)) {
      errors.push(`${at}: expected an object`);
      continue;
    }
    const actualFields = sorted(Object.keys(row));
    const expectedFields = sorted(COVERAGE_ROW_FIELDS);
    if (!sameStrings(actualFields, expectedFields)) {
      errors.push(`${at}: expected exactly fields ${JSON.stringify(expectedFields)}, got ${JSON.stringify(actualFields)}`);
    }
    if (validateString(row.provider_capability_id, `${at}.provider_capability_id`, errors)) {
      if (!/^[A-Za-z0-9][A-Za-z0-9._:-]*$/.test(row.provider_capability_id)) {
        errors.push(`${at}.provider_capability_id: contains unsupported characters`);
      }
      if (capabilityIds.has(row.provider_capability_id)) {
        errors.push(`${at}.provider_capability_id: duplicate ID ${JSON.stringify(row.provider_capability_id)}`);
      }
      capabilityIds.add(row.provider_capability_id);
    }
    if (validateString(row.provider, `${at}.provider`, errors)
        && typeof document.provider === "string"
        && row.provider !== document.provider) {
      errors.push(`${at}.provider: expected top-level provider ${JSON.stringify(document.provider)}`);
    }
    validateString(row.protocol_family, `${at}.protocol_family`, errors);
    validateString(row.device_surface, `${at}.device_surface`, errors);
    validateString(row.reason, `${at}.reason`, errors);

    const upstreamCommandIds = validatePositiveIntegerArray(
      row.upstream_command_ids,
      `${at}.upstream_command_ids`,
      errors,
    );
    const operations = validateStringArray(row.normalized_operations, `${at}.normalized_operations`, errors);
    const techniques = validateStringArray(row.technique_bindings, `${at}.technique_bindings`, errors);
    const effectProfileRefs = validateStringArray(row.effect_profile_refs, `${at}.effect_profile_refs`, errors);
    const refs = validateStringArray(row.node_refs, `${at}.node_refs`, errors);

    for (const operation of operations) {
      if (typeof operation !== "string") continue;
      usedOperations.add(operation);
      if (!semanticRegistries.operations.has(operation)) {
        errors.push(`${at}.normalized_operations: unregistered operation ${JSON.stringify(operation)}`);
        continue;
      }
      const operationContract = semanticRegistries.operations.get(operation);
      const exposure = operationContract.exposure;
      if (exposure === "provider_private" && row.disposition !== "provider_internal") {
        errors.push(`${at}: provider-private operation ${JSON.stringify(operation)} requires provider_internal disposition`);
      }
      if (exposure === "operator_only" && row.disposition !== "operator_only") {
        errors.push(`${at}: operator-only operation ${JSON.stringify(operation)} requires operator_only disposition`);
      }
      if (exposure === "unsupported" && row.disposition !== "unsupported") {
        errors.push(`${at}: unsupported operation ${JSON.stringify(operation)} cannot be exposed by ${row.disposition}`);
      }
    }
    for (const technique of techniques) {
      if (typeof technique !== "string") continue;
      usedTechniques.add(technique);
      if (!semanticRegistries.techniques.has(technique)) {
        errors.push(`${at}.technique_bindings: unregistered technique ${JSON.stringify(technique)}`);
      }
    }

    for (const commandId of upstreamCommandIds) {
      if (!Number.isSafeInteger(commandId) || commandId <= 0) continue;
      if (!commandOwners.has(commandId)) commandOwners.set(commandId, []);
      commandOwners.get(commandId).push({
        capabilityId: row.provider_capability_id,
        disposition: row.disposition,
      });
    }

    if (Object.hasOwn(row, "abstract_operations")) {
      errors.push(`${at}.abstract_operations: legacy v0.1 field is forbidden; use normalized_operations`);
    }
    if (Object.hasOwn(row, "effect_classes")) {
      errors.push(`${at}.effect_classes: legacy v0.1 field is forbidden; use effect_profile_refs`);
    }
    for (const effectProfileRef of effectProfileRefs) {
      if (!effectProfiles.has(effectProfileRef)) {
        errors.push(`${at}.effect_profile_refs: references unknown effect profile ${JSON.stringify(effectProfileRef)}`);
      } else {
        referencedEffectProfiles.add(effectProfileRef);
      }
    }
    if (!DATA_CLASSES.has(row.data_class)) {
      errors.push(`${at}.data_class: unknown data class ${JSON.stringify(row.data_class)}`);
    }
    if (!COVERAGE_DISPOSITIONS.has(row.disposition)) {
      errors.push(`${at}.disposition: unknown disposition ${JSON.stringify(row.disposition)}`);
    }
    for (const ref of refs) {
      if (!nodeById.has(ref)) {
        errors.push(`${at}.node_refs: references unknown node ${JSON.stringify(ref)}`);
      } else if (nodeById.get(ref).kind === "P" && row.disposition !== "unsupported") {
        coveredProviderNodes.add(ref);
      }
    }

    if (row.disposition === "planned" && refs.length === 0) {
      errors.push(`${at}: planned coverage requires at least one node_ref`);
    }
    if (row.disposition === "planned" && operations.length === 0) {
      errors.push(`${at}: planned coverage requires at least one normalized_operation`);
    }
    if (row.disposition === "unsupported" && effectProfileRefs.length !== 0) {
      errors.push(`${at}: unsupported capability must not reference effect profiles`);
    }

    const effectRelevantNodes = refs
      .map((ref) => nodeById.get(ref))
      .filter((node) => node && (node.kind === "P" || node.kind === "C"));
    const allRelevantRefsAreProviders = effectRelevantNodes.length > 0
      && effectRelevantNodes.every((node) => node.kind === "P");
    const effectConsistencyExempt = row.disposition === "provider_internal"
      || row.disposition === "operator_only"
      || allRelevantRefsAreProviders;
    if (!effectConsistencyExempt) {
      for (const effectProfileRef of effectProfileRefs) {
        const profile = effectProfiles.get(effectProfileRef);
        if (!profile) continue;
        const surface = `${profile.subject_kind}.${profile.action}`;
        const represented = effectRelevantNodes.some(
          (node) => Array.isArray(node.effect_surface) && node.effect_surface.includes(surface),
        );
        if (!represented) {
          errors.push(`${at}: effect profile ${effectProfileRef} surface ${JSON.stringify(surface)} `
            + "is absent from every referenced capability/provider node effect_surface");
        }
      }
    }
  }

  validateCommandSourceRegistry(document, upstreamRegistry, commandOwners, errors);

  const registeredOperationIds = sorted(semanticRegistries.operations.keys());
  const usedOperationIds = sorted(usedOperations);
  if (!sameStrings(registeredOperationIds, usedOperationIds)) {
    const unreferenced = registeredOperationIds.filter((id) => !usedOperations.has(id));
    const unregistered = usedOperationIds.filter((id) => !semanticRegistries.operations.has(id));
    errors.push(`${label}: normalized operation registry must exactly cover used operations; unreferenced=${JSON.stringify(unreferenced)}, unregistered=${JSON.stringify(unregistered)}`);
  }
  const registeredTechniqueIds = sorted(semanticRegistries.techniques);
  const usedTechniqueIds = sorted(usedTechniques);
  if (!sameStrings(registeredTechniqueIds, usedTechniqueIds)) {
    const unreferenced = registeredTechniqueIds.filter((id) => !usedTechniques.has(id));
    const unregistered = usedTechniqueIds.filter((id) => !semanticRegistries.techniques.has(id));
    errors.push(`${label}: technique registry must exactly cover used techniques; unreferenced=${JSON.stringify(unreferenced)}, unregistered=${JSON.stringify(unregistered)}`);
  }

  const coverageSemanticsDigest = sha256Json(canonicalCoverageSemantics(document, rows));
  if (document?.upstream_command_registry?.coverage_semantics_sha256 !== coverageSemanticsDigest) {
    errors.push(`${label}: canonical coverage semantics do not match upstream_command_registry.coverage_semantics_sha256`);
  }
  if (coverageSemanticsDigest !== EXPECTED_UPSTREAM_COMMAND_REGISTRY.coverage_semantics_sha256) {
    errors.push(`${label}: coverage semantics drifted from the reviewed v0.3 map`);
  }

  const canonicalCommandOwnership = [...commandOwners]
    .flatMap(([id, owners]) => owners.map((owner) => ({
      id,
      provider_capability_id: owner.capabilityId,
      disposition: owner.disposition,
    })))
    .sort((left, right) => left.id - right.id
      || String(left.provider_capability_id).localeCompare(String(right.provider_capability_id)));
  const commandOwnershipDigest = sha256Json(canonicalCommandOwnership);
  if (document?.upstream_command_registry?.command_ownership_sha256 !== commandOwnershipDigest) {
    errors.push(`${label}: canonical ID-to-owner map does not match upstream_command_registry.command_ownership_sha256`);
  }
  if (commandOwnershipDigest !== EXPECTED_UPSTREAM_COMMAND_REGISTRY.command_ownership_sha256) {
    errors.push(`${label}: command ID ownership drifted from the reviewed v0.3 map`);
  }

  for (const [commandId, owners] of commandOwners) {
    if (!upstreamRegistry.commandUniverse.has(commandId)) {
      errors.push(`${label}: command ID ${commandId} is mapped but absent from the declared/private registry universe`);
    }
    if (owners.length !== 1) {
      const ownerLabels = owners.map((owner) => owner.capabilityId);
      errors.push(`${label}: command ID ${commandId} must have exactly one primary owner; got ${JSON.stringify(ownerLabels)}`);
    }
  }
  for (const commandId of upstreamRegistry.commandUniverse) {
    const owners = commandOwners.get(commandId) || [];
    if (owners.length === 0) {
      errors.push(`${label}: command ID ${commandId} has no primary coverage-row owner`);
    }
  }
  for (const commandId of upstreamRegistry.declaredUnregisteredIds) {
    const owners = commandOwners.get(commandId) || [];
    for (const owner of owners) {
      if (owner.disposition !== "unsupported") {
        errors.push(`${label}: declared-unregistered command ID ${commandId} must map only to unsupported rows`);
      }
    }
  }
  for (const commandId of upstreamRegistry.registryPrivateIds) {
    const owners = commandOwners.get(commandId) || [];
    for (const owner of owners) {
      if (owner.disposition !== "provider_internal" && owner.disposition !== "operator_only") {
        errors.push(`${label}: registry-private command ID ${commandId} must map to provider_internal or operator_only`);
      }
    }
  }

  for (const node of nodeById.values()) {
    if (node.kind !== "P" || PROVIDER_COVERAGE_EXEMPTIONS.has(node.id)) continue;
    if (!coveredProviderNodes.has(node.id)) {
      errors.push(`${label}: provider node ${node.id} has no non-unsupported coverage mapping`);
    }
  }

  for (const profileId of effectProfiles.keys()) {
    if (!referencedEffectProfiles.has(profileId)) {
      errors.push(`${label}.effect_profiles: unreferenced effect profile ${JSON.stringify(profileId)}`);
    }
  }

  return {
    rows,
    coveredProviderNodes,
    effectProfiles,
    referencedEffectProfiles,
    availabilityVariants: [...capabilityDependencies.values()]
      .reduce((count, dependency) => count + Object.keys(dependency?.variants || {}).length, 0),
    proofProviderCount: proofProviders.size,
    commandCounts: {
      declared: upstreamRegistry.declaredIds.size,
      mapped: commandOwners.size,
      expectedRuntime: upstreamRegistry.expectedRuntimeCount,
    },
  };
}

function run() {
  const errors = [];
  const nodesDocument = readJson(DOCUMENTS.nodes, errors);
  const hyperedgesDocument = readJson(DOCUMENTS.hyperedges, errors);
  const coverageDocument = readJson(DOCUMENTS.coverage, errors);

  for (const [name, document] of [
    [DOCUMENTS.nodes, nodesDocument],
    [DOCUMENTS.hyperedges, hyperedgesDocument],
    [DOCUMENTS.coverage, coverageDocument],
  ]) {
    if (document == null) continue;
    try {
      assertPackageSafePhysicalDesignDocument(document, name);
    } catch (error) {
      errors.push(`${name}: package-safe design sanitizer rejected the document (${error.message})`);
    }
  }

  const { nodes, nodeById } = validateNodes(nodesDocument, errors);
  const { hyperedges, projection, blockingCount } = validateHyperedges(hyperedgesDocument, nodeById, errors);
  validatePredecessorProjection(nodes, projection, errors);
  validateAcyclic(nodeById, projection, errors);
  validateReadiness(nodes, nodeById, errors);
  const {
    rows,
    coveredProviderNodes,
    effectProfiles,
    availabilityVariants,
    proofProviderCount,
    commandCounts,
  } = validateCoverage(coverageDocument, nodeById, errors);
  validateChameleonRuntimeManifest(coverageDocument, errors);

  return {
    errors,
    counts: {
      nodes: nodes.length,
      hyperedges: hyperedges.length,
      blockingHyperedges: blockingCount,
      coverageRows: rows.length,
      effectProfiles: effectProfiles.size,
      availabilityVariants,
      proofProviders: proofProviderCount,
      providerNodesMapped: coveredProviderNodes.size,
      commandsDeclared: commandCounts.declared,
      commandsMapped: commandCounts.mapped,
      commandsExpectedRuntime: commandCounts.expectedRuntime,
    },
  };
}

function main() {
  const { errors, counts } = run();
  if (errors.length > 0) {
    console.error(`plane-physical coherence FAILED (${errors.length} violation${errors.length === 1 ? "" : "s"}):`);
    for (const error of errors) console.error(`  - ${error}`);
    process.exit(1);
  }
  console.log(
    `plane-physical coherence OK (${counts.nodes} nodes, ${counts.blockingHyperedges}/${counts.hyperedges} blocking hyperedges, `
      + `${counts.coverageRows} coverage rows, ${counts.availabilityVariants} availability variants, `
      + `${counts.effectProfiles} effect profiles, ${counts.proofProviders} proof providers, `
      + `${counts.providerNodesMapped} provider nodes mapped, commands: `
      + `declared=${counts.commandsDeclared}, mapped=${counts.commandsMapped}, `
      + `expected-runtime=${counts.commandsExpectedRuntime})`,
  );
}

if (require.main === module) main();

module.exports = {
  canonicalAssuranceProfiles,
  canonicalAssuranceSatisfaction,
  canonicalCapabilityDependencies,
  canonicalCommandSourceEntryBasis,
  canonicalCommandSourceRegistry,
  canonicalCoverageSemantics,
  canonicalDependencyProofProviders,
  canonicalEffectProfiles,
  canonicalHyperedgeRegistry,
  canonicalManualActions,
  canonicalNodeContracts,
  canonicalOperationRegistry,
  canonicalUpstreamSourceProfile,
  run,
  validateHf14aClosedProbeContract,
  validateAcyclic,
  validateAssuranceProfiles,
  validateAssuranceSatisfactionRegistry,
  validateCapabilityDependencies,
  validateChameleonRuntimeManifest,
  validateCommandSourceRegistry,
  validateCoverage,
  validateEffectProfiles,
  validateDependencyProofProviders,
  validateGateTracking,
  validateHyperedges,
  validateManualActionRegistry,
  validateNodes,
  validatePredecessorProjection,
  validateReadiness,
  validateUpstreamCommandRegistry,
};
