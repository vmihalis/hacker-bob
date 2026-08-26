"use strict";

// PH-P5 provider-owned Chameleon state stewardship. This module is pure: it
// imports contracts and the reviewed semantic registry, but has no transport,
// native driver, filesystem, vault materialization, or hardware dependency.

const {
  EFFECT_DISPOSITION_VALUES,
  assertNoPublicByteMaterial,
} = require("../../bob-instrument-contracts/lib/instrument-provider-contract.js");
const {
  normalizeOpaqueRef,
} = require("../../bob-instrument-contracts/lib/physical-quantities.js");
const {
  assertPhysicalTrustedClockSample,
} = require("../../../mcp/domains/physical/physical-trusted-clock.js");
const {
  hashCanonicalJson,
} = require("../../bob-instrument-contracts/lib/verification-contracts.js");
const {
  PUBLIC_ARTIFACT_HANDLE_RE,
} = require("../../bob-artifact-vault/lib/contracts.js");
const {
  CHAMELEON_SEMANTIC_MANIFEST,
  getChameleonOperation,
  reviewedManifestSnapshot,
} = require("./operations.js");

const CHAMELEON_STATE_STEWARDSHIP_VERSION = 1;
const CHAMELEON_SLOT_COUNT = 8;
const PROVIDER_ID = "chameleon_ultra";
const HASH_PATTERN = /^[a-f0-9]{64}$/u;
const IDENTIFIER_PATTERN = /^[a-z][a-z0-9._-]{0,127}$/u;
const LEASE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:@-]{0,190}$/u;

const CHAMELEON_SNAPSHOT_KIND_VALUES = Object.freeze(["declared", "observed"]);
const CHAMELEON_ACTIVE_MODE_VALUES = Object.freeze([
  "rf_off",
  "hf_reader",
  "lf_reader",
  "hf_emulator",
  "lf_emulator",
  "maintenance",
  "bootloader",
]);
const CHAMELEON_ASSURANCE_STATUS_VALUES = Object.freeze([
  "valid",
  "invalidated",
  "quarantined",
]);
const CHAMELEON_ASSURANCE_INVALIDATION_REASON_VALUES = Object.freeze([
  "admin_configuration",
  "firmware_change",
  "data_erase",
  "quarantined_state",
]);
const CHAMELEON_SLOT_MUTATION_VALUES = Object.freeze([
  "stage",
  "overwrite",
  "erase",
  "metadata_update",
  "enablement_change",
]);
const CHAMELEON_LOG_ACTION_VALUES = Object.freeze(["preserve", "append", "clear"]);
const CHAMELEON_EFFECT_DISPOSITION_VALUES = Object.freeze(
  EFFECT_DISPOSITION_VALUES.filter((value) => value !== "not_dispatched"),
);
const CHAMELEON_RECOVERY_POLICY_VALUES = Object.freeze([
  "not_required",
  "required",
  "quarantine_only",
]);
const CHAMELEON_TRANSITION_STATE_VALUES = Object.freeze([
  "complete",
  "restore_required",
  "reconcile_required",
  "quarantine_required",
]);
const CHAMELEON_RECONCILIATION_DISPOSITION_VALUES = Object.freeze([
  "confirmed_no_effect",
  "confirmed_declared_post",
  "state_drift",
  "unobservable",
]);
const CHAMELEON_RECONCILIATION_STATE_VALUES = Object.freeze([
  "reconciled_no_effect",
  "reconciled_effect",
  "restore_required",
  "quarantine_required",
]);
const CHAMELEON_RESTORE_DISPOSITION_VALUES = Object.freeze(["restored", "quarantined"]);
const CHAMELEON_LOG_COMPLETENESS_VALUES = Object.freeze([
  "complete_for_snapshot",
  "incomplete_paginated",
  "incomplete_overflow",
]);

const SETTINGS_FIELDS = Object.freeze([
  "animation_config_digest",
  "ble_pairing_config_digest",
  "button_a_config_digest",
  "button_b_config_digest",
  "detection_config_digest",
  "hf_emulator_config_digest",
  "lf_emulator_config_digest",
  "reader_profile_config_digest",
]);

const SNAPSHOTS = new WeakSet();
const SNAPSHOT_STATE = new WeakMap();
const TRANSITIONS = new WeakSet();
const TRANSITION_STATE = new WeakMap();
const RECONCILIATIONS = new WeakSet();
const RECONCILIATION_STATE = new WeakMap();
const RESTORE_RESULTS = new WeakSet();
const RESTORE_RESULT_STATE = new WeakMap();
const LOG_PAGE_RECEIPTS = new WeakSet();
const LOG_PAGE_STATE = new WeakMap();
const MAX_PUBLIC_INPUT_GRAPH_NODES = 4096;
const MAX_PUBLIC_INPUT_GRAPH_DEPTH = 32;

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function isPlainObject(value) {
  if (value == null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function assertDataOnlyPublicGraph(value, label) {
  const seen = new WeakSet();
  const stack = [{ value, path: label, depth: 0 }];
  let nodes = 0;
  while (stack.length > 0) {
    const current = stack.pop();
    if (current.value == null || typeof current.value !== "object") continue;
    if (Buffer.isBuffer(current.value)
        || current.value instanceof ArrayBuffer
        || ArrayBuffer.isView(current.value)) {
      throw new Error(`${current.path} must not contain raw byte material`);
    }
    if (seen.has(current.value)) {
      throw new Error(`${current.path} must not contain cycles or aliased object state`);
    }
    seen.add(current.value);
    nodes += 1;
    if (nodes > MAX_PUBLIC_INPUT_GRAPH_NODES || current.depth > MAX_PUBLIC_INPUT_GRAPH_DEPTH) {
      throw new Error(`${label} exceeds the bounded public input graph`);
    }
    for (const key of Reflect.ownKeys(current.value)) {
      if (typeof key !== "string") throw new Error(`${current.path} cannot contain symbol fields`);
      const descriptor = Object.getOwnPropertyDescriptor(current.value, key);
      const arrayLength = Array.isArray(current.value) && key === "length";
      if (!descriptor || !("value" in descriptor) || (!descriptor.enumerable && !arrayLength)) {
        throw new Error(`${current.path}.${key} must be an enumerable data field`);
      }
      if (!arrayLength) {
        stack.push({
          value: descriptor.value,
          path: Array.isArray(current.value) ? `${current.path}[${key}]` : `${current.path}.${key}`,
          depth: current.depth + 1,
        });
      }
    }
  }
  assertNoPublicByteMaterial(value, label);
}

function assertClosedObject(value, label, required, optional = []) {
  if (!isPlainObject(value)) throw new Error(`${label} must be an object`);
  const ownKeys = Reflect.ownKeys(value);
  if (ownKeys.some((field) => typeof field !== "string")) {
    throw new Error(`${label} cannot contain symbol fields`);
  }
  const allowed = new Set([...required, ...optional]);
  const unknown = ownKeys.filter((field) => !allowed.has(field)).sort();
  if (unknown.length > 0) throw new Error(`${label} has unknown fields: ${unknown.join(", ")}`);
  const missing = required.filter((field) => !Object.prototype.hasOwnProperty.call(value, field));
  if (missing.length > 0) throw new Error(`${label} is missing fields: ${missing.join(", ")}`);
  for (const field of ownKeys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, field);
    if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) {
      throw new Error(`${label}.${field} must be an enumerable data field`);
    }
  }
  return value;
}

function assertClosedArray(value, label, { exactLength = null, maximumLength = null } = {}) {
  if (!Array.isArray(value)) throw new Error(`${label} must be an array`);
  if (exactLength != null && value.length !== exactLength) {
    throw new Error(`${label} must contain exactly ${exactLength} entries`);
  }
  if (maximumLength != null && value.length > maximumLength) {
    throw new Error(`${label} cannot contain more than ${maximumLength} entries`);
  }
  const allowed = new Set(["length", ...Array.from({ length: value.length }, (_, index) => String(index))]);
  const unknown = Reflect.ownKeys(value).filter((field) => (
    typeof field !== "string" || !allowed.has(field)
  ));
  if (unknown.length > 0) throw new Error(`${label} must be a closed array without extra fields`);
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) {
      throw new Error(`${label}[${index}] must be an enumerable data entry`);
    }
  }
  return value;
}

function assertEnum(value, values, label) {
  if (!values.includes(value)) throw new Error(`${label} must be one of ${values.join(", ")}`);
  return value;
}

function assertDigest(value, label) {
  if (typeof value !== "string" || !HASH_PATTERN.test(value)) {
    throw new Error(`${label} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function assertIdentifier(value, label) {
  if (typeof value !== "string" || !IDENTIFIER_PATTERN.test(value)) {
    throw new Error(`${label} must be a lowercase identifier`);
  }
  return value;
}

function assertLeaseId(value, label) {
  if (typeof value !== "string" || !LEASE_ID_PATTERN.test(value)) {
    throw new Error(`${label} must be a bounded lease identifier`);
  }
  return value;
}

function assertInteger(value, label, minimum = 0, maximum = Number.MAX_SAFE_INTEGER) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${label} must be a safe integer from ${minimum} through ${maximum}`);
  }
  return value;
}

function normalizeArtifactHandle(value, label, { nullable = false } = {}) {
  if (nullable && value == null) return null;
  if (typeof value !== "string" || !PUBLIC_ARTIFACT_HANDLE_RE.test(value)) {
    throw new Error(`${label} must be an opaque artifact:v1 vault handle`);
  }
  return value;
}

function assertDerivedDigest(input, field, expected, label) {
  if (Object.prototype.hasOwnProperty.call(input, field)
      && assertDigest(input[field], `${label}.${field}`) !== expected) {
    throw new Error(`${label}.${field} does not match normalized state`);
  }
}

function normalizeTrustedTimestamp(sampleInput) {
  const sample = assertPhysicalTrustedClockSample(sampleInput);
  return Object.freeze({
    recorded_at: sample.trusted_utc,
    recorded_at_earliest: sample.trusted_utc_earliest,
    recorded_at_latest: sample.trusted_utc_latest,
    trusted_clock_id: sample.clock_id,
    trusted_monotonic_epoch_id: sample.monotonic_epoch_id,
    trusted_monotonic_ms: sample.monotonic_ms,
    trusted_clock_mapping_generation: sample.mapping_generation,
    trusted_clock_mapping_digest: sample.signed_mapping_digest,
    trusted_clock_max_uncertainty_ms: sample.max_uncertainty_ms,
    trusted_clock_trust_root_epoch: sample.trust_root_epoch,
    trusted_clock_authority_epoch: sample.authority_epoch,
    trusted_clock_revocation_generation: sample.revocation_generation,
  });
}

function assertTimestampProgression(previous, next, label) {
  if (previous.trusted_clock_id !== next.trusted_clock_id
      || previous.trusted_monotonic_epoch_id !== next.trusted_monotonic_epoch_id
      || next.trusted_monotonic_ms < previous.trusted_monotonic_ms
      || next.trusted_clock_mapping_generation < previous.trusted_clock_mapping_generation
      || (next.trusted_clock_mapping_generation === previous.trusted_clock_mapping_generation
        && next.trusted_clock_mapping_digest !== previous.trusted_clock_mapping_digest)
      || next.trusted_clock_trust_root_epoch < previous.trusted_clock_trust_root_epoch
      || next.trusted_clock_authority_epoch < previous.trusted_clock_authority_epoch
      || next.trusted_clock_revocation_generation < previous.trusted_clock_revocation_generation
      || Date.parse(next.recorded_at_earliest) < Date.parse(previous.recorded_at_earliest)
      || Date.parse(next.recorded_at_latest) < Date.parse(previous.recorded_at_latest)) {
    throw new Error(`${label} trusted timestamp moved backwards or changed clock identity`);
  }
}

function normalizeSlot(input, index, label) {
  assertClosedObject(input, label, [
    "slot_index",
    "slot_revision",
    "slot_status",
    "hf_enabled",
    "lf_enabled",
    "hf_type_id",
    "lf_type_id",
    "metadata_artifact_handle",
    "content_artifact_handle",
  ], ["slot_digest"]);
  if (input.slot_index !== index) throw new Error(`${label}.slot_index must be ${index}`);
  if (typeof input.hf_enabled !== "boolean" || typeof input.lf_enabled !== "boolean") {
    throw new Error(`${label} enablement fields must be booleans`);
  }
  const status = assertEnum(input.slot_status, ["empty", "occupied"], `${label}.slot_status`);
  const normalized = {
    slot_index: index,
    slot_revision: assertInteger(input.slot_revision, `${label}.slot_revision`, 0),
    slot_status: status,
    hf_enabled: input.hf_enabled,
    lf_enabled: input.lf_enabled,
    hf_type_id: input.hf_type_id == null
      ? null
      : assertIdentifier(input.hf_type_id, `${label}.hf_type_id`),
    lf_type_id: input.lf_type_id == null
      ? null
      : assertIdentifier(input.lf_type_id, `${label}.lf_type_id`),
    metadata_artifact_handle: normalizeArtifactHandle(
      input.metadata_artifact_handle,
      `${label}.metadata_artifact_handle`,
      { nullable: true },
    ),
    content_artifact_handle: normalizeArtifactHandle(
      input.content_artifact_handle,
      `${label}.content_artifact_handle`,
      { nullable: true },
    ),
  };
  if (status === "empty") {
    if (normalized.hf_enabled || normalized.lf_enabled || normalized.hf_type_id != null
        || normalized.lf_type_id != null || normalized.metadata_artifact_handle != null
        || normalized.content_artifact_handle != null) {
      throw new Error(`${label} empty slot cannot retain enablement, types, or artifact state`);
    }
  } else if (normalized.metadata_artifact_handle == null
      || normalized.content_artifact_handle == null
      || (normalized.hf_enabled && normalized.hf_type_id == null)
      || (normalized.lf_enabled && normalized.lf_type_id == null)
      || (!normalized.hf_enabled && normalized.hf_type_id != null)
      || (!normalized.lf_enabled && normalized.lf_type_id != null)) {
    throw new Error(`${label} occupied slot must have exact artifacts and enabled media types`);
  }
  const slotDigest = hashCanonicalJson(normalized);
  assertDerivedDigest(input, "slot_digest", slotDigest, label);
  return deepFreeze({ ...normalized, slot_digest: slotDigest });
}

function normalizeSlots(input, label) {
  assertClosedArray(input, label, { exactLength: CHAMELEON_SLOT_COUNT });
  const output = [];
  for (let index = 0; index < CHAMELEON_SLOT_COUNT; index += 1) {
    if (!Object.prototype.hasOwnProperty.call(input, index)) {
      throw new Error(`${label} cannot be sparse`);
    }
    output.push(normalizeSlot(input[index], index + 1, `${label}[${index}]`));
  }
  return Object.freeze(output);
}

function normalizeSettings(input, label) {
  assertClosedObject(input, label, SETTINGS_FIELDS, ["settings_digest"]);
  const normalized = {};
  for (const field of SETTINGS_FIELDS) normalized[field] = assertDigest(input[field], `${label}.${field}`);
  const settingsDigest = hashCanonicalJson(normalized);
  assertDerivedDigest(input, "settings_digest", settingsDigest, label);
  return deepFreeze({ ...normalized, settings_digest: settingsDigest });
}

function normalizeLogState(input, label) {
  assertClosedObject(input, label, [
    "log_generation",
    "origin_cursor_ref",
    "tail_cursor_ref",
    "retained_event_count",
    "overflow_count",
    "overflow_status",
  ], ["log_state_digest"]);
  const normalized = {
    log_generation: assertInteger(input.log_generation, `${label}.log_generation`, 1),
    origin_cursor_ref: normalizeOpaqueRef(
      input.origin_cursor_ref,
      `${label}.origin_cursor_ref`,
      { prefix: "log-cursor" },
    ),
    tail_cursor_ref: normalizeOpaqueRef(
      input.tail_cursor_ref,
      `${label}.tail_cursor_ref`,
      { prefix: "log-cursor" },
    ),
    retained_event_count: assertInteger(
      input.retained_event_count,
      `${label}.retained_event_count`,
      0,
    ),
    overflow_count: assertInteger(input.overflow_count, `${label}.overflow_count`, 0),
    overflow_status: assertEnum(input.overflow_status, ["none", "observed"], `${label}.overflow_status`),
  };
  if ((normalized.overflow_count === 0) !== (normalized.overflow_status === "none")) {
    throw new Error(`${label} overflow count and status disagree`);
  }
  if (normalized.retained_event_count === 0
      && normalized.origin_cursor_ref !== normalized.tail_cursor_ref) {
    throw new Error(`${label} empty log must have identical origin and tail cursors`);
  }
  if (normalized.retained_event_count > 0
      && normalized.origin_cursor_ref === normalized.tail_cursor_ref) {
    throw new Error(`${label} non-empty log must advance its tail cursor`);
  }
  const logStateDigest = hashCanonicalJson(normalized);
  assertDerivedDigest(input, "log_state_digest", logStateDigest, label);
  return deepFreeze({ ...normalized, log_state_digest: logStateDigest });
}

function operationContract(operationId, suppliedDigest, label) {
  const operation = getChameleonOperation(assertIdentifier(operationId, `${label}.operation_id`));
  if (!operation) throw new Error(`${label}.operation_id is not in the reviewed Chameleon registry`);
  if (assertDigest(suppliedDigest, `${label}.operation_contract_digest`)
      !== operation.operation_contract_digest) {
    throw new Error(`${label}.operation_contract_digest drifted from the reviewed registry`);
  }
  return operation;
}

function createPolicy(operationId, overrides = {}) {
  const operation = getChameleonOperation(operationId);
  if (!operation) throw new Error(`unknown operation policy ${operationId}`);
  const basis = {
    operation_id: operationId,
    operation_contract_digest: operation.operation_contract_digest,
    workspace_mutation: false,
    mode_mutation: false,
    allowed_post_modes: [],
    allowed_slot_actions: [],
    allowed_settings_change_ids: [],
    allowed_log_actions: ["preserve"],
    assurance_action: "preserve",
    restore_only: false,
    ...overrides,
  };
  basis.allowed_post_modes = Object.freeze([...basis.allowed_post_modes].sort());
  basis.allowed_slot_actions = Object.freeze([...basis.allowed_slot_actions].sort());
  basis.allowed_settings_change_ids = Object.freeze([...basis.allowed_settings_change_ids].sort());
  basis.allowed_log_actions = Object.freeze([...basis.allowed_log_actions].sort());
  return deepFreeze({ ...basis, policy_digest: hashCanonicalJson(basis) });
}

const POLICY_OVERRIDES = Object.freeze({
  "emulator.configure": {
    workspace_mutation: true,
    mode_mutation: true,
    allowed_post_modes: ["rf_off", "hf_emulator", "lf_emulator"],
    allowed_slot_actions: CHAMELEON_SLOT_MUTATION_VALUES,
    allowed_log_actions: ["clear", "preserve"],
  },
  "emulator.present": { allowed_log_actions: ["append", "preserve"] },
  "emulator.profile_configure": {
    workspace_mutation: true,
    allowed_settings_change_ids: [
      "detection_config_digest",
      "hf_emulator_config_digest",
      "lf_emulator_config_digest",
    ],
    allowed_log_actions: ["clear", "preserve"],
  },
  "instrument.admin_configure": {
    workspace_mutation: true,
    allowed_settings_change_ids: SETTINGS_FIELDS,
    allowed_log_actions: ["clear", "preserve"],
    assurance_action: "invalidate_admin_configuration",
  },
  "instrument.erase": {
    workspace_mutation: true,
    mode_mutation: true,
    allowed_post_modes: ["rf_off", "maintenance"],
    allowed_slot_actions: ["erase"],
    allowed_settings_change_ids: SETTINGS_FIELDS,
    allowed_log_actions: ["clear"],
    assurance_action: "invalidate_data_erase",
  },
  "instrument.firmware_manage": {
    workspace_mutation: true,
    mode_mutation: true,
    allowed_post_modes: ["rf_off", "maintenance", "bootloader"],
    allowed_log_actions: ["clear", "preserve"],
    assurance_action: "invalidate_firmware_change",
  },
  "instrument.manual_action": {
    workspace_mutation: true,
    mode_mutation: true,
    allowed_post_modes: CHAMELEON_ACTIVE_MODE_VALUES,
    allowed_slot_actions: CHAMELEON_SLOT_MUTATION_VALUES,
    allowed_settings_change_ids: SETTINGS_FIELDS,
    allowed_log_actions: ["clear", "preserve"],
  },
  "instrument.restore": { restore_only: true },
  "reader_profile.configure": {
    workspace_mutation: true,
    allowed_settings_change_ids: ["reader_profile_config_digest"],
  },
  "representation.stage": {
    workspace_mutation: true,
    allowed_slot_actions: ["stage", "overwrite", "metadata_update", "enablement_change"],
  },
  "response_profile.stage": {
    workspace_mutation: true,
    allowed_slot_actions: ["metadata_update", "enablement_change"],
    allowed_settings_change_ids: [
      "detection_config_digest",
      "hf_emulator_config_digest",
      "lf_emulator_config_digest",
    ],
  },
  "rf_session.acquire": {
    workspace_mutation: true,
    mode_mutation: true,
    allowed_post_modes: ["hf_reader", "lf_reader", "hf_emulator", "lf_emulator"],
  },
  "rf_session.release": {
    workspace_mutation: true,
    mode_mutation: true,
    allowed_post_modes: ["rf_off"],
  },
  "transport.connect": {
    workspace_mutation: true,
    mode_mutation: true,
    allowed_post_modes: ["rf_off"],
  },
  "transport.disconnect": {
    workspace_mutation: true,
    mode_mutation: true,
    allowed_post_modes: ["rf_off"],
  },
  "workspace.restore": { restore_only: true },
});

const reviewedOperationIds = Object.keys(reviewedManifestSnapshot().normalized_operation_registry).sort();
const policyMap = new Map(reviewedOperationIds.map((operationId) => [
  operationId,
  createPolicy(operationId, POLICY_OVERRIDES[operationId] || {}),
]));
for (const operationId of Object.keys(POLICY_OVERRIDES)) {
  if (!policyMap.has(operationId)) throw new Error(`state policy names unknown operation ${operationId}`);
}
const CHAMELEON_OPERATION_STATE_POLICIES = deepFreeze(
  Object.fromEntries([...policyMap.entries()]),
);

function getChameleonStateOperationPolicy(operationId) {
  if (typeof operationId !== "string") return null;
  return policyMap.get(operationId) || null;
}

function createChameleonStateSnapshot(
  input,
  trustedClockSample,
  label = "chameleon_state_snapshot",
) {
  assertDataOnlyPublicGraph(input, label);
  assertClosedObject(input, label, [
    "version",
    "snapshot_kind",
    "instrument_ref",
    "instrument_identity_digest",
    "provider_id",
    "provider_descriptor_digest",
    "semantic_manifest_digest",
    "assurance_profile_id",
    "assurance_claims_digest",
    "assurance_epoch",
    "assurance_status",
    "assurance_invalidation_reason",
    "state_epoch",
    "active_mode",
    "enabled_slot",
    "slots",
    "settings",
    "log_state",
    "lease_id",
    "fencing_generation",
    "operation_id",
    "operation_contract_digest",
    "attempt_ref",
    "snapshot_artifact_handle",
    "snapshot_plan_digest",
  ], [
    "restorable_workspace_digest",
    "workspace_state_digest",
    "snapshot_digest",
  ]);
  if (input.version !== CHAMELEON_STATE_STEWARDSHIP_VERSION) {
    throw new Error(`${label}.version must be ${CHAMELEON_STATE_STEWARDSHIP_VERSION}`);
  }
  const kind = assertEnum(input.snapshot_kind, CHAMELEON_SNAPSHOT_KIND_VALUES, `${label}.snapshot_kind`);
  if (input.provider_id !== PROVIDER_ID
      || input.semantic_manifest_digest !== CHAMELEON_SEMANTIC_MANIFEST.manifest_digest) {
    throw new Error(`${label} provider or semantic manifest binding drifted`);
  }
  const operation = operationContract(input.operation_id, input.operation_contract_digest, label);
  const assuranceStatus = assertEnum(
    input.assurance_status,
    CHAMELEON_ASSURANCE_STATUS_VALUES,
    `${label}.assurance_status`,
  );
  const assuranceReason = input.assurance_invalidation_reason == null
    ? null
    : assertEnum(
      input.assurance_invalidation_reason,
      CHAMELEON_ASSURANCE_INVALIDATION_REASON_VALUES,
      `${label}.assurance_invalidation_reason`,
    );
  if ((assuranceStatus === "valid") !== (assuranceReason == null)
      || (assuranceStatus === "quarantined") !== (assuranceReason === "quarantined_state")) {
    throw new Error(`${label} assurance status and invalidation reason disagree`);
  }
  const mode = assertEnum(input.active_mode, CHAMELEON_ACTIVE_MODE_VALUES, `${label}.active_mode`);
  const enabledSlot = input.enabled_slot == null
    ? null
    : assertInteger(input.enabled_slot, `${label}.enabled_slot`, 1, CHAMELEON_SLOT_COUNT);
  const slots = normalizeSlots(input.slots, `${label}.slots`);
  if (mode === "hf_emulator" || mode === "lf_emulator") {
    if (enabledSlot == null) throw new Error(`${label} emulator mode requires an enabled slot`);
    const slot = slots[enabledSlot - 1];
    if ((mode === "hf_emulator" && !slot.hf_enabled)
        || (mode === "lf_emulator" && !slot.lf_enabled)) {
      throw new Error(`${label} active emulator mode is not enabled on the selected slot`);
    }
  }
  const settings = normalizeSettings(input.settings, `${label}.settings`);
  const logState = normalizeLogState(input.log_state, `${label}.log_state`);
  const artifactHandle = normalizeArtifactHandle(
    input.snapshot_artifact_handle,
    `${label}.snapshot_artifact_handle`,
    { nullable: true },
  );
  if ((kind === "observed") !== (artifactHandle != null)) {
    throw new Error(`${label} observed snapshots require a vault handle and declarations cannot carry one`);
  }
  const timestamp = normalizeTrustedTimestamp(trustedClockSample);
  const restorableBasis = {
    active_mode: mode,
    enabled_slot: enabledSlot,
    slots,
    settings,
  };
  const restorableWorkspaceDigest = hashCanonicalJson(restorableBasis);
  const workspaceBasis = {
    restorable_workspace_digest: restorableWorkspaceDigest,
    log_state: logState,
    assurance_profile_id: assertIdentifier(input.assurance_profile_id, `${label}.assurance_profile_id`),
    assurance_claims_digest: assertDigest(
      input.assurance_claims_digest,
      `${label}.assurance_claims_digest`,
    ),
    assurance_epoch: assertInteger(input.assurance_epoch, `${label}.assurance_epoch`, 1),
    assurance_status: assuranceStatus,
    assurance_invalidation_reason: assuranceReason,
    state_epoch: assertInteger(input.state_epoch, `${label}.state_epoch`, 1),
  };
  const workspaceStateDigest = hashCanonicalJson(workspaceBasis);
  assertDerivedDigest(input, "restorable_workspace_digest", restorableWorkspaceDigest, label);
  assertDerivedDigest(input, "workspace_state_digest", workspaceStateDigest, label);
  const basis = {
    version: CHAMELEON_STATE_STEWARDSHIP_VERSION,
    snapshot_kind: kind,
    instrument_ref: normalizeOpaqueRef(
      input.instrument_ref,
      `${label}.instrument_ref`,
      { prefix: "instrument" },
    ),
    instrument_identity_digest: assertDigest(
      input.instrument_identity_digest,
      `${label}.instrument_identity_digest`,
    ),
    provider_id: PROVIDER_ID,
    provider_descriptor_digest: assertDigest(
      input.provider_descriptor_digest,
      `${label}.provider_descriptor_digest`,
    ),
    semantic_manifest_digest: CHAMELEON_SEMANTIC_MANIFEST.manifest_digest,
    ...workspaceBasis,
    active_mode: mode,
    enabled_slot: enabledSlot,
    slots,
    settings,
    restorable_workspace_digest: restorableWorkspaceDigest,
    workspace_state_digest: workspaceStateDigest,
    lease_id: assertLeaseId(input.lease_id, `${label}.lease_id`),
    fencing_generation: assertInteger(
      input.fencing_generation,
      `${label}.fencing_generation`,
      1,
    ),
    operation_id: operation.operation_id,
    operation_contract_digest: operation.operation_contract_digest,
    attempt_ref: normalizeOpaqueRef(
      input.attempt_ref,
      `${label}.attempt_ref`,
      { prefix: "attempt" },
    ),
    snapshot_artifact_handle: artifactHandle,
    snapshot_plan_digest: assertDigest(input.snapshot_plan_digest, `${label}.snapshot_plan_digest`),
    ...timestamp,
  };
  const snapshotDigest = hashCanonicalJson(basis);
  assertDerivedDigest(input, "snapshot_digest", snapshotDigest, label);
  const snapshot = deepFreeze({ ...basis, snapshot_digest: snapshotDigest });
  SNAPSHOTS.add(snapshot);
  SNAPSHOT_STATE.set(snapshot, { consumed_as_pre: false, log_chain_started: false });
  return snapshot;
}

function assertChameleonStateSnapshot(input) {
  if (!input || !SNAPSHOTS.has(input) || !SNAPSHOT_STATE.has(input) || !Object.isFrozen(input)) {
    throw new Error("chameleon state snapshot must be a private branded snapshot");
  }
  return input;
}

function assertCommonSnapshotBinding(left, right, label) {
  for (const field of [
    "instrument_ref",
    "instrument_identity_digest",
    "provider_id",
    "provider_descriptor_digest",
    "semantic_manifest_digest",
    "lease_id",
    "fencing_generation",
    "attempt_ref",
  ]) {
    if (left[field] !== right[field]) throw new Error(`${label}.${field} binding drift`);
  }
  assertTimestampProgression(left, right, label);
}

function normalizeModeChange(input, pre, post, label) {
  const changed = pre.active_mode !== post.active_mode || pre.enabled_slot !== post.enabled_slot;
  if (!changed) {
    if (input != null) throw new Error(`${label} must be null when mode and enabled slot are unchanged`);
    return null;
  }
  assertClosedObject(input, label, [
    "pre_mode",
    "post_mode",
    "pre_enabled_slot",
    "post_enabled_slot",
    "change_plan_digest",
  ]);
  if (input.pre_mode !== pre.active_mode || input.post_mode !== post.active_mode
      || input.pre_enabled_slot !== pre.enabled_slot || input.post_enabled_slot !== post.enabled_slot) {
    throw new Error(`${label} does not exactly declare the mode transition`);
  }
  return deepFreeze({
    pre_mode: pre.active_mode,
    post_mode: post.active_mode,
    pre_enabled_slot: pre.enabled_slot,
    post_enabled_slot: post.enabled_slot,
    change_plan_digest: assertDigest(input.change_plan_digest, `${label}.change_plan_digest`),
  });
}

function slotCore(slot) {
  const { slot_digest, ...core } = slot;
  return core;
}

function normalizeSlotMutation(input, pre, post, label) {
  assertClosedObject(input, label, [
    "slot_index",
    "action",
    "pre_slot_digest",
    "post_slot_digest",
    "authorization_plan_digest",
    "source_artifact_handle",
    "preimage_artifact_handle",
  ]);
  const slotIndex = assertInteger(input.slot_index, `${label}.slot_index`, 1, CHAMELEON_SLOT_COUNT);
  const before = pre.slots[slotIndex - 1];
  const after = post.slots[slotIndex - 1];
  if (input.pre_slot_digest !== before.slot_digest || input.post_slot_digest !== after.slot_digest
      || before.slot_digest === after.slot_digest) {
    throw new Error(`${label} does not bind one actual changed slot`);
  }
  const action = assertEnum(input.action, CHAMELEON_SLOT_MUTATION_VALUES, `${label}.action`);
  const source = normalizeArtifactHandle(
    input.source_artifact_handle,
    `${label}.source_artifact_handle`,
    { nullable: true },
  );
  const preimage = normalizeArtifactHandle(
    input.preimage_artifact_handle,
    `${label}.preimage_artifact_handle`,
    { nullable: true },
  );
  if (action === "stage") {
    if (before.slot_status !== "empty" || after.slot_status !== "occupied"
        || source !== after.content_artifact_handle || preimage != null) {
      throw new Error(`${label} stage must populate an empty slot from its exact vault handle`);
    }
  } else if (action === "overwrite") {
    if (before.slot_status !== "occupied" || after.slot_status !== "occupied"
        || source !== after.content_artifact_handle || preimage !== before.content_artifact_handle
        || (before.content_artifact_handle === after.content_artifact_handle
          && before.metadata_artifact_handle === after.metadata_artifact_handle)) {
      throw new Error(`${label} overwrite must bind exact source and preimage vault handles`);
    }
  } else if (action === "erase") {
    if (before.slot_status !== "occupied" || after.slot_status !== "empty"
        || source != null || preimage !== before.content_artifact_handle) {
      throw new Error(`${label} erase must bind the exact preimage and cannot name source content`);
    }
  } else if (action === "metadata_update") {
    const beforeCore = slotCore(before);
    const afterCore = slotCore(after);
    for (const field of [
      "slot_status", "hf_enabled", "lf_enabled", "hf_type_id", "lf_type_id",
      "content_artifact_handle",
    ]) {
      if (beforeCore[field] !== afterCore[field]) {
        throw new Error(`${label} metadata_update changed content, type, or enablement`);
      }
    }
    if (source !== after.metadata_artifact_handle || preimage !== before.metadata_artifact_handle
        || before.metadata_artifact_handle === after.metadata_artifact_handle) {
      throw new Error(`${label} metadata_update must bind exact metadata handles`);
    }
  } else {
    for (const field of [
      "slot_status", "metadata_artifact_handle", "content_artifact_handle",
    ]) {
      if (before[field] !== after[field]) {
        throw new Error(`${label} enablement_change altered retained slot content`);
      }
    }
    if (before.hf_enabled === after.hf_enabled && before.lf_enabled === after.lf_enabled) {
      throw new Error(`${label} enablement_change did not change enablement`);
    }
    if (source != null || preimage != null) {
      throw new Error(`${label} enablement_change cannot carry content handles`);
    }
  }
  if (after.slot_revision !== before.slot_revision + 1) {
    throw new Error(`${label} changed slot revision must advance exactly once`);
  }
  return deepFreeze({
    slot_index: slotIndex,
    action,
    pre_slot_digest: before.slot_digest,
    post_slot_digest: after.slot_digest,
    authorization_plan_digest: assertDigest(
      input.authorization_plan_digest,
      `${label}.authorization_plan_digest`,
    ),
    source_artifact_handle: source,
    preimage_artifact_handle: preimage,
  });
}

function normalizeSlotMutations(input, pre, post, label) {
  assertClosedArray(input, label, { maximumLength: CHAMELEON_SLOT_COUNT });
  const changed = pre.slots.filter((slot, index) => slot.slot_digest !== post.slots[index].slot_digest)
    .map((slot) => slot.slot_index);
  const normalized = input.map((entry, index) => normalizeSlotMutation(
    entry,
    pre,
    post,
    `${label}[${index}]`,
  )).sort((left, right) => left.slot_index - right.slot_index);
  if (new Set(normalized.map((entry) => entry.slot_index)).size !== normalized.length
      || changed.length !== normalized.length
      || changed.some((slotIndex, index) => slotIndex !== normalized[index].slot_index)) {
    throw new Error(`${label} must declare every changed slot exactly once and no unchanged slot`);
  }
  return Object.freeze(normalized);
}

function normalizeSettingsChanges(input, planDigest, pre, post, label) {
  assertClosedArray(input, label, { maximumLength: SETTINGS_FIELDS.length });
  const changed = SETTINGS_FIELDS.filter((field) => pre.settings[field] !== post.settings[field]);
  const normalized = input.map((field, index) => {
    if (!SETTINGS_FIELDS.includes(field)) throw new Error(`${label}[${index}] is not a closed setting field`);
    return field;
  }).sort();
  if (new Set(normalized).size !== normalized.length
      || normalized.length !== changed.length
      || normalized.some((field, index) => field !== changed[index])) {
    throw new Error(`${label} must declare every changed setting exactly once`);
  }
  if (normalized.length === 0) {
    if (planDigest != null) throw new Error(`${label} plan digest must be null without changes`);
  } else {
    assertDigest(planDigest, `${label}.settings_change_plan_digest`);
  }
  return Object.freeze(normalized);
}

function assertPolicyStateDeltas(policy, modeChange, slotMutations, settingsChangeIds, label) {
  if (modeChange != null) {
    if (!policy.mode_mutation || !policy.allowed_post_modes.includes(modeChange.post_mode)) {
      throw new Error(
        `${label} operation cannot authorize the declared mode or enabled-slot transition`,
      );
    }
  }
  for (const mutation of slotMutations) {
    if (!policy.allowed_slot_actions.includes(mutation.action)) {
      throw new Error(
        `${label} operation cannot authorize ${mutation.action} slot mutation`,
      );
    }
  }
  for (const settingId of settingsChangeIds) {
    if (!policy.allowed_settings_change_ids.includes(settingId)) {
      throw new Error(
        `${label} operation cannot authorize ${settingId} settings mutation`,
      );
    }
  }
}

function deriveLogAction(pre, post) {
  const before = pre.log_state;
  const after = post.log_state;
  if (before.log_state_digest === after.log_state_digest) return "preserve";
  if (after.log_generation === before.log_generation + 1
      && after.retained_event_count === 0 && after.overflow_count === 0
      && after.overflow_status === "none"
      && after.origin_cursor_ref === after.tail_cursor_ref) {
    return "clear";
  }
  if (after.log_generation === before.log_generation
      && after.overflow_count >= before.overflow_count
      && after.tail_cursor_ref !== before.tail_cursor_ref) {
    if (after.overflow_count === before.overflow_count
        && after.origin_cursor_ref === before.origin_cursor_ref
        && after.retained_event_count > before.retained_event_count) {
      return "append";
    }
    if (after.overflow_count > before.overflow_count
        && after.origin_cursor_ref !== before.origin_cursor_ref) {
      return "append";
    }
  }
  throw new Error("log state changed without a monotonic append or explicit generation clear");
}

function expectedInvalidation(policy) {
  if (policy.assurance_action === "invalidate_admin_configuration") return "admin_configuration";
  if (policy.assurance_action === "invalidate_firmware_change") return "firmware_change";
  if (policy.assurance_action === "invalidate_data_erase") return "data_erase";
  return null;
}

function assertAssuranceTransition(policy, pre, post, label) {
  const reason = expectedInvalidation(policy);
  if (reason == null) {
    for (const field of [
      "assurance_profile_id",
      "assurance_claims_digest",
      "assurance_epoch",
      "assurance_status",
      "assurance_invalidation_reason",
    ]) {
      if (post[field] !== pre[field]) throw new Error(`${label} unexpectedly changed assurance ${field}`);
    }
    return false;
  }
  if (post.assurance_epoch !== pre.assurance_epoch + 1
      || post.assurance_status !== "invalidated"
      || post.assurance_invalidation_reason !== reason
      || post.assurance_profile_id !== pre.assurance_profile_id
      || post.assurance_claims_digest !== pre.assurance_claims_digest) {
    throw new Error(`${label} admin, firmware, or erase operation did not invalidate assurance exactly`);
  }
  return true;
}

function transitionResultState(effectDisposition, stateChanged, recoveryPolicy) {
  if (effectDisposition === "ambiguous" || effectDisposition === "unknown") {
    return "reconcile_required";
  }
  if (effectDisposition === "confirmed_no_effect" || !stateChanged) return "complete";
  if (recoveryPolicy === "required") return "restore_required";
  if (recoveryPolicy === "quarantine_only") return "quarantine_required";
  return "complete";
}

function createChameleonStateTransition(
  input,
  preSnapshotInput,
  declaredPostSnapshotInput,
  observedPostSnapshotInput,
  trustedClockSample,
  label = "chameleon_state_transition",
) {
  assertDataOnlyPublicGraph(input, label);
  assertClosedObject(input, label, [
    "version",
    "transition_ref",
    "operation_id",
    "operation_contract_digest",
    "attempt_ref",
    "request_digest",
    "lease_id",
    "fencing_generation",
    "authorized_effects_digest",
    "recovery_policy",
    "restore_plan_digest",
    "restore_effects_digest",
    "slot_mutations",
    "mode_change",
    "settings_change_ids",
    "settings_change_plan_digest",
    "log_action",
    "effect_disposition",
    "receipt_ref",
  ], ["transition_digest"]);
  if (input.version !== CHAMELEON_STATE_STEWARDSHIP_VERSION) {
    throw new Error(`${label}.version must be ${CHAMELEON_STATE_STEWARDSHIP_VERSION}`);
  }
  const pre = assertChameleonStateSnapshot(preSnapshotInput);
  const declaredPost = assertChameleonStateSnapshot(declaredPostSnapshotInput);
  const observedPost = observedPostSnapshotInput == null
    ? null
    : assertChameleonStateSnapshot(observedPostSnapshotInput);
  if (pre.snapshot_kind !== "observed" || declaredPost.snapshot_kind !== "declared"
      || (observedPost != null && observedPost.snapshot_kind !== "observed")) {
    throw new Error(`${label} requires observed pre-state, declared post-state, and optional observed post-state`);
  }
  const prePrivate = SNAPSHOT_STATE.get(pre);
  if (prePrivate.consumed_as_pre) throw new Error(`${label} pre-state snapshot was already consumed`);
  const operation = operationContract(input.operation_id, input.operation_contract_digest, label);
  const policy = getChameleonStateOperationPolicy(operation.operation_id);
  if (policy.restore_only) throw new Error(`${label} restore-only operations use the restore contract`);
  for (const snapshot of [pre, declaredPost, ...(observedPost == null ? [] : [observedPost])]) {
    if (snapshot.operation_id !== operation.operation_id
        || snapshot.operation_contract_digest !== operation.operation_contract_digest
        || snapshot.attempt_ref !== input.attempt_ref
        || snapshot.lease_id !== input.lease_id
        || snapshot.fencing_generation !== input.fencing_generation) {
      throw new Error(`${label} snapshot operation, attempt, lease, or fence binding drift`);
    }
  }
  assertCommonSnapshotBinding(pre, declaredPost, `${label}.declared_post`);
  if (observedPost != null) assertCommonSnapshotBinding(declaredPost, observedPost, `${label}.observed_post`);

  const workspaceChanged = pre.restorable_workspace_digest !== declaredPost.restorable_workspace_digest;
  const logAction = deriveLogAction(pre, declaredPost);
  if (input.log_action !== logAction || !policy.allowed_log_actions.includes(logAction)) {
    throw new Error(`${label}.log_action is undeclared or forbidden for ${operation.operation_id}`);
  }
  if (workspaceChanged && !policy.workspace_mutation) {
    throw new Error(`${label} operation cannot mutate provider workspace state`);
  }
  const assuranceChanged = assertAssuranceTransition(policy, pre, declaredPost, label);
  const stateChanged = workspaceChanged || logAction !== "preserve" || assuranceChanged;
  if (declaredPost.state_epoch !== pre.state_epoch + (stateChanged ? 1 : 0)) {
    throw new Error(`${label} state_epoch must advance exactly once for declared state mutation`);
  }
  const modeChange = normalizeModeChange(input.mode_change, pre, declaredPost, `${label}.mode_change`);
  const slotMutations = normalizeSlotMutations(
    input.slot_mutations,
    pre,
    declaredPost,
    `${label}.slot_mutations`,
  );
  const settingsChangeIds = normalizeSettingsChanges(
    input.settings_change_ids,
    input.settings_change_plan_digest,
    pre,
    declaredPost,
    `${label}.settings_change_ids`,
  );
  assertPolicyStateDeltas(
    policy,
    modeChange,
    slotMutations,
    settingsChangeIds,
    label,
  );
  const recoveryPolicy = assertEnum(
    input.recovery_policy,
    CHAMELEON_RECOVERY_POLICY_VALUES,
    `${label}.recovery_policy`,
  );
  if ((assuranceChanged || logAction === "clear") && recoveryPolicy !== "quarantine_only") {
    throw new Error(`${label} assurance-invalidating and log-clearing operations are quarantine-only`);
  }
  if (stateChanged && recoveryPolicy === "not_required") {
    throw new Error(`${label} state mutations require exact restore or quarantine policy`);
  }
  const restorePlanDigest = input.restore_plan_digest == null
    ? null
    : assertDigest(input.restore_plan_digest, `${label}.restore_plan_digest`);
  const restoreEffectsDigest = input.restore_effects_digest == null
    ? null
    : assertDigest(input.restore_effects_digest, `${label}.restore_effects_digest`);
  if ((recoveryPolicy === "required") !== (restorePlanDigest != null && restoreEffectsDigest != null)
      || (recoveryPolicy !== "required" && (restorePlanDigest != null || restoreEffectsDigest != null))) {
    throw new Error(`${label} restore plan/effects are required only for exact restoration`);
  }
  const effectDisposition = assertEnum(
    input.effect_disposition,
    CHAMELEON_EFFECT_DISPOSITION_VALUES,
    `${label}.effect_disposition`,
  );
  if (["confirmed_effect", "confirmed_no_effect"].includes(effectDisposition) !== (observedPost != null)) {
    throw new Error(`${label} confirmed dispositions require observed post-state; ambiguity forbids it`);
  }
  if (effectDisposition === "confirmed_effect"
      && observedPost.workspace_state_digest !== declaredPost.workspace_state_digest) {
    throw new Error(`${label} confirmed effect did not match its exact declared post-state`);
  }
  if (effectDisposition === "confirmed_no_effect"
      && observedPost.workspace_state_digest !== pre.workspace_state_digest) {
    throw new Error(`${label} confirmed no-effect state did not match exact pre-state`);
  }
  const timestamp = normalizeTrustedTimestamp(trustedClockSample);
  assertTimestampProgression(observedPost || declaredPost, timestamp, label);
  const basis = {
    version: CHAMELEON_STATE_STEWARDSHIP_VERSION,
    transition_ref: normalizeOpaqueRef(
      input.transition_ref,
      `${label}.transition_ref`,
      { prefix: "state-transition" },
    ),
    instrument_ref: pre.instrument_ref,
    instrument_identity_digest: pre.instrument_identity_digest,
    provider_id: PROVIDER_ID,
    provider_descriptor_digest: pre.provider_descriptor_digest,
    semantic_manifest_digest: pre.semantic_manifest_digest,
    operation_id: operation.operation_id,
    operation_contract_digest: operation.operation_contract_digest,
    operation_state_policy_digest: policy.policy_digest,
    attempt_ref: normalizeOpaqueRef(input.attempt_ref, `${label}.attempt_ref`, { prefix: "attempt" }),
    request_digest: assertDigest(input.request_digest, `${label}.request_digest`),
    lease_id: assertLeaseId(input.lease_id, `${label}.lease_id`),
    fencing_generation: assertInteger(input.fencing_generation, `${label}.fencing_generation`, 1),
    authorized_effects_digest: assertDigest(
      input.authorized_effects_digest,
      `${label}.authorized_effects_digest`,
    ),
    recovery_policy: recoveryPolicy,
    restore_plan_digest: restorePlanDigest,
    restore_effects_digest: restoreEffectsDigest,
    pre_snapshot_digest: pre.snapshot_digest,
    declared_post_snapshot_digest: declaredPost.snapshot_digest,
    observed_post_snapshot_digest: observedPost?.snapshot_digest || null,
    pre_workspace_state_digest: pre.workspace_state_digest,
    declared_post_workspace_state_digest: declaredPost.workspace_state_digest,
    observed_post_workspace_state_digest: observedPost?.workspace_state_digest || null,
    pre_state_epoch: pre.state_epoch,
    declared_post_state_epoch: declaredPost.state_epoch,
    slot_mutations: slotMutations,
    mode_change: modeChange,
    settings_change_ids: settingsChangeIds,
    settings_change_plan_digest: settingsChangeIds.length === 0
      ? null
      : assertDigest(input.settings_change_plan_digest, `${label}.settings_change_plan_digest`),
    log_action: logAction,
    effect_disposition: effectDisposition,
    transition_state: transitionResultState(effectDisposition, stateChanged, recoveryPolicy),
    receipt_ref: normalizeOpaqueRef(input.receipt_ref, `${label}.receipt_ref`, { prefix: "receipt" }),
    ...timestamp,
  };
  const transitionDigest = hashCanonicalJson(basis);
  assertDerivedDigest(input, "transition_digest", transitionDigest, label);
  const transition = deepFreeze({ ...basis, transition_digest: transitionDigest });
  TRANSITIONS.add(transition);
  TRANSITION_STATE.set(transition, {
    pre,
    declared_post: declaredPost,
    observed_post: observedPost,
    claimed: false,
  });
  prePrivate.consumed_as_pre = true;
  return transition;
}

function assertChameleonStateTransition(input) {
  if (!input || !TRANSITIONS.has(input) || !TRANSITION_STATE.has(input) || !Object.isFrozen(input)) {
    throw new Error("chameleon state transition must be a private branded transition");
  }
  return input;
}

function createChameleonStateReconciliation(
  input,
  transitionInput,
  observedSnapshotInput,
  trustedClockSample,
  label = "chameleon_state_reconciliation",
) {
  assertDataOnlyPublicGraph(input, label);
  assertClosedObject(input, label, [
    "version",
    "reconciliation_ref",
    "disposition",
    "observation_ref",
    "receipt_ref",
  ], ["reconciliation_digest"]);
  if (input.version !== CHAMELEON_STATE_STEWARDSHIP_VERSION) {
    throw new Error(`${label}.version must be ${CHAMELEON_STATE_STEWARDSHIP_VERSION}`);
  }
  const transition = assertChameleonStateTransition(transitionInput);
  const privateState = TRANSITION_STATE.get(transition);
  if (transition.transition_state !== "reconcile_required" || privateState.claimed) {
    throw new Error(`${label} requires one unclaimed reconcile-required transition`);
  }
  const disposition = assertEnum(
    input.disposition,
    CHAMELEON_RECONCILIATION_DISPOSITION_VALUES,
    `${label}.disposition`,
  );
  const observed = observedSnapshotInput == null
    ? null
    : assertChameleonStateSnapshot(observedSnapshotInput);
  if ((disposition === "unobservable") !== (observed == null)) {
    throw new Error(`${label} unobservable is the only disposition without an exact observed state`);
  }
  if (observed != null) {
    if (observed.snapshot_kind !== "observed") throw new Error(`${label} observation must be observed state`);
    assertCommonSnapshotBinding(privateState.declared_post, observed, label);
    if (observed.operation_id !== transition.operation_id
        || observed.operation_contract_digest !== transition.operation_contract_digest) {
      throw new Error(`${label} observed operation binding drift`);
    }
    if (disposition === "confirmed_no_effect"
        && observed.workspace_state_digest !== privateState.pre.workspace_state_digest) {
      throw new Error(`${label} confirmed_no_effect does not equal exact pre-state`);
    }
    if (disposition === "confirmed_declared_post"
        && observed.workspace_state_digest !== privateState.declared_post.workspace_state_digest) {
      throw new Error(`${label} confirmed_declared_post does not equal the declaration`);
    }
    if (disposition === "state_drift"
        && [privateState.pre.workspace_state_digest, privateState.declared_post.workspace_state_digest]
          .includes(observed.workspace_state_digest)) {
      throw new Error(`${label} state_drift must differ from both exact states`);
    }
    if (disposition === "state_drift"
        && observed.state_epoch < Math.max(
          privateState.pre.state_epoch + 1,
          privateState.declared_post.state_epoch,
        )) {
      throw new Error(`${label} state_drift cannot rewind the monotonic state epoch`);
    }
  }
  let reconciliationState;
  if (disposition === "confirmed_no_effect") reconciliationState = "reconciled_no_effect";
  else if (disposition === "confirmed_declared_post") {
    reconciliationState = transition.recovery_policy === "required"
      ? "restore_required"
      : transition.recovery_policy === "quarantine_only"
        ? "quarantine_required"
        : "reconciled_effect";
  } else if (disposition === "state_drift" && transition.recovery_policy === "required") {
    reconciliationState = "restore_required";
  } else reconciliationState = "quarantine_required";
  const timestamp = normalizeTrustedTimestamp(trustedClockSample);
  assertTimestampProgression(transition, timestamp, label);
  const basis = {
    version: CHAMELEON_STATE_STEWARDSHIP_VERSION,
    reconciliation_ref: normalizeOpaqueRef(
      input.reconciliation_ref,
      `${label}.reconciliation_ref`,
      { prefix: "reconciliation" },
    ),
    transition_ref: transition.transition_ref,
    transition_digest: transition.transition_digest,
    instrument_ref: transition.instrument_ref,
    instrument_identity_digest: transition.instrument_identity_digest,
    provider_id: transition.provider_id,
    provider_descriptor_digest: transition.provider_descriptor_digest,
    semantic_manifest_digest: transition.semantic_manifest_digest,
    operation_id: transition.operation_id,
    operation_contract_digest: transition.operation_contract_digest,
    operation_state_policy_digest: transition.operation_state_policy_digest,
    attempt_ref: transition.attempt_ref,
    lease_id: transition.lease_id,
    fencing_generation: transition.fencing_generation,
    pre_state_epoch: transition.pre_state_epoch,
    declared_post_state_epoch: transition.declared_post_state_epoch,
    disposition,
    observed_snapshot_digest: observed?.snapshot_digest || null,
    observed_workspace_state_digest: observed?.workspace_state_digest || null,
    observed_state_epoch: observed?.state_epoch || null,
    reconciliation_state: reconciliationState,
    observation_ref: normalizeOpaqueRef(
      input.observation_ref,
      `${label}.observation_ref`,
      { prefix: "observation" },
    ),
    receipt_ref: normalizeOpaqueRef(input.receipt_ref, `${label}.receipt_ref`, { prefix: "receipt" }),
    ...timestamp,
  };
  const reconciliationDigest = hashCanonicalJson(basis);
  assertDerivedDigest(input, "reconciliation_digest", reconciliationDigest, label);
  const reconciliation = deepFreeze({ ...basis, reconciliation_digest: reconciliationDigest });
  RECONCILIATIONS.add(reconciliation);
  RECONCILIATION_STATE.set(reconciliation, {
    transition,
    observed,
    claimed: false,
  });
  privateState.claimed = true;
  return reconciliation;
}

function assertChameleonStateReconciliation(input) {
  if (!input || !RECONCILIATIONS.has(input) || !RECONCILIATION_STATE.has(input)
      || !Object.isFrozen(input)) {
    throw new Error("chameleon state reconciliation must be a private branded reconciliation");
  }
  return input;
}

function resolveRecoverySource(input, label) {
  if (TRANSITIONS.has(input)) {
    const transition = assertChameleonStateTransition(input);
    const state = TRANSITION_STATE.get(transition);
    if (!["restore_required", "quarantine_required"].includes(transition.transition_state)
        || state.claimed) {
      throw new Error(`${label} transition is not an unclaimed recovery source`);
    }
    return { source: transition, source_state: transition.transition_state, transition, state };
  }
  const reconciliation = assertChameleonStateReconciliation(input);
  const state = RECONCILIATION_STATE.get(reconciliation);
  if (!["restore_required", "quarantine_required"].includes(reconciliation.reconciliation_state)
      || state.claimed) {
    throw new Error(`${label} reconciliation is not an unclaimed recovery source`);
  }
  return {
    source: reconciliation,
    source_state: reconciliation.reconciliation_state,
    transition: state.transition,
    state,
  };
}

function createChameleonStateRestoreResult(
  input,
  recoverySourceInput,
  restoredSnapshotInput,
  trustedClockSample,
  label = "chameleon_state_restore_result",
) {
  assertDataOnlyPublicGraph(input, label);
  assertClosedObject(input, label, [
    "version",
    "restore_ref",
    "restore_attempt_ref",
    "operation_id",
    "operation_contract_digest",
    "lease_id",
    "fencing_generation",
    "snapshot_artifact_handle",
    "restore_plan_digest",
    "restore_effects_digest",
    "log_action",
    "disposition",
    "receipt_ref",
  ], ["restore_result_digest"]);
  if (input.version !== CHAMELEON_STATE_STEWARDSHIP_VERSION) {
    throw new Error(`${label}.version must be ${CHAMELEON_STATE_STEWARDSHIP_VERSION}`);
  }
  const resolved = resolveRecoverySource(recoverySourceInput, label);
  const transition = resolved.transition;
  const transitionPrivate = TRANSITION_STATE.get(transition);
  const operation = operationContract(input.operation_id, input.operation_contract_digest, label);
  const policy = getChameleonStateOperationPolicy(operation.operation_id);
  if (!policy.restore_only) throw new Error(`${label}.operation_id must be a reviewed restore operation`);
  const disposition = assertEnum(
    input.disposition,
    CHAMELEON_RESTORE_DISPOSITION_VALUES,
    `${label}.disposition`,
  );
  const restored = restoredSnapshotInput == null
    ? null
    : assertChameleonStateSnapshot(restoredSnapshotInput);
  if ((disposition === "restored") !== (restored != null)
      || (disposition === "restored" && resolved.source_state !== "restore_required")) {
    throw new Error(`${label} restored requires exact state and a restore-required source`);
  }
  if (input.lease_id !== transition.lease_id
      || input.fencing_generation !== transition.fencing_generation
      || input.restore_plan_digest !== transition.restore_plan_digest
      || input.restore_effects_digest !== transition.restore_effects_digest
      || input.snapshot_artifact_handle !== transitionPrivate.pre.snapshot_artifact_handle) {
    throw new Error(`${label} lease, fence, snapshot, plan, or effect binding drift`);
  }
  const restorePlanDigest = input.restore_plan_digest == null
    ? null
    : assertDigest(input.restore_plan_digest, `${label}.restore_plan_digest`);
  const restoreEffectsDigest = input.restore_effects_digest == null
    ? null
    : assertDigest(input.restore_effects_digest, `${label}.restore_effects_digest`);
  if (disposition === "restored" && (restorePlanDigest == null || restoreEffectsDigest == null)) {
    throw new Error(`${label} restored disposition requires precommitted restore plan and effects`);
  }
  const current = RECONCILIATIONS.has(resolved.source)
    ? RECONCILIATION_STATE.get(resolved.source).observed
    : transitionPrivate.observed_post;
  let restoreLogAction = "preserve";
  if (restored != null) {
    if (restored.snapshot_kind !== "observed"
        || restored.operation_id !== operation.operation_id
        || restored.operation_contract_digest !== operation.operation_contract_digest
        || restored.attempt_ref !== input.restore_attempt_ref
        || restored.lease_id !== transition.lease_id
        || restored.fencing_generation !== transition.fencing_generation
        || restored.instrument_ref !== transition.instrument_ref
        || restored.instrument_identity_digest !== transition.instrument_identity_digest
        || restored.provider_descriptor_digest !== transition.provider_descriptor_digest
        || restored.restorable_workspace_digest
          !== transitionPrivate.pre.restorable_workspace_digest) {
      throw new Error(`${label} restored state does not exactly restore the precommitted workspace`);
    }
    const currentEpoch = Math.max(
      transitionPrivate.pre.state_epoch,
      transitionPrivate.declared_post.state_epoch,
      current?.state_epoch || 0,
    );
    if (restored.state_epoch !== currentEpoch + 1
        || restored.assurance_profile_id !== transitionPrivate.pre.assurance_profile_id
        || restored.assurance_claims_digest !== transitionPrivate.pre.assurance_claims_digest
        || restored.assurance_epoch !== transitionPrivate.pre.assurance_epoch
        || restored.assurance_status !== transitionPrivate.pre.assurance_status
        || restored.assurance_invalidation_reason
          !== transitionPrivate.pre.assurance_invalidation_reason) {
      throw new Error(`${label} restored epoch or assurance does not match the precommitted state`);
    }
    if (current != null) {
      const beforeLog = current.log_state;
      const afterLog = restored.log_state;
      restoreLogAction = deriveLogAction(current, restored);
      if (restoreLogAction === "clear") {
        throw new Error(`${label} restore cannot clear or rewind evidentiary logs`);
      }
      assertTimestampProgression(current, restored, label);
    }
    assertTimestampProgression(resolved.source, restored, label);
  }
  if (input.log_action !== restoreLogAction) {
    throw new Error(`${label}.log_action must exactly declare preserve or append restoration logging`);
  }
  const timestamp = normalizeTrustedTimestamp(trustedClockSample);
  const temporalAnchor = restored || resolved.source;
  assertTimestampProgression(temporalAnchor, timestamp, label);
  const basis = {
    version: CHAMELEON_STATE_STEWARDSHIP_VERSION,
    restore_ref: normalizeOpaqueRef(input.restore_ref, `${label}.restore_ref`, { prefix: "restore" }),
    source_ref: resolved.source.transition_ref || resolved.source.reconciliation_ref,
    source_digest: resolved.source.transition_digest || resolved.source.reconciliation_digest,
    source_state: resolved.source_state,
    instrument_ref: transition.instrument_ref,
    instrument_identity_digest: transition.instrument_identity_digest,
    provider_id: transition.provider_id,
    provider_descriptor_digest: transition.provider_descriptor_digest,
    semantic_manifest_digest: transition.semantic_manifest_digest,
    operation_id: operation.operation_id,
    operation_contract_digest: operation.operation_contract_digest,
    operation_state_policy_digest: policy.policy_digest,
    restore_attempt_ref: normalizeOpaqueRef(
      input.restore_attempt_ref,
      `${label}.restore_attempt_ref`,
      { prefix: "attempt" },
    ),
    lease_id: assertLeaseId(input.lease_id, `${label}.lease_id`),
    fencing_generation: assertInteger(input.fencing_generation, `${label}.fencing_generation`, 1),
    snapshot_artifact_handle: normalizeArtifactHandle(
      input.snapshot_artifact_handle,
      `${label}.snapshot_artifact_handle`,
    ),
    restore_plan_digest: restorePlanDigest,
    restore_effects_digest: restoreEffectsDigest,
    log_action: restoreLogAction,
    disposition,
    restored_snapshot_digest: restored?.snapshot_digest || null,
    restored_workspace_state_digest: restored?.workspace_state_digest || null,
    receipt_ref: normalizeOpaqueRef(input.receipt_ref, `${label}.receipt_ref`, { prefix: "receipt" }),
    ...timestamp,
  };
  const restoreResultDigest = hashCanonicalJson(basis);
  assertDerivedDigest(input, "restore_result_digest", restoreResultDigest, label);
  const result = deepFreeze({ ...basis, restore_result_digest: restoreResultDigest });
  RESTORE_RESULTS.add(result);
  RESTORE_RESULT_STATE.set(result, { source: resolved.source, restored });
  resolved.state.claimed = true;
  return result;
}

function assertChameleonStateRestoreResult(input) {
  if (!input || !RESTORE_RESULTS.has(input) || !RESTORE_RESULT_STATE.has(input)
      || !Object.isFrozen(input)) {
    throw new Error("chameleon state restore result must be a private branded result");
  }
  return input;
}

function createChameleonLogPageReceipt(
  input,
  snapshotInput,
  previousPageInput,
  trustedClockSample,
  label = "chameleon_log_page_receipt",
) {
  assertDataOnlyPublicGraph(input, label);
  assertClosedObject(input, label, [
    "version",
    "page_ref",
    "operation_id",
    "operation_contract_digest",
    "attempt_ref",
    "start_cursor_ref",
    "end_cursor_ref",
    "record_count",
    "has_more",
    "overflow_observed",
    "page_artifact_handle",
    "receipt_ref",
  ], ["page_receipt_digest"]);
  if (input.version !== CHAMELEON_STATE_STEWARDSHIP_VERSION) {
    throw new Error(`${label}.version must be ${CHAMELEON_STATE_STEWARDSHIP_VERSION}`);
  }
  const snapshot = assertChameleonStateSnapshot(snapshotInput);
  if (snapshot.snapshot_kind !== "observed") throw new Error(`${label} requires observed state`);
  const operation = operationContract(input.operation_id, input.operation_contract_digest, label);
  if (operation.operation_id !== "interaction.trace") {
    throw new Error(`${label}.operation_id must be interaction.trace`);
  }
  const attemptRef = normalizeOpaqueRef(
    input.attempt_ref,
    `${label}.attempt_ref`,
    { prefix: "attempt" },
  );
  if (snapshot.operation_id !== operation.operation_id
      || snapshot.operation_contract_digest !== operation.operation_contract_digest
      || snapshot.attempt_ref !== attemptRef) {
    throw new Error(`${label} snapshot operation or attempt binding drift`);
  }
  const previous = previousPageInput == null
    ? null
    : (() => {
      if (!LOG_PAGE_RECEIPTS.has(previousPageInput) || !LOG_PAGE_STATE.has(previousPageInput)) {
        throw new Error(`${label} previous page must be a private branded page receipt`);
      }
      return previousPageInput;
    })();
  const start = normalizeOpaqueRef(
    input.start_cursor_ref,
    `${label}.start_cursor_ref`,
    { prefix: "log-cursor" },
  );
  const end = normalizeOpaqueRef(input.end_cursor_ref, `${label}.end_cursor_ref`, { prefix: "log-cursor" });
  const recordCount = assertInteger(input.record_count, `${label}.record_count`, 0);
  const pageRef = normalizeOpaqueRef(input.page_ref, `${label}.page_ref`, { prefix: "log-page" });
  const pageArtifactHandle = normalizeArtifactHandle(
    input.page_artifact_handle,
    `${label}.page_artifact_handle`,
  );
  const receiptRef = normalizeOpaqueRef(
    input.receipt_ref,
    `${label}.receipt_ref`,
    { prefix: "receipt" },
  );
  if (typeof input.has_more !== "boolean" || typeof input.overflow_observed !== "boolean") {
    throw new Error(`${label} pagination and overflow fields must be booleans`);
  }
  const snapshotOverflow = snapshot.log_state.overflow_status === "observed";
  if (input.overflow_observed !== snapshotOverflow) {
    throw new Error(`${label}.overflow_observed must exactly reflect the bound snapshot`);
  }
  let chainStartedAtOrigin;
  let chainOverflow;
  let cumulativeRecordCount;
  let pageIndex;
  let seenCursorRefs;
  let seenPageRefs;
  let seenArtifactHandles;
  let seenReceiptRefs;
  if (previous == null) {
    const snapshotPrivate = SNAPSHOT_STATE.get(snapshot);
    if (snapshotPrivate.log_chain_started) {
      throw new Error(`${label} snapshot already has a log pagination chain`);
    }
    if (start !== snapshot.log_state.origin_cursor_ref) {
      throw new Error(`${label} first page must start at the snapshot origin cursor`);
    }
    chainStartedAtOrigin = true;
    chainOverflow = snapshotOverflow;
    cumulativeRecordCount = recordCount;
    pageIndex = 0;
    seenCursorRefs = new Set([start]);
    seenPageRefs = new Set();
    seenArtifactHandles = new Set();
    seenReceiptRefs = new Set();
  } else {
    const state = LOG_PAGE_STATE.get(previous);
    if (state.claimed || previous.has_more !== true
        || previous.snapshot_digest !== snapshot.snapshot_digest
        || previous.attempt_ref !== attemptRef
        || previous.operation_id !== operation.operation_id
        || start !== previous.end_cursor_ref) {
      throw new Error(`${label} previous page was consumed, terminal, cross-snapshot, or discontinuous`);
    }
    if (state.seen_cursor_refs.has(end)) {
      throw new Error(`${label} pagination cursor cannot revisit an earlier chain position`);
    }
    if (state.seen_page_refs.has(pageRef)
        || state.seen_artifact_handles.has(pageArtifactHandle)
        || state.seen_receipt_refs.has(receiptRef)) {
      throw new Error(`${label} pagination page, artifact, and receipt references must be unique`);
    }
    chainStartedAtOrigin = state.chain_started_at_origin;
    chainOverflow = state.chain_overflow;
    cumulativeRecordCount = state.cumulative_record_count + recordCount;
    pageIndex = previous.page_index + 1;
    seenCursorRefs = new Set(state.seen_cursor_refs);
    seenPageRefs = new Set(state.seen_page_refs);
    seenArtifactHandles = new Set(state.seen_artifact_handles);
    seenReceiptRefs = new Set(state.seen_receipt_refs);
  }
  if (cumulativeRecordCount > snapshot.log_state.retained_event_count) {
    throw new Error(`${label} pages exceed the snapshot retained event count`);
  }
  if (input.has_more && (recordCount === 0 || start === end
      || end === snapshot.log_state.tail_cursor_ref)) {
    throw new Error(`${label} non-terminal page must make progress before the snapshot tail`);
  }
  if (!input.has_more && end !== snapshot.log_state.tail_cursor_ref) {
    throw new Error(`${label} terminal page must end at the snapshot tail cursor`);
  }
  if (!input.has_more && cumulativeRecordCount !== snapshot.log_state.retained_event_count) {
    throw new Error(`${label} terminal chain must account for every retained snapshot event`);
  }
  if (recordCount > 0 && start === end) {
    throw new Error(`${label} non-empty page must advance its cursor`);
  }
  chainOverflow = chainOverflow || input.overflow_observed;
  seenCursorRefs.add(end);
  seenPageRefs.add(pageRef);
  seenArtifactHandles.add(pageArtifactHandle);
  seenReceiptRefs.add(receiptRef);
  const completeness = chainOverflow
    ? "incomplete_overflow"
    : input.has_more
      ? "incomplete_paginated"
      : chainStartedAtOrigin && end === snapshot.log_state.tail_cursor_ref
        ? "complete_for_snapshot"
        : "incomplete_paginated";
  const timestamp = normalizeTrustedTimestamp(trustedClockSample);
  assertTimestampProgression(previous || snapshot, timestamp, label);
  const basis = {
    version: CHAMELEON_STATE_STEWARDSHIP_VERSION,
    page_ref: pageRef,
    snapshot_digest: snapshot.snapshot_digest,
    instrument_ref: snapshot.instrument_ref,
    instrument_identity_digest: snapshot.instrument_identity_digest,
    provider_id: snapshot.provider_id,
    provider_descriptor_digest: snapshot.provider_descriptor_digest,
    semantic_manifest_digest: snapshot.semantic_manifest_digest,
    log_state_digest: snapshot.log_state.log_state_digest,
    log_generation: snapshot.log_state.log_generation,
    lease_id: snapshot.lease_id,
    fencing_generation: snapshot.fencing_generation,
    operation_id: operation.operation_id,
    operation_contract_digest: operation.operation_contract_digest,
    attempt_ref: attemptRef,
    page_index: pageIndex,
    previous_page_ref: previous?.page_ref || null,
    start_cursor_ref: start,
    end_cursor_ref: end,
    record_count: recordCount,
    cumulative_record_count: cumulativeRecordCount,
    has_more: input.has_more,
    overflow_observed: input.overflow_observed,
    evidence_completeness: assertEnum(
      completeness,
      CHAMELEON_LOG_COMPLETENESS_VALUES,
      `${label}.evidence_completeness`,
    ),
    page_artifact_handle: pageArtifactHandle,
    receipt_ref: receiptRef,
    ...timestamp,
  };
  const pageReceiptDigest = hashCanonicalJson(basis);
  assertDerivedDigest(input, "page_receipt_digest", pageReceiptDigest, label);
  const receipt = deepFreeze({ ...basis, page_receipt_digest: pageReceiptDigest });
  LOG_PAGE_RECEIPTS.add(receipt);
  LOG_PAGE_STATE.set(receipt, {
    snapshot,
    chain_started_at_origin: chainStartedAtOrigin,
    chain_overflow: chainOverflow,
    cumulative_record_count: cumulativeRecordCount,
    seen_cursor_refs: seenCursorRefs,
    seen_page_refs: seenPageRefs,
    seen_artifact_handles: seenArtifactHandles,
    seen_receipt_refs: seenReceiptRefs,
    claimed: false,
  });
  if (previous == null) SNAPSHOT_STATE.get(snapshot).log_chain_started = true;
  if (previous != null) LOG_PAGE_STATE.get(previous).claimed = true;
  return receipt;
}

function assertChameleonLogPageReceipt(input) {
  if (!input || !LOG_PAGE_RECEIPTS.has(input) || !LOG_PAGE_STATE.has(input)
      || !Object.isFrozen(input)) {
    throw new Error("chameleon log page receipt must be a private branded receipt");
  }
  return input;
}

module.exports = {
  CHAMELEON_ACTIVE_MODE_VALUES,
  CHAMELEON_ASSURANCE_INVALIDATION_REASON_VALUES,
  CHAMELEON_ASSURANCE_STATUS_VALUES,
  CHAMELEON_EFFECT_DISPOSITION_VALUES,
  CHAMELEON_LOG_ACTION_VALUES,
  CHAMELEON_LOG_COMPLETENESS_VALUES,
  CHAMELEON_OPERATION_STATE_POLICIES,
  CHAMELEON_RECONCILIATION_DISPOSITION_VALUES,
  CHAMELEON_RECONCILIATION_STATE_VALUES,
  CHAMELEON_RECOVERY_POLICY_VALUES,
  CHAMELEON_RESTORE_DISPOSITION_VALUES,
  CHAMELEON_SLOT_COUNT,
  CHAMELEON_SLOT_MUTATION_VALUES,
  CHAMELEON_SNAPSHOT_KIND_VALUES,
  CHAMELEON_STATE_STEWARDSHIP_VERSION,
  CHAMELEON_TRANSITION_STATE_VALUES,
  assertChameleonLogPageReceipt,
  assertChameleonStateReconciliation,
  assertChameleonStateRestoreResult,
  assertChameleonStateSnapshot,
  assertChameleonStateTransition,
  createChameleonLogPageReceipt,
  createChameleonStateReconciliation,
  createChameleonStateRestoreResult,
  createChameleonStateSnapshot,
  createChameleonStateTransition,
  getChameleonStateOperationPolicy,
};
