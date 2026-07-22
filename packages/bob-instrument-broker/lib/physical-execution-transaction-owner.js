"use strict";

// Provider-neutral conformance foundation for the one owner that must
// eventually serialize every physical effect transaction. This module has no
// production constructor, callback port, native binding, persistence backend,
// clock, or hardware authority. Its private bounded in-memory ledger exists to
// make the record, CAS, recovery, and terminal-outbox contracts hostile-testable
// before independently privileged durable owners are enrolled.

const crypto = require("node:crypto");
const { types: utilTypes } = require("node:util");

const arrayIsArray = Array.isArray;
const arrayPrototypeIndexOf = Array.prototype.indexOf;
const arrayPrototypeSort = Array.prototype.sort;
const bufferByteLength = Buffer.byteLength;
const cryptoCreateHash = crypto.createHash;
const cryptoHashDigest = crypto.Hash.prototype.digest;
const cryptoHashUpdate = crypto.Hash.prototype.update;
const ErrorConstructor = Error;
const JSONIntrinsic = JSON;
const jsonStringify = JSON.stringify;
const MapConstructor = Map;
const numberIsSafeInteger = Number.isSafeInteger;
const NUMBER_MAX_SAFE_INTEGER = Number.MAX_SAFE_INTEGER;
const objectDefineProperty = Object.defineProperty;
const objectFreeze = Object.freeze;
const objectGetOwnPropertyDescriptors = Object.getOwnPropertyDescriptors;
const objectGetPrototypeOf = Object.getPrototypeOf;
const objectHasOwn = Object.hasOwn;
const objectIsFrozen = Object.isFrozen;
const objectKeys = Object.keys;
const ObjectIntrinsic = Object;
const objectPrototype = Object.prototype;
const reflectApply = Reflect.apply;
const reflectOwnKeys = Reflect.ownKeys;
const regexpPrototypeExec = RegExp.prototype.exec;
const mapPrototypeGet = Map.prototype.get;
const mapPrototypeSet = Map.prototype.set;
const weakMapPrototypeGet = WeakMap.prototype.get;
const weakMapPrototypeHas = WeakMap.prototype.has;
const weakMapPrototypeSet = WeakMap.prototype.set;
const weakSetPrototypeAdd = WeakSet.prototype.add;
const weakSetPrototypeHas = WeakSet.prototype.has;
const utilIsProxy = utilTypes.isProxy;

const PHYSICAL_EXECUTION_TRANSACTION_OWNER_VERSION = 1;
const PHYSICAL_EXECUTION_TRANSACTION_PROTOCOL =
  "hacker-bob/physical-execution-transaction/v1";
const PHYSICAL_EXECUTION_COMPOSITE_BINDING_DOMAIN =
  "hacker-bob/physical-execution-composite-binding/v1";
const PHYSICAL_EXECUTION_TRANSACTION_KEY_DOMAIN =
  "hacker-bob/physical-execution-transaction-key/v1";
const PHYSICAL_EXECUTION_TRANSACTION_RECORD_DOMAIN =
  "hacker-bob/physical-execution-transaction-record/v1";
const PHYSICAL_EXECUTION_CLAIM_RECEIPT_DOMAIN =
  "hacker-bob/physical-execution-claim-receipt/v1";
const PHYSICAL_EXECUTION_TRANSITION_RECEIPT_DOMAIN =
  "hacker-bob/physical-execution-transition-receipt/v1";
const PHYSICAL_EXECUTION_TERMINAL_OUTBOX_DOMAIN =
  "hacker-bob/physical-execution-terminal-outbox/v1";
const PHYSICAL_EXECUTION_RECOVERY_PROJECTION_DOMAIN =
  "hacker-bob/physical-execution-recovery-projection/v1";
const PHYSICAL_EXECUTION_TRANSACTION_OWNER_ASSURANCE =
  "bounded_in_memory_non_authorizing_conformance_only";
const PHYSICAL_EXECUTION_TRANSACTION_RECORD_ASSURANCE =
  "in_memory_conformance_record_not_durable_evidence";
const MAX_TRANSACTION_CAPACITY = 4096;
const MAX_REF_BYTES = 512;
const DIGEST_PATTERN = /^[a-f0-9]{64}$/u;
const REF_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,511}$/u;

const PHYSICAL_EXECUTION_TRANSACTION_PHASES = objectFreeze([
  "CLAIMED",
  "GO_DURABLE",
  "EFFECT_ARMED",
  "EFFECT_RECORDED",
  "EFFECT_UNKNOWN",
  "VAULT_COMMITTED",
  "RESTORING",
  "TERMINAL",
]);

const EFFECT_DISPOSITIONS = objectFreeze([
  "not_started",
  "armed",
  "recorded",
  "ambiguous",
  "rejected_no_effect",
]);
const SEMANTIC_DISPOSITIONS = objectFreeze([
  "unavailable",
  "validated_success",
  "nonsemantic_raw_custody",
  "rejected_no_effect",
]);
const TERMINAL_DISPOSITIONS = objectFreeze([
  "pending",
  "completed",
  "ambiguous_quarantined",
  "rejected_no_effect",
]);

const COMPOSITE_BINDING_FIELDS = objectFreeze([
  "version",
  "protocol",
  "transaction_ref",
  "execution_lineage_digest",
  "session_nucleus_hash",
  "attempt_ref",
  "replay_identity_digest",
  "execution_request_digest",
  "authority_admission_digest",
  "capability_grant_digest",
  "commit_go_digest",
  "dispatch_admission_digest",
  "provider_worker_vault_binding_digest",
  "transaction_capability_digest",
  "resource_admission_digest",
  "resource_fence_digest",
  "lease_ref",
  "lease_digest",
  "bootstrap_sequence_digest",
  "compiler_manifest_digest",
  "compiler_registry_digest",
  "requested_effects_digest",
  "compiled_operation_digest",
  "compiled_command_digest",
  "active_command_input_digest",
  "cleanup_command_input_digest",
  "native_launch_ticket_digest",
  "worker_bundle_digest",
  "worker_launch_digest",
  "worker_fence_digest",
  "transport_binding_digest",
  "vault_ingest_capability_digest",
  "artifact_allocation_digest",
  "safety_plan_digest",
  "cleanup_plan_digest",
  "clock_identity_digest",
  "deadline_binding_digest",
  "vault_reservation_ref",
  "vault_reservation_digest",
  "restoration_plan_digest",
  "terminal_projection_plan_digest",
]);

const TRANSACTION_RECORD_FIELDS = objectFreeze([
  "version",
  "protocol",
  "kind",
  "transaction_ref",
  "execution_lineage_digest",
  "transaction_key_digest",
  "composite_binding_digest",
  "record_ref",
  "generation",
  "predecessor_record_digest",
  "phase",
  "claim_receipt_digest",
  "go_durable_receipt_digest",
  "effect_arm_receipt_digest",
  "effect_disposition",
  "semantic_disposition",
  "effect_evidence_digest",
  "vault_artifact_ref",
  "vault_receipt_digest",
  "restoration_proof_digest",
  "restoration_claim_digest",
  "terminal_disposition",
  "terminal_proof_digest",
  "no_effect_proof_digest",
  "capabilities_closed",
  "durability_assurance",
  "durability_evidence_digest",
  "production_ready",
  "hardware_access_authorized",
  "execution_authority",
]);

const OWNER_CONFIG_FIELDS = objectFreeze([
  "version",
  "kind",
  "test_only",
  "maximum_transactions",
  "simulate_claim_response_loss_once",
  "simulate_transition_response_loss_generation",
  "simulate_outbox_redelivery_response_loss_once",
]);

const CLAIM_QUERY_FIELDS = objectFreeze([
  "version", "kind", "binding",
]);
const READ_QUERY_FIELDS = objectFreeze([
  "version", "kind", "transaction_ref", "execution_lineage_digest",
  "transaction_key_digest", "composite_binding_digest",
]);
const TRANSITION_QUERY_FIELDS = objectFreeze([
  "version", "kind", "transaction_ref", "execution_lineage_digest",
  "transaction_key_digest", "composite_binding_digest", "expected_generation",
  "expected_predecessor_record_digest", "next_record",
]);
const OUTBOX_QUERY_FIELDS = objectFreeze([
  "version", "kind", "transaction_ref", "execution_lineage_digest",
  "transaction_key_digest", "composite_binding_digest", "outbox_ref", "outbox_digest",
]);

const PRODUCTION_BLOCKERS = objectFreeze([
  "external_linearizable_transaction_ledger_missing",
  "qualified_native_effect_owner_missing",
  "trusted_monotonic_deadline_preemption_missing",
  "independent_restoration_custodian_missing",
  "durable_terminal_outbox_custodian_missing",
  "complete_authority_to_native_binding_missing",
  "hardware_in_loop_qualification_missing",
]);

const LEGAL_SUCCESSORS = objectFreeze({
  CLAIMED: objectFreeze(["GO_DURABLE", "TERMINAL"]),
  GO_DURABLE: objectFreeze(["EFFECT_ARMED", "TERMINAL"]),
  EFFECT_ARMED: objectFreeze(["EFFECT_RECORDED", "EFFECT_UNKNOWN"]),
  EFFECT_RECORDED: objectFreeze(["VAULT_COMMITTED"]),
  EFFECT_UNKNOWN: objectFreeze(["VAULT_COMMITTED"]),
  VAULT_COMMITTED: objectFreeze(["RESTORING"]),
  RESTORING: objectFreeze(["TERMINAL"]),
  TERMINAL: objectFreeze([]),
});

const OWNERS = new WeakSet();
const OWNER_PRIVATE = new WeakMap();

function transactionError(code, cause = null) {
  const error = new ErrorConstructor(code, cause == null ? undefined : { cause });
  objectDefineProperty(error, "code", {
    value: code,
    enumerable: true,
    writable: false,
    configurable: false,
  });
  return error;
}

function contains(array, value) {
  return reflectApply(arrayPrototypeIndexOf, array, [value]) !== -1;
}

function isPlainDataObject(value) {
  if (value == null || typeof value !== "object" || utilIsProxy(value)
      || arrayIsArray(value)) {
    return false;
  }
  const prototype = objectGetPrototypeOf(value);
  return prototype === objectPrototype || prototype === null;
}

function assertExactDataObject(value, required, optional, label) {
  if (!isPlainDataObject(value)) {
    throw transactionError(`${label}_must_be_closed_data`);
  }
  const descriptors = objectGetOwnPropertyDescriptors(value);
  const keys = reflectOwnKeys(descriptors);
  for (let index = 0; index < keys.length; index += 1) {
    const key = keys[index];
    if (typeof key !== "string") {
      throw transactionError(`${label}_symbol_field_forbidden`);
    }
    if (!contains(required, key) && !contains(optional, key)) {
      throw transactionError(`${label}_unknown_field`);
    }
    const descriptor = descriptors[key];
    if (!descriptor || !objectHasOwn(descriptor, "value") || !descriptor.enumerable) {
      throw transactionError(`${label}_${key}_must_be_enumerable_data`);
    }
  }
  for (let index = 0; index < required.length; index += 1) {
    if (!objectHasOwn(descriptors, required[index])) {
      throw transactionError(`${label}_field_set_invalid`);
    }
  }
  return descriptors;
}

function descriptorValue(descriptors, field) {
  return descriptors[field].value;
}

function assertVersion(value, label) {
  if (value !== PHYSICAL_EXECUTION_TRANSACTION_OWNER_VERSION) {
    throw transactionError(`${label}_version_invalid`);
  }
  return value;
}

function assertProtocol(value, label) {
  if (value !== PHYSICAL_EXECUTION_TRANSACTION_PROTOCOL) {
    throw transactionError(`${label}_protocol_invalid`);
  }
  return value;
}

function assertDigest(value, label) {
  if (typeof value !== "string"
      || reflectApply(regexpPrototypeExec, DIGEST_PATTERN, [value]) === null) {
    throw transactionError(`${label}_digest_invalid`);
  }
  return value;
}

function assertNullableDigest(value, label) {
  return value === null ? null : assertDigest(value, label);
}

function assertRef(value, label) {
  if (typeof value !== "string"
      || reflectApply(regexpPrototypeExec, REF_PATTERN, [value]) === null
      || bufferByteLength(value, "utf8") > MAX_REF_BYTES) {
    throw transactionError(`${label}_ref_invalid`);
  }
  return value;
}

function assertNullableRef(value, label) {
  return value === null ? null : assertRef(value, label);
}

function assertBoolean(value, label) {
  if (typeof value !== "boolean") {
    throw transactionError(`${label}_boolean_invalid`);
  }
  return value;
}

function assertSafeInteger(value, label, minimum = 0, maximum = NUMBER_MAX_SAFE_INTEGER) {
  if (!numberIsSafeInteger(value) || value < minimum || value > maximum) {
    throw transactionError(`${label}_integer_invalid`);
  }
  return value;
}

function assertNullableSafeInteger(value, label, minimum = 0, maximum = NUMBER_MAX_SAFE_INTEGER) {
  return value === null ? null : assertSafeInteger(value, label, minimum, maximum);
}

function assertEnum(value, values, label) {
  if (!contains(values, value)) {
    throw transactionError(`${label}_enum_invalid`);
  }
  return value;
}

function assertNull(value, label) {
  if (value !== null) throw transactionError(`${label}_must_be_null`);
  return null;
}

function hashDomain(domain, value) {
  return hashCanonicalJson({ domain, ...value });
}

function canonicalJsonPrimitive(value) {
  const serialized = reflectApply(jsonStringify, JSONIntrinsic, [value]);
  if (typeof serialized !== "string") {
    throw transactionError("physical_execution_hash_value_invalid");
  }
  return serialized;
}

function hardenedCanonicalJson(value) {
  if (value === null || typeof value === "string" || typeof value === "boolean"
      || typeof value === "number") {
    return canonicalJsonPrimitive(value);
  }
  if (arrayIsArray(value)) {
    let serialized = "[";
    for (let index = 0; index < value.length; index += 1) {
      if (index > 0) serialized += ",";
      const child = value[index];
      serialized += child === undefined ? "null" : hardenedCanonicalJson(child);
    }
    return `${serialized}]`;
  }
  if (value && typeof value === "object") {
    const keys = reflectApply(objectKeys, ObjectIntrinsic, [value]);
    reflectApply(arrayPrototypeSort, keys, []);
    let serialized = "{";
    let emitted = 0;
    for (let index = 0; index < keys.length; index += 1) {
      const key = keys[index];
      const child = value[key];
      if (child === undefined) continue;
      if (emitted > 0) serialized += ",";
      serialized += `${canonicalJsonPrimitive(key)}:${hardenedCanonicalJson(child)}`;
      emitted += 1;
    }
    return `${serialized}}`;
  }
  throw transactionError("physical_execution_hash_value_invalid");
}

function hashCanonicalJson(value) {
  const hash = reflectApply(cryptoCreateHash, crypto, ["sha256"]);
  reflectApply(cryptoHashUpdate, hash, [hardenedCanonicalJson(value), "utf8"]);
  return reflectApply(cryptoHashDigest, hash, ["hex"]);
}

function normalizePhysicalExecutionCompositeBindingWithLabel(input, label) {
  const descriptors = assertExactDataObject(
    input,
    COMPOSITE_BINDING_FIELDS,
    ["transaction_key_digest", "composite_binding_digest"],
    label,
  );
  const value = {
    version: assertVersion(descriptorValue(descriptors, "version"), label),
    protocol: assertProtocol(descriptorValue(descriptors, "protocol"), label),
    transaction_ref: assertRef(
      descriptorValue(descriptors, "transaction_ref"),
      `${label}_transaction`,
    ),
    execution_lineage_digest: assertDigest(
      descriptorValue(descriptors, "execution_lineage_digest"),
      `${label}_execution_lineage`,
    ),
    session_nucleus_hash: assertDigest(
      descriptorValue(descriptors, "session_nucleus_hash"),
      `${label}_session_nucleus`,
    ),
    attempt_ref: assertRef(descriptorValue(descriptors, "attempt_ref"), `${label}_attempt`),
    replay_identity_digest: assertDigest(
      descriptorValue(descriptors, "replay_identity_digest"),
      `${label}_replay_identity`,
    ),
    execution_request_digest: assertDigest(
      descriptorValue(descriptors, "execution_request_digest"),
      `${label}_execution_request`,
    ),
    authority_admission_digest: assertDigest(
      descriptorValue(descriptors, "authority_admission_digest"),
      `${label}_authority_admission`,
    ),
    capability_grant_digest: assertDigest(
      descriptorValue(descriptors, "capability_grant_digest"),
      `${label}_capability_grant`,
    ),
    commit_go_digest: assertDigest(
      descriptorValue(descriptors, "commit_go_digest"),
      `${label}_commit_go`,
    ),
    dispatch_admission_digest: assertDigest(
      descriptorValue(descriptors, "dispatch_admission_digest"),
      `${label}_dispatch_admission`,
    ),
    provider_worker_vault_binding_digest: assertDigest(
      descriptorValue(descriptors, "provider_worker_vault_binding_digest"),
      `${label}_provider_worker_vault_binding`,
    ),
    transaction_capability_digest: assertDigest(
      descriptorValue(descriptors, "transaction_capability_digest"),
      `${label}_transaction_capability`,
    ),
    resource_admission_digest: assertDigest(
      descriptorValue(descriptors, "resource_admission_digest"),
      `${label}_resource_admission`,
    ),
    resource_fence_digest: assertDigest(
      descriptorValue(descriptors, "resource_fence_digest"),
      `${label}_resource_fence`,
    ),
    lease_ref: assertRef(descriptorValue(descriptors, "lease_ref"), `${label}_lease`),
    lease_digest: assertDigest(
      descriptorValue(descriptors, "lease_digest"),
      `${label}_lease`,
    ),
    bootstrap_sequence_digest: assertDigest(
      descriptorValue(descriptors, "bootstrap_sequence_digest"),
      `${label}_bootstrap_sequence`,
    ),
    compiler_manifest_digest: assertDigest(
      descriptorValue(descriptors, "compiler_manifest_digest"),
      `${label}_compiler_manifest`,
    ),
    compiler_registry_digest: assertDigest(
      descriptorValue(descriptors, "compiler_registry_digest"),
      `${label}_compiler_registry`,
    ),
    requested_effects_digest: assertDigest(
      descriptorValue(descriptors, "requested_effects_digest"),
      `${label}_requested_effects`,
    ),
    compiled_operation_digest: assertDigest(
      descriptorValue(descriptors, "compiled_operation_digest"),
      `${label}_compiled_operation`,
    ),
    compiled_command_digest: assertDigest(
      descriptorValue(descriptors, "compiled_command_digest"),
      `${label}_compiled_command`,
    ),
    active_command_input_digest: assertDigest(
      descriptorValue(descriptors, "active_command_input_digest"),
      `${label}_active_command_input`,
    ),
    cleanup_command_input_digest: assertDigest(
      descriptorValue(descriptors, "cleanup_command_input_digest"),
      `${label}_cleanup_command_input`,
    ),
    native_launch_ticket_digest: assertDigest(
      descriptorValue(descriptors, "native_launch_ticket_digest"),
      `${label}_native_launch_ticket`,
    ),
    worker_bundle_digest: assertDigest(
      descriptorValue(descriptors, "worker_bundle_digest"),
      `${label}_worker_bundle`,
    ),
    worker_launch_digest: assertDigest(
      descriptorValue(descriptors, "worker_launch_digest"),
      `${label}_worker_launch`,
    ),
    worker_fence_digest: assertDigest(
      descriptorValue(descriptors, "worker_fence_digest"),
      `${label}_worker_fence`,
    ),
    transport_binding_digest: assertDigest(
      descriptorValue(descriptors, "transport_binding_digest"),
      `${label}_transport_binding`,
    ),
    vault_ingest_capability_digest: assertDigest(
      descriptorValue(descriptors, "vault_ingest_capability_digest"),
      `${label}_vault_ingest_capability`,
    ),
    artifact_allocation_digest: assertDigest(
      descriptorValue(descriptors, "artifact_allocation_digest"),
      `${label}_artifact_allocation`,
    ),
    safety_plan_digest: assertDigest(
      descriptorValue(descriptors, "safety_plan_digest"),
      `${label}_safety_plan`,
    ),
    cleanup_plan_digest: assertDigest(
      descriptorValue(descriptors, "cleanup_plan_digest"),
      `${label}_cleanup_plan`,
    ),
    clock_identity_digest: assertDigest(
      descriptorValue(descriptors, "clock_identity_digest"),
      `${label}_clock_identity`,
    ),
    deadline_binding_digest: assertDigest(
      descriptorValue(descriptors, "deadline_binding_digest"),
      `${label}_deadline_binding`,
    ),
    vault_reservation_ref: assertRef(
      descriptorValue(descriptors, "vault_reservation_ref"),
      `${label}_vault_reservation`,
    ),
    vault_reservation_digest: assertDigest(
      descriptorValue(descriptors, "vault_reservation_digest"),
      `${label}_vault_reservation`,
    ),
    restoration_plan_digest: assertDigest(
      descriptorValue(descriptors, "restoration_plan_digest"),
      `${label}_restoration_plan`,
    ),
    terminal_projection_plan_digest: assertDigest(
      descriptorValue(descriptors, "terminal_projection_plan_digest"),
      `${label}_terminal_projection_plan`,
    ),
  };
  const transactionKeyDigest = hashDomain(PHYSICAL_EXECUTION_TRANSACTION_KEY_DOMAIN, {
    session_nucleus_hash: value.session_nucleus_hash,
    execution_lineage_digest: value.execution_lineage_digest,
  });
  if (objectHasOwn(descriptors, "transaction_key_digest")
      && assertDigest(
        descriptorValue(descriptors, "transaction_key_digest"),
        `${label}_transaction_key`,
      ) !== transactionKeyDigest) {
    throw transactionError(`${label}_transaction_key_mismatch`);
  }
  const boundValue = { ...value, transaction_key_digest: transactionKeyDigest };
  const digest = hashDomain(PHYSICAL_EXECUTION_COMPOSITE_BINDING_DOMAIN, boundValue);
  if (objectHasOwn(descriptors, "composite_binding_digest")
      && assertDigest(
        descriptorValue(descriptors, "composite_binding_digest"),
        `${label}_composite_binding`,
      ) !== digest) {
    throw transactionError(`${label}_digest_mismatch`);
  }
  return objectFreeze({ ...boundValue, composite_binding_digest: digest });
}

function normalizePhysicalExecutionCompositeBinding(input) {
  if (arguments.length !== 1) {
    throw transactionError("physical_execution_composite_binding_argument_count_invalid");
  }
  return normalizePhysicalExecutionCompositeBindingWithLabel(
    input,
    "physical_execution_composite_binding",
  );
}

function assertEmptyPreEffectFields(record, label) {
  assertNull(record.effect_evidence_digest, `${label}_effect_evidence`);
  assertNull(record.vault_artifact_ref, `${label}_vault_artifact`);
  assertNull(record.vault_receipt_digest, `${label}_vault_receipt`);
  assertNull(record.restoration_proof_digest, `${label}_restoration_proof`);
  if (record.terminal_disposition === "pending") {
    assertNull(record.terminal_proof_digest, `${label}_terminal_proof`);
  }
}

function assertReceiptCommitments(record, label) {
  if (record.claim_receipt_digest === null) {
    throw transactionError(`${label}_claim_receipt_required`);
  }
  if (record.phase === "TERMINAL" && record.terminal_disposition === "rejected_no_effect") {
    if (record.effect_arm_receipt_digest !== null
        || record.restoration_claim_digest !== null
        || record.no_effect_proof_digest === null
        || record.capabilities_closed !== true) {
      throw transactionError(`${label}_rejected_no_effect_commitments_invalid`);
    }
    return;
  }
  if (record.phase === "CLAIMED") {
    if (record.go_durable_receipt_digest !== null
        || record.effect_arm_receipt_digest !== null
        || record.restoration_claim_digest !== null
        || record.no_effect_proof_digest !== null
        || record.capabilities_closed !== false) {
      throw transactionError(`${label}_claimed_commitments_invalid`);
    }
    return;
  }
  if (record.go_durable_receipt_digest === null || record.no_effect_proof_digest !== null) {
    throw transactionError(`${label}_go_commitment_invalid`);
  }
  if (record.phase === "GO_DURABLE") {
    if (record.effect_arm_receipt_digest !== null
        || record.restoration_claim_digest !== null
        || record.capabilities_closed !== false) {
      throw transactionError(`${label}_go_commitments_invalid`);
    }
    return;
  }
  if (record.effect_arm_receipt_digest === null) {
    throw transactionError(`${label}_effect_arm_receipt_required`);
  }
  if (record.phase === "RESTORING" || record.phase === "TERMINAL") {
    if (record.restoration_claim_digest === null) {
      throw transactionError(`${label}_restoration_claim_required`);
    }
  } else if (record.restoration_claim_digest !== null) {
    throw transactionError(`${label}_restoration_claim_premature`);
  }
  if ((record.phase === "TERMINAL") !== record.capabilities_closed) {
    throw transactionError(`${label}_capability_closure_invalid`);
  }
}

function assertPendingTerminal(record, label) {
  if (record.terminal_disposition !== "pending" || record.terminal_proof_digest !== null) {
    throw transactionError(`${label}_terminal_must_be_pending`);
  }
}

function assertEffectEvidence(record, label) {
  if (record.effect_evidence_digest === null) {
    throw transactionError(`${label}_effect_evidence_required`);
  }
}

function assertVaultEvidence(record, label) {
  assertEffectEvidence(record, label);
  if (record.vault_artifact_ref === null || record.vault_receipt_digest === null) {
    throw transactionError(`${label}_vault_evidence_required`);
  }
}

function assertEffectSemanticPair(record, label) {
  if (record.effect_disposition === "recorded") {
    if (record.semantic_disposition !== "validated_success"
        && record.semantic_disposition !== "nonsemantic_raw_custody") {
      throw transactionError(`${label}_recorded_semantic_invalid`);
    }
    return;
  }
  if (record.effect_disposition === "ambiguous") {
    if (record.semantic_disposition !== "nonsemantic_raw_custody") {
      throw transactionError(`${label}_ambiguous_cannot_be_semantic_success`);
    }
    return;
  }
  throw transactionError(`${label}_effect_disposition_invalid_for_phase`);
}

function assertPhysicalExecutionRecordPhase(record, label) {
  assertReceiptCommitments(record, label);
  if (record.phase === "CLAIMED" || record.phase === "GO_DURABLE") {
    if (record.effect_disposition !== "not_started"
        || record.semantic_disposition !== "unavailable") {
      throw transactionError(`${label}_pre_effect_disposition_invalid`);
    }
    assertPendingTerminal(record, label);
    assertEmptyPreEffectFields(record, label);
    return;
  }
  if (record.phase === "EFFECT_ARMED") {
    if (record.effect_disposition !== "armed"
        || record.semantic_disposition !== "unavailable") {
      throw transactionError(`${label}_armed_disposition_invalid`);
    }
    assertPendingTerminal(record, label);
    assertEmptyPreEffectFields(record, label);
    return;
  }
  if (record.phase === "EFFECT_RECORDED" || record.phase === "EFFECT_UNKNOWN") {
    assertEffectSemanticPair(record, label);
    if (record.phase === "EFFECT_RECORDED" && record.effect_disposition !== "recorded") {
      throw transactionError(`${label}_recorded_effect_required`);
    }
    if (record.phase === "EFFECT_UNKNOWN" && record.effect_disposition !== "ambiguous") {
      throw transactionError(`${label}_ambiguous_effect_required`);
    }
    assertEffectEvidence(record, label);
    assertNull(record.vault_artifact_ref, `${label}_vault_artifact`);
    assertNull(record.vault_receipt_digest, `${label}_vault_receipt`);
    assertNull(record.restoration_proof_digest, `${label}_restoration_proof`);
    assertPendingTerminal(record, label);
    return;
  }
  if (record.phase === "VAULT_COMMITTED" || record.phase === "RESTORING") {
    assertEffectSemanticPair(record, label);
    assertVaultEvidence(record, label);
    assertNull(record.restoration_proof_digest, `${label}_restoration_proof`);
    assertPendingTerminal(record, label);
    return;
  }
  if (record.phase === "TERMINAL") {
    if (record.terminal_proof_digest === null) {
      throw transactionError(`${label}_terminal_proof_required`);
    }
    if (record.terminal_disposition === "rejected_no_effect") {
      if (record.effect_disposition !== "rejected_no_effect"
          || record.semantic_disposition !== "rejected_no_effect") {
        throw transactionError(`${label}_rejected_no_effect_disposition_invalid`);
      }
      assertNull(record.effect_evidence_digest, `${label}_effect_evidence`);
      assertNull(record.vault_artifact_ref, `${label}_vault_artifact`);
      assertNull(record.vault_receipt_digest, `${label}_vault_receipt`);
      assertNull(record.restoration_proof_digest, `${label}_restoration_proof`);
      return;
    }
    assertEffectSemanticPair(record, label);
    assertVaultEvidence(record, label);
    if (record.restoration_proof_digest === null) {
      throw transactionError(`${label}_restoration_proof_required`);
    }
    if (record.effect_disposition === "recorded"
        && record.semantic_disposition === "validated_success") {
      if (record.terminal_disposition !== "completed") {
        throw transactionError(`${label}_validated_success_terminal_invalid`);
      }
      return;
    }
    if (record.terminal_disposition !== "ambiguous_quarantined") {
      throw transactionError(`${label}_nonsemantic_terminal_must_be_quarantined`);
    }
    return;
  }
  throw transactionError(`${label}_phase_invalid`);
}

function normalizePhysicalExecutionTransactionRecordWithLabel(input, label) {
  const descriptors = assertExactDataObject(
    input,
    TRANSACTION_RECORD_FIELDS,
    ["record_digest"],
    label,
  );
  const value = {
    version: assertVersion(descriptorValue(descriptors, "version"), label),
    protocol: assertProtocol(descriptorValue(descriptors, "protocol"), label),
    kind: descriptorValue(descriptors, "kind"),
    transaction_ref: assertRef(
      descriptorValue(descriptors, "transaction_ref"),
      `${label}_transaction`,
    ),
    execution_lineage_digest: assertDigest(
      descriptorValue(descriptors, "execution_lineage_digest"),
      `${label}_execution_lineage`,
    ),
    transaction_key_digest: assertDigest(
      descriptorValue(descriptors, "transaction_key_digest"),
      `${label}_transaction_key`,
    ),
    composite_binding_digest: assertDigest(
      descriptorValue(descriptors, "composite_binding_digest"),
      `${label}_composite_binding`,
    ),
    record_ref: assertRef(descriptorValue(descriptors, "record_ref"), `${label}_record`),
    generation: assertSafeInteger(
      descriptorValue(descriptors, "generation"),
      `${label}_generation`,
      1,
    ),
    predecessor_record_digest: assertNullableDigest(
      descriptorValue(descriptors, "predecessor_record_digest"),
      `${label}_predecessor_record`,
    ),
    phase: assertEnum(
      descriptorValue(descriptors, "phase"),
      PHYSICAL_EXECUTION_TRANSACTION_PHASES,
      `${label}_phase`,
    ),
    claim_receipt_digest: assertNullableDigest(
      descriptorValue(descriptors, "claim_receipt_digest"),
      `${label}_claim_receipt`,
    ),
    go_durable_receipt_digest: assertNullableDigest(
      descriptorValue(descriptors, "go_durable_receipt_digest"),
      `${label}_go_durable_receipt`,
    ),
    effect_arm_receipt_digest: assertNullableDigest(
      descriptorValue(descriptors, "effect_arm_receipt_digest"),
      `${label}_effect_arm_receipt`,
    ),
    effect_disposition: assertEnum(
      descriptorValue(descriptors, "effect_disposition"),
      EFFECT_DISPOSITIONS,
      `${label}_effect_disposition`,
    ),
    semantic_disposition: assertEnum(
      descriptorValue(descriptors, "semantic_disposition"),
      SEMANTIC_DISPOSITIONS,
      `${label}_semantic_disposition`,
    ),
    effect_evidence_digest: assertNullableDigest(
      descriptorValue(descriptors, "effect_evidence_digest"),
      `${label}_effect_evidence`,
    ),
    vault_artifact_ref: assertNullableRef(
      descriptorValue(descriptors, "vault_artifact_ref"),
      `${label}_vault_artifact`,
    ),
    vault_receipt_digest: assertNullableDigest(
      descriptorValue(descriptors, "vault_receipt_digest"),
      `${label}_vault_receipt`,
    ),
    restoration_proof_digest: assertNullableDigest(
      descriptorValue(descriptors, "restoration_proof_digest"),
      `${label}_restoration_proof`,
    ),
    restoration_claim_digest: assertNullableDigest(
      descriptorValue(descriptors, "restoration_claim_digest"),
      `${label}_restoration_claim`,
    ),
    terminal_disposition: assertEnum(
      descriptorValue(descriptors, "terminal_disposition"),
      TERMINAL_DISPOSITIONS,
      `${label}_terminal_disposition`,
    ),
    terminal_proof_digest: assertNullableDigest(
      descriptorValue(descriptors, "terminal_proof_digest"),
      `${label}_terminal_proof`,
    ),
    no_effect_proof_digest: assertNullableDigest(
      descriptorValue(descriptors, "no_effect_proof_digest"),
      `${label}_no_effect_proof`,
    ),
    capabilities_closed: assertBoolean(
      descriptorValue(descriptors, "capabilities_closed"),
      `${label}_capabilities_closed`,
    ),
    durability_assurance: descriptorValue(descriptors, "durability_assurance"),
    durability_evidence_digest: descriptorValue(descriptors, "durability_evidence_digest"),
    production_ready: assertBoolean(
      descriptorValue(descriptors, "production_ready"),
      `${label}_production_ready`,
    ),
    hardware_access_authorized: assertBoolean(
      descriptorValue(descriptors, "hardware_access_authorized"),
      `${label}_hardware_access_authorized`,
    ),
    execution_authority: assertBoolean(
      descriptorValue(descriptors, "execution_authority"),
      `${label}_execution_authority`,
    ),
  };
  if (value.kind !== "physical_execution_transaction_record") {
    throw transactionError(`${label}_kind_invalid`);
  }
  if (value.durability_assurance !== PHYSICAL_EXECUTION_TRANSACTION_RECORD_ASSURANCE
      || value.durability_evidence_digest !== null
      || value.production_ready !== false
      || value.hardware_access_authorized !== false
      || value.execution_authority !== false) {
    throw transactionError(`${label}_conformance_assurance_invalid`);
  }
  if ((value.generation === 1) !== (value.predecessor_record_digest === null)) {
    throw transactionError(`${label}_predecessor_generation_invalid`);
  }
  if (value.generation === 1 && value.phase !== "CLAIMED") {
    throw transactionError(`${label}_genesis_phase_invalid`);
  }
  assertPhysicalExecutionRecordPhase(value, label);
  const digest = hashDomain(PHYSICAL_EXECUTION_TRANSACTION_RECORD_DOMAIN, value);
  if (objectHasOwn(descriptors, "record_digest")
      && assertDigest(descriptorValue(descriptors, "record_digest"), `${label}_record`) !== digest) {
    throw transactionError(`${label}_digest_mismatch`);
  }
  return objectFreeze({ ...value, record_digest: digest });
}

function normalizePhysicalExecutionTransactionRecord(input) {
  if (arguments.length !== 1) {
    throw transactionError("physical_execution_transaction_record_argument_count_invalid");
  }
  return normalizePhysicalExecutionTransactionRecordWithLabel(
    input,
    "physical_execution_transaction_record",
  );
}

function assertEqualField(previous, next, field, code) {
  if (previous[field] !== next[field]) throw transactionError(code);
}

function assertPhysicalExecutionTransactionPhaseSuccessor(previousPhase, nextPhase) {
  if (arguments.length !== 2) {
    throw transactionError(
      "physical_execution_transaction_phase_successor_argument_count_invalid",
    );
  }
  if (typeof previousPhase !== "string"
      || !contains(PHYSICAL_EXECUTION_TRANSACTION_PHASES, previousPhase)) {
    throw transactionError("physical_execution_transaction_predecessor_phase_invalid");
  }
  if (typeof nextPhase !== "string"
      || !contains(PHYSICAL_EXECUTION_TRANSACTION_PHASES, nextPhase)) {
    throw transactionError("physical_execution_transaction_successor_phase_invalid");
  }
  if (!contains(LEGAL_SUCCESSORS[previousPhase], nextPhase)) {
    throw transactionError("physical_execution_transaction_transition_illegal");
  }
  return nextPhase;
}

function assertPhysicalExecutionTransactionTransition(previousInput, nextInput) {
  const previous = normalizePhysicalExecutionTransactionRecordWithLabel(
    previousInput,
    "previous_record",
  );
  const next = normalizePhysicalExecutionTransactionRecordWithLabel(nextInput, "next_record");
  assertEqualField(previous, next, "transaction_ref", "physical_execution_transaction_fork");
  assertEqualField(
    previous,
    next,
    "execution_lineage_digest",
    "physical_execution_transaction_fork",
  );
  assertEqualField(
    previous,
    next,
    "transaction_key_digest",
    "physical_execution_transaction_key_fork",
  );
  assertEqualField(
    previous,
    next,
    "composite_binding_digest",
    "physical_execution_transaction_binding_fork",
  );
  assertEqualField(
    previous,
    next,
    "claim_receipt_digest",
    "physical_execution_claim_receipt_fork",
  );
  if (next.generation !== previous.generation + 1
      || next.predecessor_record_digest !== previous.record_digest) {
    throw transactionError("physical_execution_transaction_cas_mismatch");
  }
  assertPhysicalExecutionTransactionPhaseSuccessor(previous.phase, next.phase);
  if (next.phase === "TERMINAL" && previous.phase !== "RESTORING") {
    assertEqualField(
      previous,
      next,
      "go_durable_receipt_digest",
      "physical_execution_go_receipt_fork",
    );
    if (next.terminal_disposition !== "rejected_no_effect"
        || next.effect_disposition !== "rejected_no_effect"
        || next.semantic_disposition !== "rejected_no_effect"
        || next.terminal_proof_digest === null) {
      throw transactionError("physical_execution_rejected_no_effect_proof_invalid");
    }
    return next;
  }
  if (previous.phase === "CLAIMED" && next.phase === "GO_DURABLE") {
    assertEqualField(previous, next, "effect_evidence_digest", "physical_execution_evidence_fork");
    return next;
  }
  if (previous.go_durable_receipt_digest !== null) {
    assertEqualField(
      previous,
      next,
      "go_durable_receipt_digest",
      "physical_execution_go_receipt_fork",
    );
  }
  if (previous.effect_arm_receipt_digest !== null) {
    assertEqualField(
      previous,
      next,
      "effect_arm_receipt_digest",
      "physical_execution_effect_arm_receipt_fork",
    );
  }
  if (previous.phase === "EFFECT_RECORDED" || previous.phase === "EFFECT_UNKNOWN"
      || previous.phase === "VAULT_COMMITTED" || previous.phase === "RESTORING") {
    assertEqualField(previous, next, "effect_disposition", "physical_execution_effect_fork");
    assertEqualField(previous, next, "semantic_disposition", "physical_execution_semantic_fork");
    assertEqualField(previous, next, "effect_evidence_digest", "physical_execution_evidence_fork");
  }
  if (previous.phase === "VAULT_COMMITTED" || previous.phase === "RESTORING") {
    assertEqualField(previous, next, "vault_artifact_ref", "physical_execution_vault_fork");
    assertEqualField(previous, next, "vault_receipt_digest", "physical_execution_vault_fork");
  }
  if (previous.restoration_claim_digest !== null) {
    assertEqualField(
      previous,
      next,
      "restoration_claim_digest",
      "physical_execution_restoration_claim_fork",
    );
  }
  return next;
}

function recoveryActionForPhase(phase) {
  if (phase === "CLAIMED") return "commit_go_or_reject_no_effect";
  if (phase === "GO_DURABLE") return "record_effect_arm_commitment_or_reject_no_effect";
  if (phase === "EFFECT_ARMED") return "reconcile_effect_without_execution_or_retry";
  if (phase === "EFFECT_RECORDED" || phase === "EFFECT_UNKNOWN") {
    return "commit_existing_effect_evidence_to_vault";
  }
  if (phase === "VAULT_COMMITTED") return "run_bound_restoration_without_effect_execution";
  if (phase === "RESTORING") return "complete_restoration_without_effect_execution";
  return "redeliver_exact_terminal_outbox_only";
}

function derivePhysicalExecutionTransactionRecovery(input) {
  const record = normalizePhysicalExecutionTransactionRecord(input);
  const effectArmedOrLater = contains([
    "EFFECT_ARMED", "EFFECT_RECORDED", "EFFECT_UNKNOWN", "VAULT_COMMITTED",
    "RESTORING", "TERMINAL",
  ], record.phase);
  const value = {
    version: PHYSICAL_EXECUTION_TRANSACTION_OWNER_VERSION,
    kind: "physical_execution_transaction_recovery_projection",
    transaction_ref: record.transaction_ref,
    execution_lineage_digest: record.execution_lineage_digest,
    transaction_key_digest: record.transaction_key_digest,
    composite_binding_digest: record.composite_binding_digest,
    record_ref: record.record_ref,
    record_digest: record.record_digest,
    phase: record.phase,
    recovery_action: recoveryActionForPhase(record.phase),
    conformance_arm_transition_permitted: record.phase === "GO_DURABLE",
    effect_execution_permitted: false,
    provider_effect_execution_permitted: false,
    effect_retry_permitted: false,
    post_arm_execution_forbidden: effectArmedOrLater,
    production_ready: false,
    hardware_access_authorized: false,
    execution_authority: false,
  };
  return objectFreeze({
    ...value,
    recovery_projection_digest: hashDomain(PHYSICAL_EXECUTION_RECOVERY_PROJECTION_DOMAIN, value),
  });
}

function normalizeOwnerConfig(input) {
  const label = "physical_execution_transaction_owner_config";
  const descriptors = assertExactDataObject(input, OWNER_CONFIG_FIELDS, [], label);
  const value = {
    version: assertVersion(descriptorValue(descriptors, "version"), label),
    kind: descriptorValue(descriptors, "kind"),
    test_only: assertBoolean(descriptorValue(descriptors, "test_only"), `${label}_test_only`),
    maximum_transactions: assertSafeInteger(
      descriptorValue(descriptors, "maximum_transactions"),
      `${label}_maximum_transactions`,
      1,
      MAX_TRANSACTION_CAPACITY,
    ),
    simulate_claim_response_loss_once: assertBoolean(
      descriptorValue(descriptors, "simulate_claim_response_loss_once"),
      `${label}_simulate_claim_response_loss_once`,
    ),
    simulate_transition_response_loss_generation: assertNullableSafeInteger(
      descriptorValue(descriptors, "simulate_transition_response_loss_generation"),
      `${label}_simulate_transition_response_loss_generation`,
      2,
    ),
    simulate_outbox_redelivery_response_loss_once: assertBoolean(
      descriptorValue(descriptors, "simulate_outbox_redelivery_response_loss_once"),
      `${label}_simulate_outbox_redelivery_response_loss_once`,
    ),
  };
  if (value.kind !== "physical_execution_transaction_conformance_owner_config"
      || value.test_only !== true) {
    throw transactionError(`${label}_fixture_enrollment_required`);
  }
  return objectFreeze(value);
}

function makeInitialRecord(binding) {
  const claimReceiptDigest = hashCanonicalJson({
    domain: "hacker-bob/physical-execution-conformance-claim-commitment/v1",
    transaction_ref: binding.transaction_ref,
    transaction_key_digest: binding.transaction_key_digest,
    composite_binding_digest: binding.composite_binding_digest,
  });
  const recordIdentity = hashCanonicalJson({
    domain: "hacker-bob/physical-execution-transaction-record-ref/v1",
    transaction_ref: binding.transaction_ref,
    execution_lineage_digest: binding.execution_lineage_digest,
    transaction_key_digest: binding.transaction_key_digest,
    composite_binding_digest: binding.composite_binding_digest,
    generation: 1,
  });
  return normalizePhysicalExecutionTransactionRecord({
    version: PHYSICAL_EXECUTION_TRANSACTION_OWNER_VERSION,
    protocol: PHYSICAL_EXECUTION_TRANSACTION_PROTOCOL,
    kind: "physical_execution_transaction_record",
    transaction_ref: binding.transaction_ref,
    execution_lineage_digest: binding.execution_lineage_digest,
    transaction_key_digest: binding.transaction_key_digest,
    composite_binding_digest: binding.composite_binding_digest,
    record_ref: `transaction-record:v1:${recordIdentity}`,
    generation: 1,
    predecessor_record_digest: null,
    phase: "CLAIMED",
    claim_receipt_digest: claimReceiptDigest,
    go_durable_receipt_digest: null,
    effect_arm_receipt_digest: null,
    effect_disposition: "not_started",
    semantic_disposition: "unavailable",
    effect_evidence_digest: null,
    vault_artifact_ref: null,
    vault_receipt_digest: null,
    restoration_proof_digest: null,
    restoration_claim_digest: null,
    terminal_disposition: "pending",
    terminal_proof_digest: null,
    no_effect_proof_digest: null,
    capabilities_closed: false,
    durability_assurance: PHYSICAL_EXECUTION_TRANSACTION_RECORD_ASSURANCE,
    durability_evidence_digest: null,
    production_ready: false,
    hardware_access_authorized: false,
    execution_authority: false,
  });
}

function makeClaimReceipt(binding, record) {
  const value = {
    version: PHYSICAL_EXECUTION_TRANSACTION_OWNER_VERSION,
    kind: "physical_execution_transaction_claim_receipt",
    transaction_ref: binding.transaction_ref,
    execution_lineage_digest: binding.execution_lineage_digest,
    transaction_key_digest: binding.transaction_key_digest,
    composite_binding_digest: binding.composite_binding_digest,
    claim_disposition: "claimed_or_exact_readback",
    generation: record.generation,
    head_record_ref: record.record_ref,
    head_record_digest: record.record_digest,
    durability_assurance: PHYSICAL_EXECUTION_TRANSACTION_OWNER_ASSURANCE,
    production_ready: false,
    hardware_access_authorized: false,
    execution_authority: false,
  };
  return objectFreeze({
    ...value,
    receipt_digest: record.claim_receipt_digest,
    claim_projection_digest: hashDomain(PHYSICAL_EXECUTION_CLAIM_RECEIPT_DOMAIN, {
      ...value,
      receipt_digest: record.claim_receipt_digest,
    }),
  });
}

function createTerminalOutbox(record) {
  const identity = hashCanonicalJson({
    domain: `${PHYSICAL_EXECUTION_TERMINAL_OUTBOX_DOMAIN}/identity`,
    transaction_ref: record.transaction_ref,
    execution_lineage_digest: record.execution_lineage_digest,
    transaction_key_digest: record.transaction_key_digest,
    composite_binding_digest: record.composite_binding_digest,
    terminal_record_digest: record.record_digest,
  });
  const value = {
    version: PHYSICAL_EXECUTION_TRANSACTION_OWNER_VERSION,
    kind: "physical_execution_terminal_outbox_projection",
    outbox_ref: `terminal-outbox:v1:${identity}`,
    transaction_ref: record.transaction_ref,
    execution_lineage_digest: record.execution_lineage_digest,
    transaction_key_digest: record.transaction_key_digest,
    composite_binding_digest: record.composite_binding_digest,
    terminal_record_ref: record.record_ref,
    terminal_record_digest: record.record_digest,
    terminal_disposition: record.terminal_disposition,
    claim_receipt_digest: record.claim_receipt_digest,
    go_durable_receipt_digest: record.go_durable_receipt_digest,
    effect_arm_receipt_digest: record.effect_arm_receipt_digest,
    effect_evidence_digest: record.effect_evidence_digest,
    vault_artifact_ref: record.vault_artifact_ref,
    vault_receipt_digest: record.vault_receipt_digest,
    restoration_proof_digest: record.restoration_proof_digest,
    restoration_claim_digest: record.restoration_claim_digest,
    terminal_proof_digest: record.terminal_proof_digest,
    no_effect_proof_digest: record.no_effect_proof_digest,
    capabilities_closed: record.capabilities_closed,
    delivery_disposition: "redeliver_exact_projection_only",
    production_ready: false,
    hardware_access_authorized: false,
    execution_authority: false,
  };
  return objectFreeze({ ...value, outbox_digest: hashDomain(PHYSICAL_EXECUTION_TERMINAL_OUTBOX_DOMAIN, value) });
}

function makeTransitionReceipt(record, outbox) {
  const value = {
    version: PHYSICAL_EXECUTION_TRANSACTION_OWNER_VERSION,
    kind: "physical_execution_transaction_transition_receipt",
    transaction_ref: record.transaction_ref,
    execution_lineage_digest: record.execution_lineage_digest,
    transaction_key_digest: record.transaction_key_digest,
    composite_binding_digest: record.composite_binding_digest,
    generation: record.generation,
    record_ref: record.record_ref,
    record_digest: record.record_digest,
    phase: record.phase,
    outbox_ref: outbox === null ? null : outbox.outbox_ref,
    outbox_digest: outbox === null ? null : outbox.outbox_digest,
    commit_disposition: "committed_or_exact_readback",
    durability_assurance: PHYSICAL_EXECUTION_TRANSACTION_OWNER_ASSURANCE,
    production_ready: false,
    hardware_access_authorized: false,
    execution_authority: false,
  };
  return objectFreeze({
    ...value,
    receipt_digest: hashDomain(PHYSICAL_EXECUTION_TRANSITION_RECEIPT_DOMAIN, value),
  });
}

function createPhysicalExecutionTransactionConformanceOwner(input) {
  const config = normalizeOwnerConfig(input);
  const configDigest = hashCanonicalJson(config);
  const owner = objectFreeze({
    version: PHYSICAL_EXECUTION_TRANSACTION_OWNER_VERSION,
    kind: "physical_execution_transaction_conformance_owner",
    owner_ref: `physical-transaction-owner:v1:${configDigest}`,
    owner_configuration_digest: configDigest,
    assurance: PHYSICAL_EXECUTION_TRANSACTION_OWNER_ASSURANCE,
    maximum_transactions: config.maximum_transactions,
    production_ready: false,
    hardware_access_authorized: false,
    execution_authority: false,
    durability_attested: false,
    blockers: PRODUCTION_BLOCKERS,
  });
  const privateState = {
    config,
    transactions_by_ref: new MapConstructor(),
    lineage_to_transaction_ref: new MapConstructor(),
    transaction_key_to_transaction_ref: new MapConstructor(),
    transaction_count: 0,
    claim_response_loss_pending: config.simulate_claim_response_loss_once,
    transition_response_loss_pending:
      config.simulate_transition_response_loss_generation !== null,
    outbox_response_loss_pending: config.simulate_outbox_redelivery_response_loss_once,
    active_operation: null,
  };
  reflectApply(weakSetPrototypeAdd, OWNERS, [owner]);
  reflectApply(weakMapPrototypeSet, OWNER_PRIVATE, [owner, privateState]);
  return owner;
}

function assertPhysicalExecutionTransactionOwner(owner) {
  if (!owner || utilIsProxy(owner)
      || !reflectApply(weakSetPrototypeHas, OWNERS, [owner])
      || !reflectApply(weakMapPrototypeHas, OWNER_PRIVATE, [owner])
      || !objectIsFrozen(owner)) {
    throw transactionError("physical_execution_transaction_owner_private_brand_required");
  }
  return owner;
}

function ownerState(owner) {
  assertPhysicalExecutionTransactionOwner(owner);
  return reflectApply(weakMapPrototypeGet, OWNER_PRIVATE, [owner]);
}

function withOwnerOperation(owner, operation, body) {
  const state = ownerState(owner);
  if (state.active_operation !== null) {
    throw transactionError("physical_execution_transaction_owner_reentrant_operation");
  }
  state.active_operation = operation;
  try {
    return body(state);
  } finally {
    state.active_operation = null;
  }
}

function getMap(map, key) {
  return reflectApply(mapPrototypeGet, map, [key]);
}

function setMap(map, key, value) {
  reflectApply(mapPrototypeSet, map, [key, value]);
}

function assertTransactionBinding(
  transaction,
  transactionRef,
  lineageDigest,
  transactionKeyDigest,
  bindingDigest,
) {
  if (transaction.binding.transaction_ref !== transactionRef
      || transaction.binding.execution_lineage_digest !== lineageDigest
      || transaction.binding.transaction_key_digest !== transactionKeyDigest
      || transaction.binding.composite_binding_digest !== bindingDigest) {
    throw transactionError("physical_execution_transaction_binding_fork");
  }
}

function normalizeReadQuery(input, kind) {
  const label = kind;
  const descriptors = assertExactDataObject(input, READ_QUERY_FIELDS, [], label);
  assertVersion(descriptorValue(descriptors, "version"), label);
  if (descriptorValue(descriptors, "kind") !== kind) {
    throw transactionError(`${label}_kind_invalid`);
  }
  return objectFreeze({
    transaction_ref: assertRef(
      descriptorValue(descriptors, "transaction_ref"),
      `${label}_transaction`,
    ),
    execution_lineage_digest: assertDigest(
      descriptorValue(descriptors, "execution_lineage_digest"),
      `${label}_execution_lineage`,
    ),
    transaction_key_digest: assertDigest(
      descriptorValue(descriptors, "transaction_key_digest"),
      `${label}_transaction_key`,
    ),
    composite_binding_digest: assertDigest(
      descriptorValue(descriptors, "composite_binding_digest"),
      `${label}_composite_binding`,
    ),
  });
}

function claimOrReadPhysicalExecutionTransaction(owner, input) {
  return withOwnerOperation(owner, "claim_or_read", (state) => {
    const label = "physical_execution_transaction_claim";
    const descriptors = assertExactDataObject(input, CLAIM_QUERY_FIELDS, [], label);
    assertVersion(descriptorValue(descriptors, "version"), label);
    if (descriptorValue(descriptors, "kind") !== label) {
      throw transactionError(`${label}_kind_invalid`);
    }
    const binding = normalizePhysicalExecutionCompositeBinding(
      descriptorValue(descriptors, "binding"),
    );
    let transaction = getMap(state.transactions_by_ref, binding.transaction_ref);
    const lineageOwner = getMap(
      state.lineage_to_transaction_ref,
      binding.execution_lineage_digest,
    );
    const transactionKeyOwner = getMap(
      state.transaction_key_to_transaction_ref,
      binding.transaction_key_digest,
    );
    if (transaction !== undefined) {
      assertTransactionBinding(
        transaction,
        binding.transaction_ref,
        binding.execution_lineage_digest,
        binding.transaction_key_digest,
        binding.composite_binding_digest,
      );
      return transaction.claim_receipt;
    }
    if (lineageOwner !== undefined) {
      throw transactionError("physical_execution_transaction_lineage_fork");
    }
    if (transactionKeyOwner !== undefined) {
      throw transactionError("physical_execution_transaction_key_fork");
    }
    if (state.transaction_count >= state.config.maximum_transactions) {
      throw transactionError("physical_execution_transaction_owner_capacity_exhausted");
    }
    const record = makeInitialRecord(binding);
    const claimReceipt = makeClaimReceipt(binding, record);
    transaction = {
      binding,
      head: record,
      records_by_digest: new MapConstructor(),
      receipts_by_record_digest: new MapConstructor(),
      claim_receipt: claimReceipt,
      terminal_outbox: null,
    };
    setMap(transaction.records_by_digest, record.record_digest, record);
    setMap(state.transactions_by_ref, binding.transaction_ref, transaction);
    setMap(
      state.lineage_to_transaction_ref,
      binding.execution_lineage_digest,
      binding.transaction_ref,
    );
    setMap(
      state.transaction_key_to_transaction_ref,
      binding.transaction_key_digest,
      binding.transaction_ref,
    );
    state.transaction_count += 1;
    if (state.claim_response_loss_pending) {
      state.claim_response_loss_pending = false;
      throw transactionError("physical_execution_transaction_claim_response_lost");
    }
    return claimReceipt;
  });
}

function readPhysicalExecutionTransaction(owner, input) {
  return withOwnerOperation(owner, "read", (state) => {
    const query = normalizeReadQuery(input, "physical_execution_transaction_read");
    const transaction = getMap(state.transactions_by_ref, query.transaction_ref);
    if (transaction === undefined) {
      throw transactionError("physical_execution_transaction_not_found");
    }
    assertTransactionBinding(
      transaction,
      query.transaction_ref,
      query.execution_lineage_digest,
      query.transaction_key_digest,
      query.composite_binding_digest,
    );
    return transaction.head;
  });
}

function normalizeTransitionQuery(input) {
  const label = "physical_execution_transaction_transition";
  const descriptors = assertExactDataObject(input, TRANSITION_QUERY_FIELDS, [], label);
  assertVersion(descriptorValue(descriptors, "version"), label);
  if (descriptorValue(descriptors, "kind") !== label) {
    throw transactionError(`${label}_kind_invalid`);
  }
  return objectFreeze({
    transaction_ref: assertRef(
      descriptorValue(descriptors, "transaction_ref"),
      `${label}_transaction`,
    ),
    execution_lineage_digest: assertDigest(
      descriptorValue(descriptors, "execution_lineage_digest"),
      `${label}_execution_lineage`,
    ),
    transaction_key_digest: assertDigest(
      descriptorValue(descriptors, "transaction_key_digest"),
      `${label}_transaction_key`,
    ),
    composite_binding_digest: assertDigest(
      descriptorValue(descriptors, "composite_binding_digest"),
      `${label}_composite_binding`,
    ),
    expected_generation: assertSafeInteger(
      descriptorValue(descriptors, "expected_generation"),
      `${label}_expected_generation`,
      1,
    ),
    expected_predecessor_record_digest: assertDigest(
      descriptorValue(descriptors, "expected_predecessor_record_digest"),
      `${label}_expected_predecessor_record`,
    ),
    next_record: normalizePhysicalExecutionTransactionRecordWithLabel(
      descriptorValue(descriptors, "next_record"),
      `${label}_next_record`,
    ),
  });
}

function transitionPhysicalExecutionTransaction(owner, input) {
  return withOwnerOperation(owner, "transition", (state) => {
    const query = normalizeTransitionQuery(input);
    const transaction = getMap(state.transactions_by_ref, query.transaction_ref);
    if (transaction === undefined) {
      throw transactionError("physical_execution_transaction_not_found");
    }
    assertTransactionBinding(
      transaction,
      query.transaction_ref,
      query.execution_lineage_digest,
      query.transaction_key_digest,
      query.composite_binding_digest,
    );
    const proposed = query.next_record;
    assertTransactionBinding(
      transaction,
      proposed.transaction_ref,
      proposed.execution_lineage_digest,
      proposed.transaction_key_digest,
      proposed.composite_binding_digest,
    );
    const exactReceipt = getMap(transaction.receipts_by_record_digest, proposed.record_digest);
    if (exactReceipt !== undefined) {
      if (proposed.generation !== query.expected_generation + 1
          || proposed.predecessor_record_digest !== query.expected_predecessor_record_digest) {
        throw transactionError("physical_execution_transaction_replay_expectation_mismatch");
      }
      return exactReceipt;
    }
    if (query.expected_generation !== transaction.head.generation
        || query.expected_predecessor_record_digest !== transaction.head.record_digest) {
      if (query.expected_generation === transaction.head.generation) {
        throw transactionError("physical_execution_transaction_expected_digest_fork");
      }
      throw transactionError("physical_execution_transaction_cas_conflict");
    }
    const normalized = assertPhysicalExecutionTransactionTransition(transaction.head, proposed);
    let outbox = null;
    if (normalized.phase === "TERMINAL") {
      outbox = createTerminalOutbox(normalized);
    }
    const receipt = makeTransitionReceipt(normalized, outbox);
    transaction.head = normalized;
    setMap(transaction.records_by_digest, normalized.record_digest, normalized);
    setMap(transaction.receipts_by_record_digest, normalized.record_digest, receipt);
    if (outbox !== null) transaction.terminal_outbox = outbox;
    if (state.transition_response_loss_pending
        && normalized.generation === state.config.simulate_transition_response_loss_generation) {
      state.transition_response_loss_pending = false;
      throw transactionError("physical_execution_transaction_transition_response_lost");
    }
    return receipt;
  });
}

function normalizeOutboxQuery(input) {
  const label = "physical_execution_terminal_outbox_read";
  const descriptors = assertExactDataObject(input, OUTBOX_QUERY_FIELDS, [], label);
  assertVersion(descriptorValue(descriptors, "version"), label);
  if (descriptorValue(descriptors, "kind") !== label) {
    throw transactionError(`${label}_kind_invalid`);
  }
  return objectFreeze({
    transaction_ref: assertRef(
      descriptorValue(descriptors, "transaction_ref"),
      `${label}_transaction`,
    ),
    execution_lineage_digest: assertDigest(
      descriptorValue(descriptors, "execution_lineage_digest"),
      `${label}_execution_lineage`,
    ),
    transaction_key_digest: assertDigest(
      descriptorValue(descriptors, "transaction_key_digest"),
      `${label}_transaction_key`,
    ),
    composite_binding_digest: assertDigest(
      descriptorValue(descriptors, "composite_binding_digest"),
      `${label}_composite_binding`,
    ),
    outbox_ref: assertRef(descriptorValue(descriptors, "outbox_ref"), `${label}_outbox`),
    outbox_digest: assertDigest(
      descriptorValue(descriptors, "outbox_digest"),
      `${label}_outbox`,
    ),
  });
}

function readOutboxFromState(state, input) {
  const query = normalizeOutboxQuery(input);
  const transaction = getMap(state.transactions_by_ref, query.transaction_ref);
  if (transaction === undefined || transaction.terminal_outbox === null) {
    throw transactionError("physical_execution_terminal_outbox_not_found");
  }
  assertTransactionBinding(
    transaction,
    query.transaction_ref,
    query.execution_lineage_digest,
    query.transaction_key_digest,
    query.composite_binding_digest,
  );
  const outbox = transaction.terminal_outbox;
  if (outbox.outbox_ref !== query.outbox_ref || outbox.outbox_digest !== query.outbox_digest) {
    throw transactionError("physical_execution_terminal_outbox_identity_mismatch");
  }
  return outbox;
}

function readPhysicalExecutionTerminalOutbox(owner, input) {
  return withOwnerOperation(owner, "read_terminal_outbox", (state) => (
    readOutboxFromState(state, input)
  ));
}

function redeliverPhysicalExecutionTerminalOutbox(owner, input) {
  return withOwnerOperation(owner, "redeliver_terminal_outbox", (state) => {
    const outbox = readOutboxFromState(state, input);
    if (state.outbox_response_loss_pending) {
      state.outbox_response_loss_pending = false;
      throw transactionError("physical_execution_terminal_outbox_response_lost");
    }
    return outbox;
  });
}

function physicalExecutionTransactionOwnerReadiness(owner) {
  const state = ownerState(owner);
  const value = {
    version: PHYSICAL_EXECUTION_TRANSACTION_OWNER_VERSION,
    kind: "physical_execution_transaction_owner_readiness",
    owner_ref: owner.owner_ref,
    owner_configuration_digest: owner.owner_configuration_digest,
    assurance: PHYSICAL_EXECUTION_TRANSACTION_OWNER_ASSURANCE,
    maximum_transactions: owner.maximum_transactions,
    transaction_count: state.transaction_count,
    remaining_transaction_capacity: owner.maximum_transactions - state.transaction_count,
    durability_attested: false,
    production_ready: false,
    hardware_access_authorized: false,
    execution_authority: false,
    blockers: PRODUCTION_BLOCKERS,
  };
  return objectFreeze({ ...value, readiness_digest: hashCanonicalJson(value) });
}

function assertPhysicalExecutionTransactionOwnerProductionReady(owner) {
  assertPhysicalExecutionTransactionOwner(owner);
  throw transactionError("physical_execution_transaction_owner_production_unavailable");
}

module.exports = objectFreeze({
  PHYSICAL_EXECUTION_TRANSACTION_OWNER_ASSURANCE,
  PHYSICAL_EXECUTION_TRANSACTION_OWNER_VERSION,
  PHYSICAL_EXECUTION_TRANSACTION_PHASES,
  PHYSICAL_EXECUTION_TRANSACTION_PROTOCOL,
  PHYSICAL_EXECUTION_TRANSACTION_RECORD_ASSURANCE,
  PRODUCTION_BLOCKERS,
  assertPhysicalExecutionTransactionOwner,
  assertPhysicalExecutionTransactionOwnerProductionReady,
  assertPhysicalExecutionTransactionPhaseSuccessor,
  assertPhysicalExecutionTransactionTransition,
  claimOrReadPhysicalExecutionTransaction,
  createPhysicalExecutionTransactionConformanceOwner,
  derivePhysicalExecutionTransactionRecovery,
  normalizePhysicalExecutionCompositeBinding,
  normalizePhysicalExecutionTransactionRecord,
  physicalExecutionTransactionOwnerReadiness,
  readPhysicalExecutionTerminalOutbox,
  readPhysicalExecutionTransaction,
  redeliverPhysicalExecutionTerminalOutbox,
  transitionPhysicalExecutionTransaction,
});
