"use strict";

// Worker-owned orchestration seam for the closed HF14A active-field probe.
// "RF-off" in this fixture name describes the required terminal field policy,
// never an effectless/HIL stage: the compiled command transmits RF to target.
// deliberately hardware-inert on import. Its only public constructor is a
// fixture/conformance port; a qualified native package must eventually own the
// same open/configure/write/read/close, raw-custody, field-off-witness, and
// durable-exchange contract without promoting these callbacks.

const crypto = require("node:crypto");
const { types: utilTypes } = require("node:util");

const {
  assertCompiledHf14aProviderCommand,
  claimCompiledHf14aProviderCommand,
} = require("./hf14a-probe-compiler.js");
const {
  assertNoPublicByteMaterial,
  hashCanonicalJson,
} = require("./closed-runtime-contracts.js");

const RF_OFF_USB_EXECUTION_PORT_VERSION = 1;
const PROVIDER_ID = "chameleon_ultra";
const TRANSPORT_KIND = "usb_cdc";
const TERMINAL_KIND = "chameleon_hf14a_probe_terminal";
const EXCHANGE_STATES = Object.freeze(["prepared", "terminal", "acknowledged"]);
const EFFECT_ADMISSION_PHASES = Object.freeze(["pre_open", "pre_transact"]);
const SHA256_PATTERN = /^[a-f0-9]{64}$/u;
const TOKEN_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:@-]{0,190}$/u;
const PORTS = new WeakSet();
const PORT_STATE = new WeakMap();
const EFFECT_ADMISSION_PORTS = new WeakSet();
const EFFECT_ADMISSION_STATE = new WeakMap();

const BINDING_FIELDS = Object.freeze([
  "version",
  "provider_id",
  "transport_kind",
  "transport_variant",
  "session_id",
  "session_nucleus_hash",
  "lease_id",
  "resource_ref",
  "reservation_fencing_token_hash",
  "authority_fencing_token_digest",
  "fencing_generation",
  "provider_descriptor_digest",
  "device_ref",
  "device_identity_digest",
  "custody_ref",
  "custody_identity_digest",
  "custody_epoch",
  "endpoint_identity_digest",
  "worker_bundle_digest",
  "worker_launch_profile_digest",
  "worker_fence_plan_digest",
  "transport_profile_digest",
  "durable_exchange_plan_digest",
  "terminal_receipt_recipient_digest",
  "vault_reservation_handle",
  "vault_reservation_digest",
  "vault_ingest_capability_digest",
  "vault_byte_limit",
  "dtr_control_model",
  "rf_field_witness_model",
]);

const REQUEST_FIELDS = Object.freeze([
  "version",
  "kind",
  "execution_binding_digest",
  "authority_claim_digest",
  "execution_lineage_digest",
  "attempt_ref",
  "operation_id",
  "requested_effects_digest",
  "safety_supervisor_plan_digest",
  "availability_evidence_digest",
  "availability_variant_digest",
  "execution_claim_receipt_digest",
  "deadline_fence_receipt_digest",
  "effect_deadline",
  "compiled_command",
]);

const RECOVERY_FIELDS = Object.freeze([
  "version",
  "kind",
  "execution_binding_digest",
  "authority_claim_digest",
  "execution_lineage_digest",
  "attempt_ref",
  "operation_id",
  "requested_effects_digest",
  "safety_supervisor_plan_digest",
  "availability_evidence_digest",
  "availability_variant_digest",
  "execution_claim_receipt_digest",
  "deadline_fence_receipt_digest",
  "effect_deadline",
  "compiled_command_id",
  "compiled_command_capability_digest",
  "compiled_operation_digest",
  "prepared_request_digest",
]);

const PREPARED_FIELDS = Object.freeze([
  "version",
  "kind",
  "execution_binding_digest",
  "authority_claim_digest",
  "execution_lineage_digest",
  "attempt_ref",
  "operation_id",
  "requested_effects_digest",
  "safety_supervisor_plan_digest",
  "availability_evidence_digest",
  "availability_variant_digest",
  "execution_claim_receipt_digest",
  "deadline_fence_receipt_digest",
  "effect_deadline",
  "compiled_command_id",
  "compiled_command_capability_digest",
  "compiled_operation_digest",
  "prepared_receipt_digest",
]);

const TERMINAL_CORE_FIELDS = Object.freeze([
  ...PREPARED_FIELDS.slice(0, -1),
  "prepared_receipt_digest",
  "terminal_state",
  "artifact_handle",
  "response_digest",
  "response_byte_length",
  "vault_commit_receipt_digest",
  "raw_custody_receipt_digest",
  "endpoint_identity_digest",
  "inventory_before_digest",
  "inventory_after_digest",
  "pre_open_admission_receipt_digest",
  "pre_transact_admission_receipt_digest",
  "dtr_before_open_asserted",
  "dtr_during_exchange_asserted",
  "dtr_after_close_asserted",
  "rf_field_before",
  "rf_field_after",
  "transport_closed",
  "terminal_rf_off_witness_digest",
  "no_active_effects_witness_digest",
  "dtr_off_qualified",
  "rf_off_qualified",
  "raw_response_bytes_projected",
  "production_ready",
  "hil_verified",
  "qualification_blocker_code",
  "terminal_witness_digest",
]);

const EFFECT_ADMISSION_RESULT_FIELDS = Object.freeze([
  "version",
  "kind",
  "phase",
  "execution_binding_digest",
  "prepared_request_digest",
  "execution_request_digest",
  "authority_claim_digest",
  "availability_evidence_digest",
  "deadline_fence_receipt_digest",
  "reservation_receipt_digest",
  "effect_authorization_digest",
  "authorized",
  "effect_admission_receipt_digest",
]);

const TERMINAL_FIELDS = Object.freeze([
  ...TERMINAL_CORE_FIELDS,
  "durable_receipt_digest",
  "outbox_record_digest",
  "outbox_delivery_state",
  "outbox_ack_digest",
]);

function executionError(code, message = code, cause = null) {
  const error = new Error(message);
  error.code = code;
  if (cause != null) Object.defineProperty(error, "cause", { value: cause });
  return error;
}

function isPlainObject(value) {
  if (value == null || typeof value !== "object" || Array.isArray(value)
      || utilTypes.isProxy(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactObject(value, label, fields) {
  if (!isPlainObject(value)) throw executionError("rf_off_usb_contract_invalid", `${label} must be an exact object`);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Reflect.ownKeys(descriptors);
  const expected = [...fields].sort();
  const actual = [...keys].sort();
  if (keys.some((key) => typeof key !== "string") || actual.length !== expected.length
      || actual.some((key, index) => key !== expected[index])) {
    throw executionError("rf_off_usb_contract_invalid", `${label} fields are not exact`);
  }
  const output = {};
  for (const field of fields) {
    const descriptor = descriptors[field];
    if (!descriptor || !Object.prototype.hasOwnProperty.call(descriptor, "value")
        || descriptor.enumerable !== true) {
      throw executionError("rf_off_usb_contract_invalid", `${label}.${field} must be an enumerable data field`);
    }
    output[field] = descriptor.value;
  }
  return output;
}

function digest(value, label) {
  if (typeof value !== "string" || !SHA256_PATTERN.test(value)) {
    throw executionError("rf_off_usb_contract_invalid", `${label} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function token(value, label) {
  if (typeof value !== "string" || !TOKEN_PATTERN.test(value)) {
    throw executionError("rf_off_usb_contract_invalid", `${label} must be a bounded token`);
  }
  return value;
}

function integer(value, label, minimum = 0, maximum = Number.MAX_SAFE_INTEGER) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw executionError("rf_off_usb_contract_invalid", `${label} is outside its integer bounds`);
  }
  return value;
}

function timestamp(value, label) {
  if (typeof value !== "string" || Number.isNaN(Date.parse(value))
      || new Date(value).toISOString() !== value) {
    throw executionError("rf_off_usb_contract_invalid", `${label} must be a canonical UTC timestamp`);
  }
  return value;
}

function nullRecord(input) {
  const output = Object.create(null);
  for (const [field, value] of Object.entries(input)) {
    Object.defineProperty(output, field, {
      value,
      enumerable: true,
      configurable: false,
      writable: false,
    });
  }
  return Object.freeze(output);
}

function normalizeBinding(input) {
  const value = exactObject(input, "rf_off_usb_execution_port.binding", BINDING_FIELDS);
  if (value.version !== RF_OFF_USB_EXECUTION_PORT_VERSION
      || value.provider_id !== PROVIDER_ID || value.transport_kind !== TRANSPORT_KIND) {
    throw executionError("rf_off_usb_binding_drift", "worker binding is not the closed Chameleon USB contract");
  }
  if (value.transport_variant !== "fixture_conformance"
      && value.transport_variant !== "current_custody_asserted_dtr") {
    throw executionError("rf_off_usb_transport_unqualified", "worker transport variant is not enrolled");
  }
  if (!["fixture_callback_unattested", "asserted_after_activation"].includes(value.dtr_control_model)) {
    throw executionError("rf_off_usb_dtr_model_invalid", "worker DTR model is not closed");
  }
  if (value.rf_field_witness_model !== "fixture_callback_unattested") {
    throw executionError("rf_off_usb_field_witness_unqualified", "no qualified independent RF-field witness is enrolled");
  }
  const normalized = {
    version: RF_OFF_USB_EXECUTION_PORT_VERSION,
    provider_id: PROVIDER_ID,
    transport_kind: TRANSPORT_KIND,
    transport_variant: value.transport_variant,
    session_id: token(value.session_id, "binding.session_id"),
    session_nucleus_hash: digest(value.session_nucleus_hash, "binding.session_nucleus_hash"),
    lease_id: token(value.lease_id, "binding.lease_id"),
    resource_ref: token(value.resource_ref, "binding.resource_ref"),
    reservation_fencing_token_hash: digest(value.reservation_fencing_token_hash, "binding.reservation_fencing_token_hash"),
    authority_fencing_token_digest: digest(value.authority_fencing_token_digest, "binding.authority_fencing_token_digest"),
    fencing_generation: integer(value.fencing_generation, "binding.fencing_generation", 1),
    provider_descriptor_digest: digest(value.provider_descriptor_digest, "binding.provider_descriptor_digest"),
    device_ref: token(value.device_ref, "binding.device_ref"),
    device_identity_digest: digest(value.device_identity_digest, "binding.device_identity_digest"),
    custody_ref: token(value.custody_ref, "binding.custody_ref"),
    custody_identity_digest: digest(value.custody_identity_digest, "binding.custody_identity_digest"),
    custody_epoch: integer(value.custody_epoch, "binding.custody_epoch", 1),
    endpoint_identity_digest: digest(value.endpoint_identity_digest, "binding.endpoint_identity_digest"),
    worker_bundle_digest: digest(value.worker_bundle_digest, "binding.worker_bundle_digest"),
    worker_launch_profile_digest: digest(value.worker_launch_profile_digest, "binding.worker_launch_profile_digest"),
    worker_fence_plan_digest: digest(value.worker_fence_plan_digest, "binding.worker_fence_plan_digest"),
    transport_profile_digest: digest(value.transport_profile_digest, "binding.transport_profile_digest"),
    durable_exchange_plan_digest: digest(value.durable_exchange_plan_digest, "binding.durable_exchange_plan_digest"),
    terminal_receipt_recipient_digest: digest(value.terminal_receipt_recipient_digest, "binding.terminal_receipt_recipient_digest"),
    vault_reservation_handle: token(value.vault_reservation_handle, "binding.vault_reservation_handle"),
    vault_reservation_digest: digest(value.vault_reservation_digest, "binding.vault_reservation_digest"),
    vault_ingest_capability_digest: digest(value.vault_ingest_capability_digest, "binding.vault_ingest_capability_digest"),
    vault_byte_limit: integer(value.vault_byte_limit, "binding.vault_byte_limit", 1, 16 * 1024),
    dtr_control_model: value.dtr_control_model,
    rf_field_witness_model: value.rf_field_witness_model,
  };
  return Object.freeze(normalized);
}

function providerDescriptorDigest(input) {
  const value = normalizeBinding({ ...input, provider_descriptor_digest: "0".repeat(64) });
  const basis = { ...value };
  delete basis.provider_descriptor_digest;
  return hashCanonicalJson({
    domain: "hacker-bob/chameleon-rf-off-usb-provider-descriptor/v1",
    ...basis,
  });
}

function normalizeRequest(input, binding, portState = null) {
  const value = exactObject(input, "rf_off_usb_execution_request", REQUEST_FIELDS);
  if (value.version !== RF_OFF_USB_EXECUTION_PORT_VERSION
      || value.kind !== "chameleon_hf14a_probe_execution_request") {
    throw executionError("rf_off_usb_contract_invalid", "worker execution request kind/version drifted");
  }
  const command = portState != null && portState.command === value.compiled_command
    ? value.compiled_command
    : assertCompiledHf14aProviderCommand(value.compiled_command);
  if (command.provider_id !== PROVIDER_ID || command.operation_id !== value.operation_id
      || command.maximum_response_bytes > binding.vault_byte_limit) {
    throw executionError("rf_off_usb_compiled_command_drift", "compiled command is cross-wired to the worker binding");
  }
  return Object.freeze({
    version: RF_OFF_USB_EXECUTION_PORT_VERSION,
    kind: value.kind,
    execution_binding_digest: digest(value.execution_binding_digest, "request.execution_binding_digest"),
    authority_claim_digest: digest(value.authority_claim_digest, "request.authority_claim_digest"),
    execution_lineage_digest: digest(value.execution_lineage_digest, "request.execution_lineage_digest"),
    attempt_ref: token(value.attempt_ref, "request.attempt_ref"),
    operation_id: token(value.operation_id, "request.operation_id"),
    requested_effects_digest: digest(value.requested_effects_digest, "request.requested_effects_digest"),
    safety_supervisor_plan_digest: digest(value.safety_supervisor_plan_digest, "request.safety_supervisor_plan_digest"),
    availability_evidence_digest: digest(value.availability_evidence_digest, "request.availability_evidence_digest"),
    availability_variant_digest: digest(value.availability_variant_digest, "request.availability_variant_digest"),
    execution_claim_receipt_digest: digest(value.execution_claim_receipt_digest, "request.execution_claim_receipt_digest"),
    deadline_fence_receipt_digest: digest(value.deadline_fence_receipt_digest, "request.deadline_fence_receipt_digest"),
    effect_deadline: timestamp(value.effect_deadline, "request.effect_deadline"),
    compiled_command: command,
  });
}

function preparedBasis(request) {
  const command = request.compiled_command;
  return {
    version: RF_OFF_USB_EXECUTION_PORT_VERSION,
    kind: "chameleon_hf14a_probe_prepared",
    execution_binding_digest: request.execution_binding_digest,
    authority_claim_digest: request.authority_claim_digest,
    execution_lineage_digest: request.execution_lineage_digest,
    attempt_ref: request.attempt_ref,
    operation_id: request.operation_id,
    requested_effects_digest: request.requested_effects_digest,
    safety_supervisor_plan_digest: request.safety_supervisor_plan_digest,
    availability_evidence_digest: request.availability_evidence_digest,
    availability_variant_digest: request.availability_variant_digest,
    execution_claim_receipt_digest: request.execution_claim_receipt_digest,
    deadline_fence_receipt_digest: request.deadline_fence_receipt_digest,
    effect_deadline: request.effect_deadline,
    compiled_command_id: command.compiled_command_id,
    compiled_command_capability_digest: command.compiled_command_capability_digest,
    compiled_operation_digest: command.compiled_operation_digest,
  };
}

function executionRequestDigest(executionBindingDigestInput, preparedRequestDigestInput) {
  const executionBindingDigest = digest(
    executionBindingDigestInput,
    "effect_admission.execution_binding_digest",
  );
  const preparedRequestDigest = digest(
    preparedRequestDigestInput,
    "effect_admission.prepared_request_digest",
  );
  return hashCanonicalJson({
    domain: "hacker-bob/chameleon-rf-off-usb-execution-request/v1",
    execution_binding_digest: executionBindingDigest,
    prepared_request_digest: preparedRequestDigest,
  });
}

function normalizePrepared(input, request) {
  const value = exactObject(input, "rf_off_usb_prepared_record", PREPARED_FIELDS);
  const expected = preparedBasis(request);
  for (const field of Object.keys(expected)) {
    if (value[field] !== expected[field]) {
      throw executionError("rf_off_usb_durable_exchange_crosswired", `prepared ${field} drifted`);
    }
  }
  const preparedReceiptDigest = digest(value.prepared_receipt_digest, "prepared.prepared_receipt_digest");
  if (preparedReceiptDigest !== hashCanonicalJson({
    domain: "hacker-bob/chameleon-rf-off-usb-prepared-receipt/v1",
    ...expected,
  })) {
    throw executionError("rf_off_usb_durable_exchange_crosswired", "prepared receipt digest drifted");
  }
  return nullRecord({ ...expected, prepared_receipt_digest: preparedReceiptDigest });
}

function normalizeInventoryObservation(input, label, binding) {
  const value = exactObject(input, label, [
    "inventory_digest",
    "endpoint_identity_digest",
    "dtr_asserted",
    "rf_field_state",
    "field_witness_digest",
  ]);
  if (value.endpoint_identity_digest !== binding.endpoint_identity_digest) {
    throw executionError("rf_off_usb_endpoint_crosswired", `${label} endpoint drifted`);
  }
  if (typeof value.dtr_asserted !== "boolean" || !["off", "on", "unknown"].includes(value.rf_field_state)) {
    throw executionError("rf_off_usb_witness_invalid", `${label} witness fields are invalid`);
  }
  return Object.freeze({
    inventory_digest: digest(value.inventory_digest, `${label}.inventory_digest`),
    endpoint_identity_digest: binding.endpoint_identity_digest,
    dtr_asserted: value.dtr_asserted,
    rf_field_state: value.rf_field_state,
    field_witness_digest: digest(value.field_witness_digest, `${label}.field_witness_digest`),
  });
}

function normalizeOpen(input, binding) {
  const value = exactObject(input, "rf_off_usb_open_result", [
    "opened", "endpoint_identity_digest", "dtr_asserted",
  ]);
  if (value.opened !== true || value.endpoint_identity_digest !== binding.endpoint_identity_digest
      || typeof value.dtr_asserted !== "boolean") {
    throw executionError("rf_off_usb_open_unconfirmed", "USB open result is not exact");
  }
  return Object.freeze(value);
}

function normalizeConfigure(input, binding) {
  const value = exactObject(input, "rf_off_usb_configure_result", [
    "configured", "endpoint_identity_digest", "dtr_asserted",
  ]);
  if (value.configured !== true || value.endpoint_identity_digest !== binding.endpoint_identity_digest
      || typeof value.dtr_asserted !== "boolean") {
    throw executionError("rf_off_usb_configure_unconfirmed", "USB configuration result is not exact");
  }
  return Object.freeze(value);
}

function scrub(value) {
  try {
    if (Buffer.isBuffer(value) || value instanceof Uint8Array) value.fill(0);
  } catch {}
}

function rawResponse(input, maximum) {
  let transferred = null;
  let copied = null;
  try {
    const value = exactObject(input, "rf_off_usb_transaction_result", ["response_bytes"]);
    transferred = value.response_bytes;
    if (!Buffer.isBuffer(transferred) && !(transferred instanceof Uint8Array)) {
      throw executionError("rf_off_usb_response_invalid", "transport response must be private bytes");
    }
    if (transferred.byteLength < 1 || transferred.byteLength > maximum) {
      throw executionError("rf_off_usb_response_oversize", "transport response exceeds its signed ceiling");
    }
    copied = Buffer.from(transferred);
    return copied;
  } finally {
    scrub(transferred);
  }
}

function normalizeArtifactReceipt(input, expectedResponse, binding) {
  const value = exactObject(input, "rf_off_usb_artifact_receipt", [
    "artifact_handle",
    "response_digest",
    "response_byte_length",
    "vault_commit_receipt_digest",
    "raw_custody_receipt_digest",
    "vault_reservation_digest",
    "vault_ingest_capability_digest",
  ]);
  if (value.response_digest !== expectedResponse.response_digest
      || value.response_byte_length !== expectedResponse.response_byte_length
      || value.vault_reservation_digest !== binding.vault_reservation_digest
      || value.vault_ingest_capability_digest !== binding.vault_ingest_capability_digest) {
    throw executionError("rf_off_usb_artifact_commit_crosswired", "artifact receipt drifted from private response custody");
  }
  return Object.freeze({
    artifact_handle: token(value.artifact_handle, "artifact_receipt.artifact_handle"),
    response_digest: expectedResponse.response_digest,
    response_byte_length: integer(value.response_byte_length, "artifact_receipt.response_byte_length", 1, binding.vault_byte_limit),
    vault_commit_receipt_digest: digest(value.vault_commit_receipt_digest, "artifact_receipt.vault_commit_receipt_digest"),
    raw_custody_receipt_digest: digest(value.raw_custody_receipt_digest, "artifact_receipt.raw_custody_receipt_digest"),
  });
}

function assertArtifactResponseUnchanged(response, expectedResponse) {
  let observedDigest;
  let observedLength;
  try {
    observedLength = response.length;
    observedDigest = crypto.createHash("sha256").update(response).digest("hex");
  } catch (cause) {
    throw executionError(
      "rf_off_usb_artifact_commit_crosswired",
      "artifact callback invalidated private response custody",
      cause,
    );
  }
  if (observedDigest !== expectedResponse.response_digest
      || observedLength !== expectedResponse.response_byte_length) {
    throw executionError(
      "rf_off_usb_artifact_commit_crosswired",
      "artifact callback mutated private response custody",
    );
  }
}

function normalizeClose(input, binding) {
  const value = exactObject(input, "rf_off_usb_close_result", [
    "closed",
    "endpoint_identity_digest",
    "dtr_asserted",
    "rf_field_state",
    "terminal_rf_off_witness_digest",
    "no_active_effects_witness_digest",
    "witness_qualified",
  ]);
  if (value.closed !== true || value.endpoint_identity_digest !== binding.endpoint_identity_digest
      || typeof value.dtr_asserted !== "boolean" || value.rf_field_state !== "off"
      || typeof value.witness_qualified !== "boolean") {
    throw executionError("rf_off_usb_terminal_state_unconfirmed", "terminal close/RF state is not exact");
  }
  return Object.freeze({
    ...value,
    terminal_rf_off_witness_digest: digest(value.terminal_rf_off_witness_digest, "close.terminal_rf_off_witness_digest"),
    no_active_effects_witness_digest: digest(value.no_active_effects_witness_digest, "close.no_active_effects_witness_digest"),
  });
}

function terminalCore(
  prepared,
  artifact,
  before,
  configured,
  after,
  closed,
  preOpenAdmission,
  preTransactAdmission,
  binding,
) {
  // The fixture witness is useful for orchestration assertions only. Even a
  // callback that reports RF=off and DTR=false cannot qualify the physical
  // claim. Current custody is additionally truthful about asserted DTR.
  const dtrOff = before.dtr_asserted === false
    && configured.dtr_asserted === false && closed.dtr_asserted === false;
  const blocker = binding.dtr_control_model === "asserted_after_activation"
    ? "current_usb_custody_dtr_asserted"
    : "independent_rf_field_off_native_witness_missing";
  const basis = {
    ...Object.fromEntries(PREPARED_FIELDS.slice(0, -1).map((field) => [field, prepared[field]])),
    kind: TERMINAL_KIND,
    prepared_receipt_digest: prepared.prepared_receipt_digest,
    terminal_state: "completed",
    artifact_handle: artifact.artifact_handle,
    response_digest: artifact.response_digest,
    response_byte_length: artifact.response_byte_length,
    vault_commit_receipt_digest: artifact.vault_commit_receipt_digest,
    raw_custody_receipt_digest: artifact.raw_custody_receipt_digest,
    endpoint_identity_digest: binding.endpoint_identity_digest,
    inventory_before_digest: before.inventory_digest,
    inventory_after_digest: after.inventory_digest,
    pre_open_admission_receipt_digest: preOpenAdmission.effect_admission_receipt_digest,
    pre_transact_admission_receipt_digest: preTransactAdmission.effect_admission_receipt_digest,
    dtr_before_open_asserted: before.dtr_asserted,
    dtr_during_exchange_asserted: configured.dtr_asserted,
    dtr_after_close_asserted: closed.dtr_asserted,
    rf_field_before: before.rf_field_state,
    rf_field_after: after.rf_field_state,
    transport_closed: true,
    terminal_rf_off_witness_digest: closed.terminal_rf_off_witness_digest,
    no_active_effects_witness_digest: closed.no_active_effects_witness_digest,
    dtr_off_qualified: false,
    rf_off_qualified: false,
    raw_response_bytes_projected: false,
    production_ready: false,
    hil_verified: false,
    qualification_blocker_code: blocker,
  };
  // Preserve observed truth separately from qualification. This check prevents
  // a future refactor from silently claiming DTR-off while reporting asserted.
  if (!dtrOff && blocker !== "current_usb_custody_dtr_asserted") {
    basis.qualification_blocker_code = "dtr_off_state_not_observed";
  }
  return nullRecord({
    ...basis,
    terminal_witness_digest: hashCanonicalJson({
      domain: "hacker-bob/chameleon-rf-off-usb-terminal-witness/v1",
      ...basis,
    }),
  });
}

function normalizeTerminal(input, request, binding) {
  const value = exactObject(input, "rf_off_usb_terminal_record", TERMINAL_FIELDS);
  const expectedPrepared = preparedBasis(request);
  for (const field of Object.keys(expectedPrepared).filter((field) => field !== "kind")) {
    if (value[field] !== expectedPrepared[field]) {
      throw executionError("rf_off_usb_durable_exchange_crosswired", `terminal ${field} drifted`);
    }
  }
  for (const field of [
    "prepared_receipt_digest", "artifact_handle", "response_digest",
    "vault_commit_receipt_digest", "raw_custody_receipt_digest",
    "endpoint_identity_digest", "inventory_before_digest", "inventory_after_digest",
    "pre_open_admission_receipt_digest", "pre_transact_admission_receipt_digest",
    "terminal_rf_off_witness_digest", "no_active_effects_witness_digest",
    "terminal_witness_digest", "durable_receipt_digest", "outbox_record_digest",
  ]) {
    if (field === "artifact_handle") token(value[field], `terminal.${field}`);
    else digest(value[field], `terminal.${field}`);
  }
  if (value.outbox_ack_digest != null) digest(value.outbox_ack_digest, "terminal.outbox_ack_digest");
  integer(value.response_byte_length, "terminal.response_byte_length", 1, binding.vault_byte_limit);
  token(value.qualification_blocker_code, "terminal.qualification_blocker_code");
  if (!["off", "on", "unknown"].includes(value.rf_field_before)
      || ![
        "current_usb_custody_dtr_asserted",
        "independent_rf_field_off_native_witness_missing",
        "dtr_off_state_not_observed",
      ].includes(value.qualification_blocker_code)
      || value.kind !== TERMINAL_KIND || value.terminal_state !== "completed"
      || value.transport_closed !== true
      || value.raw_response_bytes_projected !== false || value.production_ready !== false
      || value.hil_verified !== false || value.dtr_off_qualified !== false
      || value.rf_off_qualified !== false || value.rf_field_after !== "off"
      || typeof value.dtr_before_open_asserted !== "boolean"
      || typeof value.dtr_during_exchange_asserted !== "boolean"
      || typeof value.dtr_after_close_asserted !== "boolean"
      || !["pending", "acknowledged"].includes(value.outbox_delivery_state)
      || (value.outbox_delivery_state === "pending" && value.outbox_ack_digest !== null)
      || (value.outbox_delivery_state === "acknowledged" && value.outbox_ack_digest == null)) {
    throw executionError("rf_off_usb_terminal_invalid", "durable terminal record is not fail-closed");
  }
  const core = Object.fromEntries(TERMINAL_CORE_FIELDS.map((field) => [field, value[field]]));
  const witnessBasis = { ...core };
  delete witnessBasis.terminal_witness_digest;
  if (value.terminal_witness_digest !== hashCanonicalJson({
    domain: "hacker-bob/chameleon-rf-off-usb-terminal-witness/v1",
    ...witnessBasis,
  })) {
    throw executionError("rf_off_usb_terminal_invalid", "terminal witness digest drifted");
  }
  const output = nullRecord(Object.fromEntries(TERMINAL_FIELDS.map((field) => [field, value[field]])));
  assertNoPublicByteMaterial(output, "rf_off_usb_terminal_record");
  if (Object.getPrototypeOf(output) !== null) {
    throw executionError("rf_off_usb_public_projection_unsafe", "terminal projection prototype must be null");
  }
  return output;
}

function assertTerminalCoreExact(terminal, core) {
  for (const field of TERMINAL_CORE_FIELDS) {
    if (terminal[field] !== core[field]) {
      throw executionError(
        "rf_off_usb_terminal_commit_crosswired",
        `durable terminal altered worker-owned ${field}`,
      );
    }
  }
  return terminal;
}

function callback(input, field, { synchronous = false } = {}) {
  const value = input[field];
  if (typeof value !== "function" || utilTypes.isProxy(value)) {
    throw executionError("rf_off_usb_contract_invalid", `${field} must be a non-proxy function`);
  }
  if (synchronous && utilTypes.isAsyncFunction(value)) {
    throw executionError("rf_off_usb_contract_invalid", `${field} must be synchronous`);
  }
  return value;
}

function assertSynchronous(value, label) {
  if (utilTypes.isPromise(value) || (value != null && typeof value === "object"
      && typeof Object.getOwnPropertyDescriptor(value, "then")?.value === "function")) {
    throw executionError("rf_off_usb_durable_exchange_async", `${label} must be synchronously durable`);
  }
  return value;
}

function createFixtureRfOffUsbEffectAdmissionPort(input = {}) {
  const value = exactObject(input, "fixture_rf_off_usb_effect_admission_port", [
    "version",
    "port_id",
    "test_only",
    "execution_binding_digest",
    "prepared_request_digest",
    "execution_request_digest",
    "assert_current",
  ]);
  if (value.version !== RF_OFF_USB_EXECUTION_PORT_VERSION || value.test_only !== true) {
    throw executionError(
      "rf_off_usb_effect_admission_fixture_only",
      "same-process RF-off USB effect admission is test-only",
    );
  }
  const executionBindingDigest = digest(
    value.execution_binding_digest,
    "effect_admission.execution_binding_digest",
  );
  const preparedRequestDigest = digest(
    value.prepared_request_digest,
    "effect_admission.prepared_request_digest",
  );
  const expectedExecutionRequestDigest = executionRequestDigest(
    executionBindingDigest,
    preparedRequestDigest,
  );
  if (value.execution_request_digest !== expectedExecutionRequestDigest) {
    throw executionError(
      "rf_off_usb_effect_admission_crosswired",
      "effect admission execution request digest is cross-wired",
    );
  }
  const port = nullRecord({
    version: RF_OFF_USB_EXECUTION_PORT_VERSION,
    kind: "fixture_chameleon_rf_off_usb_effect_admission_port",
    port_id: token(value.port_id, "effect_admission.port_id"),
    execution_binding_digest: executionBindingDigest,
    prepared_request_digest: preparedRequestDigest,
    execution_request_digest: expectedExecutionRequestDigest,
    phase_order_digest: hashCanonicalJson(EFFECT_ADMISSION_PHASES),
    test_only: true,
    production_ready: false,
    hil_verified: false,
  });
  EFFECT_ADMISSION_PORTS.add(port);
  EFFECT_ADMISSION_STATE.set(port, {
    callback: callback(value, "assert_current", { synchronous: true }),
    next_phase_index: 0,
    failed: false,
  });
  return port;
}

function assertEffectAdmissionPort(portInput, workerPort, request) {
  if (!portInput || utilTypes.isProxy(portInput) || !Object.isFrozen(portInput)
      || Object.getPrototypeOf(portInput) !== null || !EFFECT_ADMISSION_PORTS.has(portInput)
      || !EFFECT_ADMISSION_STATE.has(portInput)) {
    throw executionError(
      "rf_off_usb_effect_admission_untrusted",
      "RF-off USB effect execution requires a privately branded admission port",
    );
  }
  const preparedRequestDigest = hashCanonicalJson(preparedBasis(request));
  const expectedExecutionRequestDigest = executionRequestDigest(
    workerPort.execution_binding_digest,
    preparedRequestDigest,
  );
  if (portInput.execution_binding_digest !== workerPort.execution_binding_digest
      || portInput.prepared_request_digest !== preparedRequestDigest
      || portInput.execution_request_digest !== expectedExecutionRequestDigest) {
    throw executionError(
      "rf_off_usb_effect_admission_crosswired",
      "effect admission port belongs to another worker request",
    );
  }
  return portInput;
}

function invokeEffectAdmission(portInput, workerPort, request, phase) {
  const port = assertEffectAdmissionPort(portInput, workerPort, request);
  const state = EFFECT_ADMISSION_STATE.get(port);
  const expectedPhase = EFFECT_ADMISSION_PHASES[state.next_phase_index];
  if (state.failed || expectedPhase !== phase) {
    throw executionError(
      "rf_off_usb_effect_admission_sequence_invalid",
      "effect admission phases must execute exactly once in pre-open/pre-transact order",
    );
  }
  state.next_phase_index += 1;
  const challenge = nullRecord({
    version: RF_OFF_USB_EXECUTION_PORT_VERSION,
    kind: "chameleon_hf14a_probe_effect_admission_challenge",
    phase,
    execution_binding_digest: port.execution_binding_digest,
    prepared_request_digest: port.prepared_request_digest,
    execution_request_digest: port.execution_request_digest,
  });
  try {
    const raw = assertSynchronous(
      state.callback(challenge),
      `RF-off USB ${phase} effect admission`,
    );
    const value = exactObject(
      raw,
      `rf_off_usb_${phase}_effect_admission_result`,
      EFFECT_ADMISSION_RESULT_FIELDS,
    );
    for (const field of [
      "execution_binding_digest",
      "prepared_request_digest",
      "execution_request_digest",
    ]) {
      if (value[field] !== challenge[field]) {
        throw executionError(
          "rf_off_usb_effect_admission_crosswired",
          `${phase} effect admission ${field} drifted`,
        );
      }
    }
    if (value.version !== RF_OFF_USB_EXECUTION_PORT_VERSION
        || value.kind !== "chameleon_hf14a_probe_effect_admission"
        || value.phase !== phase || value.authorized !== true) {
      throw executionError(
        "rf_off_usb_effect_admission_rejected",
        `${phase} effect admission was not exact and affirmative`,
      );
    }
    for (const field of [
      "authority_claim_digest",
      "availability_evidence_digest",
      "deadline_fence_receipt_digest",
      "reservation_receipt_digest",
      "effect_authorization_digest",
      "effect_admission_receipt_digest",
    ]) digest(value[field], `effect_admission.${field}`);
    const receiptBasis = Object.fromEntries(
      EFFECT_ADMISSION_RESULT_FIELDS.slice(0, -1).map((field) => [field, value[field]]),
    );
    if (value.effect_admission_receipt_digest !== hashCanonicalJson({
      domain: "hacker-bob/chameleon-rf-off-usb-effect-admission/v1",
      ...receiptBasis,
    })) {
      throw executionError(
        "rf_off_usb_effect_admission_crosswired",
        `${phase} effect admission receipt digest drifted`,
      );
    }
    return nullRecord(Object.fromEntries(
      EFFECT_ADMISSION_RESULT_FIELDS.map((field) => [field, value[field]]),
    ));
  } catch (cause) {
    state.failed = true;
    if (cause?.code === "rf_off_usb_effect_admission_crosswired"
        || cause?.code === "rf_off_usb_effect_admission_rejected"
        || cause?.code === "rf_off_usb_durable_exchange_async"
        || cause?.code === "rf_off_usb_contract_invalid") throw cause;
    throw executionError(
      "rf_off_usb_effect_admission_rejected",
      `${phase} effect admission recheck failed`,
      cause,
    );
  }
}

function createFixtureRfOffUsbExecutionPort(input = {}) {
  const value = exactObject(input, "fixture_rf_off_usb_execution_port", [
    "version",
    "port_id",
    "test_only",
    "binding",
    "read_exchange",
    "prepare_exchange",
    "commit_terminal",
    "ack_terminal",
    "observe_before",
    "open_transport",
    "configure_transport",
    "transact_transport",
    "commit_artifact_raw_custody",
    "observe_after",
    "close_transport",
  ]);
  if (value.version !== RF_OFF_USB_EXECUTION_PORT_VERSION || value.test_only !== true) {
    throw executionError("rf_off_usb_fixture_only", "RF-off USB callback port is test-only");
  }
  const binding = normalizeBinding(value.binding);
  const expectedProviderDescriptor = providerDescriptorDigest(binding);
  if (binding.provider_descriptor_digest !== expectedProviderDescriptor) {
    throw executionError("rf_off_usb_provider_descriptor_drift", "provider descriptor does not bind the exact worker/device/custody/session/lease/resource/vault tuple");
  }
  const portId = token(value.port_id, "fixture_rf_off_usb_execution_port.port_id");
  const publicBasis = {
    version: RF_OFF_USB_EXECUTION_PORT_VERSION,
    kind: "fixture_chameleon_rf_off_usb_execution_port",
    port_id: portId,
    provider_id: PROVIDER_ID,
    transport_kind: TRANSPORT_KIND,
    provider_descriptor_digest: binding.provider_descriptor_digest,
    execution_binding_digest: hashCanonicalJson({
      domain: "hacker-bob/chameleon-rf-off-usb-execution-port-binding/v1",
      port_id: portId,
      ...binding,
    }),
    test_only: true,
    production_ready: false,
    hil_verified: false,
    dtr_off_qualified: false,
    rf_off_qualified: false,
    raw_response_bytes_projected: false,
    target_rf_transmit: true,
    rf_off_stage_qualified: false,
    qualification_blocker_code: binding.dtr_control_model === "asserted_after_activation"
      ? "current_usb_custody_dtr_asserted"
      : "independent_rf_field_off_native_witness_missing",
  };
  const port = nullRecord(publicBasis);
  PORTS.add(port);
  PORT_STATE.set(port, {
    binding,
    callbacks: {
      read: callback(value, "read_exchange", { synchronous: true }),
      prepare: callback(value, "prepare_exchange", { synchronous: true }),
      commit: callback(value, "commit_terminal", { synchronous: true }),
      ack: callback(value, "ack_terminal", { synchronous: true }),
      before: callback(value, "observe_before"),
      open: callback(value, "open_transport"),
      configure: callback(value, "configure_transport"),
      transact: callback(value, "transact_transport"),
      artifact: callback(value, "commit_artifact_raw_custody"),
      after: callback(value, "observe_after"),
      close: callback(value, "close_transport"),
    },
    in_flight: false,
    request_digest: null,
    command: null,
    failed: null,
    ack_settlement_digest: null,
  });
  return port;
}

function assertRfOffUsbExecutionPort(port) {
  if (!port || utilTypes.isProxy(port) || !Object.isFrozen(port)
      || Object.getPrototypeOf(port) !== null || !PORTS.has(port) || !PORT_STATE.has(port)) {
    throw executionError("rf_off_usb_port_untrusted", "RF-off USB execution requires a privately branded worker port");
  }
  return port;
}

function projectRfOffUsbExecutionPort(portInput) {
  const port = assertRfOffUsbExecutionPort(portInput);
  const state = PORT_STATE.get(port);
  return nullRecord({
    ...Object.fromEntries(Object.keys(port).map((field) => [field, port[field]])),
    ...state.binding,
  });
}

function readRawExchange(state, request) {
  let raw;
  try {
    raw = assertSynchronous(state.callbacks.read(nullRecord({
      version: RF_OFF_USB_EXECUTION_PORT_VERSION,
      kind: "read_chameleon_rf_off_usb_exchange",
      execution_binding_digest: request.execution_binding_digest,
    })), "RF-off USB durable readback");
  } catch (cause) {
    throw executionError("rf_off_usb_durable_read_failed", "RF-off USB durable readback failed", cause);
  }
  if (raw == null) return null;
  if (!isPlainObject(raw)) {
    throw executionError("rf_off_usb_durable_exchange_crosswired", "RF-off USB durable readback is malformed");
  }
  const kind = Object.getOwnPropertyDescriptor(raw, "kind")?.value;
  if (kind === "chameleon_hf14a_probe_prepared") {
    return { state: "prepared", value: normalizePrepared(raw, request) };
  }
  if (kind === TERMINAL_KIND) {
    return {
      state: raw.outbox_delivery_state === "acknowledged" ? "acknowledged" : "terminal",
      value: normalizeTerminal(raw, request, state.binding),
    };
  }
  throw executionError("rf_off_usb_durable_exchange_crosswired", "RF-off USB durable readback kind is unknown");
}

function normalizeRecoveryBinding(input, port) {
  const value = exactObject(input, "rf_off_usb_recovery_binding", RECOVERY_FIELDS);
  if (value.version !== RF_OFF_USB_EXECUTION_PORT_VERSION
      || value.kind !== "chameleon_hf14a_probe_recovery_binding"
      || value.execution_binding_digest !== port.execution_binding_digest) {
    throw executionError("rf_off_usb_recovery_crosswired", "recovery binding belongs to another worker execution");
  }
  const output = {
    version: RF_OFF_USB_EXECUTION_PORT_VERSION,
    kind: value.kind,
    execution_binding_digest: digest(value.execution_binding_digest, "recovery.execution_binding_digest"),
    authority_claim_digest: digest(value.authority_claim_digest, "recovery.authority_claim_digest"),
    execution_lineage_digest: digest(value.execution_lineage_digest, "recovery.execution_lineage_digest"),
    attempt_ref: token(value.attempt_ref, "recovery.attempt_ref"),
    operation_id: token(value.operation_id, "recovery.operation_id"),
    requested_effects_digest: digest(value.requested_effects_digest, "recovery.requested_effects_digest"),
    safety_supervisor_plan_digest: digest(value.safety_supervisor_plan_digest, "recovery.safety_supervisor_plan_digest"),
    availability_evidence_digest: digest(value.availability_evidence_digest, "recovery.availability_evidence_digest"),
    availability_variant_digest: digest(value.availability_variant_digest, "recovery.availability_variant_digest"),
    execution_claim_receipt_digest: digest(value.execution_claim_receipt_digest, "recovery.execution_claim_receipt_digest"),
    deadline_fence_receipt_digest: digest(value.deadline_fence_receipt_digest, "recovery.deadline_fence_receipt_digest"),
    effect_deadline: timestamp(value.effect_deadline, "recovery.effect_deadline"),
    compiled_command_id: token(value.compiled_command_id, "recovery.compiled_command_id"),
    compiled_command_capability_digest: digest(value.compiled_command_capability_digest, "recovery.compiled_command_capability_digest"),
    compiled_operation_digest: digest(value.compiled_operation_digest, "recovery.compiled_operation_digest"),
    prepared_request_digest: digest(value.prepared_request_digest, "recovery.prepared_request_digest"),
  };
  return Object.freeze(output);
}

function readRawRecovery(state, port, recovery) {
  let raw;
  try {
    raw = assertSynchronous(state.callbacks.read(nullRecord({
      version: RF_OFF_USB_EXECUTION_PORT_VERSION,
      kind: "read_chameleon_rf_off_usb_exchange",
      execution_binding_digest: recovery.execution_binding_digest,
    })), "RF-off USB recovery readback");
  } catch (cause) {
    throw executionError("rf_off_usb_durable_read_failed", "RF-off USB recovery readback failed", cause);
  }
  if (raw == null) return null;
  if (!isPlainObject(raw)) {
    throw executionError("rf_off_usb_durable_exchange_crosswired", "RF-off USB recovery readback is malformed");
  }
  const kind = Object.getOwnPropertyDescriptor(raw, "kind")?.value;
  if (kind === "chameleon_hf14a_probe_prepared") {
    throw executionError(
      "rf_off_usb_prepared_recovery_requires_quarantine",
      "a prepared execution without a terminal cannot be replayed after worker restart",
    );
  }
  if (kind !== TERMINAL_KIND) {
    throw executionError("rf_off_usb_durable_exchange_crosswired", "RF-off USB recovery readback kind is unknown");
  }
  const rawValues = exactObject(raw, "rf_off_usb_recovered_terminal_record", TERMINAL_FIELDS);
  const pseudoRequest = {
    execution_binding_digest: rawValues.execution_binding_digest,
    authority_claim_digest: rawValues.authority_claim_digest,
    execution_lineage_digest: rawValues.execution_lineage_digest,
    attempt_ref: rawValues.attempt_ref,
    operation_id: rawValues.operation_id,
    requested_effects_digest: rawValues.requested_effects_digest,
    safety_supervisor_plan_digest: rawValues.safety_supervisor_plan_digest,
    availability_evidence_digest: rawValues.availability_evidence_digest,
    availability_variant_digest: rawValues.availability_variant_digest,
    execution_claim_receipt_digest: rawValues.execution_claim_receipt_digest,
    deadline_fence_receipt_digest: rawValues.deadline_fence_receipt_digest,
    effect_deadline: rawValues.effect_deadline,
    compiled_command: {
      compiled_command_id: rawValues.compiled_command_id,
      compiled_command_capability_digest: rawValues.compiled_command_capability_digest,
      compiled_operation_digest: rawValues.compiled_operation_digest,
    },
  };
  const terminal = normalizeTerminal(rawValues, pseudoRequest, state.binding);
  for (const field of [
    "execution_binding_digest", "authority_claim_digest", "execution_lineage_digest",
    "attempt_ref", "operation_id", "requested_effects_digest",
    "safety_supervisor_plan_digest", "availability_evidence_digest",
    "availability_variant_digest", "execution_claim_receipt_digest",
    "deadline_fence_receipt_digest", "effect_deadline",
    "compiled_command_id", "compiled_command_capability_digest", "compiled_operation_digest",
  ]) {
    if (terminal[field] !== recovery[field]) {
      throw executionError("rf_off_usb_recovery_crosswired", `durable terminal ${field} drifted from recovery authority`);
    }
  }
  const recoveredPreparedRequestDigest = hashCanonicalJson(preparedBasis(pseudoRequest));
  if (recoveredPreparedRequestDigest !== recovery.prepared_request_digest) {
    throw executionError(
      "rf_off_usb_recovery_crosswired",
      "durable terminal does not match the externally retained prepared request digest",
    );
  }
  state.request_digest = recovery.prepared_request_digest;
  return terminal;
}

function recoverRfOffUsbTerminal(portInput, recoveryInput) {
  const port = assertRfOffUsbExecutionPort(portInput);
  const state = PORT_STATE.get(port);
  const recovery = normalizeRecoveryBinding(recoveryInput, port);
  return readRawRecovery(state, port, recovery);
}

function prepareRfOffUsbExecution(portInput, requestInput) {
  const port = assertRfOffUsbExecutionPort(portInput);
  const state = PORT_STATE.get(port);
  const request = normalizeRequest(requestInput, state.binding, state);
  if (request.execution_binding_digest !== port.execution_binding_digest) {
    throw executionError("rf_off_usb_execution_binding_drift", "request belongs to another worker port");
  }
  const requestDigest = hashCanonicalJson(preparedBasis(request));
  if (state.request_digest != null && state.request_digest !== requestDigest) {
    throw executionError("rf_off_usb_execution_crosswired", "worker port is already bound to another execution");
  }
  state.request_digest = requestDigest;
  if (state.command == null) state.command = request.compiled_command;
  const existing = readRawExchange(state, request);
  if (existing != null) return existing.value;
  const basis = preparedBasis(request);
  let committed;
  try {
    committed = assertSynchronous(state.callbacks.prepare(nullRecord(basis)), "RF-off USB prepare commit");
  } catch (cause) {
    const recovered = readRawExchange(state, request);
    if (recovered != null) return recovered.value;
    throw executionError("rf_off_usb_prepare_ambiguous", "RF-off USB prepared intent commit is ambiguous", cause);
  }
  normalizePrepared(committed, request);
  const readback = readRawExchange(state, request);
  if (readback == null || readback.state !== "prepared") {
    throw executionError("rf_off_usb_prepare_not_durable", "RF-off USB prepared intent is not exactly readable");
  }
  return readback.value;
}

async function executeRfOffUsbExecution(portInput, requestInput, effectAdmissionPortInput = null) {
  const port = assertRfOffUsbExecutionPort(portInput);
  const state = PORT_STATE.get(port);
  const request = normalizeRequest(requestInput, state.binding, state);
  if (request.execution_binding_digest !== port.execution_binding_digest) {
    throw executionError("rf_off_usb_execution_binding_drift", "request belongs to another worker port");
  }
  const existing = readRawExchange(state, request);
  if (existing == null) {
    throw executionError("rf_off_usb_not_prepared", "RF-off USB execution requires a durable prepared intent");
  }
  if (existing.state !== "prepared") return existing.value;
  if (state.failed != null) {
    throw executionError(
      "rf_off_usb_execution_fenced",
      `RF-off USB execution was fenced after ${state.failed}`,
    );
  }
  if (state.in_flight) throw executionError("rf_off_usb_in_progress", "RF-off USB execution is already in progress");
  state.in_flight = true;
  let claimed = null;
  let response = null;
  let transportOpened = false;
  let prepared = existing.value;
  let preOpenAdmission = null;
  let preTransactAdmission = null;
  try {
    const before = normalizeInventoryObservation(
      await state.callbacks.before(nullRecord({
        version: RF_OFF_USB_EXECUTION_PORT_VERSION,
        execution_binding_digest: request.execution_binding_digest,
        endpoint_identity_digest: state.binding.endpoint_identity_digest,
      })),
      "rf_off_usb_inventory_before",
      state.binding,
    );
    preOpenAdmission = invokeEffectAdmission(
      effectAdmissionPortInput,
      port,
      request,
      "pre_open",
    );
    normalizeOpen(await state.callbacks.open(nullRecord({
      version: RF_OFF_USB_EXECUTION_PORT_VERSION,
      execution_binding_digest: request.execution_binding_digest,
      endpoint_identity_digest: state.binding.endpoint_identity_digest,
    })), state.binding);
    transportOpened = true;
    const configured = normalizeConfigure(await state.callbacks.configure(nullRecord({
      version: RF_OFF_USB_EXECUTION_PORT_VERSION,
      execution_binding_digest: request.execution_binding_digest,
      endpoint_identity_digest: state.binding.endpoint_identity_digest,
      dtr_control_model: state.binding.dtr_control_model,
    })), state.binding);
    preTransactAdmission = invokeEffectAdmission(
      effectAdmissionPortInput,
      port,
      request,
      "pre_transact",
    );
    claimed = claimCompiledHf14aProviderCommand(request.compiled_command);
    let raw;
    try {
      raw = await state.callbacks.transact(Object.freeze({
        version: RF_OFF_USB_EXECUTION_PORT_VERSION,
        execution_binding_digest: request.execution_binding_digest,
        endpoint_identity_digest: state.binding.endpoint_identity_digest,
        request_bytes: claimed.request_bytes,
        maximum_response_bytes: claimed.maximum_response_bytes,
        timeout_ms: claimed.timeout_ms,
      }));
      response = rawResponse(raw, Math.min(claimed.maximum_response_bytes, state.binding.vault_byte_limit));
    } finally {
      scrub(claimed?.request_bytes);
    }
    const expectedArtifactResponse = Object.freeze({
      response_digest: crypto.createHash("sha256").update(response).digest("hex"),
      response_byte_length: response.length,
    });
    const artifactReceipt = await state.callbacks.artifact(Object.freeze({
      version: RF_OFF_USB_EXECUTION_PORT_VERSION,
      execution_binding_digest: request.execution_binding_digest,
      execution_lineage_digest: request.execution_lineage_digest,
      execution_claim_receipt_digest: request.execution_claim_receipt_digest,
      deadline_fence_receipt_digest: request.deadline_fence_receipt_digest,
      vault_reservation_handle: state.binding.vault_reservation_handle,
      vault_reservation_digest: state.binding.vault_reservation_digest,
      vault_ingest_capability_digest: state.binding.vault_ingest_capability_digest,
      response_bytes: response,
    }));
    assertArtifactResponseUnchanged(response, expectedArtifactResponse);
    const artifact = normalizeArtifactReceipt(
      artifactReceipt,
      expectedArtifactResponse,
      state.binding,
    );
    response.fill(0);
    response = null;
    const after = normalizeInventoryObservation(
      await state.callbacks.after(nullRecord({
        version: RF_OFF_USB_EXECUTION_PORT_VERSION,
        execution_binding_digest: request.execution_binding_digest,
        endpoint_identity_digest: state.binding.endpoint_identity_digest,
      })),
      "rf_off_usb_inventory_after",
      state.binding,
    );
    const closed = normalizeClose(await state.callbacks.close(nullRecord({
      version: RF_OFF_USB_EXECUTION_PORT_VERSION,
      execution_binding_digest: request.execution_binding_digest,
      endpoint_identity_digest: state.binding.endpoint_identity_digest,
      terminal_required: true,
    })), state.binding);
    transportOpened = false;
    const core = terminalCore(
      prepared,
      artifact,
      before,
      configured,
      after,
      closed,
      preOpenAdmission,
      preTransactAdmission,
      state.binding,
    );
    let committed;
    try {
      committed = assertSynchronous(state.callbacks.commit(core), "RF-off USB terminal commit");
    } catch (cause) {
      const recovered = readRawExchange(state, request);
      if (recovered != null && recovered.state !== "prepared") {
        return assertTerminalCoreExact(recovered.value, core);
      }
      throw executionError("rf_off_usb_terminal_commit_ambiguous", "RF-off USB terminal receipt/outbox commit is ambiguous", cause);
    }
    assertTerminalCoreExact(normalizeTerminal(committed, request, state.binding), core);
    const readback = readRawExchange(state, request);
    if (readback == null || readback.state === "prepared") {
      throw executionError("rf_off_usb_terminal_not_durable", "RF-off USB terminal receipt/outbox is not exactly readable");
    }
    return assertTerminalCoreExact(readback.value, core);
  } catch (cause) {
    state.failed = cause && typeof cause.code === "string"
      ? cause.code : "rf_off_usb_execution_ambiguous";
    if (transportOpened) {
      try {
        await state.callbacks.close(nullRecord({
          version: RF_OFF_USB_EXECUTION_PORT_VERSION,
          execution_binding_digest: request.execution_binding_digest,
          endpoint_identity_digest: state.binding.endpoint_identity_digest,
          terminal_required: true,
        }));
      } catch {}
    }
    if (cause && typeof cause.code === "string" && cause.code.startsWith("rf_off_usb_")) throw cause;
    throw executionError("rf_off_usb_execution_ambiguous", "RF-off USB worker execution is ambiguous", cause);
  } finally {
    scrub(claimed?.request_bytes);
    scrub(response);
    state.in_flight = false;
  }
}

function acknowledgeRfOffUsbExecution(portInput, requestInput, brokerSettlementDigestInput) {
  const port = assertRfOffUsbExecutionPort(portInput);
  const state = PORT_STATE.get(port);
  const request = normalizeRequest(requestInput, state.binding, state);
  const settlementDigest = digest(brokerSettlementDigestInput, "broker_settlement_digest");
  const existing = readRawExchange(state, request);
  if (existing == null || existing.state === "prepared") {
    throw executionError("rf_off_usb_terminal_missing", "cannot acknowledge a missing terminal record");
  }
  const ackRequest = nullRecord({
    version: RF_OFF_USB_EXECUTION_PORT_VERSION,
    kind: "acknowledge_chameleon_rf_off_usb_terminal",
    execution_binding_digest: request.execution_binding_digest,
    terminal_witness_digest: existing.value.terminal_witness_digest,
    durable_receipt_digest: existing.value.durable_receipt_digest,
    outbox_record_digest: existing.value.outbox_record_digest,
    broker_settlement_digest: settlementDigest,
  });
  const expectedAckDigest = hashCanonicalJson({
    domain: "hacker-bob/chameleon-rf-off-usb-outbox-ack/v1",
    ...ackRequest,
  });
  if (state.ack_settlement_digest != null
      && state.ack_settlement_digest !== settlementDigest) {
    throw executionError(
      "rf_off_usb_outbox_ack_crosswired",
      "terminal outbox was already acknowledged by another broker settlement",
    );
  }
  if (existing.state === "acknowledged") {
    if (existing.value.outbox_ack_digest !== expectedAckDigest) {
      throw executionError(
        "rf_off_usb_outbox_ack_crosswired",
        "durable outbox acknowledgement does not bind this broker settlement",
      );
    }
    state.ack_settlement_digest = settlementDigest;
    return existing.value;
  }
  try {
    assertSynchronous(state.callbacks.ack(ackRequest), "RF-off USB outbox acknowledgement");
  } catch (cause) {
    const recovered = readRawExchange(state, request);
    if (recovered != null && recovered.state === "acknowledged"
        && recovered.value.outbox_ack_digest === expectedAckDigest) {
      state.ack_settlement_digest = settlementDigest;
      return recovered.value;
    }
    throw executionError("rf_off_usb_outbox_ack_ambiguous", "RF-off USB outbox acknowledgement is ambiguous", cause);
  }
  const readback = readRawExchange(state, request);
  if (readback == null || readback.state !== "acknowledged"
      || readback.value.outbox_ack_digest !== expectedAckDigest) {
    throw executionError("rf_off_usb_outbox_ack_not_durable", "RF-off USB outbox acknowledgement is not exactly readable");
  }
  state.ack_settlement_digest = settlementDigest;
  return readback.value;
}

function acknowledgeRecoveredRfOffUsbExecution(
  portInput,
  recoveryInput,
  brokerSettlementDigestInput,
) {
  const port = assertRfOffUsbExecutionPort(portInput);
  const state = PORT_STATE.get(port);
  const recovery = normalizeRecoveryBinding(recoveryInput, port);
  const settlementDigest = digest(brokerSettlementDigestInput, "broker_settlement_digest");
  const existing = readRawRecovery(state, port, recovery);
  if (existing == null) {
    throw executionError("rf_off_usb_terminal_missing", "cannot acknowledge a missing recovered terminal record");
  }
  const ackRequest = nullRecord({
    version: RF_OFF_USB_EXECUTION_PORT_VERSION,
    kind: "acknowledge_chameleon_rf_off_usb_terminal",
    execution_binding_digest: recovery.execution_binding_digest,
    terminal_witness_digest: existing.terminal_witness_digest,
    durable_receipt_digest: existing.durable_receipt_digest,
    outbox_record_digest: existing.outbox_record_digest,
    broker_settlement_digest: settlementDigest,
  });
  const expectedAckDigest = hashCanonicalJson({
    domain: "hacker-bob/chameleon-rf-off-usb-outbox-ack/v1",
    ...ackRequest,
  });
  if (state.ack_settlement_digest != null
      && state.ack_settlement_digest !== settlementDigest) {
    throw executionError("rf_off_usb_outbox_ack_crosswired", "recovered outbox was acknowledged by another settlement");
  }
  if (existing.outbox_delivery_state === "acknowledged") {
    if (existing.outbox_ack_digest !== expectedAckDigest) {
      throw executionError("rf_off_usb_outbox_ack_crosswired", "recovered ACK does not bind this settlement");
    }
    state.ack_settlement_digest = settlementDigest;
    return existing;
  }
  try {
    assertSynchronous(state.callbacks.ack(ackRequest), "RF-off USB recovered outbox acknowledgement");
  } catch (cause) {
    const recovered = readRawRecovery(state, port, recovery);
    if (recovered != null && recovered.outbox_delivery_state === "acknowledged"
        && recovered.outbox_ack_digest === expectedAckDigest) {
      state.ack_settlement_digest = settlementDigest;
      return recovered;
    }
    throw executionError("rf_off_usb_outbox_ack_ambiguous", "recovered outbox acknowledgement is ambiguous", cause);
  }
  const readback = readRawRecovery(state, port, recovery);
  if (readback == null || readback.outbox_delivery_state !== "acknowledged"
      || readback.outbox_ack_digest !== expectedAckDigest) {
    throw executionError("rf_off_usb_outbox_ack_not_durable", "recovered outbox ACK is not exactly readable");
  }
  state.ack_settlement_digest = settlementDigest;
  return readback;
}

function readRfOffUsbExecution(portInput, requestInput) {
  const port = assertRfOffUsbExecutionPort(portInput);
  const state = PORT_STATE.get(port);
  const request = normalizeRequest(requestInput, state.binding, state);
  if (request.execution_binding_digest !== port.execution_binding_digest) {
    throw executionError("rf_off_usb_execution_binding_drift", "request belongs to another worker port");
  }
  return readRawExchange(state, request)?.value || null;
}

module.exports = Object.freeze({
  EFFECT_ADMISSION_PHASES,
  EXCHANGE_STATES,
  RF_OFF_USB_EXECUTION_PORT_VERSION,
  acknowledgeRecoveredRfOffUsbExecution,
  acknowledgeRfOffUsbExecution,
  assertRfOffUsbExecutionPort,
  chameleonRfOffUsbProviderDescriptorDigest: providerDescriptorDigest,
  chameleonRfOffUsbExecutionRequestDigest: executionRequestDigest,
  createFixtureRfOffUsbEffectAdmissionPort,
  createFixtureRfOffUsbExecutionPort,
  executeRfOffUsbExecution,
  prepareRfOffUsbExecution,
  projectRfOffUsbExecutionPort,
  readRfOffUsbExecution,
  recoverRfOffUsbTerminal,
});
