"use strict";

// Fixed broker-owned completion-evidence join for the one source-owned
// Chameleon get_app_version acceptance operation.  It never receives response
// bytes, a callback, a module path, or a caller readiness claim.  Instead it
// re-reads the artifact vault's privately branded authenticated raw-custody and
// semantic receipts, joins them to a verified native-dispatch ticket and the
// broker's exact completion binding, and emits only the closed digest-only
// record required by physical-provider-dispatch.
//
// This is deliberately not a production owner.  The native-dispatch public key
// is supplied by the caller rather than resolved from an independently enrolled
// current-principal trust owner, and both vault receipt ports are explicitly
// non-production.  The fixed adapter therefore improves replay/recovery and
// lineage integrity without turning conformance evidence into hardware
// authority.

const crypto = require("node:crypto");
const { types: utilTypes } = require("node:util");

const {
  CHAMELEON_GET_APP_VERSION_SEMANTIC_VALIDATOR_PROFILE,
  assertChameleonGetAppVersionSemanticObservationReceipt,
  readChameleonGetAppVersionSemanticObservationReceipt,
} = require("./get-app-version-semantic-validator.js");
const {
  assertProviderResponseRawCustodyReceipt,
  assertProviderResponseRawCustodyReceiptPort,
  assertProviderResponseSemanticValidationPort,
  readProviderResponseRawCustodyReceipt,
} = require("../../bob-artifact-vault/lib/provider-response-vault.js");
const {
  normalizeSignedNativeDispatchTicket,
  verifySignedNativeDispatchTicket,
} = require("../../bob-instrument-broker/lib/native-dispatch-contract.js");
const {
  hashCanonicalJson,
} = require("../../../mcp/core/verification/verification-contracts.js");

const arrayIsArray = Array.isArray;
const bufferIsBuffer = Buffer.isBuffer;
const objectFreeze = Object.freeze;
const objectGetOwnPropertyDescriptors = Object.getOwnPropertyDescriptors;
const objectGetPrototypeOf = Object.getPrototypeOf;
const objectHasOwn = Object.hasOwn;
const objectPrototype = Object.prototype;
const reflectOwnKeys = Reflect.ownKeys;
const utilIsPromise = utilTypes.isPromise;
const utilIsProxy = utilTypes.isProxy;

const PROVIDER_COMPLETION_EVIDENCE_ADAPTER_VERSION = 1;
const CHAMELEON_GET_APP_VERSION_COMPLETION_ADAPTER_KIND =
  "chameleon_get_app_version_provider_completion_evidence_adapter";
const CHAMELEON_GET_APP_VERSION_COMPLETION_PORT_ID =
  "chameleon_get_app_version_vault_completion";
const COMPLETE_NATIVE_SETTLEMENT =
  "native-settlement:fixture_complete_non_authorizing";
const COMPLETION_BINDING_DOMAIN =
  "hacker-bob/physical-provider-completion-binding/v1";
const COMPLETION_RECEIPT_DOMAIN =
  "hacker-bob/physical-provider-completion-receipt/v1";
const COMPLETION_EVIDENCE_DOMAIN =
  "hacker-bob/physical-provider-completion-evidence/v1";
const PROVIDER_RESULT_DOMAIN =
  "hacker-bob/chameleon-get-app-version-provider-result/v1";
const ADAPTER_EVIDENCE_DOMAIN =
  "hacker-bob/chameleon-get-app-version-completion-adapter-domain/v1";
const NATIVE_ARTIFACT_HANDLE_DIGEST_DOMAIN =
  "hacker-bob/native-response-vault-artifact-handle/v1\0";
const MAX_PUBLIC_KEY_BYTES = 16 * 1024;
const MAX_STRING_BYTES = 1024;
const SHA256_RE = /^[a-f0-9]{64}$/u;
const IDENTIFIER_RE = /^[a-z][a-z0-9._-]{0,127}$/u;
const TOKEN_RE = /^[A-Za-z0-9][A-Za-z0-9._:@-]{0,511}$/u;
const BASE64URL_RE = /^[A-Za-z0-9_-]{1,512}$/u;

const EXECUTION_LINEAGE_BINDING_FIELDS = objectFreeze([
  "experiment_plan_hash",
  "execution_lineage_digest",
  "compiler_id",
  "compiler_manifest_digest",
  "compiler_registry_digest",
  "compiled_command_id",
  "compiled_command_capability_digest",
  "compiled_operation_digest",
  "provider_command_ref",
  "active_command_input_ref",
  "active_command_input_digest",
  "maximum_response_bytes",
  "vault_reservation_handle",
  "vault_reservation_digest",
  "vault_ingest_capability_digest",
  "vault_byte_limit",
  "worker_bundle_digest",
  "worker_launch_profile_digest",
  "worker_fence_plan_digest",
  "transport_profile_digest",
  "durable_exchange_plan_digest",
  "terminal_receipt_recipient_digest",
  "safety_supervisor_plan_digest",
]);

const ACTIVE_ADMISSION_BINDING_FIELDS = objectFreeze([
  "physical_scope_axis_digest",
  "physical_scope_policy_id",
  "physical_scope_policy_digest",
  "physical_scope_projection_digest",
  "authority_epoch",
  "revocation_generation",
  "authority_resolution_digest",
  "caller_role_id",
  "requester_principal_id",
  "ipc_peer_principal_id",
  "capability_pack_id",
  "capability_pack_version",
  "capability_pack_digest",
  "technique_cell_id",
  "inventory_observation_ref",
  "inventory_observation_digest",
  "assurance_profile_id",
  "assurance_claims_digest",
  "provider_manifest_digest",
  "availability_variant_id",
  "availability_variant_digest",
  "authorized_transition_set_digest",
  "workspace_snapshot_ref",
  "workspace_snapshot_digest",
  "observer_plan_digest",
  "control_plan_digest",
  "cleanup_plan_digest",
]);

const COMPLETION_BINDING_FIELDS = objectFreeze([
  "domain",
  "version",
  ...EXECUTION_LINEAGE_BINDING_FIELDS,
  ...ACTIVE_ADMISSION_BINDING_FIELDS,
  "active_admission_binding_digest",
  "completion_verification_port_id",
  "completion_evidence_domain_digest",
  "reservation_ref",
  "admission_receipt_digest",
  "effect_receipt_digest",
  "reservation_request_digest",
  "reservation_binding_digest",
  "node_id",
  "contract_hash",
  "source_graph_hash",
  "session_nucleus_hash",
  "resource_bundle_digest",
  "allocation_plan_digest",
  "allocation_digest",
  "attempt_ref",
  "execution_principal_ref",
  "session_id",
  "admission_credential_binding_digest",
  "effect_credential_binding_digest",
  "effect_authorization_digest",
  "fencing_semantics",
  "effect_not_before",
  "effect_deadline",
  "task_graph_dispatch_head_fence_digest",
  "prep_token_hash",
  "dispatch_event_id",
  "graph_context_hash",
  "provider_id",
  "provider_descriptor_digest",
  "semantic_manifest_digest",
  "provider_binding_digest",
  "device_ref",
  "device_identity_digest",
  "custody_ref",
  "custody_identity_digest",
  "custody_epoch",
  "command_kind",
  "command_ref",
  "operation_id",
  "operation_digest",
  "semantic_owner_ref",
  "semantic_owner_digest",
  "requested_effect_digest",
  "requested_effects_digest",
  "command_projection_digest",
  "command_authorization_digest",
  "semantic_authority_digest",
  "authorization_epoch",
  "reservation_command_authority_digest",
  "resource_alias",
  "resource_ref",
  "resource_requirement_digest",
  "command_input_ref",
  "command_input_digest",
  "command_sequence",
  "provider_dispatch_capability_digest",
  "completion_binding_digest",
]);

const DIGEST_BINDING_FIELDS = new Set([
  ...EXECUTION_LINEAGE_BINDING_FIELDS.filter((field) => field.endsWith("_digest")
    || field.endsWith("_hash")),
  ...ACTIVE_ADMISSION_BINDING_FIELDS.filter((field) => field.endsWith("_digest")),
  "active_admission_binding_digest",
  "completion_evidence_domain_digest",
  "admission_receipt_digest",
  "effect_receipt_digest",
  "reservation_request_digest",
  "reservation_binding_digest",
  "contract_hash",
  "source_graph_hash",
  "session_nucleus_hash",
  "resource_bundle_digest",
  "allocation_plan_digest",
  "allocation_digest",
  "admission_credential_binding_digest",
  "effect_credential_binding_digest",
  "effect_authorization_digest",
  "task_graph_dispatch_head_fence_digest",
  "prep_token_hash",
  "graph_context_hash",
  "provider_descriptor_digest",
  "semantic_manifest_digest",
  "provider_binding_digest",
  "device_identity_digest",
  "custody_identity_digest",
  "operation_digest",
  "semantic_owner_digest",
  "requested_effect_digest",
  "requested_effects_digest",
  "command_projection_digest",
  "command_authorization_digest",
  "semantic_authority_digest",
  "reservation_command_authority_digest",
  "resource_requirement_digest",
  "command_input_digest",
  "provider_dispatch_capability_digest",
  "completion_binding_digest",
]);

const INTEGER_BINDING_FIELDS = new Set([
  "maximum_response_bytes",
  "vault_byte_limit",
  "authority_epoch",
  "revocation_generation",
  "custody_epoch",
  "authorization_epoch",
  "command_sequence",
]);

const ADAPTERS = new WeakSet();
const ADAPTER_PRIVATE = new WeakMap();

const PRODUCTION_BLOCKERS = objectFreeze([
  "independently_enrolled_native_dispatch_trust_owner_missing",
  "current_provider_principal_trust_verification_missing",
  "separately_isolated_vault_receipt_process_and_key_missing",
  "external_monotonic_completion_receipt_anchor_missing",
  "privately_branded_native_terminal_owner_missing",
  "provider_cleanup_completion_semantics_missing",
  "hardware_in_loop_qualification_missing",
]);

function adapterError(code, cause = null) {
  const error = new Error(code);
  error.code = code;
  if (cause != null) Object.defineProperty(error, "cause", { value: cause });
  return error;
}

function isPlainDataObject(value) {
  if (value == null || typeof value !== "object" || arrayIsArray(value)
      || bufferIsBuffer(value) || utilIsProxy(value) || utilIsPromise(value)) {
    return false;
  }
  const prototype = objectGetPrototypeOf(value);
  return prototype === objectPrototype || prototype === null;
}

function assertExactDataObject(value, fields, label) {
  if (!isPlainDataObject(value)) throw adapterError(`${label}_must_be_closed_data`);
  const descriptors = objectGetOwnPropertyDescriptors(value);
  const keys = reflectOwnKeys(descriptors);
  if (keys.some((key) => typeof key !== "string")) {
    throw adapterError(`${label}_symbol_field_forbidden`);
  }
  const missing = fields.filter((field) => !objectHasOwn(descriptors, field));
  const unknown = keys.filter((field) => !fields.includes(field));
  if (missing.length > 0 || unknown.length > 0) {
    throw adapterError(`${label}_field_set_invalid`);
  }
  for (const field of fields) {
    const descriptor = descriptors[field];
    if (!descriptor || !objectHasOwn(descriptor, "value")
        || descriptor.enumerable !== true) {
      throw adapterError(`${label}_${field}_must_be_data`);
    }
  }
  return descriptors;
}

function descriptorValue(descriptors, field) {
  return descriptors[field].value;
}

function assertVersion(value, label) {
  if (value !== PROVIDER_COMPLETION_EVIDENCE_ADAPTER_VERSION) {
    throw adapterError(`${label}_version_invalid`);
  }
  return value;
}

function assertDigest(value, label) {
  if (typeof value !== "string" || !SHA256_RE.test(value)) {
    throw adapterError(`${label}_digest_invalid`);
  }
  return value;
}

function assertIdentifier(value, label) {
  if (typeof value !== "string" || !IDENTIFIER_RE.test(value)) {
    throw adapterError(`${label}_identifier_invalid`);
  }
  return value;
}

function assertToken(value, label) {
  if (typeof value !== "string" || !TOKEN_RE.test(value)
      || Buffer.byteLength(value, "utf8") > MAX_STRING_BYTES) {
    throw adapterError(`${label}_token_invalid`);
  }
  return value;
}

function assertPositiveInteger(value, label) {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw adapterError(`${label}_integer_invalid`);
  }
  return value;
}

function assertNonnegativeInteger(value, label) {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw adapterError(`${label}_integer_invalid`);
  }
  return value;
}

function assertCanonicalTimestamp(value, label) {
  if (typeof value !== "string" || Number.isNaN(Date.parse(value))
      || new Date(value).toISOString() !== value) {
    throw adapterError(`${label}_timestamp_invalid`);
  }
  return value;
}

function rejectSerialization() {
  throw adapterError("provider_completion_evidence_adapter_not_serializable");
}

function normalizeCompletionBinding(input) {
  const label = "provider_completion_adapter_binding";
  const descriptors = assertExactDataObject(input, COMPLETION_BINDING_FIELDS, label);
  const output = {};
  for (const field of COMPLETION_BINDING_FIELDS) {
    const value = descriptorValue(descriptors, field);
    if (field === "domain") {
      if (value !== COMPLETION_BINDING_DOMAIN) {
        throw adapterError("provider_completion_adapter_binding_domain_invalid");
      }
      output[field] = value;
    } else if (field === "version") {
      output[field] = assertVersion(value, label);
    } else if (DIGEST_BINDING_FIELDS.has(field)) {
      output[field] = assertDigest(value, `${label}_${field}`);
    } else if (INTEGER_BINDING_FIELDS.has(field)) {
      output[field] = field === "revocation_generation"
        ? assertNonnegativeInteger(value, `${label}_${field}`)
        : assertPositiveInteger(value, `${label}_${field}`);
    } else if (field === "effect_not_before" || field === "effect_deadline") {
      output[field] = assertCanonicalTimestamp(value, `${label}_${field}`);
    } else {
      output[field] = assertToken(value, `${label}_${field}`);
    }
  }
  if (Date.parse(output.effect_not_before) >= Date.parse(output.effect_deadline)) {
    throw adapterError("provider_completion_adapter_effect_window_invalid");
  }
  if (output.command_kind !== "command") {
    throw adapterError("provider_completion_adapter_command_kind_unsupported");
  }
  const basis = {};
  for (const field of COMPLETION_BINDING_FIELDS) {
    if (field !== "completion_binding_digest") basis[field] = output[field];
  }
  if (output.completion_binding_digest !== hashCanonicalJson(basis)) {
    throw adapterError("provider_completion_adapter_binding_digest_invalid");
  }
  return objectFreeze(output);
}

function normalizeProviderClaim(input) {
  const label = "provider_completion_adapter_claim";
  const descriptors = assertExactDataObject(input, [
    "version",
    "completion",
    "provider_result_digest",
    "provider_receipt_ref",
  ], label);
  assertVersion(descriptorValue(descriptors, "version"), label);
  if (descriptorValue(descriptors, "completion") !== "confirmed") {
    throw adapterError("provider_completion_adapter_claim_not_confirmed");
  }
  return objectFreeze({
    version: PROVIDER_COMPLETION_EVIDENCE_ADAPTER_VERSION,
    completion: "confirmed",
    provider_result_digest: assertDigest(
      descriptorValue(descriptors, "provider_result_digest"),
      `${label}_provider_result`,
    ),
    provider_receipt_ref: assertToken(
      descriptorValue(descriptors, "provider_receipt_ref"),
      `${label}_provider_receipt_ref`,
    ),
  });
}

function nativeArtifactHandleDigest(artifactHandle) {
  return crypto.createHash("sha256")
    .update(NATIVE_ARTIFACT_HANDLE_DIGEST_DOMAIN, "utf8")
    .update(assertToken(artifactHandle, "provider_completion_adapter_artifact_handle"), "utf8")
    .digest("hex");
}

function deriveEvidenceDomainDigest(nativePayload, ticketDigest) {
  return hashCanonicalJson({
    domain: ADAPTER_EVIDENCE_DOMAIN,
    version: PROVIDER_COMPLETION_EVIDENCE_ADAPTER_VERSION,
    adapter_kind: CHAMELEON_GET_APP_VERSION_COMPLETION_ADAPTER_KIND,
    provider_id: CHAMELEON_GET_APP_VERSION_SEMANTIC_VALIDATOR_PROFILE.provider_id,
    operation_id: CHAMELEON_GET_APP_VERSION_SEMANTIC_VALIDATOR_PROFILE.operation_id,
    validator_registry_digest:
      CHAMELEON_GET_APP_VERSION_SEMANTIC_VALIDATOR_PROFILE.validator_registry_digest,
    native_dispatch_envelope_digest: ticketDigest,
    execution_lineage_digest: nativePayload.execution_lineage_digest,
  });
}

function assertFixedNativePayload(payload, ticketDigest) {
  const profile = CHAMELEON_GET_APP_VERSION_SEMANTIC_VALIDATOR_PROFILE;
  const exact = {
    version: PROVIDER_COMPLETION_EVIDENCE_ADAPTER_VERSION,
    protocol: "hacker-bob/physical-native-dispatch/v1",
    grant_kind: "bootstrap",
    command_kind: "observe",
    effect_class: "none",
    rf_constraint: "rf_off",
    provider_id: profile.provider_id,
    semantic_manifest_digest: profile.semantic_manifest_digest,
    operation_id: profile.operation_id,
    requested_effects_digest: profile.requested_effects_digest,
    command_bytes_digest: profile.canonical_request_digest,
    one_use: true,
  };
  for (const [field, expected] of Object.entries(exact)) {
    if (payload[field] !== expected) {
      throw adapterError(`provider_completion_adapter_native_${field}_mismatch`);
    }
  }
  if (payload.command_byte_length !== 10
      || payload.maximum_response_bytes < 10
      || payload.vault_byte_ceiling < payload.maximum_response_bytes
      || BigInt(payload.ticket_sequence) < 1n
      || BigInt(payload.authority_epoch) > BigInt(Number.MAX_SAFE_INTEGER)
      || BigInt(payload.revocation_generation) > BigInt(Number.MAX_SAFE_INTEGER)
      || BigInt(payload.connection_generation) > BigInt(Number.MAX_SAFE_INTEGER)
      || BigInt(payload.command_sequence) > BigInt(Number.MAX_SAFE_INTEGER)
      || !SHA256_RE.test(ticketDigest)) {
    throw adapterError("provider_completion_adapter_native_bounds_invalid");
  }
  return payload;
}

function normalizeCreationRequest(input) {
  const label = "create_provider_completion_evidence_adapter_request";
  const descriptors = assertExactDataObject(input, [
    "version",
    "kind",
    "raw_custody_receipt_port",
    "semantic_validation_port",
    "native_dispatch_ticket",
    "native_dispatch_public_key_pem",
    "native_dispatch_key_id",
  ], label);
  assertVersion(descriptorValue(descriptors, "version"), label);
  if (descriptorValue(descriptors, "kind") !== label) {
    throw adapterError("provider_completion_adapter_creation_kind_invalid");
  }
  const publicKeyPem = descriptorValue(descriptors, "native_dispatch_public_key_pem");
  if (typeof publicKeyPem !== "string" || Buffer.byteLength(publicKeyPem, "utf8") < 80
      || Buffer.byteLength(publicKeyPem, "utf8") > MAX_PUBLIC_KEY_BYTES
      || !publicKeyPem.startsWith("-----BEGIN PUBLIC KEY-----\n")
      || !publicKeyPem.endsWith("-----END PUBLIC KEY-----\n")) {
    throw adapterError("provider_completion_adapter_public_key_invalid");
  }
  const keyId = assertToken(
    descriptorValue(descriptors, "native_dispatch_key_id"),
    "provider_completion_adapter_native_key_id",
  );
  const rawPort = assertProviderResponseRawCustodyReceiptPort(
    descriptorValue(descriptors, "raw_custody_receipt_port"),
  );
  const semanticPort = assertProviderResponseSemanticValidationPort(
    descriptorValue(descriptors, "semantic_validation_port"),
  );
  let ticket;
  let payload;
  try {
    ticket = normalizeSignedNativeDispatchTicket(
      descriptorValue(descriptors, "native_dispatch_ticket"),
    );
    payload = verifySignedNativeDispatchTicket(ticket, publicKeyPem, keyId);
  } catch (cause) {
    throw adapterError("provider_completion_adapter_native_ticket_untrusted", cause);
  }
  assertFixedNativePayload(payload, ticket.envelope_digest);
  return objectFreeze({
    raw_port: rawPort,
    semantic_port: semanticPort,
    native_payload: payload,
    ticket_digest: ticket.envelope_digest,
    key_id: keyId,
  });
}

function createChameleonGetAppVersionProviderCompletionEvidenceAdapter(input) {
  const normalized = normalizeCreationRequest(input);
  const evidenceDomainDigest = deriveEvidenceDomainDigest(
    normalized.native_payload,
    normalized.ticket_digest,
  );
  let selfRef;
  const adapter = objectFreeze({
    version: PROVIDER_COMPLETION_EVIDENCE_ADAPTER_VERSION,
    kind: CHAMELEON_GET_APP_VERSION_COMPLETION_ADAPTER_KIND,
    port_id: CHAMELEON_GET_APP_VERSION_COMPLETION_PORT_ID,
    evidence_domain_digest: evidenceDomainDigest,
    provider_id: CHAMELEON_GET_APP_VERSION_SEMANTIC_VALIDATOR_PROFILE.provider_id,
    operation_id: CHAMELEON_GET_APP_VERSION_SEMANTIC_VALIDATOR_PROFILE.operation_id,
    execution_lineage_digest: normalized.native_payload.execution_lineage_digest,
    native_dispatch_envelope_digest: normalized.ticket_digest,
    consistency_contract: "synchronous-linearizable-derived-vault-readback-v1",
    durability_assurance:
      "broker_fixed_authenticated_vault_raw_semantic_receipt_projection_nonproduction",
    production_ready: false,
    hardware_access_authorized: false,
    execution_authority: false,
    callback_input_accepted: false,
    module_path_input_accepted: false,
    response_byte_input_accepted: false,
    readiness_input_accepted: false,
    production_blockers: PRODUCTION_BLOCKERS,
    // Provider-neutral injection seam: the composition root validates this
    // adapter against the neutral assertProviderCompletionEvidenceAdapter and
    // wires these two synchronous methods into a completion verification port.
    read_committed(query) {
      return readCommittedChameleonGetAppVersionProviderCompletionEvidence(selfRef, query);
    },
    verify_and_commit(query) {
      return verifyAndCommitChameleonGetAppVersionProviderCompletionEvidence(selfRef, query);
    },
    toJSON: rejectSerialization,
  });
  selfRef = adapter;
  ADAPTERS.add(adapter);
  ADAPTER_PRIVATE.set(adapter, {
    ...normalized,
    evidence_domain_digest: evidenceDomainDigest,
    pinned_completion_binding_digest: null,
  });
  return adapter;
}

function assertChameleonGetAppVersionProviderCompletionEvidenceAdapter(input) {
  const state = input == null ? null : ADAPTER_PRIVATE.get(input);
  if (!input || !state || !ADAPTERS.has(input) || !Object.isFrozen(input)
      || input.version !== PROVIDER_COMPLETION_EVIDENCE_ADAPTER_VERSION
      || input.kind !== CHAMELEON_GET_APP_VERSION_COMPLETION_ADAPTER_KIND
      || input.port_id !== CHAMELEON_GET_APP_VERSION_COMPLETION_PORT_ID
      || input.evidence_domain_digest !== state.evidence_domain_digest
      || input.execution_lineage_digest !== state.native_payload.execution_lineage_digest
      || input.native_dispatch_envelope_digest !== state.ticket_digest
      || input.production_ready !== false
      || input.hardware_access_authorized !== false
      || input.execution_authority !== false
      || input.callback_input_accepted !== false
      || input.module_path_input_accepted !== false
      || input.response_byte_input_accepted !== false
      || input.readiness_input_accepted !== false
      || input.production_blockers !== PRODUCTION_BLOCKERS
      || input.toJSON !== rejectSerialization
      || typeof input.read_committed !== "function"
      || typeof input.verify_and_commit !== "function"
      || reflectOwnKeys(input).length !== 21) {
    throw adapterError("provider_completion_evidence_adapter_untrusted");
  }
  return input;
}

function projectChameleonGetAppVersionProviderCompletionEvidenceAdapter(input) {
  assertChameleonGetAppVersionProviderCompletionEvidenceAdapter(input);
  return objectFreeze({
    version: input.version,
    kind: input.kind,
    port_id: input.port_id,
    evidence_domain_digest: input.evidence_domain_digest,
    consistency_contract: input.consistency_contract,
    durability_assurance: input.durability_assurance,
    production_ready: false,
    hardware_access_authorized: false,
    execution_authority: false,
    production_blockers: input.production_blockers,
  });
}

function assertBindingMatchesNative(state, binding) {
  const payload = state.native_payload;
  const profile = CHAMELEON_GET_APP_VERSION_SEMANTIC_VALIDATOR_PROFILE;
  const exact = {
    completion_verification_port_id: CHAMELEON_GET_APP_VERSION_COMPLETION_PORT_ID,
    completion_evidence_domain_digest: state.evidence_domain_digest,
    execution_lineage_digest: payload.execution_lineage_digest,
    provider_id: payload.provider_id,
    provider_descriptor_digest: payload.provider_descriptor_digest,
    semantic_manifest_digest: payload.semantic_manifest_digest,
    device_identity_digest: payload.device_identity_digest,
    custody_identity_digest: payload.worker_process_start_digest,
    custody_epoch: Number(payload.connection_generation),
    session_nucleus_hash: payload.session_nucleus_hash,
    node_id: payload.node_id,
    contract_hash: payload.contract_hash,
    attempt_ref: payload.attempt_ref,
    execution_principal_ref: payload.execution_principal_id,
    authority_epoch: Number(payload.authority_epoch),
    revocation_generation: Number(payload.revocation_generation),
    authority_resolution_digest: payload.authority_resolution_digest,
    observer_plan_digest: payload.observer_plan_digest,
    operation_id: payload.operation_id,
    operation_digest: payload.operation_digest,
    requested_effects_digest: payload.requested_effects_digest,
    resource_bundle_digest: payload.resource_bundle_digest,
    allocation_digest: payload.allocation_digest,
    effect_receipt_digest: payload.reservation_receipt_digest,
    command_sequence: Number(payload.command_sequence),
    maximum_response_bytes: payload.maximum_response_bytes,
    vault_reservation_digest: payload.vault_reservation_digest,
    vault_ingest_capability_digest: payload.vault_ingest_capability_digest,
    vault_byte_limit: payload.vault_byte_ceiling,
    worker_bundle_digest: payload.worker_bundle_digest,
    safety_supervisor_plan_digest: payload.safety_contract_digest,
    compiler_id: profile.compiler_id,
    compiler_manifest_digest: profile.semantic_manifest_digest,
    compiler_registry_digest: profile.validator_registry_digest,
    compiled_operation_digest: profile.compiled_operation_digest,
    active_command_input_digest: profile.canonical_request_digest,
  };
  for (const [field, expected] of Object.entries(exact)) {
    if (binding[field] !== expected) {
      throw adapterError(`provider_completion_adapter_binding_${field}_mismatch`);
    }
  }
  const activeAdmission = {};
  for (const field of ACTIVE_ADMISSION_BINDING_FIELDS) {
    activeAdmission[field] = binding[field];
  }
  if (binding.active_admission_binding_digest !== hashCanonicalJson({
    domain: "hacker-bob/physical-provider-active-admission-binding/v1",
    ...activeAdmission,
  })) {
    throw adapterError("provider_completion_adapter_active_admission_digest_invalid");
  }
  const providerBindingBasis = {
    version: PROVIDER_COMPLETION_EVIDENCE_ADAPTER_VERSION,
    provider_id: binding.provider_id,
    provider_descriptor_digest: binding.provider_descriptor_digest,
    semantic_manifest_digest: binding.semantic_manifest_digest,
    device_ref: binding.device_ref,
    device_identity_digest: binding.device_identity_digest,
    custody_ref: binding.custody_ref,
    custody_identity_digest: binding.custody_identity_digest,
    custody_epoch: binding.custody_epoch,
  };
  if (binding.provider_binding_digest !== hashCanonicalJson(providerBindingBasis)) {
    throw adapterError("provider_completion_adapter_provider_binding_digest_invalid");
  }
  if (binding.task_graph_dispatch_head_fence_digest !== binding.reservation_binding_digest) {
    throw adapterError("provider_completion_adapter_dispatch_head_binding_mismatch");
  }
  if (binding.command_ref !== binding.provider_command_ref
      || binding.command_input_ref !== binding.active_command_input_ref
      || binding.command_input_digest !== binding.active_command_input_digest
      || binding.maximum_response_bytes > binding.vault_byte_limit) {
    throw adapterError("provider_completion_adapter_command_input_binding_mismatch");
  }
  return binding;
}

function pinExactBinding(state, bindingInput) {
  const binding = assertBindingMatchesNative(state, normalizeCompletionBinding(bindingInput));
  if (state.pinned_completion_binding_digest === null) {
    state.pinned_completion_binding_digest = binding.completion_binding_digest;
  } else if (state.pinned_completion_binding_digest !== binding.completion_binding_digest) {
    throw adapterError("provider_completion_adapter_binding_transplant_rejected");
  }
  return binding;
}

function readRawReceipt(state, allowAbsent) {
  try {
    return assertProviderResponseRawCustodyReceipt(
      readProviderResponseRawCustodyReceipt(state.raw_port, {
        version: PROVIDER_COMPLETION_EVIDENCE_ADAPTER_VERSION,
        kind: "read_provider_response_raw_custody_receipt_request",
        execution_lineage_digest: state.native_payload.execution_lineage_digest,
      }),
    );
  } catch (cause) {
    if (allowAbsent && cause && cause.code === "ENOENT") return null;
    throw adapterError("provider_completion_adapter_raw_custody_read_failed", cause);
  }
}

function readSemanticReceipt(state) {
  try {
    return assertChameleonGetAppVersionSemanticObservationReceipt(
      readChameleonGetAppVersionSemanticObservationReceipt(state.semantic_port, {
        version: PROVIDER_COMPLETION_EVIDENCE_ADAPTER_VERSION,
        kind: "read_chameleon_get_app_version_semantic_observation_receipt_request",
        execution_lineage_digest: state.native_payload.execution_lineage_digest,
      }),
    );
  } catch (cause) {
    throw adapterError("provider_completion_adapter_semantic_read_failed", cause);
  }
}

function assertReceiptJoin(state, binding, raw, semantic) {
  const payload = state.native_payload;
  const profile = CHAMELEON_GET_APP_VERSION_SEMANTIC_VALIDATOR_PROFILE;
  const rawExact = {
    execution_lineage_digest: binding.execution_lineage_digest,
    provider_id: binding.provider_id,
    operation_id: binding.operation_id,
    compiler_id: binding.compiler_id,
    compiler_manifest_digest: binding.compiler_manifest_digest,
    compiler_registry_digest: binding.compiler_registry_digest,
    compiled_operation_digest: binding.compiled_operation_digest,
    provider_command_ref: binding.provider_command_ref,
    requested_effects_digest: binding.requested_effects_digest,
    compiled_command_id: binding.compiled_command_id,
    compiled_command_capability_digest: binding.compiled_command_capability_digest,
    active_command_input_ref: binding.active_command_input_ref,
    active_command_input_digest: binding.active_command_input_digest,
    worker_launch_digest: binding.worker_launch_profile_digest,
    worker_fence_digest: binding.worker_fence_plan_digest,
    transport_binding_digest: binding.transport_profile_digest,
    vault_reservation_handle: binding.vault_reservation_handle,
    vault_reservation_digest: binding.vault_reservation_digest,
    vault_ingest_capability_digest: binding.vault_ingest_capability_digest,
    transport_settlement_kind: COMPLETE_NATIVE_SETTLEMENT,
    dispatch_envelope_digest: state.ticket_digest,
    source_descriptor_identity_digest: payload.delegated_descriptor_identity_digest,
    sink_descriptor_identity_digest: payload.vault_sink_descriptor_identity_digest,
    ticket_sequence: payload.ticket_sequence,
  };
  for (const [field, expected] of Object.entries(rawExact)) {
    if (raw[field] !== expected) {
      throw adapterError(`provider_completion_adapter_raw_${field}_mismatch`);
    }
  }
  if (raw.response_byte_length < 1
      || raw.response_byte_length > binding.maximum_response_bytes
      || raw.response_byte_length > binding.vault_byte_limit
      || raw.semantic_validation_performed !== false
      || raw.production_ready !== false
      || raw.hardware_access_authorized !== false
      || raw.authoritative !== false
      || payload.artifact_handle_digest !== nativeArtifactHandleDigest(raw.artifact_handle)) {
    throw adapterError("provider_completion_adapter_raw_custody_contract_invalid");
  }
  const semanticExact = {
    validator_id: profile.validator_id,
    validator_registry_digest: profile.validator_registry_digest,
    execution_lineage_digest: raw.execution_lineage_digest,
    raw_custody_receipt_digest: raw.raw_custody_receipt_digest,
    vault_reservation_digest: raw.vault_reservation_digest,
    vault_ingest_capability_digest: raw.vault_ingest_capability_digest,
    artifact_handle: raw.artifact_handle,
    response_digest: raw.response_digest,
    response_byte_length: raw.response_byte_length,
    provider_id: raw.provider_id,
    operation_id: raw.operation_id,
    semantic_manifest_digest: profile.semantic_manifest_digest,
    source_profile_digest: profile.source_profile_digest,
    codec_profile_digest: profile.codec_profile_digest,
    operation_schema_id: profile.schema_id,
    operation_schema_digest: profile.operation_schema_digest,
    canonical_request_digest: profile.canonical_request_digest,
    command_id: 1000,
    status: 0x0068,
    transport_settlement_kind: raw.transport_settlement_kind,
    dispatch_envelope_digest: raw.dispatch_envelope_digest,
    settled_monotonic_ns: raw.settled_monotonic_ns,
    semantic_validation_performed: true,
    plaintext_cleanup_reconciled: true,
    device_state_claim_emitted: false,
    production_ready: false,
    hardware_access_authorized: false,
    authoritative: false,
  };
  for (const [field, expected] of Object.entries(semanticExact)) {
    if (semantic[field] !== expected) {
      throw adapterError(`provider_completion_adapter_semantic_${field}_mismatch`);
    }
  }
  if (typeof semantic.application_version !== "string"
      || !/^(?:0|[1-9][0-9]{0,2})\.(?:0|[1-9][0-9]{0,2})$/u
        .test(semantic.application_version)
      || !SHA256_RE.test(semantic.decoded_payload_digest)
      || !SHA256_RE.test(semantic.raw_custody_cleanup_receipt_digest)
      || !SHA256_RE.test(semantic.semantic_observation_digest)) {
    throw adapterError("provider_completion_adapter_semantic_contract_invalid");
  }
  return objectFreeze({ raw, semantic });
}

function providerResultBasis(rawInput, semanticInput) {
  const raw = assertProviderResponseRawCustodyReceipt(rawInput);
  const semantic = assertChameleonGetAppVersionSemanticObservationReceipt(semanticInput);
  for (const field of [
    "execution_lineage_digest",
    "provider_id",
    "operation_id",
    "artifact_handle",
    "response_digest",
    "response_byte_length",
    "transport_settlement_kind",
    "dispatch_envelope_digest",
    "settled_monotonic_ns",
  ]) {
    if (semantic[field] !== raw[field]) {
      throw adapterError(`provider_completion_adapter_claim_${field}_mismatch`);
    }
  }
  if (semantic.raw_custody_receipt_digest !== raw.raw_custody_receipt_digest) {
    throw adapterError("provider_completion_adapter_claim_raw_receipt_mismatch");
  }
  return objectFreeze({
    domain: PROVIDER_RESULT_DOMAIN,
    version: PROVIDER_COMPLETION_EVIDENCE_ADAPTER_VERSION,
    provider_id: semantic.provider_id,
    operation_id: semantic.operation_id,
    execution_lineage_digest: semantic.execution_lineage_digest,
    dispatch_envelope_digest: semantic.dispatch_envelope_digest,
    artifact_handle: semantic.artifact_handle,
    response_digest: semantic.response_digest,
    response_byte_length: semantic.response_byte_length,
    raw_custody_receipt_digest: raw.raw_custody_receipt_digest,
    raw_custody_cleanup_receipt_digest: semantic.raw_custody_cleanup_receipt_digest,
    semantic_observation_digest: semantic.semantic_observation_digest,
    decoded_payload_digest: semantic.decoded_payload_digest,
    status: semantic.status,
    application_version: semantic.application_version,
  });
}

function deriveChameleonGetAppVersionProviderClaimFromReceipts(raw, semantic) {
  const basis = providerResultBasis(raw, semantic);
  return objectFreeze({
    version: PROVIDER_COMPLETION_EVIDENCE_ADAPTER_VERSION,
    completion: "confirmed",
    provider_result_digest: hashCanonicalJson(basis),
    provider_receipt_ref:
      `provider-receipt:chameleon-get-app-version:${basis.semantic_observation_digest.slice(0, 32)}`,
  });
}

function deriveCompletionEvidence(binding, raw, semantic) {
  const claim = deriveChameleonGetAppVersionProviderClaimFromReceipts(raw, semantic);
  const evidence = {
    version: PROVIDER_COMPLETION_EVIDENCE_ADAPTER_VERSION,
    completion_binding_digest: binding.completion_binding_digest,
    completion: claim.completion,
    effect_disposition: "requested_effect_committed",
    provider_result_digest: claim.provider_result_digest,
    provider_receipt_ref: claim.provider_receipt_ref,
    committed_receipt_ref:
      `completion-receipt:chameleon-get-app-version:${binding.completion_binding_digest.slice(0, 32)}`,
  };
  const receiptBasis = {
    domain: COMPLETION_RECEIPT_DOMAIN,
    ...evidence,
  };
  const committedReceiptDigest = hashCanonicalJson(receiptBasis);
  return objectFreeze({
    ...evidence,
    committed_receipt_digest: committedReceiptDigest,
    completion_evidence_digest: hashCanonicalJson({
      ...receiptBasis,
      domain: COMPLETION_EVIDENCE_DOMAIN,
      committed_receipt_digest: committedReceiptDigest,
    }),
  });
}

function readJoinedEvidence(adapter, bindingInput, allowAbsent) {
  assertChameleonGetAppVersionProviderCompletionEvidenceAdapter(adapter);
  const state = ADAPTER_PRIVATE.get(adapter);
  const binding = pinExactBinding(state, bindingInput);
  const raw = readRawReceipt(state, allowAbsent);
  if (raw === null) return null;
  const semantic = readSemanticReceipt(state);
  const joined = assertReceiptJoin(state, binding, raw, semantic);
  return deriveCompletionEvidence(binding, joined.raw, joined.semantic);
}

function normalizeReadQuery(input) {
  const label = "provider_completion_adapter_read_query";
  const descriptors = assertExactDataObject(
    input,
    ["version", "completion_binding"],
    label,
  );
  assertVersion(descriptorValue(descriptors, "version"), label);
  return descriptorValue(descriptors, "completion_binding");
}

function normalizeVerifyQuery(input) {
  const label = "provider_completion_adapter_verify_query";
  const descriptors = assertExactDataObject(
    input,
    ["version", "completion_binding", "provider_claim"],
    label,
  );
  assertVersion(descriptorValue(descriptors, "version"), label);
  return objectFreeze({
    completion_binding: descriptorValue(descriptors, "completion_binding"),
    provider_claim: normalizeProviderClaim(descriptorValue(descriptors, "provider_claim")),
  });
}

function readCommittedChameleonGetAppVersionProviderCompletionEvidence(adapter, input) {
  const binding = normalizeReadQuery(input);
  return readJoinedEvidence(adapter, binding, true);
}

function verifyAndCommitChameleonGetAppVersionProviderCompletionEvidence(adapter, input) {
  const query = normalizeVerifyQuery(input);
  const evidence = readJoinedEvidence(adapter, query.completion_binding, false);
  if (evidence === null) {
    throw adapterError("provider_completion_adapter_durable_receipts_missing");
  }
  if (query.provider_claim.completion !== evidence.completion
      || query.provider_claim.provider_result_digest !== evidence.provider_result_digest
      || query.provider_claim.provider_receipt_ref !== evidence.provider_receipt_ref) {
    throw adapterError("provider_completion_adapter_claim_drift");
  }
  // The evidence is a deterministic projection of two independently
  // authenticated durable vault receipts.  Re-read the same durable sources
  // rather than acknowledging a process-local cache as a commit.
  const readback = readJoinedEvidence(adapter, query.completion_binding, false);
  if (readback === null
      || readback.completion_evidence_digest !== evidence.completion_evidence_digest
      || readback.committed_receipt_digest !== evidence.committed_receipt_digest) {
    throw adapterError("provider_completion_adapter_readback_drift");
  }
  return evidence;
}

module.exports = objectFreeze({
  CHAMELEON_GET_APP_VERSION_COMPLETION_ADAPTER_KIND,
  CHAMELEON_GET_APP_VERSION_COMPLETION_PORT_ID,
  PROVIDER_COMPLETION_EVIDENCE_ADAPTER_VERSION,
  PROVIDER_COMPLETION_EVIDENCE_PRODUCTION_BLOCKERS: PRODUCTION_BLOCKERS,
  assertChameleonGetAppVersionProviderCompletionEvidenceAdapter,
  createChameleonGetAppVersionProviderCompletionEvidenceAdapter,
  deriveChameleonGetAppVersionProviderClaimFromReceipts,
  projectChameleonGetAppVersionProviderCompletionEvidenceAdapter,
  readCommittedChameleonGetAppVersionProviderCompletionEvidence,
  verifyAndCommitChameleonGetAppVersionProviderCompletionEvidence,
  _internals: objectFreeze({
    ACTIVE_ADMISSION_BINDING_FIELDS,
    COMPLETION_BINDING_FIELDS,
    normalizeCompletionBinding,
  }),
});
