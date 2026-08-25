"use strict";

// Provider-owned Chameleon get_app_version semantic validator. This module was
// severed from the provider-neutral artifact vault: the vault owns raw byte
// custody, durable state persistence, and the provider-neutral
// semantic-validation-PORT interface, and exposes those primitives through a
// data-only substrate. The Chameleon-specific decode/normalize/profile logic
// lives here and plugs into that substrate, and registers itself as the
// normalizer for its receipt kind so the neutral state layer never names a
// provider. Nothing in the vault requires this file; the composition root wires
// the two together.

const {
  providerResponseSemanticSubstrate: V,
} = require("../../bob-artifact-vault/lib/provider-response-vault.js");
const {
  createFrameParser,
  eraseDecodedFrameCustodyBytes,
} = require("./codec.js");
const {
  CHAMELEON_GET_APP_VERSION_RESPONSE_SCHEMA,
  assertChameleonGetAppVersionDecodedPayload,
  decodeChameleonGetAppVersionResponsePayload,
} = require("./bootstrap-response-payloads.js");
const {
  TRUSTED_CLOCK_VERSION,
  assertPhysicalTrustedClockPort,
  assertPhysicalTrustedClockSample,
  samplePhysicalTrustedClock,
} = require("../../../mcp/domains/physical/physical-trusted-clock.js");

const objectFreeze = Object.freeze;
const objectHasOwn = Object.hasOwn;
const bufferIsBuffer = Buffer.isBuffer;

const {
  PROVIDER_RESPONSE_VAULT_VERSION,
  PUBLIC_ARTIFACT_HANDLE_RE,
  sha256,
  canonicalJson,
  digestRecord,
  assertExactDataObject,
  descriptorValue,
  assertVersion,
  assertDigest,
  assertOpaqueRef,
  assertNonnegativeInteger,
  assertUint64,
  assertCanonicalTimestamp,
  projectionWithoutField,
  normalizeTransportLineage,
  normalizeReadbackRequest,
  assertProviderResponseRawCustodyReceipt,
  assertProviderResponseSemanticValidationPort,
  getProviderResponseVaultOwner,
  materializeForWorker,
  ensureReceiptRoot,
  readRawCustodyStateFile,
  writeStateFile,
  reconcileRawCustodyPreparedStateLocked,
  assertReservationJournalFenceMatches,
  registerSemanticValidationPort,
  readSemanticValidationPortPrivate,
  registerSemanticReceiptNormalizer,
} = V;

const PROVIDER_SEMANTIC_VALIDATOR_REGISTRY_DIGEST_DOMAIN =
  "hacker-bob/provider-response-semantic-validator-registry/v1";
const CHAMELEON_GET_APP_VERSION_SEMANTIC_OBSERVATION_DIGEST_DOMAIN =
  "hacker-bob/chameleon-get-app-version-semantic-observation/v1";
const CHAMELEON_GET_APP_VERSION_MAX_VALIDATION_AGE_MS = 5 * 60 * 1000;
const CHAMELEON_GET_APP_VERSION_MAX_CLOCK_UNCERTAINTY_MS = 1000;

const CHAMELEON_GET_APP_VERSION_SEMANTIC_RECEIPT_KIND =
  "chameleon_get_app_version_semantic_observation_receipt";

const CHAMELEON_GET_APP_VERSION_SEMANTIC_RECEIPT_FIELDS = objectFreeze([
  "version",
  "kind",
  "validator_id",
  "validator_registry_digest",
  "execution_lineage_digest",
  "raw_custody_receipt_digest",
  "raw_custody_cleanup_receipt_digest",
  "vault_reservation_digest",
  "vault_ingest_capability_digest",
  "artifact_handle",
  "response_digest",
  "response_byte_length",
  "provider_id",
  "operation_id",
  "semantic_manifest_digest",
  "source_profile_digest",
  "codec_profile_digest",
  "operation_schema_id",
  "operation_schema_digest",
  "canonical_request_digest",
  "command_id",
  "status",
  "application_version",
  "decoded_payload_digest",
  "transport_settlement_kind",
  "dispatch_envelope_digest",
  "settled_monotonic_ns",
  "validation_age_ms",
  "validated_at",
  "validated_at_earliest",
  "validated_at_latest",
  "trusted_clock_id",
  "trusted_monotonic_epoch_id",
  "trusted_monotonic_ms",
  "trusted_clock_mapping_generation",
  "trusted_clock_mapping_digest",
  "trusted_clock_max_uncertainty_ms",
  "trusted_clock_trust_root_epoch",
  "trusted_clock_authority_epoch",
  "trusted_clock_revocation_generation",
  "trusted_clock_sample_digest",
  "semantic_validation_performed",
  "plaintext_cleanup_reconciled",
  "device_state_claim_emitted",
  "production_ready",
  "hardware_access_authorized",
  "authoritative",
  "semantic_observation_digest",
]);

const CHAMELEON_GET_APP_VERSION_REQUESTED_EFFECTS = objectFreeze({
  grant_kind: "bootstrap",
  command_kind: "observe",
  effect_class: "none",
  rf_constraint: "rf_off",
});
const CHAMELEON_GET_APP_VERSION_REQUESTED_EFFECTS_DIGEST = digestRecord(
  "hacker-bob/chameleon-get-app-version-requested-effects/v1",
  CHAMELEON_GET_APP_VERSION_REQUESTED_EFFECTS,
);
const CHAMELEON_GET_APP_VERSION_VALIDATOR_ENTRY = objectFreeze({
  validator_id: CHAMELEON_GET_APP_VERSION_RESPONSE_SCHEMA.validator_id,
  provider_id: CHAMELEON_GET_APP_VERSION_RESPONSE_SCHEMA.provider_id,
  operation_id: CHAMELEON_GET_APP_VERSION_RESPONSE_SCHEMA.operation_id,
  compiler_id: CHAMELEON_GET_APP_VERSION_RESPONSE_SCHEMA.compiler_id,
  semantic_manifest_digest:
    CHAMELEON_GET_APP_VERSION_RESPONSE_SCHEMA.semantic_manifest_digest,
  source_profile_digest:
    CHAMELEON_GET_APP_VERSION_RESPONSE_SCHEMA.source_profile_digest,
  codec_profile_digest:
    CHAMELEON_GET_APP_VERSION_RESPONSE_SCHEMA.codec_profile_digest,
  schema_id: CHAMELEON_GET_APP_VERSION_RESPONSE_SCHEMA.schema_id,
  operation_schema_digest:
    CHAMELEON_GET_APP_VERSION_RESPONSE_SCHEMA.operation_schema_digest,
  canonical_request_digest:
    CHAMELEON_GET_APP_VERSION_RESPONSE_SCHEMA.canonical_request_digest,
  requested_effects_digest: CHAMELEON_GET_APP_VERSION_REQUESTED_EFFECTS_DIGEST,
  maximum_validation_age_ms: CHAMELEON_GET_APP_VERSION_MAX_VALIDATION_AGE_MS,
  maximum_trusted_clock_uncertainty_ms:
    CHAMELEON_GET_APP_VERSION_MAX_CLOCK_UNCERTAINTY_MS,
});
const PROVIDER_SEMANTIC_VALIDATOR_REGISTRY_PROJECTION = objectFreeze({
  version: PROVIDER_RESPONSE_VAULT_VERSION,
  kind: "provider_response_semantic_validator_registry",
  validators: objectFreeze([CHAMELEON_GET_APP_VERSION_VALIDATOR_ENTRY]),
});
const PROVIDER_SEMANTIC_VALIDATOR_REGISTRY_DIGEST = digestRecord(
  PROVIDER_SEMANTIC_VALIDATOR_REGISTRY_DIGEST_DOMAIN,
  PROVIDER_SEMANTIC_VALIDATOR_REGISTRY_PROJECTION,
);
const CHAMELEON_GET_APP_VERSION_SEMANTIC_VALIDATOR_PROFILE = objectFreeze({
  ...CHAMELEON_GET_APP_VERSION_VALIDATOR_ENTRY,
  validator_registry_digest: PROVIDER_SEMANTIC_VALIDATOR_REGISTRY_DIGEST,
  capability_id: CHAMELEON_GET_APP_VERSION_RESPONSE_SCHEMA.capability_id,
  variant_id: CHAMELEON_GET_APP_VERSION_RESPONSE_SCHEMA.variant_id,
  parameter_selector_id:
    CHAMELEON_GET_APP_VERSION_RESPONSE_SCHEMA.parameter_selector_id,
  expected_result_code:
    CHAMELEON_GET_APP_VERSION_RESPONSE_SCHEMA.expected_result_code,
  compiled_operation_digest:
    CHAMELEON_GET_APP_VERSION_RESPONSE_SCHEMA.operation_schema_digest,
});
const PROVIDER_SEMANTIC_VALIDATION_ASSURANCE = objectFreeze({
  version: PROVIDER_RESPONSE_VAULT_VERSION,
  assurance: "fixed_provider_owned_chameleon_semantic_validator_v1",
  validator_id: CHAMELEON_GET_APP_VERSION_SEMANTIC_VALIDATOR_PROFILE.validator_id,
  validator_registry_digest: PROVIDER_SEMANTIC_VALIDATOR_REGISTRY_DIGEST,
  production_ready: false,
  hardware_access_authorized: false,
  execution_authority: false,
  caller_callback_accepted: false,
  caller_module_path_accepted: false,
  caller_raw_bytes_accepted: false,
  caller_operation_accepted: false,
  caller_readiness_claim_accepted: false,
  raw_plaintext_returned: false,
  vault_owned_plaintext_materialization: true,
  fixed_bounded_chameleon_codec: true,
  fixed_source_owned_payload_decoder: true,
  raw_receipt_and_execution_lineage_bound: true,
  semantic_manifest_and_operation_schema_bound: true,
  signed_current_trusted_time_required: true,
  native_plaintext_cleanup_confirmation_required: true,
  safe_semantic_observation_only: true,
  device_state_claim_emitted: false,
  separately_isolated_vault_principal: false,
  current_provider_principal_trust_verified: false,
  hardware_in_loop_proven: false,
  production_blockers: objectFreeze([
    "separately_isolated_vault_principal_missing",
    "current_provider_principal_trust_verifier_missing",
    "native_chameleon_semantic_validator_hil_missing",
    "external_monotonic_semantic_receipt_anchor_missing",
  ]),
});

const CHAMELEON_GET_APP_VERSION_SEMANTIC_RECEIPTS = new WeakSet();

function assertCanonicalApplicationVersion(value, label) {
  if (typeof value !== "string" || !/^(?:0|[1-9][0-9]{0,2})\.(?:0|[1-9][0-9]{0,2})$/u.test(value)) {
    throw new Error(`${label} must be a canonical u8.u8 application version`);
  }
  const [major, minor] = value.split(".").map(Number);
  if (major > 255 || minor > 255) {
    throw new Error(`${label} must be a canonical u8.u8 application version`);
  }
  return value;
}

function decodedGetAppVersionPayloadDigest(applicationVersion) {
  return sha256(canonicalJson({
    version: CHAMELEON_GET_APP_VERSION_RESPONSE_SCHEMA.version,
    projection_kind: "chameleon_get_app_version_semantic_payload",
    validator_id: CHAMELEON_GET_APP_VERSION_SEMANTIC_VALIDATOR_PROFILE.validator_id,
    provider_id: CHAMELEON_GET_APP_VERSION_SEMANTIC_VALIDATOR_PROFILE.provider_id,
    operation_id: CHAMELEON_GET_APP_VERSION_SEMANTIC_VALIDATOR_PROFILE.operation_id,
    semantic_manifest_digest:
      CHAMELEON_GET_APP_VERSION_SEMANTIC_VALIDATOR_PROFILE.semantic_manifest_digest,
    source_profile_digest:
      CHAMELEON_GET_APP_VERSION_SEMANTIC_VALIDATOR_PROFILE.source_profile_digest,
    codec_profile_digest:
      CHAMELEON_GET_APP_VERSION_SEMANTIC_VALIDATOR_PROFILE.codec_profile_digest,
    operation_schema_digest:
      CHAMELEON_GET_APP_VERSION_SEMANTIC_VALIDATOR_PROFILE.operation_schema_digest,
    command_id: CHAMELEON_GET_APP_VERSION_RESPONSE_SCHEMA.command_id,
    status: CHAMELEON_GET_APP_VERSION_RESPONSE_SCHEMA.response_success_status,
    response_fields: { application_version: applicationVersion },
  }));
}

function trustedClockSampleProjectionFromSemanticReceipt(receipt) {
  return objectFreeze({
    version: TRUSTED_CLOCK_VERSION,
    clock_id: receipt.trusted_clock_id,
    monotonic_epoch_id: receipt.trusted_monotonic_epoch_id,
    mapping_generation: receipt.trusted_clock_mapping_generation,
    monotonic_ms: receipt.trusted_monotonic_ms,
    trusted_utc: receipt.validated_at,
    trusted_utc_earliest: receipt.validated_at_earliest,
    trusted_utc_latest: receipt.validated_at_latest,
    max_uncertainty_ms: receipt.trusted_clock_max_uncertainty_ms,
    signed_mapping_digest: receipt.trusted_clock_mapping_digest,
    trust_root_epoch: receipt.trusted_clock_trust_root_epoch,
    authority_epoch: receipt.trusted_clock_authority_epoch,
    revocation_generation: receipt.trusted_clock_revocation_generation,
  });
}

function normalizeChameleonGetAppVersionSemanticReceipt(
  input,
  lineage,
  reservation,
  rawReceipt,
  cleanupReceipt,
  observation,
  label = "chameleon_get_app_version_semantic_observation_receipt",
) {
  const descriptors = assertExactDataObject(
    input,
    CHAMELEON_GET_APP_VERSION_SEMANTIC_RECEIPT_FIELDS,
    label,
  );
  const receipt = {};
  for (const field of CHAMELEON_GET_APP_VERSION_SEMANTIC_RECEIPT_FIELDS) {
    receipt[field] = descriptorValue(descriptors, field);
  }
  assertVersion(receipt.version, label);
  if (receipt.kind !== "chameleon_get_app_version_semantic_observation_receipt") {
    throw new Error(`${label}.kind is invalid`);
  }
  for (const field of [
    "validator_registry_digest",
    "execution_lineage_digest",
    "raw_custody_receipt_digest",
    "raw_custody_cleanup_receipt_digest",
    "vault_reservation_digest",
    "vault_ingest_capability_digest",
    "response_digest",
    "semantic_manifest_digest",
    "source_profile_digest",
    "codec_profile_digest",
    "operation_schema_digest",
    "canonical_request_digest",
    "decoded_payload_digest",
    "dispatch_envelope_digest",
    "trusted_monotonic_epoch_id",
    "trusted_clock_mapping_digest",
    "trusted_clock_sample_digest",
    "semantic_observation_digest",
  ]) assertDigest(receipt[field], `${label}.${field}`);
  if (!PUBLIC_ARTIFACT_HANDLE_RE.test(receipt.artifact_handle || "")) {
    throw new Error(`${label}.artifact_handle is invalid`);
  }
  for (const field of [
    "validator_id",
    "provider_id",
    "operation_id",
    "operation_schema_id",
    "transport_settlement_kind",
    "trusted_clock_id",
  ]) assertOpaqueRef(receipt[field], `${label}.${field}`);
  assertNonnegativeInteger(receipt.response_byte_length, `${label}.response_byte_length`);
  assertNonnegativeInteger(
    receipt.validation_age_ms,
    `${label}.validation_age_ms`,
    CHAMELEON_GET_APP_VERSION_MAX_VALIDATION_AGE_MS,
  );
  if (receipt.validation_age_ms > CHAMELEON_GET_APP_VERSION_MAX_VALIDATION_AGE_MS) {
    throw new Error(`${label}.validation_age_ms is stale`);
  }
  for (const field of [
    "trusted_monotonic_ms",
    "trusted_clock_mapping_generation",
    "trusted_clock_max_uncertainty_ms",
    "trusted_clock_trust_root_epoch",
    "trusted_clock_authority_epoch",
    "trusted_clock_revocation_generation",
  ]) assertNonnegativeInteger(receipt[field], `${label}.${field}`, Number.MAX_SAFE_INTEGER);
  if (receipt.trusted_clock_mapping_generation < 1
      || receipt.trusted_clock_trust_root_epoch < 1
      || receipt.trusted_clock_authority_epoch < 1
      || receipt.trusted_clock_max_uncertainty_ms
        > CHAMELEON_GET_APP_VERSION_MAX_CLOCK_UNCERTAINTY_MS) {
    throw new Error(`${label} trusted clock evidence is not admissible`);
  }
  assertUint64(receipt.settled_monotonic_ns, `${label}.settled_monotonic_ns`);
  for (const field of ["validated_at", "validated_at_earliest", "validated_at_latest"]) {
    assertCanonicalTimestamp(receipt[field], `${label}.${field}`);
  }
  if (Date.parse(receipt.validated_at_earliest) > Date.parse(receipt.validated_at)
      || Date.parse(receipt.validated_at) > Date.parse(receipt.validated_at_latest)) {
    throw new Error(`${label} trusted time interval is invalid`);
  }
  if (receipt.command_id !== CHAMELEON_GET_APP_VERSION_RESPONSE_SCHEMA.command_id
      || receipt.status !== CHAMELEON_GET_APP_VERSION_RESPONSE_SCHEMA.response_success_status) {
    throw new Error(`${label} command or status drifted from the fixed validator`);
  }
  assertCanonicalApplicationVersion(receipt.application_version, `${label}.application_version`);
  if (receipt.semantic_validation_performed !== true
      || receipt.plaintext_cleanup_reconciled !== true
      || receipt.device_state_claim_emitted !== false
      || receipt.production_ready !== false
      || receipt.hardware_access_authorized !== false
      || receipt.authoritative !== false) {
    throw new Error(`${label} semantic, cleanup, device-state, or authority flags are invalid`);
  }
  const profileBindings = {
    validator_id: "validator_id",
    validator_registry_digest: "validator_registry_digest",
    provider_id: "provider_id",
    operation_id: "operation_id",
    semantic_manifest_digest: "semantic_manifest_digest",
    source_profile_digest: "source_profile_digest",
    codec_profile_digest: "codec_profile_digest",
    operation_schema_digest: "operation_schema_digest",
    canonical_request_digest: "canonical_request_digest",
  };
  for (const [receiptField, profileField] of Object.entries(profileBindings)) {
    if (receipt[receiptField]
        !== CHAMELEON_GET_APP_VERSION_SEMANTIC_VALIDATOR_PROFILE[profileField]) {
      throw new Error(`${label}.${receiptField} drifted from the fixed validator registry`);
    }
  }
  if (receipt.operation_schema_id
      !== CHAMELEON_GET_APP_VERSION_SEMANTIC_VALIDATOR_PROFILE.schema_id) {
    throw new Error(`${label}.operation_schema_id drifted from the fixed validator registry`);
  }
  const rawBindings = {
    execution_lineage_digest: lineage.execution_lineage_digest,
    raw_custody_receipt_digest: rawReceipt.raw_custody_receipt_digest,
    raw_custody_cleanup_receipt_digest: cleanupReceipt.cleanup_receipt_digest,
    vault_reservation_digest: reservation.vault_reservation_digest,
    vault_ingest_capability_digest: reservation.vault_ingest_capability_digest,
    artifact_handle: reservation.artifact_handle,
    response_digest: rawReceipt.response_digest,
    response_byte_length: rawReceipt.response_byte_length,
    transport_settlement_kind: observation.transport_settlement_kind,
    dispatch_envelope_digest: observation.dispatch_envelope_digest,
    settled_monotonic_ns: observation.settled_monotonic_ns,
  };
  for (const [field, value] of Object.entries(rawBindings)) {
    if (receipt[field] !== value) throw new Error(`${label}.${field} drifted from raw custody`);
  }
  if (receipt.decoded_payload_digest
      !== decodedGetAppVersionPayloadDigest(receipt.application_version)) {
    throw new Error(`${label}.decoded_payload_digest is invalid`);
  }
  const settledMs = Number(BigInt(receipt.settled_monotonic_ns) / 1000000n);
  if (!Number.isSafeInteger(settledMs)
      || receipt.trusted_monotonic_ms - settledMs !== receipt.validation_age_ms) {
    throw new Error(`${label}.validation_age_ms is detached from trusted monotonic time`);
  }
  const sampleProjection = trustedClockSampleProjectionFromSemanticReceipt(receipt);
  if (receipt.trusted_clock_sample_digest !== sha256(canonicalJson(sampleProjection))) {
    throw new Error(`${label}.trusted_clock_sample_digest is invalid`);
  }
  const projection = projectionWithoutField(
    receipt,
    CHAMELEON_GET_APP_VERSION_SEMANTIC_RECEIPT_FIELDS,
    "semantic_observation_digest",
  );
  if (receipt.semantic_observation_digest !== digestRecord(
    CHAMELEON_GET_APP_VERSION_SEMANTIC_OBSERVATION_DIGEST_DOMAIN,
    projection,
  )) {
    throw new Error(`${label}.semantic_observation_digest is invalid`);
  }
  return objectFreeze({
    ...projection,
    semantic_observation_digest: receipt.semantic_observation_digest,
  });
}

function brandChameleonGetAppVersionSemanticReceipt(value) {
  const output = objectFreeze({ ...value });
  CHAMELEON_GET_APP_VERSION_SEMANTIC_RECEIPTS.add(output);
  return output;
}

function assertChameleonGetAppVersionSemanticObservationReceipt(value) {
  if (!CHAMELEON_GET_APP_VERSION_SEMANTIC_RECEIPTS.has(value)) {
    throw new Error(
      "Chameleon get_app_version semantic observation receipt is not privately branded",
    );
  }
  return value;
}

function createChameleonGetAppVersionSemanticValidationPort(vault, input) {
  const label = "create_chameleon_get_app_version_semantic_validation_port_request";
  const descriptors = assertExactDataObject(
    input,
    ["version", "kind", "trusted_clock_port"],
    label,
  );
  assertVersion(descriptorValue(descriptors, "version"), label);
  if (descriptorValue(descriptors, "kind") !== label) {
    throw new Error(`${label}.kind is invalid`);
  }
  const trustedClockPort = assertPhysicalTrustedClockPort(
    descriptorValue(descriptors, "trusted_clock_port"),
  );
  const owner = getProviderResponseVaultOwner(vault);
  owner.with_lock(() => ensureReceiptRoot(owner));
  const profile = CHAMELEON_GET_APP_VERSION_SEMANTIC_VALIDATOR_PROFILE;
  const port = objectFreeze({
    version: PROVIDER_RESPONSE_VAULT_VERSION,
    kind: "chameleon_get_app_version_semantic_validation_port",
    validator_id: profile.validator_id,
    validator_registry_digest: profile.validator_registry_digest,
    semantic_manifest_digest: profile.semantic_manifest_digest,
    source_profile_digest: profile.source_profile_digest,
    codec_profile_digest: profile.codec_profile_digest,
    operation_schema_id: profile.schema_id,
    operation_schema_digest: profile.operation_schema_digest,
    canonical_request_digest: profile.canonical_request_digest,
    requested_effects_digest: profile.requested_effects_digest,
    maximum_validation_age_ms: profile.maximum_validation_age_ms,
    production_ready: false,
    hardware_access_authorized: false,
    execution_authority: false,
    byte_input_accepted: false,
    callback_input_accepted: false,
    module_path_input_accepted: false,
    operation_input_accepted: false,
    readiness_input_accepted: false,
    toJSON() {
      return {
        version: PROVIDER_RESPONSE_VAULT_VERSION,
        kind: "chameleon_get_app_version_semantic_validation_port",
        validator_id: profile.validator_id,
        validator_registry_digest: profile.validator_registry_digest,
        semantic_manifest_digest: profile.semantic_manifest_digest,
        source_profile_digest: profile.source_profile_digest,
        codec_profile_digest: profile.codec_profile_digest,
        operation_schema_id: profile.schema_id,
        operation_schema_digest: profile.operation_schema_digest,
        canonical_request_digest: profile.canonical_request_digest,
        requested_effects_digest: profile.requested_effects_digest,
        maximum_validation_age_ms: profile.maximum_validation_age_ms,
        production_ready: false,
        hardware_access_authorized: false,
        execution_authority: false,
        byte_input_accepted: false,
        callback_input_accepted: false,
        module_path_input_accepted: false,
        operation_input_accepted: false,
        readiness_input_accepted: false,
      };
    },
  });
  registerSemanticValidationPort(port, objectFreeze({
    owner,
    vault,
    trusted_clock_port: trustedClockPort,
  }));
  return port;
}

function assertFixedChameleonGetAppVersionLineage(lineage, rawReceipt) {
  const profile = CHAMELEON_GET_APP_VERSION_SEMANTIC_VALIDATOR_PROFILE;
  const expected = {
    provider_id: profile.provider_id,
    operation_id: profile.operation_id,
    compiler_id: profile.compiler_id,
    compiler_manifest_digest: profile.semantic_manifest_digest,
    compiler_registry_digest: profile.validator_registry_digest,
    source_profile_digest: profile.source_profile_digest,
    schema_id: profile.schema_id,
    capability_id: profile.capability_id,
    variant_id: profile.variant_id,
    parameter_selector_id: profile.parameter_selector_id,
    canonical_command_digest: profile.canonical_request_digest,
    compiled_operation_digest: profile.compiled_operation_digest,
    requested_effects_digest: profile.requested_effects_digest,
    expected_result_code: profile.expected_result_code,
    active_command_input_digest: profile.canonical_request_digest,
  };
  for (const [field, value] of Object.entries(expected)) {
    if (lineage[field] !== value) {
      throw new Error(`Chameleon get_app_version semantic lineage ${field} drifted`);
    }
  }
  for (const field of [
    "execution_lineage_digest",
    "provider_id",
    "operation_id",
    "compiler_id",
    "compiler_manifest_digest",
    "compiler_registry_digest",
    "source_profile_digest",
    "compiled_operation_digest",
    "requested_effects_digest",
    "active_command_input_digest",
    "vault_reservation_digest",
    "vault_ingest_capability_digest",
  ]) {
    if (objectHasOwn(rawReceipt, field) && rawReceipt[field] !== lineage[field]) {
      throw new Error(`Chameleon get_app_version raw receipt ${field} drifted from lineage`);
    }
  }
  if (rawReceipt.transport_settlement_kind
      !== "native-settlement:fixture_complete_non_authorizing") {
    throw new Error("Chameleon semantic validation requires exact complete native settlement");
  }
}

function normalizeChameleonSemanticValidationRequest(input) {
  const label = "validate_chameleon_get_app_version_raw_custody_request";
  const descriptors = assertExactDataObject(
    input,
    ["version", "kind", "lineage", "raw_custody_receipt"],
    label,
  );
  assertVersion(descriptorValue(descriptors, "version"), label);
  if (descriptorValue(descriptors, "kind") !== label) {
    throw new Error(`${label}.kind is invalid`);
  }
  return objectFreeze({
    lineage: normalizeTransportLineage(descriptorValue(descriptors, "lineage")),
    raw_custody_receipt: assertProviderResponseRawCustodyReceipt(
      descriptorValue(descriptors, "raw_custody_receipt"),
    ),
  });
}

function assertSemanticValidationRequestMatchesState(owner, request, state) {
  if (!["raw_custody_committed", "semantic_observation_committed"].includes(state.state)
      || !state.raw_custody_receipt
      || canonicalJson(state.lineage) !== canonicalJson(request.lineage)
      || canonicalJson(state.raw_custody_receipt)
        !== canonicalJson(request.raw_custody_receipt)) {
    throw new Error(
      "semantic validation request is detached from the exact raw receipt or execution lineage",
    );
  }
  assertReservationJournalFenceMatches(
    owner,
    state.reservation,
    state.lineage,
    "raw_custody",
  );
  assertFixedChameleonGetAppVersionLineage(
    state.lineage,
    state.raw_custody_receipt,
  );
  if (!state.plaintext_cleanup_receipt) {
    throw new Error(
      "Chameleon semantic validation requires durable native plaintext cleanup confirmation",
    );
  }
}

function decodeFixedChameleonGetAppVersionArtifact(plaintext) {
  const parser = createFrameParser();
  const pushed = parser.push(plaintext);
  const finished = parser.finish();
  const frames = [...pushed.frames, ...finished.frames];
  try {
    if (pushed.errors.length !== 0 || finished.errors.length !== 0
        || pushed.stream_tainted || finished.stream_tainted
        || pushed.buffered_bytes !== 0 || finished.buffered_bytes !== 0
        || pushed.poisoned || finished.poisoned || frames.length !== 1) {
      throw new Error(
        "Chameleon get_app_version raw artifact must contain exactly one untainted complete frame",
      );
    }
    return assertChameleonGetAppVersionDecodedPayload(
      decodeChameleonGetAppVersionResponsePayload(frames[0]),
    );
  } finally {
    for (const frame of frames) eraseDecodedFrameCustodyBytes(frame);
  }
}

function assertFreshSemanticTrustedTime(sampleInput, state) {
  const sample = assertPhysicalTrustedClockSample(sampleInput);
  if (sample.max_uncertainty_ms
      > CHAMELEON_GET_APP_VERSION_MAX_CLOCK_UNCERTAINTY_MS) {
    throw new Error("Chameleon semantic trusted clock uncertainty exceeds the fixed ceiling");
  }
  const settledMs = Number(
    BigInt(state.transport_observation.settled_monotonic_ns) / 1000000n,
  );
  if (!Number.isSafeInteger(settledMs) || settledMs > sample.monotonic_ms) {
    throw new Error("Chameleon semantic settlement time is future or belongs to another epoch");
  }
  const validationAgeMs = sample.monotonic_ms - settledMs;
  if (validationAgeMs > CHAMELEON_GET_APP_VERSION_MAX_VALIDATION_AGE_MS) {
    throw new Error("Chameleon semantic raw custody is stale");
  }
  const earliest = Date.parse(sample.trusted_utc_earliest);
  const latest = Date.parse(sample.trusted_utc_latest);
  for (const [field, value] of [
    ["vault commit", state.vault_committed_at],
    ["plaintext cleanup", state.plaintext_cleanup_receipt.cleanup_reconciled_at],
  ]) {
    const recorded = Date.parse(value);
    if (recorded > earliest || latest - recorded > CHAMELEON_GET_APP_VERSION_MAX_VALIDATION_AGE_MS) {
      throw new Error(`Chameleon semantic ${field} time is future or stale`);
    }
  }
  return objectFreeze({ sample, validation_age_ms: validationAgeMs });
}

function createChameleonGetAppVersionSemanticReceipt(state, decoded, timing) {
  const profile = CHAMELEON_GET_APP_VERSION_SEMANTIC_VALIDATOR_PROFILE;
  const raw = state.raw_custody_receipt;
  const cleanup = state.plaintext_cleanup_receipt;
  const sample = timing.sample;
  const projection = {
    version: PROVIDER_RESPONSE_VAULT_VERSION,
    kind: "chameleon_get_app_version_semantic_observation_receipt",
    validator_id: profile.validator_id,
    validator_registry_digest: profile.validator_registry_digest,
    execution_lineage_digest: state.execution_lineage_digest,
    raw_custody_receipt_digest: raw.raw_custody_receipt_digest,
    raw_custody_cleanup_receipt_digest: cleanup.cleanup_receipt_digest,
    vault_reservation_digest: state.reservation.vault_reservation_digest,
    vault_ingest_capability_digest: state.reservation.vault_ingest_capability_digest,
    artifact_handle: state.reservation.artifact_handle,
    response_digest: raw.response_digest,
    response_byte_length: raw.response_byte_length,
    provider_id: profile.provider_id,
    operation_id: profile.operation_id,
    semantic_manifest_digest: profile.semantic_manifest_digest,
    source_profile_digest: profile.source_profile_digest,
    codec_profile_digest: profile.codec_profile_digest,
    operation_schema_id: profile.schema_id,
    operation_schema_digest: profile.operation_schema_digest,
    canonical_request_digest: profile.canonical_request_digest,
    command_id: decoded.command_id,
    status: decoded.status,
    application_version: decoded.response_fields.application_version,
    decoded_payload_digest: decoded.decoded_payload_digest,
    transport_settlement_kind: raw.transport_settlement_kind,
    dispatch_envelope_digest: raw.dispatch_envelope_digest,
    settled_monotonic_ns: raw.settled_monotonic_ns,
    validation_age_ms: timing.validation_age_ms,
    validated_at: sample.trusted_utc,
    validated_at_earliest: sample.trusted_utc_earliest,
    validated_at_latest: sample.trusted_utc_latest,
    trusted_clock_id: sample.clock_id,
    trusted_monotonic_epoch_id: sample.monotonic_epoch_id,
    trusted_monotonic_ms: sample.monotonic_ms,
    trusted_clock_mapping_generation: sample.mapping_generation,
    trusted_clock_mapping_digest: sample.signed_mapping_digest,
    trusted_clock_max_uncertainty_ms: sample.max_uncertainty_ms,
    trusted_clock_trust_root_epoch: sample.trust_root_epoch,
    trusted_clock_authority_epoch: sample.authority_epoch,
    trusted_clock_revocation_generation: sample.revocation_generation,
    trusted_clock_sample_digest: sha256(canonicalJson(sample)),
    semantic_validation_performed: true,
    plaintext_cleanup_reconciled: true,
    device_state_claim_emitted: false,
    production_ready: false,
    hardware_access_authorized: false,
    authoritative: false,
  };
  return objectFreeze({
    ...projection,
    semantic_observation_digest: digestRecord(
      CHAMELEON_GET_APP_VERSION_SEMANTIC_OBSERVATION_DIGEST_DOMAIN,
      projection,
    ),
  });
}

function validateChameleonGetAppVersionRawCustody(port, input) {
  assertProviderResponseSemanticValidationPort(port);
  const request = normalizeChameleonSemanticValidationRequest(input);
  const portState = readSemanticValidationPortPrivate(port);
  const { owner, vault } = portState;
  owner.assert_live();
  let state = owner.with_lock(() => {
    const current = readRawCustodyStateFile(
      owner,
      request.lineage.execution_lineage_digest,
    );
    const reconciled = reconcileRawCustodyPreparedStateLocked(owner, current);
    assertSemanticValidationRequestMatchesState(owner, request, reconciled);
    return reconciled;
  });
  if (state.semantic_observation_receipt) {
    return brandChameleonGetAppVersionSemanticReceipt(
      state.semantic_observation_receipt,
    );
  }

  let plaintext = null;
  let decoded;
  let proposed;
  try {
    assertFreshSemanticTrustedTime(
      samplePhysicalTrustedClock(portState.trusted_clock_port),
      state,
    );
    const materialized = materializeForWorker(vault, state.reservation.artifact_handle);
    plaintext = materialized.plaintext;
    if (!bufferIsBuffer(plaintext)
        || canonicalJson(materialized.metadata) !== canonicalJson(state.metadata)
        || plaintext.length !== state.response_byte_length
        || sha256(plaintext) !== state.response_digest) {
      throw new Error("vault materialization drifted from exact raw custody");
    }
    decoded = decodeFixedChameleonGetAppVersionArtifact(plaintext);
    const timing = assertFreshSemanticTrustedTime(
      samplePhysicalTrustedClock(portState.trusted_clock_port),
      state,
    );
    proposed = createChameleonGetAppVersionSemanticReceipt(state, decoded, timing);
    normalizeChameleonGetAppVersionSemanticReceipt(
      proposed,
      state.lineage,
      state.reservation,
      state.raw_custody_receipt,
      state.plaintext_cleanup_receipt,
      state.transport_observation,
    );
  } finally {
    if (plaintext) plaintext.fill(0);
  }

  state = owner.with_lock(() => {
    const current = readRawCustodyStateFile(
      owner,
      request.lineage.execution_lineage_digest,
    );
    assertSemanticValidationRequestMatchesState(owner, request, current);
    if (current.semantic_observation_receipt) return current;
    const normalized = normalizeChameleonGetAppVersionSemanticReceipt(
      proposed,
      current.lineage,
      current.reservation,
      current.raw_custody_receipt,
      current.plaintext_cleanup_receipt,
      current.transport_observation,
    );
    const next = objectFreeze({
      ...current,
      state: "semantic_observation_committed",
      semantic_observation_receipt: normalized,
    });
    writeStateFile(owner, next);
    return readRawCustodyStateFile(owner, current.execution_lineage_digest);
  });
  if (state.state !== "semantic_observation_committed"
      || !state.semantic_observation_receipt) {
    throw new Error("Chameleon semantic observation receipt is not durably readable");
  }
  return brandChameleonGetAppVersionSemanticReceipt(
    state.semantic_observation_receipt,
  );
}

function readChameleonGetAppVersionSemanticObservationReceipt(port, input) {
  assertProviderResponseSemanticValidationPort(port);
  const request = normalizeReadbackRequest(
    input,
    "read_chameleon_get_app_version_semantic_observation_receipt_request",
  );
  const { owner } = readSemanticValidationPortPrivate(port);
  owner.assert_live();
  const state = owner.with_lock(() => {
    const current = readRawCustodyStateFile(
      owner,
      request.execution_lineage_digest,
    );
    assertReservationJournalFenceMatches(
      owner,
      current.reservation,
      current.lineage,
      "raw_custody",
    );
    return current;
  });
  if (state.state !== "semantic_observation_committed"
      || !state.semantic_observation_receipt) {
    throw new Error("Chameleon semantic observation receipt is not durably readable");
  }
  return brandChameleonGetAppVersionSemanticReceipt(
    state.semantic_observation_receipt,
  );
}

// Data-only registration: the neutral vault state layer re-validates an embedded
// semantic receipt by looking this normalizer up by its receipt kind, never by
// naming the provider.
registerSemanticReceiptNormalizer(
  CHAMELEON_GET_APP_VERSION_SEMANTIC_RECEIPT_KIND,
  normalizeChameleonGetAppVersionSemanticReceipt,
);

module.exports = {
  CHAMELEON_GET_APP_VERSION_SEMANTIC_VALIDATOR_PROFILE,
  PROVIDER_SEMANTIC_VALIDATION_ASSURANCE,
  assertChameleonGetAppVersionSemanticObservationReceipt,
  createChameleonGetAppVersionSemanticValidationPort,
  readChameleonGetAppVersionSemanticObservationReceipt,
  validateChameleonGetAppVersionRawCustody,
};
