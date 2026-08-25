"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const { createArtifactVault } = require("../../bob-artifact-vault/index.js");
const WORKER = require("../../bob-artifact-vault/worker.js");
const {
  NATIVE_PROVIDER_RESPONSE_RECORD_HEADER_BYTES,
  consumeNativeProviderResponseRecord,
  nativeProviderResponseSinkWriteDescriptor,
  prepareNativeProviderResponseSink,
  revokeNativeProviderResponseSinkWriteDescriptor,
} = WORKER;
const {
  confirmProviderResponseRawCustodyPlaintextCleanup,
  createProviderResponseRawCustodyReceiptPort,
  createProviderResponseSink,
} = require("../../bob-artifact-vault/lib/provider-response-vault.js");
const {
  CHAMELEON_GET_APP_VERSION_SEMANTIC_VALIDATOR_PROFILE,
  createChameleonGetAppVersionSemanticValidationPort,
  validateChameleonGetAppVersionRawCustody,
} = require("../lib/get-app-version-semantic-validator.js");
const {
  createInProcessBackupKeyCustodyFixture,
} = require("../../../test/helpers/artifact-vault-backup-key-custody.js");
const {
  signNativeDispatchTicket,
} = require("../../bob-instrument-broker/lib/native-dispatch-contract.js");
const {
  PROVIDER_COMPLETION_EVIDENCE_PRODUCTION_BLOCKERS,
  _internals,
  assertChameleonGetAppVersionProviderCompletionEvidenceAdapter,
  createChameleonGetAppVersionProviderCompletionEvidenceAdapter,
  deriveChameleonGetAppVersionProviderClaimFromReceipts,
  readCommittedChameleonGetAppVersionProviderCompletionEvidence,
  verifyAndCommitChameleonGetAppVersionProviderCompletionEvidence,
} = require("../lib/provider-completion-evidence-adapter.js");
const {
  assertPhysicalProviderCompletionVerificationPort,
  createPhysicalProviderCompletionVerificationPortFromFixedAdapter,
} = require("../../bob-instrument-broker/lib/physical-provider-dispatch.js");
const {
  TRUSTED_CLOCK_MAPPING_DOMAIN,
  createPhysicalTrustedClockPort,
  physicalClockMappingSigningMessage,
  publicKeyDigest,
} = require("../../../mcp/domains/physical/physical-trusted-clock.js");
const {
  hashCanonicalJson,
} = require("../../../mcp/core/verification/verification-contracts.js");

const SESSION_HASH = "a".repeat(64);
const LINEAGE_DOMAIN = "hacker-bob/provider-worker-vault-execution-lineage/v1";
const ACTIVE_ADMISSION_DOMAIN =
  "hacker-bob/physical-provider-active-admission-binding/v1";
let sequence = 0;

function digest(label) {
  return crypto.createHash("sha256").update(`completion-adapter-test:${label}`, "utf8")
    .digest("hex");
}

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value != null && typeof value === "object") {
    const output = Object.create(null);
    for (const key of Object.keys(value).sort()) output[key] = canonicalize(value[key]);
    return output;
  }
  return value;
}

function recordDigest(domain, projection) {
  return crypto.createHash("sha256")
    .update(JSON.stringify(canonicalize({ domain, ...projection })), "utf8")
    .digest("hex");
}

function makeAnchor(digestField) {
  const states = new Map();
  return Object.freeze({
    readState({ vault_slot: vaultSlot }) {
      const state = states.get(vaultSlot);
      return state == null ? null : structuredClone(state);
    },
    compareAndSet(request) {
      const current = states.get(request.vault_slot) || null;
      const matches = current == null
        ? request.expected_generation == null && request[`expected_${digestField}`] == null
        : request.expected_generation === current.generation
          && request[`expected_${digestField}`] === current[digestField];
      if (!matches) return false;
      states.set(request.vault_slot, structuredClone(request.next_state));
      return true;
    },
  });
}

function makeVault(t) {
  sequence += 1;
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), "bob-completion-adapter-"));
  const root = path.join(parent, "vault");
  const vaultId = `vault:v1:${crypto.randomBytes(32).toString("base64url")}`;
  const vaultSlot = `vault-slot:v1:${crypto.randomBytes(32).toString("base64url")}`;
  const masterKey = crypto.randomBytes(32);
  const custody = createInProcessBackupKeyCustodyFixture({
    vaultId,
    vaultSlot,
    sessionNucleusHash: SESSION_HASH,
  });
  const deletionLedgerAnchor = makeAnchor("ledger_digest");
  const indexStateAnchor = makeAnchor("index_digest");
  const opened = [];
  function open(createNew) {
    const key = Buffer.from(masterKey);
    try {
      const vault = createArtifactVault({
        root,
        sessionNucleusHash: SESSION_HASH,
        vaultId,
        vaultSlot,
        createNew,
        masterKey: key,
        backupKeyCustody: custody.port,
        deletionLedgerAnchor,
        indexStateAnchor,
        quotaBytes: 2 * 1024 * 1024,
        maxArtifacts: 32,
        minFreeBytes: 0,
      });
      opened.push(vault);
      return vault;
    } finally {
      key.fill(0);
    }
  }
  const setup = {
    vault: open(true),
    reopen() {
      this.vault = open(false);
      return this.vault;
    },
  };
  t.after(() => {
    for (const vault of opened) {
      try { vault.destroy(); } catch {}
    }
    custody.destroy();
    masterKey.fill(0);
    fs.rmSync(parent, { recursive: true, force: true });
  });
  return setup;
}

function trustedClock() {
  sequence += 1;
  const signer = crypto.generateKeyPairSync("ed25519");
  const monotonic = Number(process.hrtime.bigint() / 1000000n);
  const wall = Date.now();
  const payload = {
    version: 1,
    clock_id: `physical-clock:completion-adapter-${sequence}`,
    monotonic_epoch_id: digest(`clock-epoch-${sequence}`),
    mapping_generation: 1,
    reference_monotonic_ms: monotonic,
    reference_utc: new Date(wall).toISOString(),
    max_uncertainty_ms: 0,
    not_before: new Date(wall - 60_000).toISOString(),
    expires_at: new Date(wall + 60 * 60_000).toISOString(),
    trust_root_epoch: 3,
    authority_epoch: 7,
    revocation_generation: 2,
    signer_key_id: `clock-key:completion-adapter-${sequence}`,
    signer_public_key_digest: publicKeyDigest(signer.publicKey),
  };
  const payloadDigest = hashCanonicalJson(payload);
  const signature = crypto.sign(
    null,
    physicalClockMappingSigningMessage(payloadDigest),
    signer.privateKey,
  ).toString("base64url");
  const basis = {
    version: 1,
    domain: TRUSTED_CLOCK_MAPPING_DOMAIN,
    payload,
    payload_digest: payloadDigest,
    scheme: "ed25519",
    signature,
  };
  const mapping = { ...basis, signed_mapping_digest: hashCanonicalJson(basis) };
  return createPhysicalTrustedClockPort({
    port_id: `completion_adapter_clock_${sequence}`,
    clock_id: payload.clock_id,
    monotonic_epoch_id: payload.monotonic_epoch_id,
    uncertainty_ceiling_ms: 1000,
    read_monotonic_ms: () => Number(process.hrtime.bigint() / 1000000n),
    read_signed_mapping: () => mapping,
    resolve_current_trust: () => ({
      version: 1,
      trusted: true,
      revoked: false,
      clock_id: payload.clock_id,
      monotonic_epoch_id: payload.monotonic_epoch_id,
      current_mapping_generation: payload.mapping_generation,
      current_signed_mapping_digest: mapping.signed_mapping_digest,
      trust_root_epoch: payload.trust_root_epoch,
      authority_epoch: payload.authority_epoch,
      revocation_generation: payload.revocation_generation,
      signer_key_id: payload.signer_key_id,
      signer_public_key_digest: payload.signer_public_key_digest,
      public_key: signer.publicKey,
    }),
  });
}

function responseFrame() {
  const data = Buffer.from([2, 2]);
  const frame = Buffer.alloc(12);
  frame[0] = 0x11;
  frame[1] = 0xef;
  frame.writeUInt16BE(1000, 2);
  frame.writeUInt16BE(0x0068, 4);
  frame.writeUInt16BE(data.length, 6);
  let sum = 0;
  for (const byte of frame.subarray(2, 8)) sum = (sum + byte) & 0xff;
  frame[8] = (-sum) & 0xff;
  data.copy(frame, 9);
  frame[11] = (-(data[0] + data[1])) & 0xff;
  data.fill(0);
  return frame;
}

function reserveNativeSink(setup, label) {
  const now = Date.now();
  const request = {
    version: 1,
    session_nucleus_hash: SESSION_HASH,
    task_id: `task-${label}`,
    attempt_id: `attempt-${label}`,
    reservation_ref: `reservation:${label}`,
    purpose_ref: "purpose:completion-adapter",
    byte_ceiling: 64,
    expires_at: new Date(now + 30 * 60_000).toISOString(),
  };
  const reserved = setup.vault.reserve(request);
  const sink = createProviderResponseSink(setup.vault, {
    version: 1,
    reservation_handle: reserved.reservation_handle,
    metadata: {
      version: 1,
      session_nucleus_hash: SESSION_HASH,
      task_id: request.task_id,
      attempt_id: request.attempt_id,
      data_class: "credential_secret",
      media_type: "application/octet-stream",
      source_ref: "provider:chameleon-ultra-completion-adapter",
      retention_expires_at: new Date(now + 60 * 60_000).toISOString(),
    },
  });
  const nativeSink = prepareNativeProviderResponseSink(setup.vault, {
    version: 1,
    sink,
  });
  return { nativeSink, request, sink };
}

function makeLineage(sink, request, label) {
  const profile = CHAMELEON_GET_APP_VERSION_SEMANTIC_VALIDATOR_PROFILE;
  const hash = (field) => digest(`${label}:${field}`);
  const basis = {
    version: 1,
    execution_ref: `execution:${label}`,
    experiment_plan_hash: hash("experiment-plan"),
    exchange_id: `exchange:${label}`,
    grant_envelope_digest: hash("grant-envelope"),
    grant_journal_entry_digest: hash("grant-journal"),
    go_envelope_digest: hash("go-envelope"),
    go_journal_entry_digest: hash("go-journal"),
    session_nucleus_hash: SESSION_HASH,
    task_id: request.task_id,
    attempt_id: request.attempt_id,
    lease_id: `lease:${label}`,
    resource_epoch: "7",
    resource_fence_digest: hash("resource-fence"),
    effect_deadline_monotonic_ns: "18446744073709551615",
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
    provider_command_ref: `command:chameleon-get-app-version-${label}`,
    requested_effects_digest: profile.requested_effects_digest,
    safety_supervisor_plan_digest: hash("safety-plan"),
    runtime_availability: "runtime:fixture-only",
    compiled_command_id: `compiled-command:${label}`,
    compiled_command_capability_digest: hash("compiled-capability"),
    expected_result_code: profile.expected_result_code,
    active_command_input_ref: `command-input:active-${label}`,
    active_command_input_digest: profile.canonical_request_digest,
    cleanup_command_input_ref: `command-input:cleanup-${label}`,
    cleanup_command_input_digest: hash("cleanup-input"),
    maximum_response_bytes: sink.byte_ceiling,
    vault_reservation_handle: sink.vault_reservation_handle,
    vault_reservation_digest: sink.vault_reservation_digest,
    vault_ingest_capability_digest: sink.vault_ingest_capability_digest,
    vault_byte_ceiling: sink.byte_ceiling,
    worker_bundle_digest: hash("worker-bundle"),
    worker_launch_digest: hash("worker-launch"),
    worker_process_instance_digest: hash("worker-process-instance"),
    worker_fence_digest: hash("worker-fence"),
    transport_binding_digest: hash("transport-binding"),
    durable_exchange_plan_digest: hash("durable-exchange"),
    terminal_receipt_recipient_digest: hash("terminal-recipient"),
  };
  return Object.freeze({
    ...basis,
    execution_lineage_digest: recordDigest(LINEAGE_DOMAIN, basis),
  });
}

function nativePayload(lineage, nativeSink, label) {
  const command = Buffer.from([0x11, 0xef, 0x03, 0xe8, 0, 0, 0, 0, 0x15, 0]);
  command[9] = 0;
  const payload = {
    version: 1,
    protocol: "hacker-bob/physical-native-dispatch/v1",
    grant_kind: "bootstrap",
    command_kind: "observe",
    effect_class: "none",
    rf_constraint: "rf_off",
    ticket_id: `native-ticket:${label}`,
    ticket_nonce: Buffer.alloc(24, 7).toString("base64url"),
    ticket_sequence: "1",
    provider_id: lineage.provider_id,
    provider_descriptor_digest: digest(`${label}:provider-descriptor`),
    provider_implementation_digest: digest(`${label}:provider-implementation`),
    semantic_manifest_digest:
      CHAMELEON_GET_APP_VERSION_SEMANTIC_VALIDATOR_PROFILE.semantic_manifest_digest,
    device_identity_digest: digest(`${label}:device-identity`),
    device_enrollment_digest: digest(`${label}:device-enrollment`),
    connection_generation: "4",
    execution_principal_id: `principal:${label}`,
    worker_process_start_digest: digest(`${label}:worker-process-start`),
    worker_bundle_digest: lineage.worker_bundle_digest,
    native_loaded_image_identity_digest: digest(`${label}:native-image`),
    launcher_ticket_digest: digest(`${label}:launcher-ticket`),
    launcher_delegation_receipt_digest: digest(`${label}:launcher-delegation`),
    device_descriptor_inventory_digest: digest(`${label}:descriptor-inventory`),
    session_nucleus_hash: lineage.session_nucleus_hash,
    node_id: "PH-C1",
    contract_hash: digest(`${label}:contract`),
    attempt_ref: `attempt:${label}`,
    signed_grant_digest: digest(`${label}:signed-grant`),
    execution_request_digest: digest(`${label}:execution-request`),
    authority_resolution_digest: digest(`${label}:authority-resolution`),
    authority_epoch: "9",
    revocation_generation: "3",
    operation_id: lineage.operation_id,
    operation_digest: digest(`${label}:operation`),
    parameter_digest: digest(`${label}:parameters`),
    requested_effects_digest: lineage.requested_effects_digest,
    required_pre_state_digest: digest(`${label}:pre-state`),
    authorized_transition_digest: digest(`${label}:transition`),
    resource_bundle_digest: digest(`${label}:resource-bundle`),
    allocation_digest: digest(`${label}:allocation`),
    reservation_receipt_digest: digest(`${label}:effect-receipt`),
    fencing_token_digest: digest(`${label}:fence-token`),
    journal_entry_digest: digest(`${label}:journal`),
    outbox_entry_digest: digest(`${label}:outbox`),
    provider_redemption_digest: digest(`${label}:redemption`),
    safety_contract_digest: lineage.safety_supervisor_plan_digest,
    safety_custody_receipt_digest: digest(`${label}:safety-custody`),
    cleanup_precommit_digest: digest(`${label}:cleanup-precommit`),
    observer_plan_digest: digest(`${label}:observer-plan`),
    command_sequence: "1",
    command_bytes_digest:
      CHAMELEON_GET_APP_VERSION_SEMANTIC_VALIDATOR_PROFILE.canonical_request_digest,
    command_byte_length: 10,
    maximum_response_bytes: lineage.maximum_response_bytes,
    clock_epoch_digest: digest(`${label}:clock-epoch`),
    not_before_monotonic_ns: "1000000000",
    deadline_monotonic_ns: "1500000000",
    one_use: true,
    delegated_descriptor_identity_digest: digest(`${label}:delegated-descriptor`),
    execution_lineage_digest: lineage.execution_lineage_digest,
    vault_reservation_digest: lineage.vault_reservation_digest,
    vault_ingest_capability_digest: lineage.vault_ingest_capability_digest,
    vault_sink_descriptor_identity_digest: nativeSink.vault_sink_descriptor_identity_digest,
    vault_byte_ceiling: lineage.vault_byte_ceiling,
    artifact_handle_digest: nativeSink.artifact_handle_digest,
  };
  command.fill(0);
  return Object.freeze(payload);
}

function activeAdmission(payload, label) {
  return {
    physical_scope_axis_digest: digest(`${label}:scope-axis`),
    physical_scope_policy_id: "physical_scope_policy_v1",
    physical_scope_policy_digest: digest(`${label}:scope-policy`),
    physical_scope_projection_digest: digest(`${label}:scope-projection`),
    authority_epoch: Number(payload.authority_epoch),
    revocation_generation: Number(payload.revocation_generation),
    authority_resolution_digest: payload.authority_resolution_digest,
    caller_role_id: "evaluator-physical",
    requester_principal_id: `principal:requester-${label}`,
    ipc_peer_principal_id: `principal:ipc-${label}`,
    capability_pack_id: "physical",
    capability_pack_version: "1.0.0",
    capability_pack_digest: digest(`${label}:capability-pack`),
    technique_cell_id: "PH-C1",
    inventory_observation_ref: `inventory:${label}`,
    inventory_observation_digest: digest(`${label}:inventory`),
    assurance_profile_id: "physical_chameleon_acceptance_v1",
    assurance_claims_digest: digest(`${label}:assurance`),
    provider_manifest_digest: digest(`${label}:provider-manifest`),
    availability_variant_id: "chameleon_usb_cdc",
    availability_variant_digest: digest(`${label}:availability`),
    authorized_transition_set_digest: digest(`${label}:transition-set`),
    workspace_snapshot_ref: `workspace-snapshot:${label}`,
    workspace_snapshot_digest: digest(`${label}:workspace`),
    observer_plan_digest: payload.observer_plan_digest,
    control_plan_digest: digest(`${label}:control-plan`),
    cleanup_plan_digest: digest(`${label}:cleanup-plan`),
  };
}

function makeCompletionBinding(adapter, lineage, payload, label, overrides = {}) {
  const admission = activeAdmission(payload, label);
  const providerBinding = {
    version: 1,
    provider_id: payload.provider_id,
    provider_descriptor_digest: payload.provider_descriptor_digest,
    semantic_manifest_digest: payload.semantic_manifest_digest,
    device_ref: `device:${label}`,
    device_identity_digest: payload.device_identity_digest,
    custody_ref: `custody:${label}`,
    custody_identity_digest: payload.worker_process_start_digest,
    custody_epoch: Number(payload.connection_generation),
  };
  const now = Date.now();
  const basis = {
    domain: "hacker-bob/physical-provider-completion-binding/v1",
    version: 1,
    experiment_plan_hash: lineage.experiment_plan_hash,
    execution_lineage_digest: lineage.execution_lineage_digest,
    compiler_id: lineage.compiler_id,
    compiler_manifest_digest: lineage.compiler_manifest_digest,
    compiler_registry_digest: lineage.compiler_registry_digest,
    compiled_command_id: lineage.compiled_command_id,
    compiled_command_capability_digest: lineage.compiled_command_capability_digest,
    compiled_operation_digest: lineage.compiled_operation_digest,
    provider_command_ref: lineage.provider_command_ref,
    active_command_input_ref: lineage.active_command_input_ref,
    active_command_input_digest: lineage.active_command_input_digest,
    maximum_response_bytes: lineage.maximum_response_bytes,
    vault_reservation_handle: lineage.vault_reservation_handle,
    vault_reservation_digest: lineage.vault_reservation_digest,
    vault_ingest_capability_digest: lineage.vault_ingest_capability_digest,
    vault_byte_limit: lineage.vault_byte_ceiling,
    worker_bundle_digest: lineage.worker_bundle_digest,
    worker_launch_profile_digest: lineage.worker_launch_digest,
    worker_fence_plan_digest: lineage.worker_fence_digest,
    transport_profile_digest: lineage.transport_binding_digest,
    durable_exchange_plan_digest: lineage.durable_exchange_plan_digest,
    terminal_receipt_recipient_digest: lineage.terminal_receipt_recipient_digest,
    safety_supervisor_plan_digest: lineage.safety_supervisor_plan_digest,
    ...admission,
    active_admission_binding_digest: hashCanonicalJson({
      domain: ACTIVE_ADMISSION_DOMAIN,
      ...admission,
    }),
    completion_verification_port_id: adapter.port_id,
    completion_evidence_domain_digest: adapter.evidence_domain_digest,
    reservation_ref: `reservation:physical-${label}`,
    admission_receipt_digest: digest(`${label}:admission-receipt`),
    effect_receipt_digest: payload.reservation_receipt_digest,
    reservation_request_digest: digest(`${label}:reservation-request`),
    reservation_binding_digest: digest(`${label}:reservation-binding`),
    node_id: payload.node_id,
    contract_hash: payload.contract_hash,
    source_graph_hash: digest(`${label}:source-graph`),
    session_nucleus_hash: payload.session_nucleus_hash,
    resource_bundle_digest: payload.resource_bundle_digest,
    allocation_plan_digest: digest(`${label}:allocation-plan`),
    allocation_digest: payload.allocation_digest,
    attempt_ref: payload.attempt_ref,
    execution_principal_ref: payload.execution_principal_id,
    session_id: `session-${label}`,
    admission_credential_binding_digest: digest(`${label}:admission-credential`),
    effect_credential_binding_digest: digest(`${label}:effect-credential`),
    effect_authorization_digest: digest(`${label}:effect-authorization`),
    fencing_semantics: "exclusive_generation_fence",
    effect_not_before: new Date(now - 1000).toISOString(),
    effect_deadline: new Date(now + 60_000).toISOString(),
    task_graph_dispatch_head_fence_digest: digest(`${label}:reservation-binding`),
    prep_token_hash: digest(`${label}:prep-token`),
    dispatch_event_id: `dispatch-event:${label}`,
    graph_context_hash: digest(`${label}:graph-context`),
    ...providerBinding,
    provider_binding_digest: hashCanonicalJson(providerBinding),
    command_kind: "command",
    command_ref: lineage.provider_command_ref,
    operation_id: payload.operation_id,
    operation_digest: payload.operation_digest,
    semantic_owner_ref: `semantic-owner:${label}`,
    semantic_owner_digest: digest(`${label}:semantic-owner`),
    requested_effect_digest: digest(`${label}:requested-effect`),
    requested_effects_digest: payload.requested_effects_digest,
    command_projection_digest: digest(`${label}:command-projection`),
    command_authorization_digest: digest(`${label}:command-authorization`),
    semantic_authority_digest: digest(`${label}:semantic-authority`),
    authorization_epoch: 4,
    reservation_command_authority_digest: digest(`${label}:reservation-command-authority`),
    resource_alias: "chameleon_primary",
    resource_ref: `instrument:${label}`,
    resource_requirement_digest: digest(`${label}:resource-requirement`),
    command_input_ref: lineage.active_command_input_ref,
    command_input_digest: lineage.active_command_input_digest,
    command_sequence: Number(payload.command_sequence),
    provider_dispatch_capability_digest: digest(`${label}:dispatch-capability`),
    ...overrides,
  };
  return Object.freeze({ ...basis, completion_binding_digest: hashCanonicalJson(basis) });
}

function rebuildBinding(input, overrides) {
  const { completion_binding_digest: ignored, ...basis } = structuredClone(input);
  Object.assign(basis, overrides);
  const admission = {};
  for (const field of _internals.ACTIVE_ADMISSION_BINDING_FIELDS) {
    admission[field] = basis[field];
  }
  basis.active_admission_binding_digest = hashCanonicalJson({
    domain: ACTIVE_ADMISSION_DOMAIN,
    ...admission,
  });
  return Object.freeze({ ...basis, completion_binding_digest: hashCanonicalJson(basis) });
}

function makeNativeRecord(nativeSink, lineage, payload, ticket, responseInput) {
  const response = Buffer.from(responseInput);
  const header = Buffer.alloc(NATIVE_PROVIDER_RESPONSE_RECORD_HEADER_BYTES);
  header.write("HBPHVSR1", 0, "ascii");
  header.writeUInt16BE(1, 8);
  header.writeUInt16BE(3, 10);
  header.writeUInt32BE(response.length, 12);
  header.writeBigUInt64BE(BigInt(payload.ticket_sequence), 16);
  const responseDigest = crypto.createHash("sha256").update(response).digest("hex");
  for (const [offset, value] of [
    [24, lineage.execution_lineage_digest],
    [56, ticket.envelope_digest],
    [88, payload.delegated_descriptor_identity_digest],
    [120, nativeSink.vault_sink_descriptor_identity_digest],
    [152, nativeSink.vault_reservation_digest],
    [184, nativeSink.vault_ingest_capability_digest],
    [216, nativeSink.artifact_handle_digest],
    [248, responseDigest],
  ]) Buffer.from(value, "hex").copy(header, offset);
  const sinkRecordDigest = crypto.createHash("sha256").update(header).digest("hex");
  const record = Buffer.concat([header, response]);
  header.fill(0);
  response.fill(0);
  return {
    record,
    terminal: {
      version: 1,
      status: "fixture_complete_non_authorizing",
      wrote_any_command_bytes: true,
      dispatch_signature_verified: true,
      descriptor_identity_verified: true,
      deadline_rechecked_before_first_write: true,
      response_sink_committed: true,
      response_byte_length: record.length - NATIVE_PROVIDER_RESPONSE_RECORD_HEADER_BYTES,
      ticket_sequence: payload.ticket_sequence,
      settled_continuous_ns: process.hrtime.bigint().toString(),
      dispatch_envelope_digest: ticket.envelope_digest,
      delegated_descriptor_identity_digest: payload.delegated_descriptor_identity_digest,
      response_digest: responseDigest,
      vault_sink_descriptor_identity_digest: nativeSink.vault_sink_descriptor_identity_digest,
      vault_sink_record_digest: sinkRecordDigest,
      production_ready: false,
      hardware_access_authorized: false,
      authoritative: false,
    },
  };
}

function consumeRecord(nativeSink, lineage, fixture) {
  const descriptor = nativeProviderResponseSinkWriteDescriptor(nativeSink);
  try {
    let offset = 0;
    while (offset < fixture.record.length) {
      offset += fs.writeSync(
        descriptor,
        fixture.record,
        offset,
        fixture.record.length - offset,
      );
    }
    fs.fsyncSync(descriptor);
  } finally {
    revokeNativeProviderResponseSinkWriteDescriptor(nativeSink);
    fixture.record.fill(0);
  }
  return consumeNativeProviderResponseRecord(nativeSink, {
    version: 1,
    kind: "consume_native_provider_response_record_request",
    lineage,
    native_terminal_result: fixture.terminal,
    execution_claim_receipt_digest: digest("execution-claim"),
    deadline_fence_receipt_digest: digest("deadline-fence"),
  });
}

function makeFixture(t, label) {
  const setup = makeVault(t);
  const clock = trustedClock();
  const { nativeSink, request, sink } = reserveNativeSink(setup, label);
  const lineage = makeLineage(sink, request, label);
  const payload = nativePayload(lineage, nativeSink, label);
  const signer = crypto.generateKeyPairSync("ed25519");
  const keyId = `native-dispatch-key:${label}`;
  const ticket = signNativeDispatchTicket({
    payload,
    key_id: keyId,
    private_key: signer.privateKey,
  });
  const rawPort = createProviderResponseRawCustodyReceiptPort(setup.vault);
  const semanticPort = createChameleonGetAppVersionSemanticValidationPort(setup.vault, {
    version: 1,
    kind: "create_chameleon_get_app_version_semantic_validation_port_request",
    trusted_clock_port: clock,
  });
  const publicKeyPem = signer.publicKey.export({ type: "spki", format: "pem" });
  const adapterInput = {
    version: 1,
    kind: "create_provider_completion_evidence_adapter_request",
    raw_custody_receipt_port: rawPort,
    semantic_validation_port: semanticPort,
    native_dispatch_ticket: ticket,
    native_dispatch_public_key_pem: publicKeyPem,
    native_dispatch_key_id: keyId,
  };
  const adapter = createChameleonGetAppVersionProviderCompletionEvidenceAdapter(adapterInput);
  const binding = makeCompletionBinding(adapter, lineage, payload, label);
  function commit() {
    const fixture = makeNativeRecord(nativeSink, lineage, payload, ticket, responseFrame());
    const raw = consumeRecord(nativeSink, lineage, fixture);
    assert.equal(confirmProviderResponseRawCustodyPlaintextCleanup(setup.vault, raw), true);
    const semantic = validateChameleonGetAppVersionRawCustody(semanticPort, {
      version: 1,
      kind: "validate_chameleon_get_app_version_raw_custody_request",
      lineage,
      raw_custody_receipt: raw,
    });
    return { raw, semantic };
  }
  return {
    adapter,
    adapterInput,
    binding,
    clock,
    commit,
    keyId,
    lineage,
    payload,
    publicKeyPem,
    setup,
    ticket,
  };
}

test("fixed adapter joins only durable native/raw/semantic evidence and cold-restarts", (t) => {
  const fx = makeFixture(t, "durable-join");
  assert.equal(assertChameleonGetAppVersionProviderCompletionEvidenceAdapter(fx.adapter), fx.adapter);
  assert.equal(fx.adapter.production_ready, false);
  assert.equal(fx.adapter.callback_input_accepted, false);
  assert.equal(fx.adapter.module_path_input_accepted, false);
  assert.equal(fx.adapter.response_byte_input_accepted, false);
  assert.equal(fx.adapter.readiness_input_accepted, false);
  for (const blocker of [
    "independently_enrolled_native_dispatch_trust_owner_missing",
    "current_provider_principal_trust_verification_missing",
    "external_monotonic_completion_receipt_anchor_missing",
    "provider_cleanup_completion_semantics_missing",
    "hardware_in_loop_qualification_missing",
  ]) assert.ok(PROVIDER_COMPLETION_EVIDENCE_PRODUCTION_BLOCKERS.includes(blocker));

  const fixedPort = createPhysicalProviderCompletionVerificationPortFromFixedAdapter(fx.adapter);
  assert.equal(assertPhysicalProviderCompletionVerificationPort(fixedPort), fixedPort);
  assert.equal(fixedPort.port_id, fx.adapter.port_id);
  assert.equal(fixedPort.evidence_domain_digest, fx.adapter.evidence_domain_digest);
  assert.equal(fixedPort.production_ready, false);
  assert.equal(
    fixedPort.durability_assurance,
    "broker_fixed_authenticated_vault_raw_semantic_receipt_projection_nonproduction",
  );

  const before = readCommittedChameleonGetAppVersionProviderCompletionEvidence(fx.adapter, {
    version: 1,
    completion_binding: fx.binding,
  });
  assert.equal(before, null, "an absent durable raw receipt is not invented");

  const receipts = fx.commit();
  const claim = deriveChameleonGetAppVersionProviderClaimFromReceipts(
    receipts.raw,
    receipts.semantic,
  );
  const committed = verifyAndCommitChameleonGetAppVersionProviderCompletionEvidence(
    fx.adapter,
    {
      version: 1,
      completion_binding: fx.binding,
      provider_claim: claim,
    },
  );
  assert.equal(committed.completion, "confirmed");
  assert.equal(committed.effect_disposition, "requested_effect_committed");
  assert.equal(committed.completion_binding_digest, fx.binding.completion_binding_digest);
  assert.equal(committed.provider_result_digest, claim.provider_result_digest);
  assert.match(committed.committed_receipt_ref, /^completion-receipt:/u);
  assert.match(committed.completion_evidence_digest, /^[a-f0-9]{64}$/u);
  assert.equal(Object.hasOwn(committed, "application_version"), false);
  assert.equal(Object.hasOwn(committed, "response_digest"), false);
  assert.equal(JSON.stringify(committed).includes("2.2"), false);

  const again = readCommittedChameleonGetAppVersionProviderCompletionEvidence(fx.adapter, {
    version: 1,
    completion_binding: fx.binding,
  });
  assert.deepEqual(again, committed);

  const reopened = fx.setup.reopen();
  const coldAdapter = createChameleonGetAppVersionProviderCompletionEvidenceAdapter({
    ...fx.adapterInput,
    raw_custody_receipt_port: createProviderResponseRawCustodyReceiptPort(reopened),
    semantic_validation_port: createChameleonGetAppVersionSemanticValidationPort(reopened, {
      version: 1,
      kind: "create_chameleon_get_app_version_semantic_validation_port_request",
      trusted_clock_port: fx.clock,
    }),
  });
  const cold = readCommittedChameleonGetAppVersionProviderCompletionEvidence(coldAdapter, {
    version: 1,
    completion_binding: fx.binding,
  });
  assert.deepEqual(cold, committed, "cold readback derives the same evidence from durable receipts");
});

test("fixed adapter rejects replay transplant, claim drift, and type confusion", (t) => {
  const fx = makeFixture(t, "adversarial");
  const receipts = fx.commit();
  const claim = deriveChameleonGetAppVersionProviderClaimFromReceipts(
    receipts.raw,
    receipts.semantic,
  );
  const first = verifyAndCommitChameleonGetAppVersionProviderCompletionEvidence(
    fx.adapter,
    { version: 1, completion_binding: fx.binding, provider_claim: claim },
  );
  assert.equal(first.completion, "confirmed");

  const transplant = rebuildBinding(fx.binding, {
    workspace_snapshot_ref: "workspace-snapshot:foreign",
  });
  assert.throws(
    () => readCommittedChameleonGetAppVersionProviderCompletionEvidence(fx.adapter, {
      version: 1,
      completion_binding: transplant,
    }),
    (error) => error.code === "provider_completion_adapter_binding_transplant_rejected",
  );
  assert.throws(
    () => verifyAndCommitChameleonGetAppVersionProviderCompletionEvidence(fx.adapter, {
      version: 1,
      completion_binding: fx.binding,
      provider_claim: { ...claim, provider_result_digest: digest("foreign-result") },
    }),
    (error) => error.code === "provider_completion_adapter_claim_drift",
  );
  assert.throws(
    () => deriveChameleonGetAppVersionProviderClaimFromReceipts(
      structuredClone(receipts.raw),
      receipts.semantic,
    ),
    /raw custody receipt is not privately branded/u,
  );

  for (const hostile of [
    new Proxy(structuredClone(fx.binding), {}),
    { ...fx.binding, extra: "field" },
    Object.defineProperty({ ...fx.binding }, "provider_id", {
      enumerable: true,
      get() { return fx.binding.provider_id; },
    }),
    { ...fx.binding, device_ref: Buffer.from("device:hostile") },
  ]) {
    assert.throws(
      () => _internals.normalizeCompletionBinding(hostile),
      (error) => typeof error.code === "string"
        && error.code.startsWith("provider_completion_adapter_"),
    );
  }
});

test("construction accepts no caller verifier, module, bytes, readiness, or forged port", (t) => {
  const fx = makeFixture(t, "construction");
  for (const extra of [
    { verify_and_commit() {} },
    { module_path: "/tmp/hostile.js" },
    { raw_response_bytes: Buffer.from("secret") },
    { production_ready: true },
  ]) {
    assert.throws(
      () => createChameleonGetAppVersionProviderCompletionEvidenceAdapter({
        ...fx.adapterInput,
        ...extra,
      }),
      (error) => error.code
        === "create_provider_completion_evidence_adapter_request_field_set_invalid",
    );
  }
  assert.throws(
    () => createChameleonGetAppVersionProviderCompletionEvidenceAdapter({
      ...fx.adapterInput,
      raw_custody_receipt_port: Object.freeze({
        version: 1,
        kind: "provider_response_raw_custody_receipt_port",
        production_ready: true,
      }),
    }),
    /not privately branded/u,
  );
  const other = crypto.generateKeyPairSync("ed25519");
  assert.throws(
    () => createChameleonGetAppVersionProviderCompletionEvidenceAdapter({
      ...fx.adapterInput,
      native_dispatch_public_key_pem: other.publicKey.export({
        type: "spki",
        format: "pem",
      }),
    }),
    (error) => error.code === "provider_completion_adapter_native_ticket_untrusted",
  );
  assert.throws(() => JSON.stringify(fx.adapter),
    (error) => error.code === "provider_completion_evidence_adapter_not_serializable");

  const adapterModulePath = require.resolve("../lib/provider-completion-evidence-adapter.js");
  const originalExports = require.cache[adapterModulePath].exports;
  try {
    require.cache[adapterModulePath].exports = Object.freeze({
      assertChameleonGetAppVersionProviderCompletionEvidenceAdapter() {},
      projectChameleonGetAppVersionProviderCompletionEvidenceAdapter() {
        return {
          port_id: "hostile_cache_adapter",
          evidence_domain_digest: digest("hostile-cache-domain"),
          durability_assurance: "caller_asserted",
          production_ready: false,
          hardware_access_authorized: false,
          execution_authority: false,
        };
      },
      readCommittedChameleonGetAppVersionProviderCompletionEvidence() { return null; },
      verifyAndCommitChameleonGetAppVersionProviderCompletionEvidence() { return null; },
    });
    // The broker dispatch never requires the provider adapter module; it
    // validates an injected adapter only against the neutral completion-evidence
    // adapter contract. A forged/empty port is rejected by that contract, and
    // poisoning the provider module's require.cache cannot influence it.
    assert.throws(
      () => createPhysicalProviderCompletionVerificationPortFromFixedAdapter(Object.freeze({})),
      (error) => error.code === "physical_provider_completion_adapter_untrusted",
      "the fixed port must reject a forged adapter via the neutral adapter contract",
    );
  } finally {
    require.cache[adapterModulePath].exports = originalExports;
  }
});
