"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const { createArtifactVault } = require("../packages/bob-artifact-vault/index.js");
const WORKER = require("../packages/bob-artifact-vault/worker.js");
const {
  NATIVE_PROVIDER_RESPONSE_RECORD_HEADER_BYTES,
  NATIVE_PROVIDER_RESPONSE_VAULT_ASSURANCE,
  NATIVE_PROVIDER_RESPONSE_VAULT_VERSION,
  assertNativeProviderResponseSink,
  assertProviderResponseRawCustodyReceipt,
  assertProviderResponseSemanticValidationPort,
  assertProviderResponseSinkCommit,
  cancelNativeProviderResponseSink,
  commitProviderResponseRawCustody,
  commitProviderResponseSink,
  consumeNativeProviderResponseRecord,
  createProviderResponseIngestReceiptPort,
  createProviderResponseRawCustodyReceiptPort,
  createProviderResponseSink,
  nativeProviderResponseSinkWriteDescriptor,
  prepareNativeProviderResponseSink,
  readProviderResponseRawCustodyReceipt,
  readProviderResponseSinkCommit,
  revokeNativeProviderResponseSinkWriteDescriptor,
} = WORKER;
// Provider-specific Chameleon semantic validator now lives in the provider
// package; the composition root (here, the test) wires it to the neutral vault.
const {
  CHAMELEON_GET_APP_VERSION_SEMANTIC_VALIDATOR_PROFILE,
  PROVIDER_SEMANTIC_VALIDATION_ASSURANCE,
  assertChameleonGetAppVersionSemanticObservationReceipt,
  createChameleonGetAppVersionSemanticValidationPort,
  readChameleonGetAppVersionSemanticObservationReceipt,
  validateChameleonGetAppVersionRawCustody,
} = require("../packages/bob-instrument-chameleon/lib/get-app-version-semantic-validator.js");
const {
  createInProcessBackupKeyCustodyFixture,
} = require("./helpers/artifact-vault-backup-key-custody.js");
const NATIVE_DISPATCH_CONTRACT = require(
  "../packages/bob-instrument-broker/lib/native-dispatch-contract.js"
);
const {
  TRUSTED_CLOCK_MAPPING_DOMAIN,
  createPhysicalTrustedClockPort,
  physicalClockMappingSigningMessage,
  publicKeyDigest,
} = require("../mcp/domains/physical/physical-trusted-clock.js");
const {
  hashCanonicalJson,
} = require("../mcp/core/verification/verification-contracts.js");

const SESSION_HASH = "a".repeat(64);
const ZERO_DIGEST = "0".repeat(64);
const EXECUTION_LINEAGE_DOMAIN =
  "hacker-bob/provider-worker-vault-execution-lineage/v1";

function digest(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
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
  return digest(JSON.stringify(canonicalize({ domain, ...projection })));
}

function futureIso(minutes = 30) {
  return new Date(Date.now() + minutes * 60_000).toISOString();
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
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), "bob-native-response-vault-"));
  const root = path.join(parent, "vault");
  const vaultId = `vault:v1:${crypto.randomBytes(32).toString("base64url")}`;
  const vaultSlot = `vault-slot:v1:${crypto.randomBytes(32).toString("base64url")}`;
  const masterKey = crypto.randomBytes(32);
  const deletionLedgerAnchor = makeAnchor("ledger_digest");
  const indexStateAnchor = makeAnchor("index_digest");
  const custody = createInProcessBackupKeyCustodyFixture({
    vaultId,
    vaultSlot,
    sessionNucleusHash: SESSION_HASH,
  });
  const vaults = [];
  function open(createNew) {
    const keyInput = Buffer.from(masterKey);
    try {
      const opened = createArtifactVault({
        root,
        sessionNucleusHash: SESSION_HASH,
        vaultId,
        vaultSlot,
        createNew,
        masterKey: keyInput,
        backupKeyCustody: custody.port,
        deletionLedgerAnchor,
        indexStateAnchor,
        quotaBytes: 2 * 1024 * 1024,
        maxArtifacts: 64,
        minFreeBytes: 0,
      });
      vaults.push(opened);
      return opened;
    } finally {
      keyInput.fill(0);
    }
  }
  const setup = {
    parent,
    root,
    vault: open(true),
    reopen() {
      const reopened = open(false);
      this.vault = reopened;
      return reopened;
    },
  };
  t.after(() => {
    for (const opened of vaults) {
      try { opened.destroy(); } catch {}
    }
    custody.destroy();
    masterKey.fill(0);
    fs.rmSync(parent, { recursive: true, force: true });
  });
  return setup;
}

function reservation(overrides = {}) {
  const suffix = crypto.randomBytes(8).toString("hex");
  return {
    version: 1,
    session_nucleus_hash: SESSION_HASH,
    task_id: `task-${suffix}`,
    attempt_id: `attempt-${suffix}`,
    reservation_ref: `reservation:native-response-${suffix}`,
    purpose_ref: "purpose:native-provider-response",
    byte_ceiling: 64,
    expires_at: futureIso(),
    ...overrides,
  };
}

function reserveProviderSink(setup, overrides = {}) {
  const request = reservation(overrides);
  const reserved = setup.vault.reserve(request);
  const metadata = {
    version: 1,
    session_nucleus_hash: SESSION_HASH,
    task_id: request.task_id,
    attempt_id: request.attempt_id,
    data_class: "credential_secret",
    media_type: "application/octet-stream",
    source_ref: "provider:chameleon-ultra-native",
    retention_expires_at: futureIso(60),
  };
  const sink = createProviderResponseSink(setup.vault, {
    version: 1,
    reservation_handle: reserved.reservation_handle,
    metadata,
  });
  return { metadata, request, reserved, sink };
}

function reserveNativeSink(setup, overrides = {}) {
  const { metadata, request, reserved, sink } = reserveProviderSink(setup, overrides);
  const nativeSink = prepareNativeProviderResponseSink(setup.vault, { version: 1, sink });
  return { metadata, nativeSink, request, reserved, sink };
}

function lineageFor(sink, request, label = crypto.randomBytes(8).toString("hex")) {
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
    provider_id: "provider:chameleon-ultra",
    operation_id: "operation:hf14a-probe",
    compiler_id: "compiler:chameleon-v1",
    compiler_manifest_digest: hash("compiler-manifest"),
    compiler_registry_digest: hash("compiler-registry"),
    source_profile_digest: hash("source-profile"),
    schema_id: "schema:chameleon-v1",
    capability_id: "capability:hf14a-read",
    variant_id: "variant:bounded-probe",
    parameter_selector_id: "selector:fixture",
    canonical_command_digest: hash("canonical-command"),
    compiled_operation_digest: hash("compiled-operation"),
    provider_command_ref: `provider-command:${label}`,
    requested_effects_digest: hash("requested-effects"),
    safety_supervisor_plan_digest: hash("safety-plan"),
    runtime_availability: "runtime:fixture-only",
    compiled_command_id: `compiled-command:${label}`,
    compiled_command_capability_digest: hash("compiled-capability"),
    expected_result_code: "hf14a_probe_ok",
    active_command_input_ref: `command-input:active-${label}`,
    active_command_input_digest: hash("active-command-input"),
    cleanup_command_input_ref: `command-input:cleanup-${label}`,
    cleanup_command_input_digest: hash("cleanup-command-input"),
    maximum_response_bytes: sink.byte_ceiling,
    vault_reservation_handle: sink.vault_reservation_handle,
    vault_reservation_digest: sink.vault_reservation_digest,
    vault_ingest_capability_digest: sink.vault_ingest_capability_digest,
    vault_byte_ceiling: sink.byte_ceiling,
    worker_bundle_digest: hash("worker-bundle"),
    worker_launch_digest: hash("worker-launch"),
    worker_process_instance_digest: hash("worker-process"),
    worker_fence_digest: hash("worker-fence"),
    transport_binding_digest: hash("transport-binding"),
    durable_exchange_plan_digest: hash("durable-exchange-plan"),
    terminal_receipt_recipient_digest: hash("terminal-receipt-recipient"),
  };
  return {
    ...basis,
    execution_lineage_digest: recordDigest(EXECUTION_LINEAGE_DOMAIN, basis),
  };
}

function rebuildLineage(lineage, overrides = {}) {
  const { execution_lineage_digest: ignored, ...basis } = lineage;
  Object.assign(basis, overrides);
  return {
    ...basis,
    execution_lineage_digest: recordDigest(EXECUTION_LINEAGE_DOMAIN, basis),
  };
}

function semanticLineageFor(
  sink,
  request,
  label = crypto.randomBytes(8).toString("hex"),
  overrides = {},
) {
  const profile = CHAMELEON_GET_APP_VERSION_SEMANTIC_VALIDATOR_PROFILE;
  return rebuildLineage(lineageFor(sink, request, label), {
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
    ...overrides,
  });
}

function semanticValidationRequest(lineage, rawReceipt, overrides = {}) {
  return {
    version: 1,
    kind: "validate_chameleon_get_app_version_raw_custody_request",
    lineage,
    raw_custody_receipt: rawReceipt,
    ...overrides,
  };
}

let semanticClockSequence = 0;

function semanticTrustedClock(options = {}) {
  semanticClockSequence += 1;
  const keyPair = crypto.generateKeyPairSync("ed25519");
  const referenceMonotonicMs = Number(process.hrtime.bigint() / 1000000n);
  const referenceUtcMs = Date.now();
  const payload = {
    version: 1,
    clock_id: `physical-clock:semantic-vault-test-${semanticClockSequence}`,
    monotonic_epoch_id: digest(`semantic-vault-clock-epoch-${semanticClockSequence}`),
    mapping_generation: 1,
    reference_monotonic_ms: referenceMonotonicMs,
    reference_utc: new Date(referenceUtcMs).toISOString(),
    max_uncertainty_ms: options.max_uncertainty_ms || 0,
    not_before: new Date(referenceUtcMs - 60_000).toISOString(),
    expires_at: new Date(referenceUtcMs + 60 * 60_000).toISOString(),
    trust_root_epoch: 3,
    authority_epoch: 7,
    revocation_generation: 2,
    signer_key_id: `clock-key:semantic-vault-test-${semanticClockSequence}`,
    signer_public_key_digest: publicKeyDigest(keyPair.publicKey),
    ...(options.payload || {}),
  };
  const payloadDigest = hashCanonicalJson(payload);
  const signature = crypto.sign(
    null,
    physicalClockMappingSigningMessage(payloadDigest),
    keyPair.privateKey,
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
    port_id: `semantic_vault_test_clock_${semanticClockSequence}`,
    clock_id: payload.clock_id,
    monotonic_epoch_id: payload.monotonic_epoch_id,
    uncertainty_ceiling_ms: Math.max(payload.max_uncertainty_ms, 1000),
    read_monotonic_ms: options.read_monotonic_ms
      || (() => Number(process.hrtime.bigint() / 1000000n)),
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
      public_key: keyPair.publicKey,
      ...(options.trust || {}),
    }),
  });
}

function createSemanticPort(vault, trustedClockPort = semanticTrustedClock()) {
  return createChameleonGetAppVersionSemanticValidationPort(vault, {
    version: 1,
    kind: "create_chameleon_get_app_version_semantic_validation_port_request",
    trusted_clock_port: trustedClockPort,
  });
}

function committedSemanticRawFixture(t, label, options = {}) {
  const setup = options.setup || makeVault(t);
  const trustedClock = options.trusted_clock || semanticTrustedClock();
  const semanticPort = createSemanticPort(setup.vault, trustedClock);
  const { nativeSink, request, sink } = reserveNativeSink(setup);
  const lineage = semanticLineageFor(
    sink,
    request,
    label,
    options.lineage_overrides,
  );
  const response = options.response || chameleonResponseFrame(1000, 0x0068, [2, 2]);
  const fixture = makeRecord(nativeSink, lineage, response, {
    settled_continuous_ns: options.settled_continuous_ns
      || process.hrtime.bigint().toString(),
  });
  const rawReceipt = consumeFixtureRecordThroughProductionDescriptor(
    nativeSink,
    fixtureRequest(lineage, fixture),
  );
  return { lineage, rawReceipt, semanticPort, setup, trustedClock };
}

function makeRecord(nativeSink, lineage, responseInput, overrides = {}) {
  const response = Buffer.from(responseInput);
  const header = Buffer.alloc(NATIVE_PROVIDER_RESPONSE_RECORD_HEADER_BYTES);
  header.write("HBPHVSR1", 0, "ascii");
  header.writeUInt16BE(1, 8);
  const status = overrides.status ?? 3;
  const responseLength = overrides.response_length ?? response.length;
  const ticketSequence = overrides.ticket_sequence ?? "7";
  const dispatchEnvelopeDigest = overrides.dispatch_envelope_digest
    || digest("native-dispatch-envelope");
  const deviceDescriptorDigest = overrides.device_descriptor_digest
    || digest("native-device-descriptor");
  const responseDigest = overrides.response_digest
    || (response.length === 0 ? ZERO_DIGEST : digest(response));
  header.writeUInt16BE(status, 10);
  header.writeUInt32BE(responseLength, 12);
  header.writeBigUInt64BE(BigInt(ticketSequence), 16);
  const fields = [
    [24, overrides.execution_lineage_digest || lineage.execution_lineage_digest],
    [56, dispatchEnvelopeDigest],
    [88, deviceDescriptorDigest],
    [120, overrides.sink_descriptor_digest
      || nativeSink.vault_sink_descriptor_identity_digest],
    [152, overrides.reservation_digest || nativeSink.vault_reservation_digest],
    [184, overrides.capability_digest || nativeSink.vault_ingest_capability_digest],
    [216, overrides.artifact_handle_digest || nativeSink.artifact_handle_digest],
    [248, responseDigest],
  ];
  for (const [offset, value] of fields) Buffer.from(value, "hex").copy(header, offset);
  const record = Buffer.concat([header, response]);
  const nativeTerminalResult = {
    version: 1,
    status: status === 2 ? "ambiguous_quarantined" : "fixture_complete_non_authorizing",
    wrote_any_command_bytes: true,
    dispatch_signature_verified: true,
    descriptor_identity_verified: true,
    deadline_rechecked_before_first_write: true,
    response_sink_committed: true,
    response_byte_length: responseLength,
    ticket_sequence: ticketSequence,
    settled_continuous_ns: overrides.settled_continuous_ns || "123456789",
    dispatch_envelope_digest: dispatchEnvelopeDigest,
    delegated_descriptor_identity_digest: deviceDescriptorDigest,
    response_digest: responseDigest,
    vault_sink_descriptor_identity_digest: fields[3][1],
    vault_sink_record_digest: digest(header),
    production_ready: false,
    hardware_access_authorized: false,
    authoritative: false,
  };
  header.fill(0);
  response.fill(0);
  return {
    context: {
      native_terminal_result: nativeTerminalResult,
      execution_claim_receipt_digest: digest("execution-claim"),
      deadline_fence_receipt_digest: digest("deadline-fence"),
    },
    record,
  };
}

function fixtureRequest(lineage, fixture, overrides = {}) {
  return {
    version: 1,
    kind: "consume_native_provider_response_fixture_record_request",
    lineage,
    ...fixture.context,
    record_bytes: fixture.record,
    ...overrides,
  };
}

function fileRequest(lineage, fixture, overrides = {}) {
  return {
    version: 1,
    kind: "consume_native_provider_response_record_request",
    lineage,
    ...fixture.context,
    ...overrides,
  };
}

function semanticCommitRequest(lineage, responseBytes, overrides = {}) {
  return {
    version: 1,
    kind: "commit_provider_response_sink_request",
    lineage,
    execution_claim_receipt_digest: digest("semantic-execution-claim"),
    deadline_fence_receipt_digest: digest("semantic-deadline-fence"),
    transaction_ref: `transaction:semantic:${crypto.randomBytes(8).toString("hex")}`,
    result_code: lineage.expected_result_code,
    device_state_digest: digest("genuine-semantic-device-state"),
    response_bytes: responseBytes,
    ...overrides,
  };
}

function rawCustodyCommitRequest(lineage, responseBytes, label, overrides = {}) {
  return {
    version: 1,
    kind: "commit_provider_response_raw_custody_request",
    lineage,
    execution_claim_receipt_digest: digest(`${label}:raw-execution-claim`),
    deadline_fence_receipt_digest: digest(`${label}:raw-deadline-fence`),
    custody_ref: `raw-custody:test:${label}`,
    transport_observation: {
      transport_settlement_kind: "native-settlement:fixture_complete_non_authorizing",
      dispatch_envelope_digest: digest(`${label}:dispatch-envelope`),
      source_descriptor_identity_digest: digest(`${label}:source-descriptor`),
      sink_descriptor_identity_digest: digest(`${label}:sink-descriptor`),
      sink_record_digest: digest(`${label}:sink-record`),
      ticket_sequence: "1",
      settled_monotonic_ns: "123456789",
    },
    response_bytes: responseBytes,
    ...overrides,
  };
}

function lrc(bytes) {
  let sum = 0;
  for (const byte of bytes) sum = (sum + byte) & 0xff;
  return (-sum) & 0xff;
}

function chameleonResponseFrame(command, status, dataInput) {
  const data = Buffer.from(dataInput);
  const frame = Buffer.alloc(10 + data.length);
  frame[0] = 0x11;
  frame[1] = 0xef;
  frame.writeUInt16BE(command, 2);
  frame.writeUInt16BE(status, 4);
  frame.writeUInt16BE(data.length, 6);
  frame[8] = lrc(frame.subarray(2, 8));
  data.copy(frame, 9);
  frame[9 + data.length] = lrc(data);
  data.fill(0);
  return frame;
}

function consumeFixtureRecordThroughProductionDescriptor(port, input) {
  const descriptors = Object.getOwnPropertyDescriptors(input);
  const sourceDescriptor = descriptors.record_bytes;
  const source = sourceDescriptor && Object.hasOwn(sourceDescriptor, "value")
    ? sourceDescriptor.value
    : null;
  if (!Buffer.isBuffer(source)) throw new Error("fixture record_bytes must be an exact Buffer");
  const request = {};
  for (const [field, descriptor] of Object.entries(descriptors)) {
    if (field === "record_bytes") continue;
    if (!Object.hasOwn(descriptor, "value") || descriptor.enumerable !== true) {
      source.fill(0);
      throw new Error(`fixture request.${field} must be an enumerable data field`);
    }
    request[field] = descriptor.value;
  }
  request.kind = "consume_native_provider_response_record_request";
  try {
    const descriptor = nativeProviderResponseSinkWriteDescriptor(port);
    let offset = 0;
    while (offset < source.length) {
      offset += fs.writeSync(descriptor, source, offset, source.length - offset);
    }
    fs.fsyncSync(descriptor);
    revokeNativeProviderResponseSinkWriteDescriptor(port);
    return consumeNativeProviderResponseRecord(port, request);
  } finally {
    source.fill(0);
  }
}

function assertNoBytesOrPath(value, seen = new Set()) {
  if (value == null || typeof value !== "object" || seen.has(value)) return;
  seen.add(value);
  assert.equal(Buffer.isBuffer(value), false);
  assert.equal(ArrayBuffer.isView(value), false);
  for (const [key, entry] of Object.entries(value)) {
    assert.doesNotMatch(key, /(?:path|file|descriptor|fd)$/u);
    assertNoBytesOrPath(entry, seen);
  }
}

test("native record commits only a distinct privately branded raw-custody receipt", (t) => {
  const setup = makeVault(t);
  const { nativeSink, request, sink } = reserveNativeSink(setup);
  const lineage = lineageFor(sink, request);
  const fixture = makeRecord(nativeSink, lineage, Buffer.from("0123456789native-response"));
  const recordDigestValue = fixture.context.native_terminal_result.vault_sink_record_digest;

  assert.equal(NATIVE_PROVIDER_RESPONSE_VAULT_VERSION, 1);
  assert.equal(NATIVE_PROVIDER_RESPONSE_RECORD_HEADER_BYTES, 280);
  assert.equal(NATIVE_PROVIDER_RESPONSE_VAULT_ASSURANCE.production_ready, false);
  assert.equal(NATIVE_PROVIDER_RESPONSE_VAULT_ASSURANCE.execution_authority, false);
  assert.equal(NATIVE_PROVIDER_RESPONSE_VAULT_ASSURANCE.caller_selected_paths_accepted, false);
  assert.equal(NATIVE_PROVIDER_RESPONSE_VAULT_ASSURANCE.semantic_result_claims_emitted, false);
  assert.equal(NATIVE_PROVIDER_RESPONSE_VAULT_ASSURANCE.device_state_claims_emitted, false);
  assert.equal(
    NATIVE_PROVIDER_RESPONSE_VAULT_ASSURANCE
      .duplicate_preparation_preserves_existing_owned_inode,
    true,
  );
  assert.equal(
    NATIVE_PROVIDER_RESPONSE_VAULT_ASSURANCE.preparation_filesystem_errors_redacted,
    true,
  );
  assert.equal(
    NATIVE_PROVIDER_RESPONSE_VAULT_ASSURANCE
      .failed_partial_preparation_path_reclaimed_automatically,
    false,
  );
  assert.equal(NATIVE_PROVIDER_RESPONSE_VAULT_ASSURANCE.distinct_private_raw_custody_receipt,
    true);
  assert.equal(
    NATIVE_PROVIDER_RESPONSE_VAULT_ASSURANCE
      .ambiguous_native_settlement_committed_as_raw_custody,
    true,
  );
  assert.equal(NATIVE_PROVIDER_RESPONSE_VAULT_ASSURANCE.apfs_copy_on_write_physical_erasure_proven,
    false);
  assert.equal(
    NATIVE_PROVIDER_RESPONSE_VAULT_ASSURANCE.externally_duplicated_writer_capabilities_revoked,
    false,
  );
  assert.equal(
    NATIVE_PROVIDER_RESPONSE_VAULT_ASSURANCE
      .durable_plaintext_cleanup_under_external_writer_duplication_proven,
    false,
  );
  for (const blocker of [
    "native_terminal_private_origin_attestation_missing",
    "externally_duplicated_writer_process_lifecycle_custody_missing",
    "plaintext_sink_crash_recovery_missing",
    "failed_partial_sink_preparation_orphan_reconciliation_missing",
    "physical_media_secure_erasure_unavailable",
  ]) assert.ok(NATIVE_PROVIDER_RESPONSE_VAULT_ASSURANCE.production_blockers.includes(blocker));
  assert.equal(assertNativeProviderResponseSink(nativeSink), nativeSink);
  assertNoBytesOrPath(nativeSink);

  const receipt = consumeFixtureRecordThroughProductionDescriptor(
    nativeSink,
    fixtureRequest(lineage, fixture),
  );
  assert.equal(assertProviderResponseRawCustodyReceipt(receipt), receipt);
  assert.throws(() => assertProviderResponseSinkCommit(receipt), /not privately branded/);
  assert.deepEqual(fixture.record, Buffer.alloc(fixture.record.length));
  assert.equal(receipt.execution_lineage_digest, lineage.execution_lineage_digest);
  assert.equal(receipt.vault_reservation_digest, sink.vault_reservation_digest);
  assert.equal(receipt.vault_ingest_capability_digest, sink.vault_ingest_capability_digest);
  assert.equal(receipt.response_digest, digest("0123456789native-response"));
  assert.equal(receipt.source_descriptor_identity_digest,
    fixture.context.native_terminal_result.delegated_descriptor_identity_digest);
  assert.equal(receipt.semantic_validation_performed, false);
  assert.equal(Object.hasOwn(receipt, "result_code"), false);
  assert.equal(Object.hasOwn(receipt, "device_state_digest"), false);
  assert.equal(nativeSink.artifact_handle_digest, crypto.createHash("sha256")
    .update("hacker-bob/native-response-vault-artifact-handle/v1\0", "utf8")
    .update(receipt.artifact_handle, "utf8")
    .digest("hex"));
  assert.equal(receipt.custody_ref,
    `raw-custody:native-response-vault:${recordDigestValue}`);
  assertNoBytesOrPath(receipt);
  const again = makeRecord(nativeSink, lineage, Buffer.from("0123456789again"));
  assert.throws(() => consumeFixtureRecordThroughProductionDescriptor(
    nativeSink,
    fixtureRequest(lineage, again),
  ), /one-use|no longer live/);
  assert.deepEqual(again.record, Buffer.alloc(again.record.length));
});

test("fixed vault-owned get_app_version validation emits only a safe restart-durable observation", (t) => {
  const setup = makeVault(t);
  const trustedClock = semanticTrustedClock();
  const semanticPort = createSemanticPort(setup.vault, trustedClock);
  assert.equal(assertProviderResponseSemanticValidationPort(semanticPort), semanticPort);
  assert.equal(semanticPort.validator_id, "chameleon_ultra.get_app_version.v1");
  assert.equal(semanticPort.byte_input_accepted, false);
  assert.equal(semanticPort.callback_input_accepted, false);
  assert.equal(semanticPort.operation_input_accepted, false);
  assert.equal(semanticPort.readiness_input_accepted, false);
  assert.equal(semanticPort.production_ready, false);
  assert.equal(PROVIDER_SEMANTIC_VALIDATION_ASSURANCE.production_ready, false);
  assert.equal(PROVIDER_SEMANTIC_VALIDATION_ASSURANCE.caller_callback_accepted, false);
  assert.equal(PROVIDER_SEMANTIC_VALIDATION_ASSURANCE.raw_plaintext_returned, false);
  assert.equal(PROVIDER_SEMANTIC_VALIDATION_ASSURANCE.device_state_claim_emitted, false);
  assert.equal(PROVIDER_SEMANTIC_VALIDATION_ASSURANCE.hardware_in_loop_proven, false);

  const { nativeSink, request, sink } = reserveNativeSink(setup);
  const lineage = semanticLineageFor(sink, request, "semantic-success");
  const response = chameleonResponseFrame(1000, 0x0068, [2, 2]);
  const fixture = makeRecord(nativeSink, lineage, response, {
    settled_continuous_ns: process.hrtime.bigint().toString(),
  });
  const rawReceipt = consumeFixtureRecordThroughProductionDescriptor(
    nativeSink,
    fixtureRequest(lineage, fixture),
  );
  const semanticReceipt = validateChameleonGetAppVersionRawCustody(
    semanticPort,
    semanticValidationRequest(lineage, rawReceipt),
  );
  assert.equal(
    assertChameleonGetAppVersionSemanticObservationReceipt(semanticReceipt),
    semanticReceipt,
  );
  assert.equal(semanticReceipt.kind,
    "chameleon_get_app_version_semantic_observation_receipt");
  assert.equal(semanticReceipt.raw_custody_receipt_digest,
    rawReceipt.raw_custody_receipt_digest);
  assert.equal(semanticReceipt.execution_lineage_digest, lineage.execution_lineage_digest);
  assert.equal(semanticReceipt.semantic_manifest_digest, semanticPort.semantic_manifest_digest);
  assert.equal(semanticReceipt.operation_schema_digest, semanticPort.operation_schema_digest);
  assert.equal(semanticReceipt.application_version, "2.2");
  assert.equal(semanticReceipt.command_id, 1000);
  assert.equal(semanticReceipt.status, 0x0068);
  assert.equal(semanticReceipt.semantic_validation_performed, true);
  assert.equal(semanticReceipt.plaintext_cleanup_reconciled, true);
  assert.equal(semanticReceipt.device_state_claim_emitted, false);
  assert.equal(semanticReceipt.production_ready, false);
  assert.equal(semanticReceipt.authoritative, false);
  assert.equal(Object.hasOwn(semanticReceipt, "result_code"), false);
  assert.equal(Object.hasOwn(semanticReceipt, "device_state_digest"), false);
  assertNoBytesOrPath(semanticReceipt);
  assert.throws(
    () => assertProviderResponseRawCustodyReceipt(semanticReceipt),
    /raw custody receipt is not privately branded/u,
  );
  assert.throws(
    () => assertChameleonGetAppVersionSemanticObservationReceipt(rawReceipt),
    /semantic observation receipt is not privately branded/u,
  );

  const replay = validateChameleonGetAppVersionRawCustody(
    semanticPort,
    semanticValidationRequest(lineage, rawReceipt),
  );
  assert.equal(replay.semantic_observation_digest, semanticReceipt.semantic_observation_digest);

  const reopened = setup.reopen();
  const reopenedRawPort = createProviderResponseRawCustodyReceiptPort(reopened);
  const reopenedRaw = readProviderResponseRawCustodyReceipt(reopenedRawPort, {
    version: 1,
    kind: "read_provider_response_raw_custody_receipt_request",
    execution_lineage_digest: lineage.execution_lineage_digest,
  });
  const reopenedSemanticPort = createSemanticPort(reopened, trustedClock);
  const reopenedSemantic = readChameleonGetAppVersionSemanticObservationReceipt(
    reopenedSemanticPort,
    {
      version: 1,
      kind: "read_chameleon_get_app_version_semantic_observation_receipt_request",
      execution_lineage_digest: lineage.execution_lineage_digest,
    },
  );
  assert.equal(reopenedRaw.raw_custody_receipt_digest, rawReceipt.raw_custody_receipt_digest);
  assert.equal(reopenedSemantic.semantic_observation_digest,
    semanticReceipt.semantic_observation_digest);
  assert.equal(assertChameleonGetAppVersionSemanticObservationReceipt(reopenedSemantic),
    reopenedSemantic);
});

test("cold-reopened raw custody can mint only the same fixed semantic receipt class", (t) => {
  const fixture = committedSemanticRawFixture(t, "cold-before-semantic");
  const reopened = fixture.setup.reopen();
  const rawPort = createProviderResponseRawCustodyReceiptPort(reopened);
  const rawReceipt = readProviderResponseRawCustodyReceipt(rawPort, {
    version: 1,
    kind: "read_provider_response_raw_custody_receipt_request",
    execution_lineage_digest: fixture.lineage.execution_lineage_digest,
  });
  const semanticPort = createSemanticPort(reopened, fixture.trustedClock);
  const semanticReceipt = validateChameleonGetAppVersionRawCustody(
    semanticPort,
    semanticValidationRequest(fixture.lineage, rawReceipt),
  );
  assert.equal(semanticReceipt.application_version, "2.2");
  assert.equal(semanticReceipt.raw_custody_receipt_digest,
    fixture.rawReceipt.raw_custody_receipt_digest);
  assert.equal(assertChameleonGetAppVersionSemanticObservationReceipt(semanticReceipt),
    semanticReceipt);
  assert.throws(
    () => validateChameleonGetAppVersionRawCustody(
      semanticPort,
      semanticValidationRequest(fixture.lineage, { ...rawReceipt }),
    ),
    /raw custody receipt is not privately branded/u,
  );
});

test("fixed semantic validator rejects status, payload, frame, operation, time, and receipt forks", (t) => {
  const invalidFrames = [
    {
      label: "error-status",
      response: chameleonResponseFrame(1000, 0x0067, [2, 2]),
      pattern: /success status 0x0068/u,
    },
    {
      label: "short-payload",
      response: chameleonResponseFrame(1000, 0x0068, [2]),
      pattern: /exactly 2 payload bytes/u,
    },
    {
      label: "extended-payload",
      response: chameleonResponseFrame(1000, 0x0068, [2, 2, 0]),
      pattern: /exactly 2 payload bytes/u,
    },
    {
      label: "alternate-command",
      response: chameleonResponseFrame(1001, 0x0068, [2, 2]),
      pattern: /command must be 1000/u,
    },
    {
      label: "additional-frame",
      response: Buffer.concat([
        chameleonResponseFrame(1000, 0x0068, [2, 2]),
        chameleonResponseFrame(1000, 0x0068, [2, 2]),
      ]),
      pattern: /exactly one untainted complete frame/u,
    },
  ];
  for (const invalid of invalidFrames) {
    const fixture = committedSemanticRawFixture(t, invalid.label, {
      response: invalid.response,
    });
    assert.equal(fixture.rawReceipt.semantic_validation_performed, false);
    assert.throws(
      () => validateChameleonGetAppVersionRawCustody(
        fixture.semanticPort,
        semanticValidationRequest(fixture.lineage, fixture.rawReceipt),
      ),
      invalid.pattern,
    );
    assert.throws(
      () => readChameleonGetAppVersionSemanticObservationReceipt(
        fixture.semanticPort,
        {
          version: 1,
          kind: "read_chameleon_get_app_version_semantic_observation_receipt_request",
          execution_lineage_digest: fixture.lineage.execution_lineage_digest,
        },
      ),
      /not durably readable/u,
    );
    invalid.response.fill(0);
  }

  const alternateOperation = committedSemanticRawFixture(t, "alternate-operation", {
    lineage_overrides: { operation_id: "get_git_version" },
  });
  assert.throws(
    () => validateChameleonGetAppVersionRawCustody(
      alternateOperation.semanticPort,
      semanticValidationRequest(
        alternateOperation.lineage,
        alternateOperation.rawReceipt,
      ),
    ),
    /operation_id drifted/u,
  );

  const staleSettlement = (
    process.hrtime.bigint()
      - BigInt(CHAMELEON_GET_APP_VERSION_SEMANTIC_VALIDATOR_PROFILE.maximum_validation_age_ms + 1)
        * 1000000n
  ).toString();
  const stale = committedSemanticRawFixture(t, "stale-settlement", {
    settled_continuous_ns: staleSettlement,
  });
  assert.throws(
    () => validateChameleonGetAppVersionRawCustody(
      stale.semanticPort,
      semanticValidationRequest(stale.lineage, stale.rawReceipt),
    ),
    /raw custody is stale/u,
  );

  const first = committedSemanticRawFixture(t, "transplant-first");
  const second = committedSemanticRawFixture(t, "transplant-second");
  assert.throws(
    () => validateChameleonGetAppVersionRawCustody(
      first.semanticPort,
      semanticValidationRequest(first.lineage, second.rawReceipt),
    ),
    /detached from the exact raw receipt/u,
  );
  assert.throws(
    () => validateChameleonGetAppVersionRawCustody(
      first.semanticPort,
      semanticValidationRequest(first.lineage, structuredClone(first.rawReceipt)),
    ),
    /raw custody receipt is not privately branded/u,
  );
  assert.throws(
    () => assertProviderResponseSemanticValidationPort({ ...first.semanticPort }),
    /semantic validation port is not privately branded/u,
  );
  for (const injected of [
    { response_bytes: Buffer.from([1, 2]) },
    { validator: () => true },
    { operation_id: "get_app_version" },
    { production_ready: true },
    { module_path: "./attacker.js" },
  ]) {
    const request = semanticValidationRequest(first.lineage, first.rawReceipt, injected);
    assert.throws(
      () => validateChameleonGetAppVersionRawCustody(first.semanticPort, request),
      /unknown fields|unknown or missing fields/u,
    );
    if (request.response_bytes) request.response_bytes.fill(0);
  }
});

test("vault-owned descriptor is issued once, explicitly revoked, and consumed without a path", (t) => {
  const setup = makeVault(t);
  const { nativeSink, request, sink } = reserveNativeSink(setup);
  const lineage = lineageFor(sink, request);
  const fixture = makeRecord(nativeSink, lineage, Buffer.from("0123456789descriptor-record"));
  const descriptor = nativeProviderResponseSinkWriteDescriptor(nativeSink);
  assert.ok(Number.isSafeInteger(descriptor));
  assert.throws(() => nativeProviderResponseSinkWriteDescriptor(nativeSink), /no longer live/);
  assert.equal(fs.writeSync(descriptor, fixture.record, 0, fixture.record.length),
    fixture.record.length);
  fs.fsyncSync(descriptor);
  fixture.record.fill(0);
  assert.equal(revokeNativeProviderResponseSinkWriteDescriptor(nativeSink), true);
  assert.throws(() => revokeNativeProviderResponseSinkWriteDescriptor(nativeSink), /no longer live/);

  const receipt = consumeNativeProviderResponseRecord(
    nativeSink,
    fileRequest(lineage, fixture),
  );
  assert.equal(assertProviderResponseRawCustodyReceipt(receipt), receipt);
  assert.throws(() => assertProviderResponseSinkCommit(receipt), /not privately branded/);
  assert.equal(receipt.response_digest, digest("0123456789descriptor-record"));
  assert.throws(() => nativeProviderResponseSinkWriteDescriptor(nativeSink), /no longer live/);
  assert.deepEqual(fs.readdirSync(path.join(setup.root, "native-provider-response-sinks")), []);
});

test("error status and malformed operation payloads remain raw custody, never semantic success", (t) => {
  const cases = [
    {
      label: "non-success-status",
      response: chameleonResponseFrame(1000, 0x0000, Buffer.from([1, 2])),
    },
    {
      label: "success-status-malformed-get-app-version-payload",
      response: chameleonResponseFrame(1000, 0x0068, Buffer.from("fixture", "ascii")),
    },
  ];
  for (const entry of cases) {
    const setup = makeVault(t);
    const { nativeSink, request, sink } = reserveNativeSink(setup);
    const lineage = lineageFor(sink, request, entry.label);
    const expectedDigest = digest(entry.response);
    const fixture = makeRecord(nativeSink, lineage, entry.response);
    const receipt = consumeFixtureRecordThroughProductionDescriptor(
      nativeSink,
      fixtureRequest(lineage, fixture),
    );
    assert.equal(assertProviderResponseRawCustodyReceipt(receipt), receipt, entry.label);
    assert.throws(() => assertProviderResponseSinkCommit(receipt), /not privately branded/,
      entry.label);
    assert.equal(receipt.response_digest, expectedDigest, entry.label);
    assert.equal(receipt.semantic_validation_performed, false, entry.label);
    assert.equal(Object.hasOwn(receipt, "result_code"), false, entry.label);
    assert.equal(Object.hasOwn(receipt, "device_state_digest"), false, entry.label);
    entry.response.fill(0);
  }
});

test("raw custody is restart-durable and mutually exclusive with semantic journal mode", (t) => {
  {
    const setup = makeVault(t);
    const { nativeSink, request, sink } = reserveNativeSink(setup);
    const lineage = lineageFor(sink, request, "raw-first-journal-mode");
    const fixture = makeRecord(nativeSink, lineage, Buffer.from("0123456789raw-first"));
    const receipt = consumeFixtureRecordThroughProductionDescriptor(
      nativeSink,
      fixtureRequest(lineage, fixture),
    );
    const semanticBytes = Buffer.from("0123456789raw-first");
    assert.throws(
      () => commitProviderResponseSink(sink, semanticCommitRequest(lineage, semanticBytes)),
      /fenced to raw custody mode|different journal mode or lineage/,
    );
    assert.deepEqual(semanticBytes, Buffer.alloc(semanticBytes.length));

    const reopened = setup.reopen();
    const rawPort = createProviderResponseRawCustodyReceiptPort(reopened);
    const readback = readProviderResponseRawCustodyReceipt(rawPort, {
      version: 1,
      kind: "read_provider_response_raw_custody_receipt_request",
      execution_lineage_digest: lineage.execution_lineage_digest,
    });
    assert.equal(assertProviderResponseRawCustodyReceipt(readback), readback);
    assert.deepEqual(readback, receipt);
    const semanticPort = createProviderResponseIngestReceiptPort(reopened);
    assert.throws(() => readProviderResponseSinkCommit(semanticPort, {
      version: 1,
      kind: "read_provider_response_sink_commit_request",
      execution_lineage_digest: lineage.execution_lineage_digest,
    }), /fenced to raw custody mode/);
  }

  {
    const setup = makeVault(t);
    const { nativeSink, request, sink } = reserveNativeSink(setup);
    const lineage = lineageFor(sink, request, "semantic-first-journal-mode");
    const semanticBytes = Buffer.from("0123456789semantic-first");
    const semantic = commitProviderResponseSink(
      sink,
      semanticCommitRequest(lineage, semanticBytes),
    );
    assert.equal(assertProviderResponseSinkCommit(semantic), semantic);
    const fixture = makeRecord(nativeSink, lineage, Buffer.from("0123456789semantic-first"));
    assert.throws(
      () => consumeFixtureRecordThroughProductionDescriptor(
        nativeSink,
        fixtureRequest(lineage, fixture),
      ),
      /fenced to a different journal mode or lineage|action failed/,
    );
    const rawPort = createProviderResponseRawCustodyReceiptPort(setup.reopen());
    assert.throws(() => readProviderResponseRawCustodyReceipt(rawPort, {
      version: 1,
      kind: "read_provider_response_raw_custody_receipt_request",
      execution_lineage_digest: lineage.execution_lineage_digest,
    }), /fenced to semantic result mode/);
  }
});

test("reservation fence survives prepared-state crashes across different lineages and modes", (t) => {
  {
    const setup = makeVault(t);
    const { metadata, request, reserved, sink } = reserveProviderSink(setup);
    const rawLineage = lineageFor(sink, request, "raw-prepared-crash");
    const semanticLineage = lineageFor(sink, request, "semantic-after-raw-prepared");
    const statePath = path.join(
      setup.root,
      "provider-response-receipts",
      `${rawLineage.execution_lineage_digest}.json`,
    );
    const originalRename = fs.renameSync;
    fs.renameSync = function crashAfterRawPrepared(source, destination) {
      if (destination === statePath) {
        originalRename(source, destination);
        throw new Error("injected crash after raw prepared publication");
      }
      return originalRename(source, destination);
    };
    try {
      assert.throws(() => commitProviderResponseRawCustody(
        sink,
        rawCustodyCommitRequest(
          rawLineage,
          Buffer.from("same-bytes-across-crash"),
          "raw-prepared-crash",
        ),
      ), /injected crash after raw prepared publication/);
    } finally {
      fs.renameSync = originalRename;
    }
    assert.equal(JSON.parse(fs.readFileSync(statePath, "utf8")).payload.state, "prepared");
    const semanticBytes = Buffer.from("same-bytes-across-crash");
    assert.throws(
      () => commitProviderResponseSink(
        sink,
        semanticCommitRequest(semanticLineage, semanticBytes),
      ),
      /fenced to a different journal mode or lineage/,
    );
    assert.deepEqual(semanticBytes, Buffer.alloc(semanticBytes.length));

    setup.vault.destroy();
    const reopened = setup.reopen();
    const reopenedSink = createProviderResponseSink(reopened, {
      version: 1,
      reservation_handle: reserved.reservation_handle,
      metadata,
    });
    const recovered = commitProviderResponseRawCustody(
      reopenedSink,
      rawCustodyCommitRequest(
        rawLineage,
        Buffer.from("same-bytes-across-crash"),
        "raw-prepared-crash",
      ),
    );
    assert.equal(assertProviderResponseRawCustodyReceipt(recovered), recovered);
    assert.throws(() => assertProviderResponseSinkCommit(recovered), /not privately branded/);
  }

  {
    const setup = makeVault(t);
    const { metadata, request, reserved, sink } = reserveProviderSink(setup);
    const semanticLineage = lineageFor(sink, request, "semantic-prepared-crash");
    const rawLineage = lineageFor(sink, request, "raw-after-semantic-prepared");
    const statePath = path.join(
      setup.root,
      "provider-response-receipts",
      `${semanticLineage.execution_lineage_digest}.json`,
    );
    const semanticBytes = Buffer.from("same-semantic-bytes-across-crash");
    const semanticRequest = semanticCommitRequest(semanticLineage, semanticBytes);
    const originalRename = fs.renameSync;
    fs.renameSync = function crashAfterSemanticPrepared(source, destination) {
      if (destination === statePath) {
        originalRename(source, destination);
        throw new Error("injected crash after semantic prepared publication");
      }
      return originalRename(source, destination);
    };
    try {
      assert.throws(
        () => commitProviderResponseSink(sink, semanticRequest),
        /injected crash after semantic prepared publication/,
      );
    } finally {
      fs.renameSync = originalRename;
    }
    assert.equal(JSON.parse(fs.readFileSync(statePath, "utf8")).payload.state, "prepared");
    assert.throws(
      () => commitProviderResponseRawCustody(
        sink,
        rawCustodyCommitRequest(
          rawLineage,
          Buffer.from("same-semantic-bytes-across-crash"),
          "raw-after-semantic-prepared",
        ),
      ),
      /fenced to a different journal mode or lineage/,
    );

    setup.vault.destroy();
    const reopened = setup.reopen();
    const reopenedSink = createProviderResponseSink(reopened, {
      version: 1,
      reservation_handle: reserved.reservation_handle,
      metadata,
    });
    const recovered = commitProviderResponseSink(reopenedSink, {
      ...semanticRequest,
      response_bytes: Buffer.from("same-semantic-bytes-across-crash"),
    });
    assert.equal(assertProviderResponseSinkCommit(recovered), recovered);
    assert.throws(() => assertProviderResponseRawCustodyReceipt(recovered),
      /not privately branded/);
  }
});

test("cold restart repairs only the exact stranded reservation-fence publication link", (t) => {
  const setup = makeVault(t);
  const { metadata, request, reserved, sink } = reserveProviderSink(setup);
  const lineage = lineageFor(sink, request, "stranded-fence-publication");
  const bytes = Buffer.from("stranded-fence-response");
  const originalUnlink = fs.unlinkSync;
  let injected = false;
  fs.unlinkSync = function strandFenceTemp(filePath) {
    if (!injected
        && path.dirname(filePath) === path.join(setup.root, "provider-response-receipts")
        && /^\.reservation-[a-f0-9]{64}\.json\./u.test(path.basename(filePath))) {
      injected = true;
      const error = new Error("injected crash after reservation fence link publication");
      error.code = "EIO";
      throw error;
    }
    return originalUnlink(filePath);
  };
  try {
    assert.throws(
      () => commitProviderResponseRawCustody(
        sink,
        rawCustodyCommitRequest(lineage, bytes, "stranded-fence-publication"),
      ),
      /single-link|journal fence/,
    );
  } finally {
    fs.unlinkSync = originalUnlink;
  }
  assert.deepEqual(bytes, Buffer.alloc(bytes.length));
  const receiptRoot = path.join(setup.root, "provider-response-receipts");
  const entries = fs.readdirSync(receiptRoot);
  const finalName = entries.find((entry) => /^reservation-[a-f0-9]{64}\.json$/u.test(entry));
  const tempName = entries.find((entry) => /^\.reservation-[a-f0-9]{64}\.json\./u.test(entry));
  assert.ok(finalName);
  assert.ok(tempName);
  const finalBefore = fs.statSync(path.join(receiptRoot, finalName));
  const tempBefore = fs.statSync(path.join(receiptRoot, tempName));
  assert.equal(finalBefore.ino, tempBefore.ino);
  assert.equal(finalBefore.nlink, 2);

  setup.vault.destroy();
  const reopened = setup.reopen();
  const reopenedSink = createProviderResponseSink(reopened, {
    version: 1,
    reservation_handle: reserved.reservation_handle,
    metadata,
  });
  const recovered = commitProviderResponseRawCustody(
    reopenedSink,
    rawCustodyCommitRequest(
      lineage,
      Buffer.from("stranded-fence-response"),
      "stranded-fence-publication",
    ),
  );
  assert.equal(assertProviderResponseRawCustodyReceipt(recovered), recovered);
  assert.equal(fs.existsSync(path.join(receiptRoot, tempName)), false);
  assert.equal(fs.statSync(path.join(receiptRoot, finalName)).nlink, 1);
  const port = createProviderResponseRawCustodyReceiptPort(reopened);
  assert.deepEqual(readProviderResponseRawCustodyReceipt(port, {
    version: 1,
    kind: "read_provider_response_raw_custody_receipt_request",
    execution_lineage_digest: lineage.execution_lineage_digest,
  }), recovered);
});

test("independent vault owners racing two lineages yield exactly one receipt class", async (t) => {
  const setup = makeVault(t);
  const { metadata, request, reserved, sink: firstSink } = reserveProviderSink(setup);
  const secondVault = setup.reopen();
  const secondSink = createProviderResponseSink(secondVault, {
    version: 1,
    reservation_handle: reserved.reservation_handle,
    metadata,
  });
  const rawLineage = lineageFor(firstSink, request, "racing-raw-lineage");
  const semanticLineage = lineageFor(secondSink, request, "racing-semantic-lineage");
  const rawBytes = Buffer.from("racing-reservation-response");
  const semanticBytes = Buffer.from("racing-reservation-response");
  const contenders = await Promise.allSettled([
    new Promise((resolve, reject) => setImmediate(() => {
      try {
        resolve(commitProviderResponseRawCustody(
          firstSink,
          rawCustodyCommitRequest(rawLineage, rawBytes, "racing-raw-lineage"),
        ));
      } catch (error) {
        reject(error);
      }
    })),
    new Promise((resolve, reject) => setImmediate(() => {
      try {
        resolve(commitProviderResponseSink(
          secondSink,
          semanticCommitRequest(semanticLineage, semanticBytes),
        ));
      } catch (error) {
        reject(error);
      }
    })),
  ]);
  assert.equal(contenders.filter((entry) => entry.status === "fulfilled").length, 1);
  assert.equal(contenders.filter((entry) => entry.status === "rejected").length, 1);
  assert.match(
    contenders.find((entry) => entry.status === "rejected").reason.message,
    /fenced to a different journal mode or lineage/,
  );
  const winner = contenders.find((entry) => entry.status === "fulfilled").value;
  const rawWinner = winner.kind === "provider_response_raw_custody_receipt";
  if (rawWinner) {
    assert.equal(assertProviderResponseRawCustodyReceipt(winner), winner);
    assert.throws(() => assertProviderResponseSinkCommit(winner), /not privately branded/);
  } else {
    assert.equal(assertProviderResponseSinkCommit(winner), winner);
    assert.throws(() => assertProviderResponseRawCustodyReceipt(winner), /not privately branded/);
  }
  assert.equal(setup.vault.usage().active_artifacts, 1);
  assert.deepEqual(rawBytes, Buffer.alloc(rawBytes.length));
  assert.deepEqual(semanticBytes, Buffer.alloc(semanticBytes.length));
});

test("ambiguous settlement is durable raw custody and can never become semantic success", (t) => {
  const setup = makeVault(t);
  const semanticPort = createSemanticPort(setup.vault);
  const { nativeSink, request, sink } = reserveNativeSink(setup);
  const lineage = semanticLineageFor(sink, request, "ambiguous-raw-custody");
  const response = chameleonResponseFrame(1000, 0x0068, [2, 2]);
  const responseDigest = digest(response);
  const fixture = makeRecord(nativeSink, lineage, response, {
    status: 2,
    settled_continuous_ns: process.hrtime.bigint().toString(),
  });
  response.fill(0);

  const receipt = consumeFixtureRecordThroughProductionDescriptor(
    nativeSink,
    fixtureRequest(lineage, fixture),
  );
  assert.equal(assertProviderResponseRawCustodyReceipt(receipt), receipt);
  assert.throws(() => assertProviderResponseSinkCommit(receipt), /not privately branded/u);
  assert.equal(receipt.transport_settlement_kind,
    "native-settlement:ambiguous_quarantined");
  assert.equal(receipt.vault_reservation_handle, sink.vault_reservation_handle);
  assert.equal(receipt.vault_reservation_digest, sink.vault_reservation_digest);
  assert.equal(receipt.vault_ingest_capability_digest,
    sink.vault_ingest_capability_digest);
  assert.equal(receipt.response_digest, responseDigest);
  assert.equal(receipt.semantic_validation_performed, false);
  assert.equal(Object.hasOwn(receipt, "result_code"), false);
  assert.equal(Object.hasOwn(receipt, "device_state_digest"), false);
  assertNoBytesOrPath(receipt);
  assert.throws(
    () => validateChameleonGetAppVersionRawCustody(
      semanticPort,
      semanticValidationRequest(lineage, receipt),
    ),
    /requires exact complete native settlement/u,
  );
  const durableState = JSON.parse(fs.readFileSync(path.join(
    setup.root,
    "provider-response-receipts",
    `${lineage.execution_lineage_digest}.json`,
  ), "utf8")).payload;
  assert.equal(durableState.state, "raw_custody_committed");
  assert.equal(durableState.raw_custody_receipt.raw_custody_receipt_digest,
    receipt.raw_custody_receipt_digest);
  assert.equal(durableState.plaintext_cleanup_receipt.raw_custody_receipt_digest,
    receipt.raw_custody_receipt_digest);

  const reopened = setup.reopen();
  const rawPort = createProviderResponseRawCustodyReceiptPort(reopened);
  const readback = readProviderResponseRawCustodyReceipt(rawPort, {
    version: 1,
    kind: "read_provider_response_raw_custody_receipt_request",
    execution_lineage_digest: lineage.execution_lineage_digest,
  });
  assert.deepEqual(readback, receipt);
  assert.equal(reopened.usage().active_artifacts, 1);
  assert.deepEqual(fs.readdirSync(path.join(setup.root, "native-provider-response-sinks")), []);
});

test("zero-byte ambiguous settlement mints raw custody but never expected-result success", (t) => {
  const setup = makeVault(t);
  const { nativeSink, request, sink } = reserveNativeSink(setup);
  const lineage = lineageFor(sink, request);
  const fixture = makeRecord(nativeSink, lineage, Buffer.alloc(0), { status: 2 });
  const receipt = consumeFixtureRecordThroughProductionDescriptor(
    nativeSink,
    fixtureRequest(lineage, fixture),
  );
  assert.equal(assertProviderResponseRawCustodyReceipt(receipt), receipt);
  assert.throws(() => assertProviderResponseSinkCommit(receipt), /not privately branded/u);
  assert.equal(receipt.transport_settlement_kind,
    "native-settlement:ambiguous_quarantined");
  assert.equal(receipt.response_byte_length, 0);
  assert.equal(receipt.response_digest, digest(Buffer.alloc(0)));
  assert.equal(receipt.semantic_validation_performed, false);
  assert.equal(setup.vault.usage().active_artifacts, 1);
  assert.throws(() => prepareNativeProviderResponseSink(setup.vault, {
    version: 1,
    sink,
  }), /active vault reservation/);
  assert.deepEqual(fixture.record, Buffer.alloc(fixture.record.length));
});

test("ambiguous raw custody survives terminal journal crash and lost acknowledgement", (t) => {
  const vectors = [
    { label: "terminal-publication-crash", publish_before_throw: false },
    { label: "terminal-publication-lost-ack", publish_before_throw: true },
  ];
  for (const vector of vectors) {
    const setup = makeVault(t);
    const { nativeSink, request, sink } = reserveNativeSink(setup);
    const lineage = lineageFor(sink, request, vector.label);
    const fixture = makeRecord(
      nativeSink,
      lineage,
      Buffer.from(`ambiguous-${vector.label}`, "utf8"),
      { status: 2 },
    );
    const receiptStatePath = path.join(
      setup.root,
      "provider-response-receipts",
      `${lineage.execution_lineage_digest}.json`,
    );
    const originalRename = fs.renameSync;
    let stateRenames = 0;
    fs.renameSync = function injectTerminalPublicationFailure(source, destination) {
      if (destination === receiptStatePath) {
        stateRenames += 1;
        if (stateRenames === 2) {
          if (vector.publish_before_throw) originalRename(source, destination);
          throw new Error(`injected ${vector.label}`);
        }
      }
      return originalRename(source, destination);
    };
    try {
      assert.throws(
        () => consumeFixtureRecordThroughProductionDescriptor(
          nativeSink,
          fixtureRequest(lineage, fixture),
        ),
        /native provider response action failed|injected terminal-publication/u,
        vector.label,
      );
    } finally {
      fs.renameSync = originalRename;
    }
    assert.equal(setup.vault.usage().active_artifacts, 1, vector.label);
    assert.deepEqual(
      fs.readdirSync(path.join(setup.root, "native-provider-response-sinks")),
      [],
      vector.label,
    );

    const reopened = setup.reopen();
    const rawPort = createProviderResponseRawCustodyReceiptPort(reopened);
    const receipt = readProviderResponseRawCustodyReceipt(rawPort, {
      version: 1,
      kind: "read_provider_response_raw_custody_receipt_request",
      execution_lineage_digest: lineage.execution_lineage_digest,
    });
    assert.equal(assertProviderResponseRawCustodyReceipt(receipt), receipt, vector.label);
    assert.equal(receipt.transport_settlement_kind,
      "native-settlement:ambiguous_quarantined", vector.label);
    assert.equal(receipt.vault_reservation_digest,
      sink.vault_reservation_digest, vector.label);
    assert.equal(receipt.semantic_validation_performed, false, vector.label);
  }
});

test("exact native terminal object rejects hostile forks and zeroizes fixture bytes", (t) => {
  const cases = [
    ["unknown terminal field", (requestInput) => {
      requestInput.native_terminal_result = {
        ...requestInput.native_terminal_result,
        forged: true,
      };
    }, /unknown or missing fields/],
    ["rejected status", (requestInput) => {
      requestInput.native_terminal_result = {
        ...requestInput.native_terminal_result,
        status: "rejected_no_effect",
      };
    }, /committed response status/],
    ["write flag", (requestInput) => {
      requestInput.native_terminal_result = {
        ...requestInput.native_terminal_result,
        wrote_any_command_bytes: false,
      };
    }, /must be true/],
    ["signature flag", (requestInput) => {
      requestInput.native_terminal_result = {
        ...requestInput.native_terminal_result,
        dispatch_signature_verified: false,
      };
    }, /must be true/],
    ["descriptor flag", (requestInput) => {
      requestInput.native_terminal_result = {
        ...requestInput.native_terminal_result,
        descriptor_identity_verified: false,
      };
    }, /must be true/],
    ["deadline flag", (requestInput) => {
      requestInput.native_terminal_result = {
        ...requestInput.native_terminal_result,
        deadline_rechecked_before_first_write: false,
      };
    }, /must be true/],
    ["sink commit flag", (requestInput) => {
      requestInput.native_terminal_result = {
        ...requestInput.native_terminal_result,
        response_sink_committed: false,
      };
    }, /must be true/],
    ["response length", (requestInput) => {
      requestInput.native_terminal_result = {
        ...requestInput.native_terminal_result,
        response_byte_length: requestInput.native_terminal_result.response_byte_length - 1,
      };
    }, /binding/],
    ["ticket sequence", (requestInput) => {
      requestInput.native_terminal_result = {
        ...requestInput.native_terminal_result,
        ticket_sequence: "8",
      };
    }, /binding/],
    ["settlement clock", (requestInput) => {
      requestInput.native_terminal_result = {
        ...requestInput.native_terminal_result,
        settled_continuous_ns: "0",
      };
    }, /positive uint64/],
    ["dispatch digest", (requestInput) => {
      requestInput.native_terminal_result = {
        ...requestInput.native_terminal_result,
        dispatch_envelope_digest: digest("forked-dispatch"),
      };
    }, /binding/],
    ["device digest", (requestInput) => {
      requestInput.native_terminal_result = {
        ...requestInput.native_terminal_result,
        delegated_descriptor_identity_digest: digest("forked-device"),
      };
    }, /binding/],
    ["sink descriptor digest", (requestInput) => {
      requestInput.native_terminal_result = {
        ...requestInput.native_terminal_result,
        vault_sink_descriptor_identity_digest: digest("forked-sink"),
      };
    }, /binding/],
    ["record digest", (requestInput) => {
      requestInput.native_terminal_result = {
        ...requestInput.native_terminal_result,
        vault_sink_record_digest: digest("forked-record"),
      };
    }, /binding/],
    ["response digest", (requestInput) => {
      requestInput.native_terminal_result = {
        ...requestInput.native_terminal_result,
        response_digest: digest("forked-response"),
      };
    }, /binding/],
    ["production promotion", (requestInput) => {
      requestInput.native_terminal_result = {
        ...requestInput.native_terminal_result,
        production_ready: true,
      };
    }, /must be false/],
    ["hardware promotion", (requestInput) => {
      requestInput.native_terminal_result = {
        ...requestInput.native_terminal_result,
        hardware_access_authorized: true,
      };
    }, /must be false/],
    ["authority promotion", (requestInput) => {
      requestInput.native_terminal_result = {
        ...requestInput.native_terminal_result,
        authoritative: true,
      };
    }, /must be false/],
  ];
  for (const [label, mutate, pattern] of cases) {
    const setup = makeVault(t);
    const { nativeSink, request, sink } = reserveNativeSink(setup);
    const lineage = lineageFor(sink, request, label.replaceAll(" ", "-"));
    const fixture = makeRecord(nativeSink, lineage, Buffer.from("0123456789terminal-fork"));
    const requestInput = fixtureRequest(lineage, fixture);
    mutate(requestInput);
    const exposed = fixture.record;
    assert.throws(
      () => consumeFixtureRecordThroughProductionDescriptor(nativeSink, requestInput),
      pattern,
      label,
    );
    assert.deepEqual(exposed, Buffer.alloc(exposed.length), label);
    assert.equal(setup.vault.usage().active_artifacts, 0, label);
  }
});

test("record parser rejects every drifted header binding and zeroizes exact bytes", (t) => {
  const cases = [
    ["magic", (fixture) => { fixture.record[0] ^= 0xff; }, /framing/],
    ["version", (fixture) => { fixture.record.writeUInt16BE(2, 8); }, /framing/],
    ["status", (_fixture, requestInput) => {
      requestInput.native_terminal_result = {
        ...requestInput.native_terminal_result,
        status: "ambiguous_quarantined",
      };
    }, /terminal status/],
    ["length", (fixture) => { fixture.record.writeUInt32BE(11, 12); }, /length/],
    ["lineage", (fixture) => { fixture.record.fill(0x11, 24, 56); }, /binding/],
    ["dispatch", (fixture) => { fixture.record.fill(0x12, 56, 88); }, /binding/],
    ["device", (fixture) => { fixture.record.fill(0x13, 88, 120); }, /binding/],
    ["sink", (fixture) => { fixture.record.fill(0x14, 120, 152); }, /binding/],
    ["reservation", (fixture) => { fixture.record.fill(0x15, 152, 184); }, /binding/],
    ["capability", (fixture) => { fixture.record.fill(0x16, 184, 216); }, /binding/],
    ["artifact", (fixture) => { fixture.record.fill(0x17, 216, 248); }, /binding/],
    ["recorded response", (fixture) => { fixture.record.fill(0x18, 248, 280); }, /binding/],
    ["raw response", (fixture) => { fixture.record[fixture.record.length - 1] ^= 0xff; }, /binding/],
  ];
  for (const [label, mutate, pattern] of cases) {
    const setup = makeVault(t);
    const { nativeSink, request, sink } = reserveNativeSink(setup);
    const lineage = lineageFor(sink, request, label.replaceAll(" ", "-"));
    const fixture = makeRecord(nativeSink, lineage, Buffer.from("0123456789hostile-record"));
    const requestInput = fixtureRequest(lineage, fixture);
    mutate(fixture, requestInput);
    const exposed = fixture.record;
    assert.throws(
      () => consumeFixtureRecordThroughProductionDescriptor(nativeSink, requestInput),
      pattern,
      label,
    );
    assert.deepEqual(exposed, Buffer.alloc(exposed.length), label);
    assert.equal(setup.vault.usage().active_artifacts, 0, label);
  }
});

test("raw-buffer fixture APIs are absent from every local and package module surface", () => {
  const internal = require(
    "../packages/bob-artifact-vault/lib/native-provider-response-vault.js"
  );
  for (const surface of [
    WORKER,
    require("../packages/bob-artifact-vault/index.js"),
    internal,
  ]) {
    assert.equal(Object.hasOwn(surface, "consumeNativeProviderResponseFixtureRecord"), false);
    assert.equal(Object.hasOwn(surface, "prepareNativeProviderResponseFixtureSink"), false);
    assert.equal(Object.hasOwn(surface, "_testing"), false);
  }
  assert.equal(fs.existsSync(path.join(
    __dirname,
    "../packages/bob-artifact-vault/testing.js",
  )), false);
  const packageJson = JSON.parse(fs.readFileSync(
    path.join(__dirname, "../packages/bob-artifact-vault/package.json"),
    "utf8",
  ));
  assert.equal(Object.values(packageJson.exports).includes("./testing.js"), false);
  assert.equal(packageJson.files.includes("testing.js"), false);
});

test("explicit cancellation is one-use and vault destruction drains every live sink", (t) => {
  {
    const setup = makeVault(t);
    const { nativeSink, sink } = reserveNativeSink(setup);
    const descriptor = nativeProviderResponseSinkWriteDescriptor(nativeSink);
    const plaintext = Buffer.from("cancelled-native-plaintext");
    fs.writeSync(descriptor, plaintext, 0, plaintext.length);
    fs.fsyncSync(descriptor);
    plaintext.fill(0);
    const cancelled = cancelNativeProviderResponseSink(nativeSink);
    assert.equal(cancelled.production_ready, false);
    assert.match(cancelled.reservation_release_receipt_digest, /^[a-f0-9]{64}$/u);
    assertNoBytesOrPath(cancelled);
    assert.deepEqual(fs.readdirSync(path.join(setup.root, "native-provider-response-sinks")), []);
    assert.throws(() => cancelNativeProviderResponseSink(nativeSink), /one-use/);
    assert.throws(() => nativeProviderResponseSinkWriteDescriptor(nativeSink), /no longer live/);
    assert.throws(() => prepareNativeProviderResponseSink(setup.vault, {
      version: 1,
      sink,
    }), /active vault reservation/);
  }
  {
    const setup = makeVault(t);
    const first = reserveNativeSink(setup);
    const second = reserveNativeSink(setup);
    const descriptor = nativeProviderResponseSinkWriteDescriptor(first.nativeSink);
    const plaintext = Buffer.from("destroy-drain-native-plaintext");
    fs.writeSync(descriptor, plaintext, 0, plaintext.length);
    fs.fsyncSync(descriptor);
    plaintext.fill(0);
    setup.vault.destroy();
    assert.deepEqual(fs.readdirSync(path.join(setup.root, "native-provider-response-sinks")), []);
    assert.throws(() => nativeProviderResponseSinkWriteDescriptor(first.nativeSink),
      /destroyed|one-use/);
    assert.throws(() => cancelNativeProviderResponseSink(second.nativeSink),
      /destroyed|one-use/);
  }
});

test("cleanup failure with a durable raw commit cannot be recovered as semantic success", (t) => {
  const setup = makeVault(t);
  const semanticPort = createSemanticPort(setup.vault);
  const { nativeSink, request, sink } = reserveNativeSink(setup);
  const lineage = semanticLineageFor(sink, request, "linked-cleanup-failure");
  const fixture = makeRecord(
    nativeSink,
    lineage,
    chameleonResponseFrame(1000, 0x0068, [2, 2]),
    { settled_continuous_ns: process.hrtime.bigint().toString() },
  );
  const descriptor = nativeProviderResponseSinkWriteDescriptor(nativeSink);
  fs.writeSync(descriptor, fixture.record, 0, fixture.record.length);
  fs.fsyncSync(descriptor);
  fixture.record.fill(0);
  revokeNativeProviderResponseSinkWriteDescriptor(nativeSink);
  const directory = path.join(setup.root, "native-provider-response-sinks");
  const [entry] = fs.readdirSync(directory);
  const stagingPath = path.join(directory, entry);
  const originalUnlink = fs.unlinkSync;
  let injected = false;
  fs.unlinkSync = function injectedNativeStagingUnlink(filePath) {
    if (!injected && filePath === stagingPath) {
      injected = true;
      const error = new Error("injected native plaintext unlink failure");
      error.code = "EIO";
      throw error;
    }
    return originalUnlink(filePath);
  };
  try {
    assert.throws(
      () => consumeNativeProviderResponseRecord(
        nativeSink,
        fileRequest(lineage, fixture),
      ),
      /cleanup reconciliation failed/,
    );
  } finally {
    fs.unlinkSync = originalUnlink;
  }
  assert.equal(fs.statSync(stagingPath).size, 0);
  const legacySemanticPort = createProviderResponseIngestReceiptPort(setup.vault);
  assert.throws(() => readProviderResponseSinkCommit(legacySemanticPort, {
    version: 1,
    kind: "read_provider_response_sink_commit_request",
    execution_lineage_digest: lineage.execution_lineage_digest,
  }), /fenced to raw custody mode/);
  const rawPort = createProviderResponseRawCustodyReceiptPort(setup.vault);
  const rawReceipt = readProviderResponseRawCustodyReceipt(rawPort, {
    version: 1,
    kind: "read_provider_response_raw_custody_receipt_request",
    execution_lineage_digest: lineage.execution_lineage_digest,
  });
  assert.equal(assertProviderResponseRawCustodyReceipt(rawReceipt), rawReceipt);
  assert.equal(rawReceipt.semantic_validation_performed, false);
  assert.equal(Object.hasOwn(rawReceipt, "result_code"), false);
  assert.equal(Object.hasOwn(rawReceipt, "device_state_digest"), false);
  assert.throws(
    () => validateChameleonGetAppVersionRawCustody(
      semanticPort,
      semanticValidationRequest(lineage, rawReceipt),
    ),
    /requires durable native plaintext cleanup confirmation/u,
  );
  // The first call reported the injected unlink failure. A second owner-side
  // drain reconciles the now-zero inode before key destruction reports success.
  setup.vault.destroy();
  assert.deepEqual(fs.readdirSync(directory), []);
});

test("malformed requests and descriptor preparation fail closed", (t) => {
  {
    const setup = makeVault(t);
    const { nativeSink, request, sink } = reserveNativeSink(setup);
    const lineage = lineageFor(sink, request, "unknown-field");
    const fixture = makeRecord(nativeSink, lineage, Buffer.from("0123456789unknown-field"));
    const malformed = { ...fixtureRequest(lineage, fixture), caller_path: "/tmp/forbidden" };
    assert.throws(() => consumeFixtureRecordThroughProductionDescriptor(nativeSink, malformed),
      /unknown or missing fields/);
    assert.deepEqual(fixture.record, Buffer.alloc(fixture.record.length));
    assert.throws(() => consumeFixtureRecordThroughProductionDescriptor(nativeSink, malformed),
      /one-use|no longer live/);
  }
  {
    const setup = makeVault(t);
    const { nativeSink, request, sink } = reserveNativeSink(
      setup,
      { byte_ceiling: 12 },
    );
    const lineage = lineageFor(sink, request, "oversize");
    const fixture = makeRecord(nativeSink, lineage, Buffer.from("0123456789abc"));
    assert.throws(() => consumeFixtureRecordThroughProductionDescriptor(
      nativeSink,
      fixtureRequest(lineage, fixture),
    ), /plaintext cleanup could not be reconciled|cleanup reconciliation failed|exceeds its byte ceiling/);
    assert.deepEqual(fixture.record, Buffer.alloc(fixture.record.length));
  }
  assert.throws(() => assertNativeProviderResponseSink(
    Object.freeze({ production_ready: true }),
  ), /vault-private/);
});

test("sink descriptor preparation is one reservation, one inode, and not caller-mintable", (t) => {
  const setup = makeVault(t);
  const { nativeSink, sink } = reserveNativeSink(setup);
  assert.match(nativeSink.vault_sink_descriptor_identity_digest, /^[a-f0-9]{64}$/u);
  assert.match(nativeSink.artifact_handle_digest, /^[a-f0-9]{64}$/u);
  assert.equal(nativeSink.byte_ceiling, sink.byte_ceiling);
  const descriptor = nativeProviderResponseSinkWriteDescriptor(nativeSink);
  const stats = fs.fstatSync(descriptor, { bigint: true });
  assert.equal(nativeSink.vault_sink_descriptor_identity_digest,
    NATIVE_DISPATCH_CONTRACT.deriveNativeResponseSinkDescriptorIdentityDigest({
      version: 1,
      role: NATIVE_DISPATCH_CONTRACT.NATIVE_RESPONSE_SINK_DESCRIPTOR_ROLE,
      fd_number: NATIVE_DISPATCH_CONTRACT.NATIVE_RESPONSE_SINK_DESCRIPTOR_FD,
      purpose: NATIVE_DISPATCH_CONTRACT.NATIVE_RESPONSE_SINK_DESCRIPTOR_PURPOSE,
      dev: stats.dev.toString(),
      ino: stats.ino.toString(),
      rdev: stats.rdev.toString(),
      mode: Number(stats.mode),
      nlink: stats.nlink.toString(),
      uid: Number(stats.uid),
      gid: Number(stats.gid),
      regular_file: true,
      access_mode: NATIVE_DISPATCH_CONTRACT.NATIVE_RESPONSE_SINK_DESCRIPTOR_ACCESS_MODE,
      status_flags: NATIVE_DISPATCH_CONTRACT.NATIVE_RESPONSE_SINK_DESCRIPTOR_STATUS_FLAGS,
      fd_flags: NATIVE_DISPATCH_CONTRACT.NATIVE_RESPONSE_SINK_DESCRIPTOR_FD_FLAGS,
      initial_size: stats.size.toString(),
    }));
  const sinkDirectory = path.join(setup.root, "native-provider-response-sinks");
  const [sinkEntry] = fs.readdirSync(sinkDirectory);
  const sinkPath = path.join(sinkDirectory, sinkEntry);
  const beforeDuplicate = fs.lstatSync(sinkPath, { bigint: true });
  const prepareAgain = () => {
    try {
      prepareNativeProviderResponseSink(setup.vault, { version: 1, sink });
      return null;
    } catch (error) {
      return error;
    }
  };
  const duplicateError = prepareAgain();
  assert.ok(duplicateError instanceof Error);
  assert.match(duplicateError.message, /native provider response sink preparation failed/u);
  assert.equal(duplicateError.code, "native_provider_response_sink_preparation_failed");
  assert.equal(duplicateError.message.includes(setup.root), false);
  assert.equal(duplicateError.message.includes(sink.vault_ingest_capability_digest), false);
  const afterDuplicate = fs.lstatSync(sinkPath, { bigint: true });
  assert.equal(afterDuplicate.dev, beforeDuplicate.dev);
  assert.equal(afterDuplicate.ino, beforeDuplicate.ino);
  const thirdPrepareError = prepareAgain();
  assert.ok(thirdPrepareError instanceof Error);
  assert.match(thirdPrepareError.message,
    /native provider response sink preparation failed/u);
  assert.equal(thirdPrepareError.code, "native_provider_response_sink_preparation_failed");
  const afterThirdPrepare = fs.lstatSync(sinkPath, { bigint: true });
  assert.equal(afterThirdPrepare.dev, beforeDuplicate.dev);
  assert.equal(afterThirdPrepare.ino, beforeDuplicate.ino);
  assert.throws(() => prepareNativeProviderResponseSink(setup.vault, {
    version: 1,
    sink: { ...sink },
  }), /privately branded/);
  assert.throws(() => prepareNativeProviderResponseSink(setup.vault, {
    version: 1,
    sink,
    path: "/tmp/not-accepted",
  }), /unknown or missing fields/);
  cancelNativeProviderResponseSink(nativeSink);
});

test("partial sink preparation leaves a fail-closed orphan and redacts filesystem errors", (t) => {
  const setup = makeVault(t);
  const { sink } = reserveProviderSink(setup);
  const sinkDirectory = path.join(setup.root, "native-provider-response-sinks");
  const sinkPath = path.join(sinkDirectory, `${sink.vault_ingest_capability_digest}.bin`);
  const originalOpen = fs.openSync;
  let sinkOpenCount = 0;
  fs.openSync = function failWriterOpen(requestedPath, flags, ...rest) {
    if (requestedPath === sinkPath) {
      sinkOpenCount += 1;
      if (sinkOpenCount === 2) {
        const error = new Error(`injected writer-open failure for ${requestedPath}`);
        error.code = "EIO";
        throw error;
      }
    }
    return Reflect.apply(originalOpen, fs, [requestedPath, flags, ...rest]);
  };
  let preparationError = null;
  try {
    prepareNativeProviderResponseSink(setup.vault, { version: 1, sink });
  } catch (error) {
    preparationError = error;
  } finally {
    fs.openSync = originalOpen;
  }
  assert.ok(preparationError instanceof Error);
  assert.equal(preparationError.code, "native_provider_response_sink_preparation_failed");
  assert.equal(preparationError.message.includes(setup.root), false);
  assert.equal(preparationError.message.includes(sink.vault_ingest_capability_digest), false);
  assert.deepEqual(fs.readdirSync(sinkDirectory), [path.basename(sinkPath)]);
  const orphan = fs.lstatSync(sinkPath, { bigint: true });
  let retryError = null;
  try {
    prepareNativeProviderResponseSink(setup.vault, { version: 1, sink });
  } catch (error) {
    retryError = error;
  }
  assert.ok(retryError instanceof Error);
  assert.equal(retryError.code, "native_provider_response_sink_preparation_failed");
  assert.equal(retryError.message.includes(setup.root), false);
  const afterRetry = fs.lstatSync(sinkPath, { bigint: true });
  assert.equal(afterRetry.dev, orphan.dev);
  assert.equal(afterRetry.ino, orphan.ino);
});
