"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const crypto = require("node:crypto");
const path = require("node:path");

const {
  AUTHENTICATED_EXCHANGE_PROTOCOL,
  AUTHENTICATED_EXCHANGE_VERSION,
  DURABILITY_EVIDENCE_ORIGIN,
  DURABLE_READBACK_CONSISTENCY_MODEL,
  DURABILITY_SCHEME,
  ROLE_DEFINITIONS,
  assertLiveExchangeState,
  canonicalRecordByteLength,
  canonicalRecordSha256,
  createFixtureDurableReadbackPort,
  createFixtureExchangeSigner,
  createFixtureExchangeVerifier,
  normalizeBinding,
  reconcileAuthenticatedExchange,
  signCapabilityGrant,
  signCommitGo,
  signDurabilityAttestation,
  signJournalEntry,
  signOutboxRecord,
  signTerminalReceipt,
  verifyCapabilityGrant,
  verifyCommitGo,
  verifySingleUseExchangeRecords,
} = require("../lib/authenticated-durable-exchange.js");
const {
  canonicalJson,
  hashCanonicalJson,
} = require("../../../mcp/lib/verification-contracts.js");

function digest(label) {
  return crypto.createHash("sha256").update(label).digest("hex");
}

function nonce(byte) {
  return Buffer.alloc(32, byte).toString("base64url");
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function incrementUint64(value) {
  return String(BigInt(value) + 1n);
}

function makeAuthority() {
  const roles = Object.keys(ROLE_DEFINITIONS);
  const keys = roles.map(() => crypto.generateKeyPairSync("ed25519"));
  const signers = Object.fromEntries(roles.map((role, index) => [role,
    createFixtureExchangeSigner({
      version: AUTHENTICATED_EXCHANGE_VERSION,
      kind: "authenticated_exchange_fixture_signer",
      role,
      principal_id: `principal:${role.replaceAll("_", "-")}`,
      key_id: `exchange-key:${role.replaceAll("_", "-")}`,
      trust_epoch: 7,
      private_key: keys[index].privateKey,
    }),
  ]));
  const verifier = createFixtureExchangeVerifier({
    version: AUTHENTICATED_EXCHANGE_VERSION,
    kind: "authenticated_exchange_fixture_keyring",
    trust_epoch: 7,
    revocation_generation: "12",
    revocation_state_digest: digest("fixture-revocation-state"),
    entries: roles.map((role, index) => ({
      role,
      key_usage: ROLE_DEFINITIONS[role].key_usage,
      principal_id: signers[role].principal_id,
      key_id: signers[role].key_id,
      trust_epoch: 7,
      revoked: false,
      public_key: keys[index].publicKey,
    })),
  });
  return { keys, roles, signers, verifier };
}

function makeBinding(seed = "main") {
  const descriptorSemantics = digest(`descriptor-semantics:${seed}`);
  return normalizeBinding({
    version: AUTHENTICATED_EXCHANGE_VERSION,
    protocol: AUTHENTICATED_EXCHANGE_PROTOCOL,
    exchange_id: `exchange:${seed}`,
    release_manifest_digest: digest(`release-manifest:${seed}`),
    component_id: "native_dispatch_custodian",
    component_manifest_digest: digest(`component-manifest:${seed}`),
    release_artifact_digest: digest(`release-artifact:${seed}`),
    capability_abi_digest: digest(`capability-abi:${seed}`),
    handoff_session_id: `handoff-session:${seed}`,
    handoff_session_digest: digest(`handoff-session:${seed}`),
    supervisor_audit_token_digest: digest(`supervisor-audit-token:${seed}`),
    supervisor_process_id: 61000,
    supervisor_process_pidversion: 80,
    supervisor_process_instance_digest: digest(`supervisor-process-instance:${seed}`),
    supervisor_process_start_digest: digest(`supervisor-process-start:${seed}`),
    supervisor_mapped_image_digest: digest(`supervisor-mapped-image:${seed}`),
    supervisor_principal_id: "principal:go-authority",
    supervisor_principal_policy_digest: digest(`supervisor-principal-policy:${seed}`),
    supervisor_listener_generation: "19",
    supervisor_listener_identity_digest: digest(`supervisor-listener-identity:${seed}`),
    worker_audit_token_digest: digest(`worker-audit-token:${seed}`),
    worker_process_id: 61001,
    worker_process_pidversion: 81,
    worker_process_instance_digest: digest(`worker-process-instance:${seed}`),
    worker_process_start_digest: digest(`worker-process-start:${seed}`),
    worker_mapped_image_digest: digest(`worker-mapped-image:${seed}`),
    worker_principal_id: "principal:effect-worker",
    worker_principal_policy_digest: digest(`worker-principal-policy:${seed}`),
    worker_direct_parent_audit_token_digest: digest(`supervisor-audit-token:${seed}`),
    worker_direct_parent_instance_digest: digest(`supervisor-process-instance:${seed}`),
    worker_direct_parent_start_digest: digest(`supervisor-process-start:${seed}`),
    launch_nonce: nonce(seed.charCodeAt(0)),
    launch_nonce_digest: crypto.createHash("sha256")
      .update(Buffer.from(nonce(seed.charCodeAt(0)), "base64url")).digest("hex"),
    launch_generation: "33",
    authority_id: "authority:physical-effect",
    authority_epoch: "21",
    revocation_generation: "12",
    revocation_state_digest: digest("fixture-revocation-state"),
    resource_epoch: "44",
    resource_state_digest: digest(`resource-state:${seed}`),
    capability_set_digest: digest(`capability-set:${seed}`),
    expected_descriptor_semantics_digest: descriptorSemantics,
    observed_descriptor_semantics_digest: descriptorSemantics,
    descriptor_identity_digest: digest(`descriptor-identity:${seed}`),
    receiver_cloexec_applied: true,
    descriptor_aliases_absent: true,
    unexpected_descriptors_closed: true,
    capability_generation: "55",
    grant_sequence: "101",
    go_sequence: "102",
    clock_epoch_digest: digest(`clock-epoch:${seed}`),
    not_before_monotonic_ns: "100",
    grant_deadline_monotonic_ns: "1000",
    go_deadline_monotonic_ns: "2000",
    result_deadline_monotonic_ns: "3000",
    cleanup_deadline_monotonic_ns: "4000",
    parent_deadline_monotonic_ns: "5000",
  });
}

function currentState(binding, overrides = {}) {
  return {
    release_manifest_digest: binding.release_manifest_digest,
    component_id: binding.component_id,
    component_manifest_digest: binding.component_manifest_digest,
    release_artifact_digest: binding.release_artifact_digest,
    capability_abi_digest: binding.capability_abi_digest,
    handoff_session_id: binding.handoff_session_id,
    handoff_session_digest: binding.handoff_session_digest,
    supervisor_audit_token_digest: binding.supervisor_audit_token_digest,
    supervisor_process_id: binding.supervisor_process_id,
    supervisor_process_pidversion: binding.supervisor_process_pidversion,
    supervisor_process_instance_digest: binding.supervisor_process_instance_digest,
    supervisor_process_start_digest: binding.supervisor_process_start_digest,
    supervisor_mapped_image_digest: binding.supervisor_mapped_image_digest,
    supervisor_principal_id: binding.supervisor_principal_id,
    supervisor_principal_policy_digest: binding.supervisor_principal_policy_digest,
    supervisor_listener_generation: binding.supervisor_listener_generation,
    supervisor_listener_identity_digest: binding.supervisor_listener_identity_digest,
    worker_audit_token_digest: binding.worker_audit_token_digest,
    worker_process_id: binding.worker_process_id,
    worker_process_pidversion: binding.worker_process_pidversion,
    worker_process_instance_digest: binding.worker_process_instance_digest,
    worker_process_start_digest: binding.worker_process_start_digest,
    worker_mapped_image_digest: binding.worker_mapped_image_digest,
    worker_principal_id: binding.worker_principal_id,
    worker_principal_policy_digest: binding.worker_principal_policy_digest,
    worker_direct_parent_audit_token_digest: binding.worker_direct_parent_audit_token_digest,
    worker_direct_parent_instance_digest: binding.worker_direct_parent_instance_digest,
    worker_direct_parent_start_digest: binding.worker_direct_parent_start_digest,
    launch_nonce: binding.launch_nonce,
    launch_nonce_digest: binding.launch_nonce_digest,
    launch_generation: binding.launch_generation,
    authority_id: binding.authority_id,
    authority_epoch: binding.authority_epoch,
    revocation_generation: binding.revocation_generation,
    revocation_state_digest: binding.revocation_state_digest,
    resource_epoch: binding.resource_epoch,
    resource_state_digest: binding.resource_state_digest,
    capability_set_digest: binding.capability_set_digest,
    expected_descriptor_semantics_digest: binding.expected_descriptor_semantics_digest,
    observed_descriptor_semantics_digest: binding.observed_descriptor_semantics_digest,
    descriptor_identity_digest: binding.descriptor_identity_digest,
    receiver_cloexec_applied: true,
    descriptor_aliases_absent: true,
    unexpected_descriptors_closed: true,
    capability_generation: binding.capability_generation,
    clock_epoch_digest: binding.clock_epoch_digest,
    observed_monotonic_ns: "1200",
    ...overrides,
  };
}

function makeScenario(options = {}) {
  const authority = options.authority || makeAuthority();
  const binding = options.binding || makeBinding(options.seed || "main");
  const bindingDigest = hashCanonicalJson(binding);
  const receiptObservation = options.receipt_observation || "present";
  const malformedReceiptDigest = receiptObservation === "malformed"
    ? digest("malformed-receipt-bytes") : null;
  const journal = [];
  const outbox = [];
  const durability = [];
  const chainOffsets = { journal: 0, outbox: 0 };
  const chainFiles = {
    journal: digest(`journal-file:${binding.exchange_id}`),
    outbox: digest(`outbox-file:${binding.exchange_id}`),
  };

  function attest(chainKind, record, completed) {
    const chain = chainKind === "journal" ? journal : outbox;
    const globalSequence = durability.length + 1;
    const attestation = signDurabilityAttestation({
      signer: authority.signers.durability_custodian,
      payload: {
        version: AUTHENTICATED_EXCHANGE_VERSION,
        protocol: AUTHENTICATED_EXCHANGE_PROTOCOL,
        kind: "durability_attestation",
        binding,
        binding_digest: bindingDigest,
        attestation_id: `durability-attestation:${globalSequence}`,
        durability_sequence: String(globalSequence),
        previous_attestation_digest: durability.length === 0
          ? null : durability.at(-1).envelope_digest,
        chain_kind: chainKind,
        chain_sequence: String(chain.length),
        record_envelope_digest: record.envelope_digest,
        record_payload_digest: record.payload_digest,
        record_canonical_sha256: canonicalRecordSha256(record),
        previous_record_envelope_digest: chain.length === 1
          ? null : chain.at(-2).envelope_digest,
        store_id: `store:${chainKind}`,
        store_epoch: "1",
        file_identity_digest: chainFiles[chainKind],
        file_generation: "1",
        record_offset: String(chainOffsets[chainKind]),
        record_byte_length: canonicalRecordByteLength(record),
        append_sequence: String(globalSequence * 3 - 2),
        append_completed_monotonic_ns: String(completed + 1),
        data_fsync_sequence: String(globalSequence * 3 - 1),
        data_fsync_completed_monotonic_ns: String(completed + 2),
        directory_fsync_sequence: String(globalSequence * 3),
        directory_fsync_completed_monotonic_ns: String(completed + 3),
        exclusive_writer_principal_id: authority.signers.durability_custodian.principal_id,
        durability_scheme: DURABILITY_SCHEME,
        evidence_origin: DURABILITY_EVIDENCE_ORIGIN,
        stable_bytes_verified: true,
      },
    });
    durability.push(attestation);
    chainOffsets[chainKind] += canonicalRecordByteLength(record);
    return attestation;
  }

  function addJournal(event, fromState, toState, subjectKind, subjectDigest, recorded) {
    const entry = signJournalEntry({
      signer: authority.signers.durability_custodian,
      payload: {
        version: AUTHENTICATED_EXCHANGE_VERSION,
        protocol: AUTHENTICATED_EXCHANGE_PROTOCOL,
        kind: "journal_entry",
        binding,
        binding_digest: bindingDigest,
        journal_id: `journal:${binding.exchange_id}`,
        entry_sequence: String(journal.length + 1),
        previous_entry_digest: journal.length === 0 ? null : journal.at(-1).envelope_digest,
        from_state: fromState,
        to_state: toState,
        event,
        subject_kind: subjectKind,
        subject_digest: subjectDigest,
        recorded_monotonic_ns: String(recorded),
      },
    });
    journal.push(entry);
    attest("journal", entry, recorded);
    return entry;
  }

  function addOutbox(event, terminalJournal, result, receipt, recorded, acknowledgement = null) {
    const sequence = outbox.length + 1;
    const entry = signOutboxRecord({
      signer: authority.signers.durability_custodian,
      payload: {
        version: AUTHENTICATED_EXCHANGE_VERSION,
        protocol: AUTHENTICATED_EXCHANGE_PROTOCOL,
        kind: "outbox_record",
        binding,
        binding_digest: bindingDigest,
        outbox_id: `outbox:${binding.exchange_id}`,
        entry_sequence: String(sequence),
        previous_entry_digest: sequence === 1 ? null : outbox.at(-1).envelope_digest,
        event,
        delivery_id: `delivery:${binding.exchange_id}`,
        delivery_state: event === "terminal_enqueued" ? "pending" : "acknowledged",
        terminal_state: receipt ? receipt.payload.terminal_state : "ambiguous_quarantined",
        terminal_journal_entry_digest: terminalJournal.envelope_digest,
        grant_envelope_digest: grant.envelope_digest,
        go_envelope_digest: go ? go.envelope_digest : null,
        receipt_observation: receiptObservation,
        receipt_envelope_digest: receipt ? receipt.envelope_digest : null,
        receipt_evidence_digest: malformedReceiptDigest,
        exact_result: result,
        exact_result_digest: hashCanonicalJson(result),
        cleanup_state: result.cleanup_state,
        retry_disposition: "effect_retry_forbidden",
        subject_digest: acknowledgement || terminalJournal.envelope_digest,
        acknowledgement_digest: acknowledgement,
        recorded_monotonic_ns: String(recorded),
      },
    });
    outbox.push(entry);
    attest("outbox", entry, recorded);
    return entry;
  }

  const grant = signCapabilityGrant({
    signer: authority.signers.grant_authority,
    payload: {
      version: AUTHENTICATED_EXCHANGE_VERSION,
      protocol: AUTHENTICATED_EXCHANGE_PROTOCOL,
      kind: "capability_grant",
      binding,
      binding_digest: bindingDigest,
      grant_id: `grant:${binding.exchange_id}`,
      grant_nonce: nonce(201),
      one_use: true,
      operation_digest: digest("operation"),
      authorized_transition_digest: digest("authorized-transition"),
      cleanup_plan_digest: digest("cleanup-plan"),
      result_contract_digest: digest("result-contract"),
      previous_journal_entry_digest: null,
      issued_monotonic_ns: "200",
      capabilities_only_after_durable_grant: true,
      effect_forbidden_before_go: true,
    },
  });
  const grantEntry = addJournal(
    "grant_fsynced", "none", "grant_reserved", "capability_grant", grant.envelope_digest, 300,
  );
  const transferDigest = digest("capability-transfer-ack");
  addJournal("capabilities_transferred", "grant_reserved", "capabilities_transferred",
    "capability_transfer_ack", transferDigest, 400);
  const readyDigest = digest("ready-no-effect");
  const readyEntry = addJournal("ready_no_effect", "capabilities_transferred", "ready_no_effect",
    "ready_no_effect", readyDigest, 500);
  const go = signCommitGo({
    signer: authority.signers.go_authority,
    payload: {
      version: AUTHENTICATED_EXCHANGE_VERSION,
      protocol: AUTHENTICATED_EXCHANGE_PROTOCOL,
      kind: "commit_go",
      binding,
      binding_digest: bindingDigest,
      go_id: `go:${binding.exchange_id}`,
      grant_envelope_digest: grant.envelope_digest,
      grant_payload_digest: grant.payload_digest,
      grant_journal_entry_digest: grantEntry.envelope_digest,
      capability_transfer_ack_digest: transferDigest,
      ready_no_effect_digest: readyDigest,
      previous_journal_entry_digest: readyEntry.envelope_digest,
      issued_monotonic_ns: "600",
      one_use: true,
      effect_only_after_durable_go: true,
    },
  });
  const goEntry = addJournal("go_fsynced", "ready_no_effect", "go_reserved", "commit_go",
    go.envelope_digest, 650);
  addJournal("effect_started", "go_reserved", "effect_started", "effect_start_authority",
    go.envelope_digest, 700);

  let receipt = null;
  let exactResult;
  let terminalEntry;
  if (receiptObservation === "present") {
    exactResult = {
      result_status: "succeeded",
      effect_state: "confirmed_effect",
      result_code: "completed",
      response_digest: digest("exact-response"),
      response_byte_length: 64,
      device_state_digest: digest("terminal-device-state"),
      external_observation_digest: digest("external-observation"),
      cleanup_state: "not_required",
      cleanup_evidence_digest: null,
    };
    receipt = signTerminalReceipt({
      signer: authority.signers.effect_worker,
      payload: {
        version: AUTHENTICATED_EXCHANGE_VERSION,
        protocol: AUTHENTICATED_EXCHANGE_PROTOCOL,
        kind: "terminal_receipt",
        binding,
        binding_digest: bindingDigest,
        receipt_id: `receipt:${binding.exchange_id}`,
        grant_envelope_digest: grant.envelope_digest,
        go_envelope_digest: go.envelope_digest,
        go_journal_entry_digest: goEntry.envelope_digest,
        receipt_sequence: "1",
        terminal_state: "completed",
        exact_result: exactResult,
        exact_result_digest: hashCanonicalJson(exactResult),
        cleanup_plan_digest: grant.payload.cleanup_plan_digest,
        capabilities_closed: true,
        transport_fenced: false,
        completed_monotonic_ns: "800",
      },
    });
    addJournal("receipt_fsynced", "effect_started", "receipt_recorded", "terminal_receipt",
      receipt.envelope_digest, 850);
    terminalEntry = addJournal("terminal_completed", "receipt_recorded", "completed",
      "terminal_receipt", receipt.envelope_digest, 900);
  } else {
    const evidence = malformedReceiptDigest;
    exactResult = {
      result_status: "ambiguous",
      effect_state: "unknown_effect",
      result_code: receiptObservation === "missing"
        ? "missing_post_go_receipt" : "malformed_post_go_receipt",
      response_digest: null,
      response_byte_length: 0,
      device_state_digest: null,
      external_observation_digest: evidence,
      cleanup_state: "failed_ambiguous",
      cleanup_evidence_digest: evidence || hashCanonicalJson({ observation: "missing" }),
    };
    terminalEntry = addJournal("terminal_ambiguous", "effect_started", "ambiguous_quarantined",
      "receipt_loss_evidence", hashCanonicalJson(exactResult), 900);
  }
  addOutbox("terminal_enqueued", terminalEntry, exactResult, receipt, 1000);
  const acknowledgement = digest("terminal-delivery-acknowledgement");
  addOutbox("terminal_acknowledged", terminalEntry, exactResult, receipt, 1100,
    acknowledgement);

  return {
    authority,
    binding,
    grant,
    go,
    receipt,
    receiptObservation,
    malformedReceiptDigest,
    exactResult,
    journal,
    outbox,
    durability,
    chainFiles,
    current: currentState(binding),
  };
}

function durableStore(scenario, chainKind, records, overrides = {}) {
  const recordBytes = records.map((record) => Buffer.from(canonicalJson(record), "utf8"));
  return {
    version: AUTHENTICATED_EXCHANGE_VERSION,
    kind: "authenticated_exchange_durable_store_readback",
    chain_kind: chainKind,
    store_id: `store:${chainKind}`,
    store_epoch: "1",
    file_identity_digest: chainKind === "durability"
      ? digest(`durability-file:${scenario.binding.exchange_id}`)
      : scenario.chainFiles[chainKind],
    file_generation: "1",
    record_count: records.length,
    record_byte_length: recordBytes.reduce((total, bytes) => total + bytes.length, 0),
    head_envelope_digest: records.length === 0 ? null : records.at(-1).envelope_digest,
    record_bytes: recordBytes,
    ...overrides,
  };
}

function durableSnapshot(scenario, overrides = {}) {
  const journal = Object.hasOwn(overrides, "journal") ? overrides.journal : scenario.journal;
  const outbox = Object.hasOwn(overrides, "outbox") ? overrides.outbox : scenario.outbox;
  const durability = Object.hasOwn(overrides, "durability")
    ? overrides.durability : scenario.durability;
  return {
    version: AUTHENTICATED_EXCHANGE_VERSION,
    kind: "authenticated_exchange_durable_snapshot",
    exchange_id: scenario.binding.exchange_id,
    binding_digest: hashCanonicalJson(scenario.binding),
    snapshot_id: `snapshot:${scenario.binding.exchange_id}:1`,
    snapshot_sequence: "1",
    journal: durableStore(scenario, "journal", journal),
    outbox: durableStore(scenario, "outbox", outbox),
    durability: durableStore(scenario, "durability", durability),
    ...overrides.snapshot,
  };
}

function makeDurableReadbackPort(scenario, overrides = {}) {
  const readSnapshot = overrides.read_snapshot || (() => durableSnapshot(scenario, overrides));
  return createFixtureDurableReadbackPort({
    version: AUTHENTICATED_EXCHANGE_VERSION,
    kind: "authenticated_exchange_fixture_durable_readback_port",
    port_id: overrides.port_id || `durable-readback:${scenario.binding.exchange_id}`,
    test_only: true,
    consistency_model: overrides.consistency_model || DURABLE_READBACK_CONSISTENCY_MODEL,
    read_snapshot: readSnapshot,
  });
}

function reconcileInput(scenario, overrides = {}) {
  const input = {
    version: AUTHENTICATED_EXCHANGE_VERSION,
    grant: scenario.grant,
    go: scenario.go,
    receipt: scenario.receipt,
    receipt_observation: scenario.receiptObservation,
    malformed_receipt_digest: scenario.malformedReceiptDigest,
    journal_entries: scenario.journal,
    outbox_entries: scenario.outbox,
    durability_attestations: scenario.durability,
    current_state: scenario.current,
    auto_retry_requested: false,
    verifier: scenario.authority.verifier,
    ...overrides,
  };
  if (!Object.hasOwn(overrides, "durable_readback_port")) {
    input.durable_readback_port = makeDurableReadbackPort(scenario, {
      journal: input.journal_entries,
      outbox: input.outbox_entries,
      durability: input.durability_attestations,
    });
  }
  return input;
}

test("four pairwise-distinct roles authenticate a fully durable terminal exchange", () => {
  const scenario = makeScenario();
  const result = reconcileAuthenticatedExchange(reconcileInput(scenario));

  assert.equal(result.state, "completed");
  assert.equal(result.authenticated_terminal, true);
  assert.equal(result.outbox_delivery_state, "acknowledged");
  assert.equal(result.recovery_action, "none");
  assert.equal(result.grant_consumed, true);
  assert.equal(result.go_consumed, true);
  assert.equal(result.automatic_effect_retry_permitted, false);
  assert.equal(result.production_ready, false);
  assert.equal(result.hardware_access_authorized, false);
  assert.equal(scenario.authority.verifier.entries.length, 4);
  assert.equal(new Set(scenario.authority.verifier.entries.map((entry) => entry.principal_id)).size, 4);
  assert.equal(new Set(scenario.authority.verifier.entries.map((entry) => entry.key_usage)).size, 4);

  const serialized = canonicalJson({
    result,
    signers: Object.values(scenario.authority.signers),
    verifier: scenario.authority.verifier,
  });
  assert.doesNotMatch(serialized, /private_key|BEGIN PRIVATE KEY|public_key[^_d]/u);
});

test("durable readback is privately branded, synchronous, strong, and least-authority", () => {
  const scenario = makeScenario({ seed: "readback-port" });
  let observedRequest = null;
  const port = makeDurableReadbackPort(scenario, {
    read_snapshot(request) {
      observedRequest = request;
      return durableSnapshot(scenario);
    },
  });
  const result = reconcileAuthenticatedExchange(reconcileInput(scenario, {
    durable_readback_port: port,
  }));
  assert.ok(Object.isFrozen(port));
  assert.equal(port.production_ready, false);
  assert.equal(port.caller_supplied_backend, true);
  assert.equal(port.read_snapshot, undefined);
  assert.ok(Object.isFrozen(observedRequest));
  assert.equal(observedRequest.exchange_id, scenario.binding.exchange_id);
  assert.equal(result.durable_snapshot_id, `snapshot:${scenario.binding.exchange_id}:1`);

  const lookalike = Object.freeze({ ...port });
  assert.throws(() => reconcileAuthenticatedExchange(reconcileInput(scenario, {
    durable_readback_port: lookalike,
  })), (error) => error.code === "durable_readback_port_invalid");

  assert.throws(() => makeDurableReadbackPort(scenario, {
    consistency_model: "eventually_consistent",
  }), /consistency_model/u);
  assert.throws(() => makeDurableReadbackPort(scenario, {
    read_snapshot: async () => durableSnapshot(scenario),
  }), (error) => error.code === "durable_readback_port_invalid");

  const promisePort = makeDurableReadbackPort(scenario, {
    read_snapshot: () => Promise.resolve(durableSnapshot(scenario)),
  });
  assert.throws(() => reconcileAuthenticatedExchange(reconcileInput(scenario, {
    durable_readback_port: promisePort,
  })), (error) => error.code === "durable_readback_async");

  let thenGetterRead = false;
  const hostileThenable = {};
  Object.defineProperty(hostileThenable, "then", {
    get() {
      thenGetterRead = true;
      return () => {};
    },
  });
  const hostilePort = makeDurableReadbackPort(scenario, {
    read_snapshot: () => hostileThenable,
  });
  assert.throws(() => reconcileAuthenticatedExchange(reconcileInput(scenario, {
    durable_readback_port: hostilePort,
  })), (error) => error.code === "durable_readback_invalid");
  assert.equal(thenGetterRead, false);
});

test("durable readback rejects alternate encodings and caller-shaped byte forks", () => {
  const scenario = makeScenario({ seed: "readback-bytes" });
  const alternateSnapshot = durableSnapshot(scenario);
  const canonical = canonicalJson(scenario.journal[0]);
  const alternate = Buffer.from(`${canonical}\n`, "utf8");
  alternateSnapshot.journal.record_bytes[0] = alternate;
  alternateSnapshot.journal.record_byte_length += 1;
  const alternatePort = makeDurableReadbackPort(scenario, {
    read_snapshot: () => alternateSnapshot,
  });
  assert.throws(() => reconcileAuthenticatedExchange(reconcileInput(scenario, {
    durable_readback_port: alternatePort,
  })), (error) => error.code === "durable_readback_invalid");

  const foreignBytes = durableSnapshot(scenario);
  foreignBytes.journal.record_bytes[0] = Buffer.from(
    canonicalJson(scenario.journal[1]), "utf8",
  );
  foreignBytes.journal.record_byte_length = foreignBytes.journal.record_bytes
    .reduce((total, bytes) => total + bytes.length, 0);
  const foreignPort = makeDurableReadbackPort(scenario, {
    read_snapshot: () => foreignBytes,
  });
  assert.throws(() => reconcileAuthenticatedExchange(reconcileInput(scenario, {
    durable_readback_port: foreignPort,
  })), (error) => ["durable_readback_invalid", "durable_readback_mismatch"].includes(error.code));

  const durable = durableSnapshot(scenario);
  const claimedForkPayload = clone(scenario.outbox[1].payload);
  claimedForkPayload.acknowledgement_digest = digest("alternate-delivery-ack");
  claimedForkPayload.subject_digest = claimedForkPayload.acknowledgement_digest;
  const claimedFork = signOutboxRecord({
    signer: scenario.authority.signers.durability_custodian,
    payload: claimedForkPayload,
  });
  assert.throws(() => reconcileAuthenticatedExchange(reconcileInput(scenario, {
    outbox_entries: [scenario.outbox[0], claimedFork],
    durable_readback_port: makeDurableReadbackPort(scenario, {
      read_snapshot: () => durable,
    }),
  })), (error) => error.code === "durable_readback_mismatch");
});

test("lost outbox acknowledgement resolves only from the exact durable suffix", () => {
  const scenario = makeScenario({ seed: "lost-outbox-ack" });
  const fullPort = makeDurableReadbackPort(scenario);
  const result = reconcileAuthenticatedExchange(reconcileInput(scenario, {
    outbox_entries: scenario.outbox.slice(0, 1),
    durability_attestations: scenario.durability.slice(0, -1),
    durable_readback_port: fullPort,
  }));
  assert.equal(result.durable_readback_recovered_acknowledgement, true);
  assert.equal(result.outbox_delivery_state, "acknowledged");
  assert.equal(result.recovery_action, "none");
  assert.equal(result.automatic_effect_retry_permitted, false);
  assert.equal(result.outbox_redelivery_permitted, false);
  assert.equal(result.terminal_outbox_identity_digest.length, 64);

  assert.throws(() => reconcileAuthenticatedExchange(reconcileInput(scenario, {
    outbox_entries: [],
    durability_attestations: scenario.durability.slice(0, -1),
    durable_readback_port: fullPort,
  })), (error) => error.code === "durable_readback_mismatch");

  const forkedSuffix = durableSnapshot(scenario);
  forkedSuffix.durability.record_bytes = forkedSuffix.durability.record_bytes.slice(0, -1);
  forkedSuffix.durability.record_count -= 1;
  forkedSuffix.durability.record_byte_length = forkedSuffix.durability.record_bytes
    .reduce((total, bytes) => total + bytes.length, 0);
  forkedSuffix.durability.head_envelope_digest = scenario.durability.at(-2).envelope_digest;
  const forkedPort = makeDurableReadbackPort(scenario, {
    read_snapshot: () => forkedSuffix,
  });
  assert.throws(() => reconcileAuthenticatedExchange(reconcileInput(scenario, {
    outbox_entries: scenario.outbox.slice(0, 1),
    durability_attestations: scenario.durability.slice(0, -1),
    durable_readback_port: forkedPort,
  })), (error) => error.code === "durable_readback_mismatch");
});

test("readback rejects cross-session, command, and signed-sequence substitution", () => {
  const scenario = makeScenario({ seed: "readback-origin" });
  const foreignSession = makeScenario({
    seed: "readback-foreign-session",
    authority: scenario.authority,
  });
  assert.throws(() => reconcileAuthenticatedExchange(reconcileInput(foreignSession, {
    durable_readback_port: makeDurableReadbackPort(scenario),
  })), (error) => ["schema_invalid", "durable_readback_invalid"].includes(error.code));

  const commandForkPayload = clone(scenario.grant.payload);
  commandForkPayload.operation_digest = digest("another-physical-command");
  const commandFork = signCapabilityGrant({
    signer: scenario.authority.signers.grant_authority,
    payload: commandForkPayload,
  });
  assert.throws(() => reconcileAuthenticatedExchange(reconcileInput(scenario, {
    grant: commandFork,
  })), (error) => error.code === "binding_invalid");

  const sequenceBinding = normalizeBinding({
    ...clone(scenario.binding),
    grant_sequence: incrementUint64(scenario.binding.grant_sequence),
    go_sequence: incrementUint64(scenario.binding.go_sequence),
  });
  const sequenceFork = makeScenario({
    authority: scenario.authority,
    binding: sequenceBinding,
  });
  assert.throws(() => reconcileAuthenticatedExchange(reconcileInput(sequenceFork, {
    durable_readback_port: makeDurableReadbackPort(scenario),
  })), (error) => ["schema_invalid", "durable_readback_invalid"].includes(error.code));

  const receiptLoss = makeScenario({
    seed: "effect-correlation",
    receipt_observation: "missing",
  });
  const detachedEffectPayload = clone(receiptLoss.journal[4].payload);
  detachedEffectPayload.subject_digest = digest("detached-effect-authority");
  const detachedEffect = signJournalEntry({
    signer: receiptLoss.authority.signers.durability_custodian,
    payload: detachedEffectPayload,
  });
  assert.throws(() => reconcileAuthenticatedExchange(reconcileInput(receiptLoss, {
    journal_entries: [...receiptLoss.journal.slice(0, 4), detachedEffect],
    outbox_entries: [],
    durability_attestations: receiptLoss.durability.slice(0, 5),
  })), (error) => error.code === "binding_invalid");
});

test("cross-usage signers and cross-usage authentication fields fail closed", () => {
  const scenario = makeScenario();
  assert.throws(() => signCapabilityGrant({
    payload: scenario.grant.payload,
    signer: scenario.authority.signers.go_authority,
  }), (error) => error.code === "signer_invalid");

  const fork = clone(scenario.grant);
  fork.authentication.key_usage = ROLE_DEFINITIONS.go_authority.key_usage;
  assert.throws(
    () => verifyCapabilityGrant(fork, scenario.authority.verifier),
    (error) => error.code === "schema_invalid",
  );

  const substitutedVerifierInput = {
    version: AUTHENTICATED_EXCHANGE_VERSION,
    kind: "authenticated_exchange_fixture_keyring",
    trust_epoch: 7,
    revocation_generation: "12",
    revocation_state_digest: digest("fixture-revocation-state"),
    entries: scenario.authority.roles.map((role, index) => ({
      role,
      key_usage: ROLE_DEFINITIONS[role].key_usage,
      principal_id: scenario.authority.signers[role].principal_id,
      key_id: scenario.authority.signers[role].key_id,
      trust_epoch: 7,
      revoked: false,
      public_key: scenario.authority.keys[(index + 1) % 4].publicKey,
    })),
  };
  const verifier = createFixtureExchangeVerifier(substitutedVerifierInput);
  assert.throws(
    () => verifyCapabilityGrant(scenario.grant, verifier),
    (error) => error.code === "authentication_invalid",
  );
});

test("grant nonce/generation and GO sequence reuse are rejected across exchanges", () => {
  const scenario = makeScenario();
  assert.throws(() => verifySingleUseExchangeRecords({
    version: AUTHENTICATED_EXCHANGE_VERSION,
    grants: [scenario.grant, scenario.grant],
    gos: [scenario.go],
    verifier: scenario.authority.verifier,
  }), (error) => error.code === "single_use_violation");
  assert.throws(() => verifySingleUseExchangeRecords({
    version: AUTHENTICATED_EXCHANGE_VERSION,
    grants: [scenario.grant],
    gos: [scenario.go, scenario.go],
    verifier: scenario.authority.verifier,
  }), (error) => error.code === "single_use_violation");
});

test("validly resigned journal and outbox chain splices are rejected", () => {
  const scenario = makeScenario();
  const splicedJournalPayload = clone(scenario.journal[1].payload);
  splicedJournalPayload.previous_entry_digest = digest("foreign-journal-head");
  const splicedJournal = signJournalEntry({
    payload: splicedJournalPayload,
    signer: scenario.authority.signers.durability_custodian,
  });
  const journal = [...scenario.journal];
  journal[1] = splicedJournal;
  assert.throws(
    () => reconcileAuthenticatedExchange(reconcileInput(scenario, { journal_entries: journal })),
    (error) => error.code === "chain_invalid",
  );

  const splicedOutboxPayload = clone(scenario.outbox[1].payload);
  splicedOutboxPayload.previous_entry_digest = digest("foreign-outbox-head");
  const splicedOutbox = signOutboxRecord({
    payload: splicedOutboxPayload,
    signer: scenario.authority.signers.durability_custodian,
  });
  const outbox = [scenario.outbox[0], splicedOutbox];
  assert.throws(
    () => reconcileAuthenticatedExchange(reconcileInput(scenario, { outbox_entries: outbox })),
    (error) => error.code === "chain_invalid",
  );

  const malformed = makeScenario({
    receipt_observation: "malformed",
    seed: "outbox-evidence-splice",
  });
  const evidenceSplicePayload = clone(malformed.outbox[1].payload);
  evidenceSplicePayload.receipt_evidence_digest = digest("foreign-malformed-receipt-evidence");
  const evidenceSplice = signOutboxRecord({
    payload: evidenceSplicePayload,
    signer: malformed.authority.signers.durability_custodian,
  });
  assert.throws(() => reconcileAuthenticatedExchange(reconcileInput(malformed, {
    outbox_entries: [malformed.outbox[0], evidenceSplice],
  })), (error) => error.code === "chain_invalid");
});

test("closed schemas reject extra fields, accessors, proxies, and descriptor contradictions", () => {
  const scenario = makeScenario();
  const extra = clone(scenario.grant);
  extra.future_field = true;
  assert.throws(() => verifyCapabilityGrant(extra, scenario.authority.verifier),
    (error) => error.code === "envelope_invalid");

  const accessor = clone(scenario.grant);
  Object.defineProperty(accessor, "payload_digest", { get() { return scenario.grant.payload_digest; },
    enumerable: true });
  assert.throws(() => verifyCapabilityGrant(accessor, scenario.authority.verifier),
    (error) => error.code === "envelope_invalid");
  assert.throws(() => verifyCapabilityGrant(new Proxy(scenario.grant, {}),
    scenario.authority.verifier), (error) => error.code === "envelope_invalid");

  const drift = clone(scenario.binding);
  drift.observed_descriptor_semantics_digest = digest("wrong-observed-masks");
  assert.throws(() => normalizeBinding(drift),
    (error) => error.code === "descriptor_semantics_invalid");
  for (const field of [
    "receiver_cloexec_applied", "descriptor_aliases_absent", "unexpected_descriptors_closed",
  ]) {
    const falseClaim = clone(scenario.binding);
    falseClaim[field] = false;
    assert.throws(() => normalizeBinding(falseClaim), (error) => error.code === "schema_invalid");
  }
});

test("lineage and replay counters are canonical uint64 strings with GO strictly after grant", () => {
  const binding = makeBinding("uint64-sequences");
  for (const goSequence of [binding.grant_sequence, "100"]) {
    const invalid = clone(binding);
    invalid.go_sequence = goSequence;
    assert.throws(() => normalizeBinding(invalid),
      (error) => error.code === "sequence_invalid");
  }

  for (const invalidGeneration of [19, "019", "18446744073709551616"]) {
    const invalid = clone(binding);
    invalid.supervisor_listener_generation = invalidGeneration;
    assert.throws(() => normalizeBinding(invalid),
      (error) => error.code === "schema_invalid");
  }

  const maximum = "18446744073709551615";
  const aboveSafeInteger = clone(binding);
  aboveSafeInteger.supervisor_listener_generation = maximum;
  aboveSafeInteger.launch_generation = maximum;
  aboveSafeInteger.authority_epoch = maximum;
  aboveSafeInteger.resource_epoch = maximum;
  aboveSafeInteger.capability_generation = maximum;
  aboveSafeInteger.grant_sequence = "18446744073709551614";
  aboveSafeInteger.go_sequence = maximum;
  assert.equal(normalizeBinding(aboveSafeInteger).go_sequence, maximum);
});

test("live GO checks reject lineage, authority, resource, revocation, and time drift", () => {
  const scenario = makeScenario();
  const cases = [
    { worker_process_pidversion: scenario.binding.worker_process_pidversion + 1 },
    { worker_direct_parent_start_digest: digest("recycled-parent") },
    { release_artifact_digest: digest("release-artifact-drift") },
    { capability_abi_digest: digest("capability-abi-drift") },
    { handoff_session_id: "handoff-session:different" },
    { supervisor_listener_generation:
      incrementUint64(scenario.binding.supervisor_listener_generation) },
    { launch_nonce: nonce(99) },
    { authority_epoch: incrementUint64(scenario.binding.authority_epoch) },
    { revocation_generation: incrementUint64(scenario.binding.revocation_generation) },
    { resource_epoch: incrementUint64(scenario.binding.resource_epoch) },
    { observed_descriptor_semantics_digest: digest("descriptor-mask-drift") },
    { observed_monotonic_ns: scenario.binding.go_deadline_monotonic_ns },
  ];
  for (const overrides of cases) {
    assert.throws(() => assertLiveExchangeState({
      binding: scenario.binding,
      current_state: currentState(scenario.binding, overrides),
      phase: "go",
    }), (error) => error.code === "live_state_drift");
  }

  const brokenParent = clone(scenario.binding);
  brokenParent.worker_direct_parent_instance_digest = digest("not-the-supervisor-instance");
  assert.throws(() => normalizeBinding(brokenParent),
    (error) => error.code === "process_lineage_invalid");
});

test("effect and result live checks use the signed result deadline at its exact boundary", () => {
  const scenario = makeScenario();
  for (const phase of ["effect", "result"]) {
    const valid = assertLiveExchangeState({
      binding: scenario.binding,
      current_state: currentState(scenario.binding, { observed_monotonic_ns: "2999" }),
      phase,
    });
    assert.equal(valid.valid, true, phase);
    assert.throws(() => assertLiveExchangeState({
      binding: scenario.binding,
      current_state: currentState(scenario.binding, {
        observed_monotonic_ns: scenario.binding.result_deadline_monotonic_ns,
      }),
      phase,
    }), (error) => error.code === "live_state_drift", phase);
  }
});

test("array prototype setters cannot intercept verified projections or chain construction", () => {
  const scenario = makeScenario({ seed: "array-prototype-setter" });
  const verifierInput = {
    version: AUTHENTICATED_EXCHANGE_VERSION,
    kind: "authenticated_exchange_fixture_keyring",
    trust_epoch: 7,
    revocation_generation: "12",
    revocation_state_digest: digest("fixture-revocation-state"),
    entries: scenario.authority.roles.map((role, index) => ({
      role,
      key_usage: ROLE_DEFINITIONS[role].key_usage,
      principal_id: scenario.authority.signers[role].principal_id,
      key_id: scenario.authority.signers[role].key_id,
      trust_epoch: 7,
      revoked: false,
      public_key: scenario.authority.keys[index].publicKey,
    })),
  };
  const previous = Object.getOwnPropertyDescriptor(Array.prototype, "0");
  let setterInvocations = 0;
  let verifier;
  let reconciliation;
  let caught = null;
  Object.defineProperty(Array.prototype, "0", {
    configurable: true,
    set() { setterInvocations += 1; },
  });
  try {
    verifier = createFixtureExchangeVerifier(verifierInput);
    reconciliation = reconcileAuthenticatedExchange(reconcileInput(scenario));
  } catch (error) {
    caught = error;
  } finally {
    if (previous) Object.defineProperty(Array.prototype, "0", previous);
    else delete Array.prototype[0];
  }
  if (caught) throw caught;
  assert.equal(setterInvocations, 0);
  assert.equal(verifier.entries.length, 4);
  assert.equal(reconciliation.state, "completed");
});

test("nonstandard array prototypes and inherited iterators fail before traversal", () => {
  const scenario = makeScenario({ seed: "hostile-array-iterator" });
  const journal = scenario.journal.slice();
  let iteratorReads = 0;
  const hostilePrototype = Object.create(Array.prototype);
  Object.defineProperty(hostilePrototype, Symbol.iterator, {
    configurable: true,
    get() {
      iteratorReads += 1;
      throw new Error("hostile inherited iterator reached");
    },
  });
  Object.setPrototypeOf(journal, hostilePrototype);
  assert.throws(() => reconcileAuthenticatedExchange(reconcileInput(scenario, {
    journal_entries: journal,
  })), (error) => error.code === "schema_invalid");
  assert.equal(iteratorReads, 0);
});

test("the module initializes under a pre-existing numeric Array prototype setter", () => {
  const target = path.resolve(__dirname, "../lib/authenticated-durable-exchange.js");
  const script = `
    const crypto = require("node:crypto");
    const fs = require("node:fs");
    const Module = require("node:module");
    const path = require("node:path");
    const util = require("node:util");
    const vm = require("node:vm");
    const target = ${JSON.stringify(target)};
    const first = require(target);
    const verificationContracts = require(path.resolve(
      path.dirname(target), "../../../mcp/lib/verification-contracts.js"));
    const source = fs.readFileSync(target, "utf8");
    const compiled = vm.runInThisContext(Module.wrap(source), { filename: target });
    const pairs = [
      crypto.generateKeyPairSync("ed25519"),
      crypto.generateKeyPairSync("ed25519"),
      crypto.generateKeyPairSync("ed25519"),
      crypto.generateKeyPairSync("ed25519"),
    ];
    const roles = ["grant_authority", "go_authority", "effect_worker", "durability_custodian"];
    const entries = [
      { role: roles[0], key_usage: first.ROLE_DEFINITIONS[roles[0]].key_usage,
        principal_id: "principal:reload-grant", key_id: "key:reload-grant", trust_epoch: 1,
        revoked: false, public_key: pairs[0].publicKey },
      { role: roles[1], key_usage: first.ROLE_DEFINITIONS[roles[1]].key_usage,
        principal_id: "principal:reload-go", key_id: "key:reload-go", trust_epoch: 1,
        revoked: false, public_key: pairs[1].publicKey },
      { role: roles[2], key_usage: first.ROLE_DEFINITIONS[roles[2]].key_usage,
        principal_id: "principal:reload-effect", key_id: "key:reload-effect", trust_epoch: 1,
        revoked: false, public_key: pairs[2].publicKey },
      { role: roles[3], key_usage: first.ROLE_DEFINITIONS[roles[3]].key_usage,
        principal_id: "principal:reload-durability", key_id: "key:reload-durability", trust_epoch: 1,
        revoked: false, public_key: pairs[3].publicKey },
    ];
    let hits = 0;
    let verifierLength = -1;
    let loaded = false;
    const previous = Object.getOwnPropertyDescriptor(Array.prototype, "0");
    Object.defineProperty(Array.prototype, "0", { configurable: true, set() { hits += 1; } });
    try {
      const moduleRecord = { exports: {} };
      const localRequire = (specifier) => {
        if (specifier === "node:crypto") return crypto;
        if (specifier === "node:util") return util;
        if (specifier === "../../../mcp/lib/verification-contracts.js") {
          return verificationContracts;
        }
        throw new Error("unexpected require: " + specifier);
      };
      compiled(moduleRecord.exports, localRequire, moduleRecord, target, path.dirname(target));
      const second = moduleRecord.exports;
      loaded = true;
      verifierLength = second.createFixtureExchangeVerifier({
        version: second.AUTHENTICATED_EXCHANGE_VERSION,
        kind: "authenticated_exchange_fixture_keyring",
        trust_epoch: 1,
        revocation_generation: "0",
        revocation_state_digest: "a".repeat(64),
        entries,
      }).entries.length;
    } finally {
      if (previous) Object.defineProperty(Array.prototype, "0", previous);
      else delete Array.prototype[0];
    }
    process.stdout.write(JSON.stringify({ loaded, hits, verifierLength }));
  `;
  const child = spawnSync(process.execPath, ["-e", script], { encoding: "utf8" });
  assert.equal(child.status, 0, child.stderr);
  const result = JSON.parse(child.stdout);
  assert.equal(result.loaded, true);
  assert.equal(result.verifierLength, 4);
  assert.equal(result.hits, 0);
});

test("GO and receipt principals plus verifier revocation state remain binding-authoritative", () => {
  const authority = makeAuthority();
  const principalDrift = clone(makeBinding("principal-drift"));
  principalDrift.supervisor_principal_id = "principal:different-supervisor";
  const driftScenario = makeScenario({
    authority,
    binding: normalizeBinding(principalDrift),
    seed: "principal-drift",
  });
  assert.throws(() => reconcileAuthenticatedExchange(reconcileInput(driftScenario)),
    (error) => error.code === "process_lineage_invalid");

  const scenario = makeScenario({ authority, seed: "revocation-drift" });
  const staleVerifier = createFixtureExchangeVerifier({
    version: AUTHENTICATED_EXCHANGE_VERSION,
    kind: "authenticated_exchange_fixture_keyring",
    trust_epoch: 7,
    revocation_generation: "13",
    revocation_state_digest: digest("new-revocation-state"),
    entries: authority.roles.map((role, index) => ({
      role,
      key_usage: ROLE_DEFINITIONS[role].key_usage,
      principal_id: authority.signers[role].principal_id,
      key_id: authority.signers[role].key_id,
      trust_epoch: 7,
      revoked: false,
      public_key: authority.keys[index].publicKey,
    })),
  });
  assert.throws(() => reconcileAuthenticatedExchange(reconcileInput(scenario, {
    verifier: staleVerifier,
  })), (error) => error.code === "authentication_invalid");
});

test("restart reconciliation distinguishes every pre/post-GO crash boundary", () => {
  const scenario = makeScenario();
  const cases = [
    {
      name: "before grant journal commit",
      patch: { go: null, receipt: null, receipt_observation: "not_applicable", journal_entries: [],
        outbox_entries: [], durability_attestations: [] },
      state: "none",
      action: "discard_uncommitted_grant",
      terminal: false,
    },
    {
      name: "after durable grant",
      patch: { go: null, receipt: null, receipt_observation: "not_applicable",
        journal_entries: scenario.journal.slice(0, 1), outbox_entries: [],
        durability_attestations: scenario.durability.slice(0, 1) },
      state: "grant_reserved",
      action: "terminate_exact_child_then_record_rejected_no_effect",
      terminal: false,
    },
    {
      name: "after durable GO before receipt",
      patch: { receipt: null, receipt_observation: "missing",
        journal_entries: scenario.journal.slice(0, 5), outbox_entries: [],
        durability_attestations: scenario.durability.slice(0, 5) },
      state: "ambiguous_quarantined",
      action: "persist_authenticated_ambiguous_quarantine",
      terminal: false,
    },
    {
      name: "after durable receipt before terminal",
      patch: { journal_entries: scenario.journal.slice(0, 6), outbox_entries: [],
        durability_attestations: scenario.durability.slice(0, 6) },
      state: "receipt_recorded",
      action: "persist_authenticated_terminal",
      terminal: false,
    },
    {
      name: "after terminal before outbox",
      patch: { outbox_entries: [], durability_attestations: scenario.durability.slice(0, 7) },
      state: "completed",
      action: "enqueue_authenticated_terminal",
      terminal: false,
    },
    {
      name: "after durable enqueue before acknowledgement",
      patch: { outbox_entries: scenario.outbox.slice(0, 1),
        durability_attestations: scenario.durability.slice(0, 8) },
      state: "completed",
      action: "redeliver_outbox_only",
      terminal: true,
    },
  ];
  for (const fixture of cases) {
    const result = reconcileAuthenticatedExchange(reconcileInput(scenario, fixture.patch));
    assert.equal(result.state, fixture.state, fixture.name);
    assert.equal(result.recovery_action, fixture.action, fixture.name);
    assert.equal(result.authenticated_terminal, fixture.terminal, fixture.name);
    assert.equal(result.automatic_effect_retry_permitted, false, fixture.name);
  }
});

test("pre-GO child exit reaches an authenticated rejected-no-effect terminal", () => {
  const scenario = makeScenario();
  const bindingDigest = hashCanonicalJson(scenario.binding);
  const journal = scenario.journal.slice(0, 3);
  const outbox = [];
  const durability = scenario.durability.slice(0, 3);
  const journalFile = scenario.durability[0].payload.file_identity_digest;
  const outboxFile = scenario.durability[7].payload.file_identity_digest;

  function attest(record, chainKind, chainSequence, completed, fileIdentity) {
    const chain = chainKind === "journal" ? journal : outbox;
    const sequence = durability.length + 1;
    const recordOffset = chain.slice(0, -1)
      .reduce((sum, item) => sum + canonicalRecordByteLength(item), 0);
    const value = signDurabilityAttestation({
      signer: scenario.authority.signers.durability_custodian,
      payload: {
        version: AUTHENTICATED_EXCHANGE_VERSION,
        protocol: AUTHENTICATED_EXCHANGE_PROTOCOL,
        kind: "durability_attestation",
        binding: scenario.binding,
        binding_digest: bindingDigest,
        attestation_id: `durability-attestation:rejected:${sequence}`,
        durability_sequence: String(sequence),
        previous_attestation_digest: durability.at(-1).envelope_digest,
        chain_kind: chainKind,
        chain_sequence: String(chainSequence),
        record_envelope_digest: record.envelope_digest,
        record_payload_digest: record.payload_digest,
        record_canonical_sha256: canonicalRecordSha256(record),
        previous_record_envelope_digest: chainSequence === 1
          ? null : chain.at(-2).envelope_digest,
        store_id: `store:${chainKind}`,
        store_epoch: "1",
        file_identity_digest: fileIdentity,
        file_generation: "1",
        record_offset: String(recordOffset),
        record_byte_length: canonicalRecordByteLength(record),
        append_sequence: String(sequence * 3 - 2),
        append_completed_monotonic_ns: String(completed + 1),
        data_fsync_sequence: String(sequence * 3 - 1),
        data_fsync_completed_monotonic_ns: String(completed + 2),
        directory_fsync_sequence: String(sequence * 3),
        directory_fsync_completed_monotonic_ns: String(completed + 3),
        exclusive_writer_principal_id:
          scenario.authority.signers.durability_custodian.principal_id,
        durability_scheme: DURABILITY_SCHEME,
        evidence_origin: DURABILITY_EVIDENCE_ORIGIN,
        stable_bytes_verified: true,
      },
    });
    durability.push(value);
  }

  const noGoEvidence = digest("exact-child-exit-and-no-go-proof");
  const terminal = signJournalEntry({
    signer: scenario.authority.signers.durability_custodian,
    payload: {
      version: AUTHENTICATED_EXCHANGE_VERSION,
      protocol: AUTHENTICATED_EXCHANGE_PROTOCOL,
      kind: "journal_entry",
      binding: scenario.binding,
      binding_digest: bindingDigest,
      journal_id: journal[0].payload.journal_id,
      entry_sequence: "4",
      previous_entry_digest: journal.at(-1).envelope_digest,
      from_state: "ready_no_effect",
      to_state: "rejected_no_effect",
      event: "rejected_no_effect",
      subject_kind: "no_go_child_exit_evidence",
      subject_digest: noGoEvidence,
      recorded_monotonic_ns: "550",
    },
  });
  const arbitraryEvidenceKind = clone(terminal.payload);
  arbitraryEvidenceKind.subject_kind = "arbitrary_digest_claim";
  assert.throws(() => signJournalEntry({
    signer: scenario.authority.signers.durability_custodian,
    payload: arbitraryEvidenceKind,
  }), (error) => error.code === "binding_invalid");
  journal.push(terminal);
  attest(terminal, "journal", 4, 550, journalFile);

  const exactResult = {
    result_status: "rejected",
    effect_state: "confirmed_none",
    result_code: "revoked_before_go",
    response_digest: null,
    response_byte_length: 0,
    device_state_digest: null,
    external_observation_digest: noGoEvidence,
    cleanup_state: "not_required",
    cleanup_evidence_digest: null,
  };
  const enqueue = signOutboxRecord({
    signer: scenario.authority.signers.durability_custodian,
    payload: {
      version: AUTHENTICATED_EXCHANGE_VERSION,
      protocol: AUTHENTICATED_EXCHANGE_PROTOCOL,
      kind: "outbox_record",
      binding: scenario.binding,
      binding_digest: bindingDigest,
      outbox_id: `outbox:${scenario.binding.exchange_id}`,
      entry_sequence: "1",
      previous_entry_digest: null,
      event: "terminal_enqueued",
      delivery_id: `delivery:${scenario.binding.exchange_id}:rejected`,
      delivery_state: "pending",
      terminal_state: "rejected_no_effect",
      terminal_journal_entry_digest: terminal.envelope_digest,
      grant_envelope_digest: scenario.grant.envelope_digest,
      go_envelope_digest: null,
      receipt_observation: "not_applicable",
      receipt_envelope_digest: null,
      receipt_evidence_digest: null,
      exact_result: exactResult,
      exact_result_digest: hashCanonicalJson(exactResult),
      cleanup_state: "not_required",
      retry_disposition: "effect_retry_forbidden",
      subject_digest: terminal.envelope_digest,
      acknowledgement_digest: null,
      recorded_monotonic_ns: "600",
    },
  });
  outbox.push(enqueue);
  attest(enqueue, "outbox", 1, 600, outboxFile);
  const acknowledgement = digest("rejected-terminal-acknowledgement");
  const ack = signOutboxRecord({
    signer: scenario.authority.signers.durability_custodian,
    payload: {
      ...clone(enqueue.payload),
      entry_sequence: "2",
      previous_entry_digest: enqueue.envelope_digest,
      event: "terminal_acknowledged",
      delivery_state: "acknowledged",
      subject_digest: acknowledgement,
      acknowledgement_digest: acknowledgement,
      recorded_monotonic_ns: "650",
    },
  });
  outbox.push(ack);
  attest(ack, "outbox", 2, 650, outboxFile);

  const result = reconcileAuthenticatedExchange(reconcileInput(scenario, {
    go: null,
    receipt: null,
    receipt_observation: "not_applicable",
    malformed_receipt_digest: null,
    journal_entries: journal,
    outbox_entries: outbox,
    durability_attestations: durability,
  }));
  assert.equal(result.state, "rejected_no_effect");
  assert.equal(result.authenticated_terminal, true);
  assert.equal(result.go_consumed, false);
  assert.equal(result.recovery_action, "none");
  assert.equal(result.automatic_effect_retry_permitted, false);
});

test("missing and malformed post-GO receipts become authenticated ambiguous quarantine", () => {
  for (const observation of ["missing", "malformed"]) {
    const scenario = makeScenario({ receipt_observation: observation, seed: observation });
    const result = reconcileAuthenticatedExchange(reconcileInput(scenario));
    assert.equal(result.state, "ambiguous_quarantined", observation);
    assert.equal(result.authenticated_terminal, true, observation);
    assert.equal(result.outbox_delivery_state, "acknowledged", observation);
    assert.equal(result.recovery_action, "none", observation);
    assert.equal(result.automatic_effect_retry_permitted, false, observation);
    assert.equal(result.exact_result_digest, hashCanonicalJson(scenario.exactResult), observation);
  }
});

test("receipt loss without signed quarantine never becomes an authenticated terminal", () => {
  const scenario = makeScenario();
  const result = reconcileAuthenticatedExchange(reconcileInput(scenario, {
    receipt: null,
    receipt_observation: "missing",
    journal_entries: scenario.journal.slice(0, 5),
    outbox_entries: [],
    durability_attestations: scenario.durability.slice(0, 5),
  }));
  assert.equal(result.state, "ambiguous_quarantined");
  assert.equal(result.authenticated_terminal, false);
  assert.equal(result.recovery_action, "persist_authenticated_ambiguous_quarantine");
});

test("automatic effect retry is rejected while outbox-only redelivery remains explicit", () => {
  const scenario = makeScenario();
  assert.throws(() => reconcileAuthenticatedExchange(reconcileInput(scenario, {
    auto_retry_requested: true,
  })), (error) => error.code === "automatic_retry_forbidden");
  const pending = reconcileAuthenticatedExchange(reconcileInput(scenario, {
    outbox_entries: scenario.outbox.slice(0, 1),
    durability_attestations: scenario.durability.slice(0, 8),
  }));
  assert.equal(pending.automatic_effect_retry_permitted, false);
  assert.equal(pending.outbox_redelivery_permitted, true);
});

test("fsync evidence is exact-byte-bound and effect/outbox ordering is enforced", () => {
  const scenario = makeScenario();
  const forkPayload = clone(scenario.durability[0].payload);
  forkPayload.record_canonical_sha256 = digest("different-record-bytes");
  const fork = signDurabilityAttestation({
    payload: forkPayload,
    signer: scenario.authority.signers.durability_custodian,
  });
  const durability = [...scenario.durability];
  durability[0] = fork;
  assert.throws(() => reconcileAuthenticatedExchange(reconcileInput(scenario, {
    durability_attestations: durability,
  })), (error) => ["durability_invalid", "durability_order_invalid", "chain_invalid"]
    .includes(error.code));

  const impossible = clone(scenario.durability[0].payload);
  impossible.data_fsync_completed_monotonic_ns = impossible.append_completed_monotonic_ns;
  assert.throws(() => signDurabilityAttestation({
    payload: impossible,
    signer: scenario.authority.signers.durability_custodian,
  }), (error) => error.code === "durability_order_invalid");

  const equalSequence = clone(scenario.durability[0].payload);
  equalSequence.directory_fsync_sequence = equalSequence.data_fsync_sequence;
  assert.throws(() => signDurabilityAttestation({
    payload: equalSequence,
    signer: scenario.authority.signers.durability_custodian,
  }), (error) => error.code === "durability_order_invalid");

  const predatesRecord = clone(scenario.durability[0].payload);
  predatesRecord.append_completed_monotonic_ns = "299";
  const predatedAttestation = signDurabilityAttestation({
    payload: predatesRecord,
    signer: scenario.authority.signers.durability_custodian,
  });
  assert.throws(() => reconcileAuthenticatedExchange(reconcileInput(scenario, {
    durability_attestations: [predatedAttestation, ...scenario.durability.slice(1)],
  })), (error) => error.code === "durability_order_invalid");

  const storageForkPayload = clone(scenario.durability[1].payload);
  storageForkPayload.file_identity_digest = digest("spliced-journal-file");
  const storageFork = signDurabilityAttestation({
    payload: storageForkPayload,
    signer: scenario.authority.signers.durability_custodian,
  });
  assert.throws(() => reconcileAuthenticatedExchange(reconcileInput(scenario, {
    go: null,
    receipt: null,
    receipt_observation: "not_applicable",
    journal_entries: scenario.journal.slice(0, 2),
    outbox_entries: [],
    durability_attestations: [scenario.durability[0], storageFork],
  })), (error) => error.code === "durability_invalid");

  const earlyEffectPayload = clone(scenario.journal[4].payload);
  earlyEffectPayload.recorded_monotonic_ns = "652";
  const earlyEffect = signJournalEntry({
    payload: earlyEffectPayload,
    signer: scenario.authority.signers.durability_custodian,
  });
  const earlyEffectDurabilityPayload = clone(scenario.durability[4].payload);
  earlyEffectDurabilityPayload.record_envelope_digest = earlyEffect.envelope_digest;
  earlyEffectDurabilityPayload.record_payload_digest = earlyEffect.payload_digest;
  earlyEffectDurabilityPayload.record_canonical_sha256 = canonicalRecordSha256(earlyEffect);
  earlyEffectDurabilityPayload.record_byte_length = canonicalRecordByteLength(earlyEffect);
  const earlyEffectDurability = signDurabilityAttestation({
    payload: earlyEffectDurabilityPayload,
    signer: scenario.authority.signers.durability_custodian,
  });
  assert.throws(() => reconcileAuthenticatedExchange(reconcileInput(scenario, {
    receipt: null,
    receipt_observation: "missing",
    journal_entries: [...scenario.journal.slice(0, 4), earlyEffect],
    outbox_entries: [],
    durability_attestations: [...scenario.durability.slice(0, 4), earlyEffectDurability],
  })), (error) => error.code === "durability_order_invalid");

  const lateTerminalPayload = clone(scenario.durability[6].payload);
  lateTerminalPayload.append_completed_monotonic_ns = "3000";
  lateTerminalPayload.data_fsync_completed_monotonic_ns = "3001";
  lateTerminalPayload.directory_fsync_completed_monotonic_ns = "3002";
  const lateTerminal = signDurabilityAttestation({
    payload: lateTerminalPayload,
    signer: scenario.authority.signers.durability_custodian,
  });
  assert.throws(() => reconcileAuthenticatedExchange(reconcileInput(scenario, {
    outbox_entries: [],
    durability_attestations: [...scenario.durability.slice(0, 6), lateTerminal],
  })), (error) => error.code === "durability_order_invalid");
});

test("all exported records are canonical, frozen, bounded, and key-free", () => {
  const scenario = makeScenario();
  for (const record of [
    scenario.grant, scenario.go, scenario.receipt, ...scenario.journal,
    ...scenario.outbox, ...scenario.durability,
  ]) {
    assert.equal(Object.isFrozen(record), true);
    assert.equal(Object.isFrozen(record.payload), true);
    assert.ok(canonicalRecordByteLength(record) <= 128 * 1024);
    assert.match(canonicalRecordSha256(record), /^[a-f0-9]{64}$/u);
    assert.doesNotMatch(canonicalJson(record), /private_key|BEGIN PRIVATE KEY/u);
  }
  assert.equal(verifyCommitGo(scenario.go, scenario.authority.verifier).envelope_digest,
    scenario.go.envelope_digest);
});
