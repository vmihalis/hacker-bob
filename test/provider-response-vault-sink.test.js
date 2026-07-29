"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const { createArtifactVault } = require("../packages/bob-artifact-vault/index.js");
const {
  PROVIDER_RESPONSE_VAULT_ASSURANCE,
  PROVIDER_RESPONSE_VAULT_VERSION,
  assertProviderResponseIngestReceipt,
  assertProviderResponseIngestReceiptPort,
  assertProviderResponseSink,
  assertProviderResponseSinkCommit,
  commitProviderResponseIngestReceipt,
  commitProviderResponseSink,
  createProviderResponseIngestReceiptPort,
  createProviderResponseSink,
  readProviderResponseIngestReceipt,
  readProviderResponseSinkCommit,
} = require("../packages/bob-artifact-vault/worker.js");
const {
  createInProcessBackupKeyCustodyFixture,
} = require("./helpers/artifact-vault-backup-key-custody.js");

const SESSION_HASH = "a".repeat(64);
const TRANSACTION_DOMAIN =
  "hacker-bob/provider-worker-vault-transport-reserved-vault-result/v1";
const INGEST_DOMAIN =
  "hacker-bob/provider-worker-vault-reserved-vault-ingest/v1";
const EXECUTION_LINEAGE_DOMAIN =
  "hacker-bob/provider-worker-vault-execution-lineage/v1";

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value != null && typeof value === "object") {
    const output = {};
    for (const key of Object.keys(value).sort()) {
      if (value[key] !== undefined) output[key] = canonicalize(value[key]);
    }
    return output;
  }
  return value;
}

function canonicalJson(value) {
  return JSON.stringify(canonicalize(value));
}

function digest(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function digestRecord(domain, projection) {
  return digest(canonicalJson({ domain, ...projection }));
}

function futureIso(minutes = 30) {
  return new Date(Date.now() + minutes * 60_000).toISOString();
}

function makeDeletionLedgerAnchor() {
  const states = new Map();
  return Object.freeze({
    readState({ vault_slot: vaultSlot }) {
      const state = states.get(vaultSlot);
      return state == null ? null : structuredClone(state);
    },
    compareAndSet(request) {
      const current = states.get(request.vault_slot) || null;
      const matches = current == null
        ? request.expected_generation == null && request.expected_ledger_digest == null
        : request.expected_generation === current.generation
          && request.expected_ledger_digest === current.ledger_digest;
      if (!matches) return false;
      states.set(request.vault_slot, structuredClone(request.next_state));
      return true;
    },
  });
}

function makeIndexStateAnchor() {
  const states = new Map();
  return Object.freeze({
    readState({ vault_slot: vaultSlot }) {
      const state = states.get(vaultSlot);
      return state == null ? null : structuredClone(state);
    },
    compareAndSet(request) {
      const current = states.get(request.vault_slot) || null;
      const matches = current == null
        ? request.expected_generation == null && request.expected_index_digest == null
        : request.expected_generation === current.generation
          && request.expected_index_digest === current.index_digest;
      if (!matches) return false;
      states.set(request.vault_slot, structuredClone(request.next_state));
      return true;
    },
  });
}

function makeVault(t, { maxArtifacts = 32 } = {}) {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), "bob-provider-response-vault-"));
  const root = path.join(parent, "vault");
  const vaultId = `vault:v1:${crypto.randomBytes(32).toString("base64url")}`;
  const vaultSlot = `vault-slot:v1:${crypto.randomBytes(32).toString("base64url")}`;
  const masterKey = crypto.randomBytes(32);
  const deletionLedgerAnchor = makeDeletionLedgerAnchor();
  const indexStateAnchor = makeIndexStateAnchor();
  const custody = createInProcessBackupKeyCustodyFixture({
    vaultId,
    vaultSlot,
    sessionNucleusHash: SESSION_HASH,
  });
  const vaults = [];

  function open(createNew) {
    const keyInput = Buffer.from(masterKey);
    try {
      const vault = createArtifactVault({
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
        maxArtifacts,
        minFreeBytes: 0,
      });
      vaults.push(vault);
      return vault;
    } finally {
      keyInput.fill(0);
    }
  }

  const setup = {
    custody,
    deletionLedgerAnchor,
    indexStateAnchor,
    masterKey,
    maxArtifacts,
    parent,
    root,
    vault: open(true),
    vaultId,
    vaultSlot,
    reopen() {
      const reopened = open(false);
      this.vault = reopened;
      return reopened;
    },
  };
  t.after(() => {
    for (const vault of vaults) {
      try { vault.destroy(); } catch {}
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
    reservation_ref: `reservation:provider-response-${suffix}`,
    purpose_ref: "purpose:provider-response",
    byte_ceiling: 64,
    expires_at: futureIso(),
    ...overrides,
  };
}

function metadataFor(reservationRequest, overrides = {}) {
  return {
    version: 1,
    session_nucleus_hash: SESSION_HASH,
    task_id: reservationRequest.task_id,
    attempt_id: reservationRequest.attempt_id,
    data_class: "credential_secret",
    media_type: "application/octet-stream",
    source_ref: "provider:chameleon-ultra",
    retention_expires_at: futureIso(60),
    ...overrides,
  };
}

function reserveSink(vault, overrides = {}) {
  const request = reservation(overrides);
  const reserved = vault.reserve(request);
  const metadata = metadataFor(request);
  const sink = createProviderResponseSink(vault, {
    version: 1,
    reservation_handle: reserved.reservation_handle,
    metadata,
  });
  return { metadata, request, reserved, sink };
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
    safety_supervisor_plan_digest: hash("safety-plan"),
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
    runtime_availability: "runtime:fixture-only",
    compiled_command_id: `compiled-command:${label}`,
    compiled_command_capability_digest: hash("compiled-capability"),
    expected_result_code: "ok",
    active_command_input_ref: `command-input:active-${label}`,
    active_command_input_digest: hash("active-command-input"),
    cleanup_command_input_ref: `command-input:cleanup-${label}`,
    cleanup_command_input_digest: hash("cleanup-command-input"),
    maximum_response_bytes: sink.byte_ceiling,
    worker_bundle_digest: hash("worker-bundle"),
    worker_launch_digest: hash("worker-launch"),
    worker_process_instance_digest: hash("worker-process"),
    worker_fence_digest: hash("worker-fence"),
    transport_binding_digest: hash("transport-binding"),
    vault_reservation_handle: sink.vault_reservation_handle,
    vault_reservation_digest: sink.vault_reservation_digest,
    vault_ingest_capability_digest: sink.vault_ingest_capability_digest,
    vault_byte_ceiling: sink.byte_ceiling,
    durable_exchange_plan_digest: hash("durable-exchange-plan"),
    terminal_receipt_recipient_digest: hash("terminal-receipt-recipient"),
  };
  return {
    ...basis,
    execution_lineage_digest: digestRecord(EXECUTION_LINEAGE_DOMAIN, basis),
  };
}

function commitRequest(lineage, bytes, overrides = {}) {
  return {
    version: 1,
    kind: "commit_provider_response_sink_request",
    lineage,
    execution_claim_receipt_digest: digest("execution-claim"),
    deadline_fence_receipt_digest: digest("deadline-fence"),
    transaction_ref: "transaction:provider-response",
    result_code: "ok",
    device_state_digest: digest("device-state"),
    response_bytes: bytes,
    ...overrides,
  };
}

function receiptRequest(lineage, transaction, overrides = {}) {
  return {
    version: 1,
    kind: "assert_reserved_vault_ingest_receipt_request",
    lineage,
    execution_claim_receipt_digest: transaction.execution_claim_receipt_digest,
    deadline_fence_receipt_digest: transaction.deadline_fence_receipt_digest,
    transaction_result: transaction,
    ...overrides,
  };
}

function readSinkRequest(lineage) {
  return {
    version: 1,
    kind: "read_provider_response_sink_commit_request",
    execution_lineage_digest: lineage.execution_lineage_digest,
  };
}

function readReceiptRequest(lineage) {
  return {
    version: 1,
    kind: "read_provider_response_ingest_receipt_request",
    execution_lineage_digest: lineage.execution_lineage_digest,
  };
}

function assertNoByteSurface(value, seen = new Set()) {
  if (value == null || typeof value !== "object" || seen.has(value)) return;
  seen.add(value);
  assert.equal(Buffer.isBuffer(value), false, "digest-only result projected a Buffer");
  assert.equal(ArrayBuffer.isView(value), false, "digest-only result projected a byte view");
  assert.equal(value instanceof ArrayBuffer, false, "digest-only result projected an ArrayBuffer");
  for (const entry of Object.values(value)) assertNoByteSurface(entry, seen);
}

function stateFile(setup, lineage) {
  return path.join(
    setup.root,
    "provider-response-receipts",
    `${lineage.execution_lineage_digest}.json`,
  );
}

test("provider response sink is privately branded, bounded, digest-only, and broker-exact", (t) => {
  const setup = makeVault(t);
  assert.equal(PROVIDER_RESPONSE_VAULT_VERSION, 1);
  assert.equal(PROVIDER_RESPONSE_VAULT_ASSURANCE.production_ready, false);
  assert.equal(PROVIDER_RESPONSE_VAULT_ASSURANCE.hardware_access_authorized, false);
  assert.equal(PROVIDER_RESPONSE_VAULT_ASSURANCE.raw_response_bytes_projected_to_broker, false);
  assert.ok(PROVIDER_RESPONSE_VAULT_ASSURANCE.production_blockers.includes(
    "qualified_native_worker_to_vault_bridge_missing",
  ));

  const { request, sink } = reserveSink(setup.vault);
  const port = createProviderResponseIngestReceiptPort(setup.vault);
  assert.equal(assertProviderResponseSink(sink), sink);
  assert.equal(assertProviderResponseIngestReceiptPort(port), port);
  assert.throws(() => assertProviderResponseSink({ ...sink }), /privately branded/);
  assert.throws(() => assertProviderResponseIngestReceiptPort({ ...port }), /privately branded/);
  assert.equal(sink.production_ready, false);
  assert.equal(sink.hardware_access_authorized, false);
  assert.equal(sink.execution_authority, false);
  assert.equal(port.byte_input_accepted, false);

  const lineage = lineageFor(sink, request);
  const response = Buffer.from("bounded chameleon response");
  const transaction = commitProviderResponseSink(sink, commitRequest(lineage, response));
  assert.deepEqual(response, Buffer.alloc(response.length));
  assert.equal(assertProviderResponseSinkCommit(transaction), transaction);
  assertNoByteSurface(transaction);
  const { transaction_receipt_digest: transactionDigest, ...transactionProjection } = transaction;
  assert.equal(transactionDigest, digestRecord(TRANSACTION_DOMAIN, transactionProjection));
  assert.equal(transaction.vault_reservation_handle, sink.vault_reservation_handle);
  assert.equal(transaction.execution_lineage_digest, lineage.execution_lineage_digest);
  assert.throws(
    () => assertProviderResponseSinkCommit({ ...transaction }),
    /privately branded/,
  );

  assert.throws(() => commitProviderResponseIngestReceipt(port, receiptRequest(
    lineage,
    transaction,
    { execution_claim_receipt_digest: digest("forged independent claim") },
  )), /drifted from durable sink state/);
  assert.throws(() => commitProviderResponseIngestReceipt(port, receiptRequest(
    lineage,
    transaction,
    { deadline_fence_receipt_digest: digest("forged independent deadline") },
  )), /drifted from durable sink state/);
  assert.throws(() => commitProviderResponseIngestReceipt(port, receiptRequest(
    lineage,
    { ...transaction, transaction_ref: "transaction:forged" },
  )), /transaction_receipt_digest is invalid/);

  const receipt = commitProviderResponseIngestReceipt(
    port,
    receiptRequest(lineage, transaction),
  );
  assert.equal(assertProviderResponseIngestReceipt(receipt), receipt);
  assert.throws(
    () => assertProviderResponseIngestReceipt({ ...receipt }),
    /privately branded/,
  );
  assertNoByteSurface(receipt);
  const { ingest_receipt_digest: receiptDigest, ...receiptProjection } = receipt;
  assert.equal(receiptDigest, digestRecord(INGEST_DOMAIN, receiptProjection));
  assert.deepEqual(readProviderResponseSinkCommit(port, readSinkRequest(lineage)), transaction);
  assert.deepEqual(readProviderResponseIngestReceipt(port, readReceiptRequest(lineage)), receipt);

  const publicRequest = reservation();
  const publicReservation = setup.vault.reserve(publicRequest);
  const publicDescriptor = setup.vault.ingest({
    reservation_handle: publicReservation.reservation_handle,
    metadata: metadataFor(publicRequest),
    plaintext: Buffer.from("public compatibility remains available"),
  });
  assert.match(publicDescriptor.artifact_handle, /^artifact:v1:/);
  assert.equal(Object.hasOwn(publicDescriptor, "production_ready"), false);
});

test("sink zeroizes malformed and oversized responses before effects, then permits the valid bounded commit", (t) => {
  const setup = makeVault(t);
  const { request, sink } = reserveSink(setup.vault, { byte_ceiling: 16 });
  const lineage = lineageFor(sink, request);

  const malformedBytes = Buffer.from("malformed");
  assert.throws(() => commitProviderResponseSink(sink, {
    ...commitRequest(lineage, malformedBytes),
    unknown_field: true,
  }), /unknown fields/);
  assert.deepEqual(malformedBytes, Buffer.alloc(malformedBytes.length));

  const oversized = Buffer.alloc(17, 0x41);
  assert.throws(
    () => commitProviderResponseSink(sink, commitRequest(lineage, oversized)),
    /exceeds its pre-stimulus byte ceiling/,
  );
  assert.deepEqual(oversized, Buffer.alloc(oversized.length));
  assert.equal(setup.vault.usage().active_reservations, 1);

  const valid = Buffer.from("valid response");
  const committed = commitProviderResponseSink(sink, commitRequest(lineage, valid));
  assert.equal(committed.response_byte_length, 14);
  assert.deepEqual(valid, Buffer.alloc(valid.length));
});

test("public ingest cannot retroactively mint a provider-response receipt", (t) => {
  const setup = makeVault(t);
  const { metadata, request, reserved, sink } = reserveSink(setup.vault);
  const lineage = lineageFor(sink, request);
  const publicBytes = Buffer.from("same response bytes");
  const descriptor = setup.vault.ingest({
    reservation_handle: reserved.reservation_handle,
    metadata,
    plaintext: publicBytes,
  });
  assert.match(descriptor.artifact_handle, /^artifact:v1:/);

  const sinkBytes = Buffer.from("same response bytes");
  assert.throws(
    () => commitProviderResponseSink(sink, commitRequest(lineage, sinkBytes)),
    /without a prepared provider sink cannot mint a receipt/,
  );
  assert.deepEqual(sinkBytes, Buffer.alloc(sinkBytes.length));
  assert.equal(fs.existsSync(stateFile(setup, lineage)), false);
});

test("sink retries are idempotent and exact lineage, claim, deadline, transaction, and bytes cannot drift", (t) => {
  const setup = makeVault(t);
  const { request, sink } = reserveSink(setup.vault);
  const lineage = lineageFor(sink, request);
  const first = commitProviderResponseSink(
    sink,
    commitRequest(lineage, Buffer.from("stable response")),
  );
  const retry = commitProviderResponseSink(
    sink,
    commitRequest(lineage, Buffer.from("stable response")),
  );
  assert.deepEqual(retry, first);
  assert.equal(setup.vault.usage().active_artifacts, 1);

  const cases = [
    {
      label: "claim",
      mutate(value) { value.execution_claim_receipt_digest = digest("other claim"); },
    },
    {
      label: "deadline",
      mutate(value) { value.deadline_fence_receipt_digest = digest("other deadline"); },
    },
    {
      label: "transaction",
      mutate(value) { value.transaction_ref = "transaction:other"; },
    },
    {
      label: "lineage",
      mutate(value) {
        value.lineage = { ...value.lineage, resource_fence_digest: digest("other resource fence") };
      },
    },
    {
      label: "cleanup command lineage",
      mutate(value) {
        value.lineage = {
          ...value.lineage,
          cleanup_command_input_digest: digest("other cleanup command input"),
        };
      },
    },
    {
      label: "cleanup command reference lineage",
      mutate(value) {
        value.lineage = {
          ...value.lineage,
          cleanup_command_input_ref: "command-input:cleanup-other",
        };
      },
    },
    {
      label: "durable exchange lineage",
      mutate(value) {
        value.lineage = {
          ...value.lineage,
          durable_exchange_plan_digest: digest("other durable exchange plan"),
        };
      },
    },
    {
      label: "terminal recipient lineage",
      mutate(value) {
        value.lineage = {
          ...value.lineage,
          terminal_receipt_recipient_digest: digest("other terminal recipient"),
        };
      },
    },
    {
      label: "bytes",
      mutate(value) { value.response_bytes = Buffer.from("drift response!"); },
    },
  ];
  for (const candidate of cases) {
    const input = commitRequest(lineage, Buffer.from("stable response"));
    candidate.mutate(input);
    const exposed = input.response_bytes;
    assert.throws(
      () => commitProviderResponseSink(sink, input),
      /different provider response binding|drifted|does not match/,
      candidate.label,
    );
    assert.deepEqual(exposed, Buffer.alloc(exposed.length), `${candidate.label} was not zeroized`);
  }
});

test("restart readback recovers the sink commit and commits the independent receipt without bytes", (t) => {
  const setup = makeVault(t);
  const { request, sink } = reserveSink(setup.vault);
  const lineage = lineageFor(sink, request);
  const transaction = commitProviderResponseSink(
    sink,
    commitRequest(lineage, Buffer.from("restart durable response")),
  );
  setup.vault.destroy();
  const reopened = setup.reopen();
  const port = createProviderResponseIngestReceiptPort(reopened);

  const recovered = readProviderResponseSinkCommit(port, readSinkRequest(lineage));
  assert.deepEqual(recovered, transaction);
  assertNoByteSurface(recovered);
  const receipt = commitProviderResponseIngestReceipt(
    port,
    receiptRequest(lineage, recovered),
  );
  const replay = commitProviderResponseIngestReceipt(
    port,
    receiptRequest(lineage, recovered),
  );
  assert.deepEqual(replay, receipt);
  assert.deepEqual(readProviderResponseIngestReceipt(port, readReceiptRequest(lineage)), receipt);
});

test("atomic rename acknowledgement loss is recoverable for sink and independent receipt commits", (t) => {
  const setup = makeVault(t);
  const { request, sink } = reserveSink(setup.vault);
  const lineage = lineageFor(sink, request);
  const originalRename = fs.renameSync;
  let responseRenames = 0;
  fs.renameSync = function injectedRename(source, destination) {
    if (destination === stateFile(setup, lineage)) {
      responseRenames += 1;
      originalRename(source, destination);
      if (responseRenames === 2) throw new Error("injected sink terminal rename acknowledgement loss");
      return;
    }
    return originalRename(source, destination);
  };
  try {
    const bytes = Buffer.from("lost acknowledgement response");
    assert.throws(
      () => commitProviderResponseSink(sink, commitRequest(lineage, bytes)),
      /injected sink terminal rename acknowledgement loss/,
    );
    assert.deepEqual(bytes, Buffer.alloc(bytes.length));
  } finally {
    fs.renameSync = originalRename;
  }

  const port = createProviderResponseIngestReceiptPort(setup.vault);
  const recovered = readProviderResponseSinkCommit(port, readSinkRequest(lineage));
  assert.equal(setup.vault.usage().active_artifacts, 1);

  let receiptRenameSeen = false;
  fs.renameSync = function injectedReceiptRename(source, destination) {
    if (!receiptRenameSeen && destination === stateFile(setup, lineage)) {
      receiptRenameSeen = true;
      originalRename(source, destination);
      throw new Error("injected ingest receipt rename acknowledgement loss");
    }
    return originalRename(source, destination);
  };
  try {
    assert.throws(
      () => commitProviderResponseIngestReceipt(port, receiptRequest(lineage, recovered)),
      /injected ingest receipt rename acknowledgement loss/,
    );
  } finally {
    fs.renameSync = originalRename;
  }
  const receipt = readProviderResponseIngestReceipt(port, readReceiptRequest(lineage));
  assert.equal(receipt.transaction_receipt_digest, recovered.transaction_receipt_digest);
});

test("restart reconciles a committed artifact when terminal journal publication never happened", (t) => {
  const setup = makeVault(t);
  const { request, sink } = reserveSink(setup.vault);
  const lineage = lineageFor(sink, request);
  const originalRename = fs.renameSync;
  let responseRenames = 0;
  fs.renameSync = function injectedRename(source, destination) {
    if (destination === stateFile(setup, lineage)) {
      responseRenames += 1;
      if (responseRenames === 2) {
        throw new Error("injected pre-publication crash boundary");
      }
    }
    return originalRename(source, destination);
  };
  try {
    assert.throws(
      () => commitProviderResponseSink(
        sink,
        commitRequest(lineage, Buffer.from("committed before journal crash")),
      ),
      /injected pre-publication crash boundary/,
    );
  } finally {
    fs.renameSync = originalRename;
  }
  assert.equal(setup.vault.usage().active_artifacts, 1);
  const beforeRestart = JSON.parse(fs.readFileSync(stateFile(setup, lineage), "utf8"));
  assert.equal(beforeRestart.payload.state, "prepared");

  setup.vault.destroy();
  const reopened = setup.reopen();
  const port = createProviderResponseIngestReceiptPort(reopened);
  const recovered = readProviderResponseSinkCommit(port, readSinkRequest(lineage));
  assert.equal(recovered.response_digest, digest("committed before journal crash"));
  assert.equal(reopened.usage().active_artifacts, 1);
  const afterRestart = JSON.parse(fs.readFileSync(stateFile(setup, lineage), "utf8"));
  assert.equal(afterRestart.payload.state, "sink_committed");
});

test("receipt HMAC tamper and mode, hardlink, symlink, or receipt-root substitution fail closed", (t) => {
  function committedSetup() {
    const setup = makeVault(t);
    const { request, sink } = reserveSink(setup.vault);
    const lineage = lineageFor(sink, request);
    commitProviderResponseSink(sink, commitRequest(lineage, Buffer.from("path safety response")));
    const port = createProviderResponseIngestReceiptPort(setup.vault);
    return { lineage, port, setup };
  }

  {
    const { lineage, port, setup } = committedSetup();
    const filePath = stateFile(setup, lineage);
    const wrapper = JSON.parse(fs.readFileSync(filePath, "utf8"));
    wrapper.payload.transaction_ref = "transaction:tampered";
    fs.writeFileSync(filePath, `${JSON.stringify(wrapper)}\n`);
    assert.throws(
      () => readProviderResponseSinkCommit(port, readSinkRequest(lineage)),
      /authentication failed/,
    );
  }

  {
    const { lineage, port, setup } = committedSetup();
    const filePath = stateFile(setup, lineage);
    fs.chmodSync(filePath, 0o644);
    assert.throws(
      () => readProviderResponseSinkCommit(port, readSinkRequest(lineage)),
      /mode-0600/,
    );
  }

  {
    const { lineage, port, setup } = committedSetup();
    const filePath = stateFile(setup, lineage);
    fs.linkSync(filePath, path.join(setup.parent, "receipt-hardlink"));
    assert.throws(
      () => readProviderResponseSinkCommit(port, readSinkRequest(lineage)),
      /single-link/,
    );
  }

  {
    const { lineage, port, setup } = committedSetup();
    const filePath = stateFile(setup, lineage);
    const target = path.join(setup.parent, "receipt-target");
    fs.writeFileSync(target, "{}\n", { mode: 0o600 });
    fs.unlinkSync(filePath);
    fs.symlinkSync(target, filePath);
    assert.throws(
      () => readProviderResponseSinkCommit(port, readSinkRequest(lineage)),
      /single-link mode-0600/,
    );
  }

  {
    const setup = makeVault(t);
    const outside = path.join(setup.parent, "outside-receipts");
    fs.mkdirSync(outside, { mode: 0o700 });
    fs.symlinkSync(outside, path.join(setup.root, "provider-response-receipts"));
    assert.throws(
      () => createProviderResponseIngestReceiptPort(setup.vault),
      /real directory owned by this process identity/,
    );
  }
});

test("durable receipt count is bounded independently of reusable artifact capacity", (t) => {
  const setup = makeVault(t, { maxArtifacts: 1 });
  const first = reserveSink(setup.vault);
  const firstLineage = lineageFor(first.sink, first.request);
  const firstTransaction = commitProviderResponseSink(
    first.sink,
    commitRequest(firstLineage, Buffer.from("first bounded receipt")),
  );
  setup.vault.erase(firstTransaction.artifact_handle, "reason:receipt-quota-test");
  assert.equal(setup.vault.usage().active_artifacts, 0);

  const second = reserveSink(setup.vault);
  const secondLineage = lineageFor(second.sink, second.request);
  const bytes = Buffer.from("second receipt");
  assert.throws(
    () => commitProviderResponseSink(second.sink, commitRequest(secondLineage, bytes)),
    /receipt count ceiling is exhausted/,
  );
  assert.deepEqual(bytes, Buffer.alloc(bytes.length));
  assert.equal(setup.vault.usage().active_reservations, 1);
  assert.equal(fs.existsSync(stateFile(setup, secondLineage)), false);
});
