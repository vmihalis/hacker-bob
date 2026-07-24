"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const {
  createArtifactVault,
} = require("../packages/bob-artifact-vault/index.js");
const workerSurface = require("../packages/bob-artifact-vault/worker.js");
const {
  createTransformRegistry,
  runTransform,
} = workerSurface;
const {
  createOperatorExportChannel,
  createOperatorTransformPolicyAuthority,
  enrollOperatorTransformPolicy,
  signOperatorTransformRequest,
} = require("../packages/bob-artifact-vault/operator.js");
const {
  claimTransformAttemptForWorker,
  inspectTransformAttemptForWorker,
} = require("../packages/bob-artifact-vault/lib/vault.js");
const {
  createInProcessBackupKeyCustodyFixture,
} = require("./helpers/artifact-vault-backup-key-custody.js");

const SESSION_HASH = "a".repeat(64);
const FIXTURE_PATH = path.join(
  __dirname,
  "fixtures",
  "artifact-transform-programs.transform.json",
);

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value != null && typeof value === "object") {
    const output = Object.create(null);
    for (const key of Object.keys(value).sort()) output[key] = canonicalize(value[key]);
    return output;
  }
  return value;
}

function digest(value) {
  const input = Buffer.isBuffer(value) ? value : Buffer.from(JSON.stringify(canonicalize(value)));
  return crypto.createHash("sha256").update(input).digest("hex");
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
  let ambiguousNextCommit = false;
  let failNextRead = false;
  return Object.freeze({
    readState({ vault_slot: vaultSlot }) {
      if (failNextRead) {
        failNextRead = false;
        throw new Error("injected post-commit anchor read failure");
      }
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
      if (ambiguousNextCommit) {
        ambiguousNextCommit = false;
        failNextRead = true;
        throw new Error("injected committed-but-unacknowledged anchor mutation");
      }
      return true;
    },
    armAmbiguousCommit() {
      ambiguousNextCommit = true;
    },
  });
}

function makeVault(t, { quotaBytes = 2 * 1024 * 1024, now } = {}) {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), "bob-transform-claims-"));
  t.after(() => fs.rmSync(parent, { recursive: true, force: true }));
  const root = path.join(parent, "vault");
  const deletionLedgerAnchor = makeDeletionLedgerAnchor();
  const indexStateAnchor = makeIndexStateAnchor();
  const masterKey = crypto.randomBytes(32);
  const reopenKey = Buffer.from(masterKey);
  const vaultId = `vault:v1:${crypto.randomBytes(32).toString("base64url")}`;
  const vaultSlot = `vault-slot:v1:${crypto.randomBytes(32).toString("base64url")}`;
  const backupKeyCustodyFixture = createInProcessBackupKeyCustodyFixture({
    vaultId,
    vaultSlot,
    sessionNucleusHash: SESSION_HASH,
  });
  t.after(() => reopenKey.fill(0));
  t.after(() => backupKeyCustodyFixture.destroy());
  const vault = createArtifactVault({
    root,
    sessionNucleusHash: SESSION_HASH,
    vaultId,
    vaultSlot,
    backupKeyCustody: backupKeyCustodyFixture.port,
    createNew: true,
    masterKey,
    deletionLedgerAnchor,
    indexStateAnchor,
    quotaBytes,
    minFreeBytes: 0,
    now,
  });
  masterKey.fill(0);
  t.after(() => vault.destroy());
  return {
    deletionLedgerAnchor,
    indexStateAnchor,
    parent,
    quotaBytes,
    reopenKey,
    root,
    vaultId,
    vaultSlot,
    vault,
    backupKeyCustody: backupKeyCustodyFixture.port,
  };
}

function makeRegistry(t, { handlerExport = "identityTransform", outputCount = 1 } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "bob-transform-programs-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const implementationModule = "programs.transform.json";
  const bytes = fs.readFileSync(FIXTURE_PATH);
  fs.writeFileSync(path.join(root, implementationModule), bytes, { flag: "wx", mode: 0o600 });
  const implementationDigest = digest(bytes);
  const currentPolicy = {
    version: 1,
    policy_id: "transform-attempt-claims-test",
    policy_epoch: 1,
    status: "trusted",
    trusted_implementation_root: root,
    trusted_implementation_digests: [implementationDigest],
  };
  const policyAuthority = createOperatorTransformPolicyAuthority({
    version: 1,
    authority_id: "transform-attempt-claims-authority",
    resolve_current_policy: () => structuredClone(currentPolicy),
  });
  const policy = enrollOperatorTransformPolicy({
    version: 1,
    policy_authority_id: policyAuthority.authority_id,
    policy_authority_digest: policyAuthority.authority_digest,
    policy_id: currentPolicy.policy_id,
  }, policyAuthority);
  const registry = createTransformRegistry([{
    implementation_module: implementationModule,
    manifest: {
      version: 1,
      tool_id: "fixture.claims",
      tool_version: "1.0.0",
      implementation_digest: implementationDigest,
      handler_export: handlerExport,
      input_data_classes: ["metadata"],
      output_data_classes: ["metadata", "credential_secret"],
      parameters: {},
      max_input_handles: 1,
      max_input_bytes: 64,
      max_output_artifacts: outputCount,
      max_output_bytes: 64,
    },
  }], policy);
  return registry;
}

function futureIso(minutes = 30) {
  return new Date(Date.now() + minutes * 60_000).toISOString();
}

function reservation() {
  return {
    version: 1,
    session_nucleus_hash: SESSION_HASH,
    task_id: "task-claims",
    attempt_id: "attempt-claims",
    reservation_ref: `reservation:claim-${crypto.randomBytes(8).toString("hex")}`,
    purpose_ref: "purpose:transform-output",
    byte_ceiling: 64,
    expires_at: futureIso(),
  };
}

function metadata(overrides = {}) {
  return {
    version: 1,
    session_nucleus_hash: SESSION_HASH,
    task_id: "task-claims",
    attempt_id: "attempt-claims",
    data_class: "metadata",
    media_type: "application/octet-stream",
    source_ref: "provider:claims-fixture",
    retention_expires_at: futureIso(60),
    ...overrides,
  };
}

function ingest(vault, value = "x") {
  const reserved = vault.reserve(reservation());
  return vault.ingest({
    reservation_handle: reserved.reservation_handle,
    metadata: metadata(),
    plaintext: Buffer.from(value),
  });
}

function transformRequest(vault, registry, inputHandle, outputReservation, attemptRef, metadataOverrides = {}) {
  return {
    registry,
    registry_digest: registry.registry_digest,
    vault,
    transform_attempt_ref: attemptRef,
    tool_id: "fixture.claims",
    tool_digest: registry.manifest("fixture.claims").tool_digest,
    input_handles: [inputHandle],
    outputs: [{
      reservation_handle: outputReservation.reservation_handle,
      metadata: metadata(metadataOverrides),
    }],
    parameters: {},
  };
}

function attemptIdentity(request) {
  const batchRef = `transform-batch:v1:${digest({
    version: 1,
    transform_attempt_ref: request.transform_attempt_ref,
  })}`;
  const bindingDigest = digest({
    version: 1,
    transform_attempt_ref: request.transform_attempt_ref,
    registry_digest: request.registry_digest,
    tool_id: request.tool_id,
    tool_digest: request.tool_digest,
    input_handles: request.input_handles,
    output_bindings: request.outputs,
    parameters: request.parameters,
  });
  return { batchRef, bindingDigest };
}

function operatorRequest(action, identity, overrides = {}) {
  const now = Date.now();
  return {
    version: 1,
    action,
    batch_ref: identity.batchRef,
    binding_digest: identity.bindingDigest,
    audience: "bob.operator",
    purpose_ref: "operator:transform-crash-recovery",
    requester_principal_id: "principal:hotel-redteam-operator",
    nonce: `export-nonce:v1:${crypto.randomBytes(32).toString("base64url")}`,
    not_before: new Date(now - 1000).toISOString(),
    expires_at: new Date(now + 30_000).toISOString(),
    ...overrides,
  };
}

function openBackupFile(t, filePath) {
  const descriptor = fs.openSync(
    filePath,
    fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_RDWR | fs.constants.O_NOFOLLOW,
    0o600,
  );
  t.after(() => {
    try { fs.closeSync(descriptor); } catch {}
  });
  return descriptor;
}

test("one durable claim token wins; crash adjudication releases input pins without reopening", (t) => {
  assert.equal(workerSurface.adjudicateTransformAttempt, undefined);
  assert.equal(workerSurface.inspectTransformAttempt, undefined);
  const { vault } = makeVault(t);
  const registry = makeRegistry(t);
  const input = ingest(vault, "claim-input");
  const outputReservation = vault.reserve(reservation());
  const request = transformRequest(
    vault,
    registry,
    input.artifact_handle,
    outputReservation,
    "transform-attempt:deterministic-interleaving",
  );
  const identity = attemptIdentity(request);
  const first = claimTransformAttemptForWorker(vault, {
    batch_ref: identity.batchRef,
    binding_digest: identity.bindingDigest,
    input_handles: request.input_handles,
    outputs: request.outputs,
  });
  assert.equal(first.status, "claimed");
  assert.match(first.claim_token, /^transform-claim:v1:/);
  assert.throws(() => claimTransformAttemptForWorker(vault, {
    batch_ref: identity.batchRef,
    binding_digest: identity.bindingDigest,
    input_handles: request.input_handles,
    outputs: request.outputs,
  }), /already durably claimed/);
  assert.throws(() => runTransform(request), /already durably claimed/);
  assert.throws(
    () => vault.releaseReservation(outputReservation.reservation_handle, "transform:public-release-race"),
    /pinned as output of a claimed transform attempt/,
  );
  assert.throws(() => vault.ingest({
    reservation_handle: outputReservation.reservation_handle,
    metadata: metadata(),
    plaintext: Buffer.from("public-ingest-race"),
  }), /pinned as output of a claimed transform attempt/);
  assert.throws(
    () => vault.erase(input.artifact_handle, "operator:premature-input-erasure"),
    /pinned by a claimed transform attempt/,
  );

  const key = crypto.randomBytes(32);
  const consumed = new Set();
  const channel = createOperatorExportChannel({
    vault,
    exportKey: key,
    audience: "bob.operator",
    consumeNonce(nonce) {
      if (consumed.has(nonce)) return false;
      consumed.add(nonce);
      return true;
    },
  });
  t.after(() => channel.destroy());
  const inspectRequest = signOperatorTransformRequest(operatorRequest("inspect", identity), key);
  const observed = channel.inspectTransformAttempt(inspectRequest);
  assert.equal(observed.status, "claimed");
  assert.equal(Object.hasOwn(observed, "claim_token"), false);
  const adjudicationRequest = signOperatorTransformRequest(operatorRequest(
    "adjudicate_terminal_failed",
    identity,
    {
      expected_claimed_at: observed.claimed_at,
      evidence_ref: "operator-evidence:worker-crash-confirmed",
      verdict: "terminal_failed",
    },
  ), key);
  const adjudicated = channel.adjudicateTransformAttempt(adjudicationRequest);
  assert.match(adjudicated.adjudication_receipt, /^[a-f0-9]{64}$/);
  assert.equal(adjudicated.released_output_reservations, 1);
  assert.equal(vault.usage().active_reservations, 0);
  assert.equal(inspectTransformAttemptForWorker(
    vault,
    identity.batchRef,
    identity.bindingDigest,
  ).status, "failed");
  assert.doesNotThrow(() => vault.erase(input.artifact_handle, "operator:post-adjudication-erasure"));
  assert.throws(() => runTransform(request), /permanently failed/);
  key.fill(0);
});

test("ordinary ingest cannot forge vault-minted transform provenance", (t) => {
  const { vault } = makeVault(t);
  const reserved = vault.reserve(reservation());
  assert.throws(() => vault.ingest({
    reservation_handle: reserved.reservation_handle,
    metadata: metadata({
      transform_provenance: {
        tool_id: "forged-tool",
        tool_version: "1.0.0",
        tool_digest: "b".repeat(64),
        input_handle_count: 1,
        batch_ref: `transform-batch:v1:${"c".repeat(64)}`,
        input_handles_digest: "d".repeat(64),
      },
    }),
    plaintext: Buffer.from("forged-transform-output"),
  }), /ordinary vault ingest cannot mint transform provenance/);
  assert.equal(vault.usage().active_reservations, 1);
});

test("expiry purge cannot consume a claimed output reservation", (t) => {
  let clockMs = Date.now();
  const { vault } = makeVault(t, { now: () => new Date(clockMs) });
  const registry = makeRegistry(t);
  const input = ingest(vault, "expiry-pin-input");
  const outputReservation = vault.reserve(reservation());
  const request = transformRequest(
    vault,
    registry,
    input.artifact_handle,
    outputReservation,
    "transform-attempt:expiry-pin",
  );
  const identity = attemptIdentity(request);
  const claim = claimTransformAttemptForWorker(vault, {
    batch_ref: identity.batchRef,
    binding_digest: identity.bindingDigest,
    input_handles: request.input_handles,
    outputs: request.outputs,
  });
  clockMs += 45 * 60_000;
  assert.equal(vault.usage().active_reservations, 1, "claimed output survives ordinary expiry purge");

  const key = crypto.randomBytes(32);
  const channel = createOperatorExportChannel({
    vault,
    exportKey: key,
    audience: "bob.operator",
    consumeNonce: () => true,
  });
  t.after(() => channel.destroy());
  const adjudication = signOperatorTransformRequest(operatorRequest(
    "adjudicate_terminal_failed",
    identity,
    {
      expected_claimed_at: claim.claimed_at,
      evidence_ref: "operator-evidence:expired-claim-adjudicated",
      verdict: "terminal_failed",
    },
  ), key);
  channel.adjudicateTransformAttempt(adjudication);
  assert.equal(vault.usage().active_reservations, 0);
  key.fill(0);
});

test("committed attempt fences survive output erasure and restoration of an older backup", (t) => {
  const { parent, vault } = makeVault(t);
  const registry = makeRegistry(t);
  const input = ingest(vault, "backup-fence-input");
  const backupDescriptor = openBackupFile(t, path.join(parent, "before-transform.backup"));
  const backup = vault.createBackup(backupDescriptor);
  const outputReservation = vault.reserve(reservation());
  const request = transformRequest(
    vault,
    registry,
    input.artifact_handle,
    outputReservation,
    "transform-attempt:backup-fence",
  );
  const identity = attemptIdentity(request);
  const result = runTransform(request);
  vault.erase(result.outputs[0].artifact_handle, "retention:transform-output-erased");
  assert.throws(() => runTransform(request), /committed and fenced.*no longer retained/);

  vault.restoreBackup(backupDescriptor, {
    expected_backup_ref: backup.backup_ref,
    allow_replace: true,
  });
  const restoredFence = inspectTransformAttemptForWorker(
    vault,
    identity.batchRef,
    identity.bindingDigest,
  );
  assert.equal(restoredFence.status, "committed");
  assert.equal(restoredFence.outputs_retained, false);
  assert.throws(() => runTransform(request), /committed and fenced.*no longer retained/);
});

test("post-claim precommit failure terminalizes before reservation compensation", (t) => {
  const setup = makeVault(t);
  const { vault } = setup;
  const registry = makeRegistry(t);
  const input = ingest(vault, "terminal-failure-input");
  const outputReservation = vault.reserve(reservation());
  const request = transformRequest(
    vault,
    registry,
    input.artifact_handle,
    outputReservation,
    "transform-attempt:permanent-failure",
    { media_type: "application/json" },
  );
  const identity = attemptIdentity(request);
  assert.throws(() => runTransform(request), /content type does not match/);
  const failed = inspectTransformAttemptForWorker(vault, identity.batchRef, identity.bindingDigest);
  assert.equal(failed.status, "failed");
  assert.match(failed.failure_digest, /^[a-f0-9]{64}$/);
  assert.equal(vault.usage().active_reservations, 0);
  assert.throws(() => runTransform(request), /permanently failed/);

  vault.destroy();
  const reopened = createArtifactVault({
    root: setup.root,
    sessionNucleusHash: SESSION_HASH,
    vaultId: setup.vaultId,
    vaultSlot: setup.vaultSlot,
    masterKey: setup.reopenKey,
    backupKeyCustody: setup.backupKeyCustody,
    deletionLedgerAnchor: setup.deletionLedgerAnchor,
    indexStateAnchor: setup.indexStateAnchor,
    quotaBytes: setup.quotaBytes,
    minFreeBytes: 0,
  });
  t.after(() => reopened.destroy());
  const reopenedFailure = inspectTransformAttemptForWorker(
    reopened,
    identity.batchRef,
    identity.bindingDigest,
  );
  assert.equal(reopenedFailure.status, "failed");
  assert.equal(reopenedFailure.failure_digest, failed.failure_digest);
  assert.equal(reopened.usage().active_reservations, 0);
  assert.throws(
    () => runTransform({ ...request, vault: reopened }),
    /permanently failed/,
  );
});

test("committed-but-unacknowledged claim publication reconciles to exactly one execution", (t) => {
  const { vault, indexStateAnchor } = makeVault(t);
  const registry = makeRegistry(t);
  const input = ingest(vault, "ambiguous-claim-input");
  const outputReservation = vault.reserve(reservation());
  const request = transformRequest(
    vault,
    registry,
    input.artifact_handle,
    outputReservation,
    "transform-attempt:ambiguous-claim",
  );
  const identity = attemptIdentity(request);
  indexStateAnchor.armAmbiguousCommit();
  const result = runTransform(request);
  assert.equal(result.status, "completed");
  const committed = inspectTransformAttemptForWorker(
    vault,
    identity.batchRef,
    identity.bindingDigest,
  );
  assert.equal(committed.status, "committed");
  assert.equal(committed.outputs.length, 1);
  assert.deepEqual(runTransform(request).outputs, result.outputs);
});

test("claim admission measures the full 64-output terminal index expansion", (t) => {
  const { parent, vault } = makeVault(t, { quotaBytes: 16 * 1024 * 1024 });
  const input = ingest(vault, "capacity-input");
  const outputs = [];
  for (let index = 0; index < 64; index += 1) {
    const reserved = vault.reserve(reservation());
    outputs.push({ reservation_handle: reserved.reservation_handle, metadata: metadata() });
  }
  const batchRef = `transform-batch:v1:${digest("capacity-attempt")}`;
  const bindingDigest = digest({ batch_ref: batchRef, outputs });
  const claimed = claimTransformAttemptForWorker(vault, {
    batch_ref: batchRef,
    binding_digest: bindingDigest,
    input_handles: [input.artifact_handle],
    outputs,
  });
  assert.equal(claimed.status, "claimed");
  const indexPayload = JSON.parse(
    fs.readFileSync(path.join(parent, "vault", "index.json"), "utf8"),
  ).payload;
  assert.ok(
    indexPayload.batches[batchRef].reserved_index_bytes > 1024 + 64 * 128,
    "measured terminal reservation must exceed the retired fixed heuristic",
  );
});

test("backup restore admits inventory against reopened count, quota, and free-space limits before allocation", (t) => {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), "bob-restore-admission-"));
  t.after(() => fs.rmSync(parent, { recursive: true, force: true }));
  const root = path.join(parent, "vault");
  const deletionLedgerAnchor = makeDeletionLedgerAnchor();
  const indexStateAnchor = makeIndexStateAnchor();
  const masterKey = crypto.randomBytes(32);
  const vaultId = `vault:v1:${crypto.randomBytes(32).toString("base64url")}`;
  const vaultSlot = `vault-slot:v1:${crypto.randomBytes(32).toString("base64url")}`;
  const backupKeyCustodyFixture = createInProcessBackupKeyCustodyFixture({
    vaultId,
    vaultSlot,
    sessionNucleusHash: SESSION_HASH,
  });
  t.after(() => masterKey.fill(0));
  t.after(() => backupKeyCustodyFixture.destroy());
  const create = (options = {}) => createArtifactVault({
    root,
    sessionNucleusHash: SESSION_HASH,
    vaultId,
    vaultSlot,
    backupKeyCustody: backupKeyCustodyFixture.port,
    masterKey,
    deletionLedgerAnchor,
    indexStateAnchor,
    quotaBytes: 2 * 1024 * 1024,
    minFreeBytes: 0,
    ...options,
  });

  const initial = create({ createNew: true });
  ingest(initial, "restore-one");
  ingest(initial, "restore-two");
  const backupDescriptor = openBackupFile(t, path.join(parent, "inventory.backup"));
  const backup = initial.createBackup(backupDescriptor);
  initial.destroy();

  const countLimited = create({ maxArtifacts: 1 });
  assert.throws(() => countLimited.restoreBackup(backupDescriptor, {
    expected_backup_ref: backup.backup_ref,
    allow_replace: true,
  }), /current artifact count ceiling/);
  countLimited.destroy();

  const quotaLimited = create({ quotaBytes: 4096 });
  assert.throws(() => quotaLimited.restoreBackup(backupDescriptor, {
    expected_backup_ref: backup.backup_ref,
    allow_replace: true,
  }), /logical or physical inventory exceeds the current quota/);
  quotaLimited.destroy();

  const diskLimited = create({ minFreeBytes: Number.MAX_SAFE_INTEGER });
  assert.throws(() => diskLimited.restoreBackup(backupDescriptor, {
    expected_backup_ref: backup.backup_ref,
    allow_replace: true,
  }), /insufficient free capacity/);
  diskLimited.destroy();
  assert.equal(
    fs.readdirSync(root).some((entry) => entry.startsWith("objects-restore-")),
    false,
    "rejected restore never allocates a recovery generation",
  );
});

test("private index reads fstat the opened descriptor and bound a pre-open path swap", (t) => {
  const { parent, vault } = makeVault(t);
  ingest(vault, "descriptor-race-input");
  const indexPath = path.join(parent, "vault", "index.json");
  const oversizedPath = path.join(parent, "vault", ".oversized-index-swap");
  const oversized = fs.openSync(oversizedPath, fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY, 0o600);
  fs.ftruncateSync(oversized, 40 * 1024 * 1024);
  fs.closeSync(oversized);

  const originalOpen = fs.openSync;
  let swapped = false;
  fs.openSync = function swapBeforeIndexOpen(filePath, flags, ...args) {
    if (!swapped && filePath === indexPath && (flags & fs.constants.O_RDONLY) === fs.constants.O_RDONLY) {
      swapped = true;
      fs.renameSync(oversizedPath, indexPath);
    }
    return originalOpen.call(fs, filePath, flags, ...args);
  };
  try {
    assert.equal(vault.usage().active_artifacts, 1);
  } finally {
    fs.openSync = originalOpen;
  }
  assert.equal(swapped, true);
  assert.ok(fs.statSync(indexPath).size < 32 * 1024 * 1024, "anchored mirror repair replaced oversize swap");
});
