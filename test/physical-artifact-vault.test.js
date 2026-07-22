"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const {
  PUBLIC_ARTIFACT_HANDLE_RE,
  PUBLIC_RESERVATION_HANDLE_RE,
  createArtifactVault,
  normalizeArtifactMetadata,
} = require("../packages/bob-artifact-vault/index.js");
const {
  createTransformRegistry,
  runTransform,
} = require("../packages/bob-artifact-vault/worker.js");
const {
  createOperatorBackupKeyCustodyPort,
  createOperatorExportChannel,
  createOperatorTransformPolicyAuthority,
  enrollOperatorTransformPolicy,
  signOperatorExportRequest,
} = require("../packages/bob-artifact-vault/operator.js");
const {
  MAX_MEMBER_ARCHIVES_PER_ARTIFACT,
  retireArtifactBackupKeys,
} = require("../packages/bob-artifact-vault/lib/backup-key-custody.js");

const SESSION_HASH = "a".repeat(64);
const REVOCATION_POLICY = "whole_archive_key_on_member_erasure";
const TRANSFORM_FIXTURE_PATH = path.join(
  __dirname,
  "fixtures",
  "artifact-transform-programs.transform.json",
);

function createTestTransformPolicy(t) {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), "bob-transform-fixture-"));
  t.after(() => fs.rmSync(parent, { recursive: true, force: true }));
  const implementationRoot = path.join(parent, "programs");
  fs.mkdirSync(implementationRoot, { mode: 0o700 });
  const implementationModule = "programs.transform.json";
  const implementationPath = path.join(implementationRoot, implementationModule);
  const implementationBytes = fs.readFileSync(TRANSFORM_FIXTURE_PATH);
  fs.writeFileSync(implementationPath, implementationBytes, { flag: "wx", mode: 0o600 });
  fs.chmodSync(implementationPath, 0o600);
  const implementationDigest = crypto.createHash("sha256").update(implementationBytes).digest("hex");
  const control = {
    mode: "current",
    current: {
      version: 1,
      policy_id: "physical-vault-test-policy",
      policy_epoch: 1,
      status: "trusted",
      trusted_implementation_root: implementationRoot,
      trusted_implementation_digests: [implementationDigest],
    },
  };
  const authorityInput = {
    version: 1,
    authority_id: "physical-vault-test-policy-authority",
    resolve_current_policy() {
      if (control.mode === "outage") throw new Error("injected resolver outage");
      if (control.mode === "async") return Promise.resolve(structuredClone(control.current));
      if (control.mode === "malformed") return { version: 1, policy_id: control.current.policy_id };
      if (control.mode === "substitute") {
        return { ...structuredClone(control.current), policy_id: "substituted-policy" };
      }
      return structuredClone(control.current);
    },
  };
  const authority = createOperatorTransformPolicyAuthority(authorityInput);
  const enrollmentRequest = () => ({
    version: 1,
    policy_authority_id: authority.authority_id,
    policy_authority_digest: authority.authority_digest,
    policy_id: control.current.policy_id,
  });
  const policy = enrollOperatorTransformPolicy(enrollmentRequest(), authority);
  return {
    authority,
    authorityInput,
    control,
    enrollmentRequest,
    implementationDigest,
    implementationModule,
    implementationRoot,
    parent,
    policy,
  };
}

function createTestTransformRegistry(t, definitions) {
  const enrollment = createTestTransformPolicy(t);
  const handlerExports = {
    identity: "identityTransform",
    "reverse-bytes": "reverseBytesTransform",
    "two-output-transform": "twoOutputTransform",
    bad: "identityTransform",
  };
  return createTransformRegistry(definitions.map((definition) => ({
    implementation_module: enrollment.implementationModule,
    manifest: {
      ...definition.manifest,
      implementation_digest: enrollment.implementationDigest,
      handler_export: definition.handler_export || handlerExports[definition.manifest.tool_id],
    },
  })), enrollment.policy);
}

function futureIso(minutes = 30) {
  return new Date(Date.now() + minutes * 60_000).toISOString();
}

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value != null && typeof value === "object") {
    const output = {};
    for (const key of Object.keys(value).sort()) output[key] = canonicalize(value[key]);
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

function cloneJson(value) {
  return JSON.parse(JSON.stringify(value));
}

function memberArchiveProjection(state) {
  return {
    backup_ref: state.backup_ref,
    backup_digest: state.backup_digest,
    artifact_inventory_digest: state.artifact_inventory_digest,
    seal_effect_ref: state.seal_effect_ref,
    seal_ref: state.seal_ref,
    sealed_archive_digest: state.sealed_archive_digest,
  };
}

function makeBackupKeyCustody({ vaultId, vaultSlot, sessionNucleusHash = SESSION_HASH } = {}) {
  const custodyId = `backup-custody:v1:${crypto.randomBytes(32).toString("base64url")}`;
  const custodyEpoch = 1;
  const receiptKey = crypto.randomBytes(32);
  const archives = new Map();
  const retirements = new Map();
  const restoreFences = new Map();
  const control = {
    status: "active",
    custody_epoch: custodyEpoch,
    resolve_hook: null,
    seal_hook: null,
    read_archive_hook: null,
    open_hook: null,
    acquire_restore_hook: null,
    read_restore_hook: null,
    release_restore_hook: null,
    retire_hook: null,
    read_retirement_hook: null,
    seal_lost_ack_once: false,
    acquire_restore_lost_ack_once: false,
    release_restore_lost_ack_once: false,
    acquire_restore_read_failures_after_effect: 0,
    release_restore_read_failures_after_effect: 0,
    read_restore_failures_remaining: 0,
    retire_lost_ack_once: false,
  };
  const metrics = {
    seal_effects: 0,
    retire_effects: 0,
    open_effects: 0,
    restore_acquire_effects: 0,
    restore_release_effects: 0,
  };
  const binding = {
    custody_id: custodyId,
    custody_epoch: custodyEpoch,
    vault_id: vaultId,
    vault_slot: vaultSlot,
    session_nucleus_hash: sessionNucleusHash,
  };
  const current = () => ({
    version: 1,
    custody_id: custodyId,
    custody_epoch: control.custody_epoch,
    status: control.status,
    vault_id: vaultId,
    vault_slot: vaultSlot,
    session_nucleus_hash: sessionNucleusHash,
    production_ready: false,
    hil_verified: false,
    revocation_policy: REVOCATION_POLICY,
    backup_media_erasure_attested: false,
  });
  const callbacks = {
    resolve_current_custody(query) {
      const output = current();
      return control.resolve_hook ? control.resolve_hook(output, query) : output;
    },
    seal_archive(request, plaintext) {
      if (archives.has(request.backup_ref)) throw new Error("duplicate backup");
      if (request.artifact_inventory.some((entry) => retirements.has(entry.artifact_handle))) {
        throw new Error("retired artifact");
      }
      const archiveKey = crypto.randomBytes(32);
      const nonce = crypto.randomBytes(12);
      const aad = canonicalJson({
        ...request,
        artifact_inventory: request.artifact_inventory,
      });
      const cipher = crypto.createCipheriv("aes-256-gcm", archiveKey, nonce);
      cipher.setAAD(Buffer.from(aad));
      const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
      const sealed = Buffer.from(canonicalJson({
        algorithm: "aes-256-gcm",
        nonce: nonce.toString("base64"),
        ciphertext: ciphertext.toString("base64"),
        tag: cipher.getAuthTag().toString("base64"),
      }));
      const state = {
        version: 1,
        status: "active",
        ...binding,
        backup_ref: request.backup_ref,
        backup_digest: request.backup_digest,
        artifact_inventory_digest: request.artifact_inventory_digest,
        seal_effect_ref: request.seal_effect_ref,
        seal_ref: `backup-seal:v1:${crypto.randomBytes(32).toString("base64url")}`,
        custody_format: "test-external-aes-256-gcm-v1",
        sealed_archive: sealed.toString("base64"),
        sealed_archive_digest: digest(sealed),
        revocation_effect_ref: null,
        revoked_at: null,
      };
      sealed.fill(0);
      archives.set(request.backup_ref, {
        aad,
        artifact_handles: request.artifact_inventory.map((entry) => entry.artifact_handle),
        key: archiveKey,
        state,
      });
      metrics.seal_effects += 1;
      if (control.seal_lost_ack_once) {
        control.seal_lost_ack_once = false;
        throw new Error("injected lost seal acknowledgement");
      }
      const output = cloneJson(state);
      return control.seal_hook ? control.seal_hook(output, request) : output;
    },
    read_archive_state(request) {
      const record = archives.get(request.backup_ref);
      let output = null;
      if (record
        && record.state.backup_digest === request.backup_digest
        && record.state.artifact_inventory_digest === request.artifact_inventory_digest
        && record.state.seal_effect_ref === request.seal_effect_ref) {
        output = cloneJson(record.state);
      }
      return control.read_archive_hook ? control.read_archive_hook(output, request) : output;
    },
    open_archive(request) {
      const record = archives.get(request.backup_ref);
      if (!record || record.state.status !== "active" || !record.key) {
        throw new Error("archive key revoked");
      }
      for (const field of [
        "backup_digest",
        "artifact_inventory_digest",
        "seal_effect_ref",
        "seal_ref",
        "custody_format",
        "sealed_archive",
        "sealed_archive_digest",
      ]) {
        if (request[field] !== record.state[field]) throw new Error("archive binding mismatch");
      }
      if (request.restore_ref !== null) {
        const fence = restoreFences.get(request.restore_ref);
        if (!fence || fence.status !== "active" || fence.backup_ref !== request.backup_ref) {
          throw new Error("restore fence is absent or inactive");
        }
      }
      const envelope = JSON.parse(Buffer.from(request.sealed_archive, "base64").toString("utf8"));
      const decipher = crypto.createDecipheriv(
        "aes-256-gcm",
        record.key,
        Buffer.from(envelope.nonce, "base64"),
      );
      decipher.setAAD(Buffer.from(record.aad));
      decipher.setAuthTag(Buffer.from(envelope.tag, "base64"));
      const plaintext = Buffer.concat([
        decipher.update(Buffer.from(envelope.ciphertext, "base64")),
        decipher.final(),
      ]);
      metrics.open_effects += 1;
      const output = {
        version: 1,
        ...binding,
        backup_ref: request.backup_ref,
        backup_digest: request.backup_digest,
        artifact_inventory_digest: request.artifact_inventory_digest,
        seal_ref: request.seal_ref,
        open_ref: request.open_ref,
        restore_ref: request.restore_ref,
        plaintext_archive: plaintext,
      };
      return control.open_hook ? control.open_hook(output, request) : output;
    },
    acquire_restore_fence(request) {
      if (restoreFences.has(request.restore_ref)) {
        return cloneJson(restoreFences.get(request.restore_ref));
      }
      const archive = archives.get(request.backup_ref);
      if (!archive || archive.state.status !== "active") throw new Error("archive is not active");
      const fence = {
        version: 1,
        status: "active",
        ...binding,
        backup_ref: request.backup_ref,
        backup_digest: request.backup_digest,
        artifact_inventory_digest: request.artifact_inventory_digest,
        seal_effect_ref: request.seal_effect_ref,
        seal_ref: request.seal_ref,
        restore_ref: request.restore_ref,
        acquire_effect_ref: request.acquire_effect_ref,
        release_effect_ref: null,
        production_ready: false,
        hil_verified: false,
      };
      restoreFences.set(request.restore_ref, fence);
      metrics.restore_acquire_effects += 1;
      if (control.acquire_restore_read_failures_after_effect > 0) {
        control.read_restore_failures_remaining += control.acquire_restore_read_failures_after_effect;
        control.acquire_restore_read_failures_after_effect = 0;
      }
      if (control.acquire_restore_lost_ack_once) {
        control.acquire_restore_lost_ack_once = false;
        throw new Error("injected lost restore-fence acquisition acknowledgement");
      }
      const output = cloneJson(fence);
      return control.acquire_restore_hook
        ? control.acquire_restore_hook(output, request)
        : output;
    },
    read_restore_fence(request) {
      if (control.read_restore_failures_remaining > 0) {
        control.read_restore_failures_remaining -= 1;
        throw new Error("injected restore-fence readback outage");
      }
      const fence = restoreFences.get(request.restore_ref);
      const output = fence ? cloneJson(fence) : null;
      return control.read_restore_hook
        ? control.read_restore_hook(output, request)
        : output;
    },
    release_restore_fence(request) {
      const fence = restoreFences.get(request.restore_ref);
      if (!fence) throw new Error("restore fence is absent");
      if (fence.status === "released") {
        if (fence.release_effect_ref !== request.release_effect_ref) {
          throw new Error("restore fence release effect mismatch");
        }
        return cloneJson(fence);
      }
      const released = {
        ...fence,
        status: "released",
        release_effect_ref: request.release_effect_ref,
      };
      restoreFences.set(request.restore_ref, released);
      metrics.restore_release_effects += 1;
      if (control.release_restore_read_failures_after_effect > 0) {
        control.read_restore_failures_remaining += control.release_restore_read_failures_after_effect;
        control.release_restore_read_failures_after_effect = 0;
      }
      if (control.release_restore_lost_ack_once) {
        control.release_restore_lost_ack_once = false;
        throw new Error("injected lost restore-fence release acknowledgement");
      }
      const output = cloneJson(released);
      return control.release_restore_hook
        ? control.release_restore_hook(output, request)
        : output;
    },
    retire_artifact(request) {
      if (retirements.has(request.artifact_handle)) {
        return cloneJson(retirements.get(request.artifact_handle));
      }
      const memberRecords = [...archives.values()].filter(
        (record) => record.artifact_handles.includes(request.artifact_handle),
      );
      if (memberRecords.some((record) => [...restoreFences.values()].some(
        (fence) => fence.status === "active" && fence.backup_ref === record.state.backup_ref,
      ))) {
        throw new Error("member archive holds an active restore fence");
      }
      const revoked = [];
      for (const record of memberRecords) {
        if (record.state.status === "active") {
          record.key.fill(0);
          record.key = null;
          record.state = {
            ...record.state,
            status: "revoked",
            revocation_effect_ref: request.retirement_effect_ref,
            revoked_at: request.requested_at,
          };
        }
        const summaryPayload = {
          backup_ref: record.state.backup_ref,
          backup_digest: record.state.backup_digest,
          artifact_inventory_digest: record.state.artifact_inventory_digest,
          seal_effect_ref: record.state.seal_effect_ref,
          seal_ref: record.state.seal_ref,
          sealed_archive_digest: record.state.sealed_archive_digest,
          revocation_effect_ref: record.state.revocation_effect_ref,
          revoked_at: record.state.revoked_at,
        };
        revoked.push({
          ...summaryPayload,
          revocation_receipt: crypto.createHmac("sha256", receiptKey)
            .update("archive-revocation\0")
            .update(canonicalJson(summaryPayload))
            .digest("hex"),
        });
      }
      revoked.sort((left, right) => left.backup_ref.localeCompare(right.backup_ref));
      const observedMemberRegistry = revoked.map((entry) => ({
        backup_ref: entry.backup_ref,
        backup_digest: entry.backup_digest,
        artifact_inventory_digest: entry.artifact_inventory_digest,
        seal_effect_ref: entry.seal_effect_ref,
        seal_ref: entry.seal_ref,
        sealed_archive_digest: entry.sealed_archive_digest,
      }));
      if (canonicalJson(observedMemberRegistry) !== canonicalJson(request.member_archive_registry)
        || digest(canonicalJson(observedMemberRegistry)) !== request.member_archive_registry_digest) {
        throw new Error("member archive registry mismatch");
      }
      const retirementPayload = {
        version: 1,
        status: "retired",
        ...binding,
        artifact_handle: request.artifact_handle,
        reason_ref: request.reason_ref,
        retirement_effect_ref: request.retirement_effect_ref,
        retired_at: request.requested_at,
        revocation_policy: REVOCATION_POLICY,
        member_archive_registry_digest: request.member_archive_registry_digest,
        revoked_archives: revoked,
        revoked_archives_digest: digest(canonicalJson(revoked)),
        active_archive_count: 0,
        production_ready: false,
        hil_verified: false,
        backup_media_erasure_attested: false,
      };
      const retirement = {
        ...retirementPayload,
        retirement_receipt: crypto.createHmac("sha256", receiptKey)
          .update("artifact-retirement\0")
          .update(canonicalJson(retirementPayload))
          .digest("hex"),
      };
      retirements.set(request.artifact_handle, retirement);
      metrics.retire_effects += 1;
      if (control.retire_lost_ack_once) {
        control.retire_lost_ack_once = false;
        throw new Error("injected lost retirement acknowledgement");
      }
      const output = cloneJson(retirement);
      return control.retire_hook ? control.retire_hook(output, request) : output;
    },
    read_artifact_retirement(request) {
      const value = retirements.get(request.artifact_handle);
      const output = value ? cloneJson(value) : null;
      return control.read_retirement_hook
        ? control.read_retirement_hook(output, request)
        : output;
    },
  };
  const port = createOperatorBackupKeyCustodyPort({
    version: 1,
    ...binding,
    ...callbacks,
  });
  return {
    archives,
    control,
    metrics,
    port,
    retirements,
    restoreFences,
    destroy() {
      for (const record of archives.values()) {
        if (record.key) record.key.fill(0);
      }
      receiptKey.fill(0);
    },
  };
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
      const expectedMatches = current == null
        ? request.expected_generation == null && request.expected_ledger_digest == null
        : request.expected_generation === current.generation
          && request.expected_ledger_digest === current.ledger_digest;
      if (!expectedMatches) return false;
      states.set(request.vault_slot, structuredClone(request.next_state));
      return true;
    },
    peekStates() {
      return [...states.values()].map((state) => structuredClone(state));
    },
  });
}

function makeIndexStateAnchor() {
  const states = new Map();
  let beforeNextCommit = null;
  let commitThenFailRead = false;
  let readFailuresRemaining = 0;
  let rejectNextCommit = false;
  return Object.freeze({
    readState({ vault_slot: vaultSlot }) {
      if (readFailuresRemaining > 0) {
        readFailuresRemaining -= 1;
        throw new Error("injected external anchor read failure");
      }
      const state = states.get(vaultSlot);
      return state == null ? null : structuredClone(state);
    },
    compareAndSet(request) {
      if (rejectNextCommit) {
        rejectNextCommit = false;
        return false;
      }
      const current = states.get(request.vault_slot) || null;
      const expectedMatches = current == null
        ? request.expected_generation == null && request.expected_index_digest == null
        : request.expected_generation === current.generation
          && request.expected_index_digest === current.index_digest;
      if (!expectedMatches) return false;
      if (beforeNextCommit) {
        const callback = beforeNextCommit;
        beforeNextCommit = null;
        callback();
      }
      states.set(request.vault_slot, structuredClone(request.next_state));
      if (commitThenFailRead) {
        commitThenFailRead = false;
        readFailuresRemaining = 1;
        throw new Error("injected committed CAS acknowledgement failure");
      }
      return true;
    },
    armCommitThenReadFailure() {
      commitThenFailRead = true;
    },
    rejectNextCommit() {
      rejectNextCommit = true;
    },
    runBeforeNextCommit(callback) {
      if (typeof callback !== "function") throw new Error("index anchor commit hook must be a function");
      if (beforeNextCommit) throw new Error("index anchor commit hook is already armed");
      beforeNextCommit = callback;
    },
    peekStates() {
      return [...states.values()].map((state) => structuredClone(state));
    },
  });
}

function transformAttemptRef(label = "test") {
  return `transform-attempt:${label}-${crypto.randomBytes(8).toString("hex")}`;
}

function openBackupFile(t, filePath) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true, mode: 0o700 });
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

function makeVault(t, options = {}) {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), "bob-physical-vault-"));
  t.after(() => fs.rmSync(parent, { recursive: true, force: true }));
  const root = path.join(parent, "vault");
  const backupRoot = path.join(parent, "operator-backups");
  const masterKey = crypto.randomBytes(32);
  const reopenKey = Buffer.from(masterKey);
  const deletionLedgerAnchor = makeDeletionLedgerAnchor();
  const indexStateAnchor = makeIndexStateAnchor();
  const vaultId = `vault:v1:${crypto.randomBytes(32).toString("base64url")}`;
  const vaultSlot = `vault-slot:v1:${crypto.randomBytes(32).toString("base64url")}`;
  const backupKeyCustodyFixture = makeBackupKeyCustody({ vaultId, vaultSlot });
  const vault = createArtifactVault({
    root,
    sessionNucleusHash: SESSION_HASH,
    vaultId,
    vaultSlot,
    createNew: true,
    masterKey,
    backupKeyCustody: backupKeyCustodyFixture.port,
    deletionLedgerAnchor,
    indexStateAnchor,
    quotaBytes: options.quotaBytes || 1024 * 1024,
    minFreeBytes: 0,
    indexEncodedBytesCeiling: options.indexEncodedBytesCeiling,
    deletionLedgerEncodedBytesCeiling: options.deletionLedgerEncodedBytesCeiling,
    now: options.now,
  });
  masterKey.fill(0);
  t.after(() => vault.destroy());
  t.after(() => backupKeyCustodyFixture.destroy());
  t.after(() => reopenKey.fill(0));
  return {
    backupRoot,
    backupKeyCustody: backupKeyCustodyFixture.port,
    backupKeyCustodyFixture,
    deletionLedgerAnchor,
    indexStateAnchor,
    parent,
    reopenKey,
    root,
    vaultId,
    vaultSlot,
    vault,
  };
}

function reopenVault(t, setup) {
  const vault = createArtifactVault({
    root: setup.root,
    sessionNucleusHash: SESSION_HASH,
    vaultId: setup.vaultId,
    vaultSlot: setup.vaultSlot,
    masterKey: setup.reopenKey,
    backupKeyCustody: setup.backupKeyCustody,
    deletionLedgerAnchor: setup.deletionLedgerAnchor,
    indexStateAnchor: setup.indexStateAnchor,
    minFreeBytes: 0,
  });
  t.after(() => vault.destroy());
  return vault;
}

function reservation(overrides = {}) {
  return {
    version: 1,
    session_nucleus_hash: SESSION_HASH,
    task_id: "task-1",
    attempt_id: "attempt-1",
    reservation_ref: `reservation:test-${crypto.randomBytes(12).toString("hex")}`,
    purpose_ref: "purpose:capture",
    byte_ceiling: 4096,
    expires_at: futureIso(),
    ...overrides,
  };
}

function metadata(overrides = {}) {
  return {
    version: 1,
    session_nucleus_hash: SESSION_HASH,
    task_id: "task-1",
    attempt_id: "attempt-1",
    data_class: "credential_secret",
    media_type: "application/octet-stream",
    source_ref: "provider:mock",
    retention_expires_at: futureIso(60),
    ...overrides,
  };
}

function ingest(vault, bytes, metadataOverrides = {}, reservationOverrides = {}) {
  const reserved = vault.reserve(reservation({
    byte_ceiling: Math.max(bytes.length, 1),
    ...reservationOverrides,
  }));
  return vault.ingest({
    reservation_handle: reserved.reservation_handle,
    metadata: metadata(metadataOverrides),
    plaintext: Buffer.from(bytes),
  });
}

test("vault contracts are closed, session-bound, and use random opaque handles", (t) => {
  const { root, vault } = makeVault(t);
  assert.throws(
    () => normalizeArtifactMetadata({ ...metadata(), raw_bytes: "no" }),
    /unknown fields: raw_bytes/,
  );
  assert.throws(
    () => vault.reserve(reservation({ session_nucleus_hash: "b".repeat(64) })),
    /does not match/,
  );
  const reserved = vault.reserve(reservation());
  assert.match(reserved.reservation_handle, PUBLIC_RESERVATION_HANDLE_RE);
  assert.ok(!reserved.reservation_handle.includes(SESSION_HASH));

  const committedMetadata = metadata();
  const descriptor = vault.ingest({
    reservation_handle: reserved.reservation_handle,
    metadata: committedMetadata,
    plaintext: Buffer.from("low entropy credential bytes"),
  });
  assert.match(descriptor.artifact_handle, PUBLIC_ARTIFACT_HANDLE_RE);
  assert.deepEqual(Object.keys(descriptor).sort(), [
    "artifact_handle",
    "byte_length",
    "created_at",
    "data_class",
    "masked_summary",
    "media_type",
    "retention_expires_at",
  ]);
  assert.doesNotMatch(JSON.stringify(descriptor), /low entropy|content_digest|wrapped_data_key|objects\//);
  assert.throws(() => vault.inspect("artifact:v1:../../etc/passwd"), /invalid/);

  const rootEntries = fs.readdirSync(root).sort();
  assert.deepEqual(rootEntries, [
    "backup-intents",
    "deletion-ledger.json",
    "index.json",
    "objects",
    "vault.json",
  ]);
  assert.equal(fs.statSync(path.join(root, "vault.json")).mode & 0o777, 0o600);
  assert.equal(fs.statSync(path.join(root, "index.json")).mode & 0o777, 0o600);
  assert.equal(fs.statSync(root).mode & 0o777, 0o700);
  assert.equal(Object.getOwnPropertySymbols(vault).length, 0, "public vault object exposes no plaintext capability symbol");
  assert.doesNotMatch(fs.readFileSync(path.join(root, "index.json"), "utf8"), /content_digest/);
});

test("randomized AEAD is non-deterministic while engagement comparison stays keyed", (t) => {
  const { root, vault } = makeVault(t);
  const first = ingest(vault, "same-secret");
  const second = ingest(vault, "same-secret");
  const third = ingest(vault, "different-secret");
  assert.notEqual(first.artifact_handle, second.artifact_handle);
  assert.deepEqual(vault.compare(first.artifact_handle, second.artifact_handle), {
    equal: true,
    comparison_scope: "engagement",
  });
  assert.equal(vault.compare(first.artifact_handle, third.artifact_handle).equal, false);

  const ciphertexts = fs.readdirSync(path.join(root, "objects"))
    .map((name) => fs.readFileSync(path.join(root, "objects", name), "utf8"));
  assert.equal(ciphertexts.length, 3);
  assert.notEqual(ciphertexts[0], ciphertexts[1]);
  assert.ok(ciphertexts.every((ciphertext) => !ciphertext.includes("same-secret")));
  assert.equal(JSON.stringify(vault.usage()).includes("comparison_token"), false);
});

test("pre-stimulus quota, task binding, expiry, and idempotent one-use reservations fail closed", (t) => {
  const { vault } = makeVault(t, { quotaBytes: 300 * 1024 });
  assert.throws(() => vault.reserve(reservation({ byte_ceiling: 140 * 1024 })), /quota is exhausted/);
  const reservationRequest = reservation({ byte_ceiling: 8 });
  const reserved = vault.reserve(reservationRequest);
  assert.deepEqual(vault.reserve(reservationRequest), reserved, "reservation retries recover the keyed handle");
  assert.throws(
    () => vault.ingest({
      reservation_handle: reserved.reservation_handle,
      metadata: metadata({ task_id: "task-2" }),
      plaintext: Buffer.from("1234"),
    }),
    /task\/attempt does not match/,
  );
  assert.throws(
    () => vault.ingest({
      reservation_handle: reserved.reservation_handle,
      metadata: metadata(),
      plaintext: Buffer.from("123456789"),
    }),
    /exceeds its pre-stimulus byte reservation/,
  );
  const committedMetadata = metadata();
  const descriptor = vault.ingest({
    reservation_handle: reserved.reservation_handle,
    metadata: committedMetadata,
    plaintext: Buffer.from("1234"),
  });
  assert.match(descriptor.artifact_handle, PUBLIC_ARTIFACT_HANDLE_RE);
  assert.deepEqual(vault.ingest({
    reservation_handle: reserved.reservation_handle,
    metadata: committedMetadata,
    plaintext: Buffer.from("1234"),
  }), descriptor, "an identical ingest retry recovers the committed artifact result");
  assert.throws(() => vault.ingest({
    reservation_handle: reserved.reservation_handle,
    metadata: committedMetadata,
    plaintext: Buffer.from("5678"),
  }), /different committed artifact binding/);
  assert.throws(
    () => vault.reserve(reservation({ expires_at: new Date(Date.now() - 1000).toISOString() })),
    /must be in the future/,
  );
  const emptyReservation = vault.reserve(reservation({ byte_ceiling: 1 }));
  assert.throws(() => vault.ingest({
    reservation_handle: emptyReservation.reservation_handle,
    metadata: metadata(),
    plaintext: Buffer.alloc(0),
  }), /non-empty explicit Buffer/);
});

test("reservation admission uses the injected trusted clock and rejects the exact expiry boundary", (t) => {
  const trustedNow = new Date(Date.now() + 2 * 60 * 60_000);
  const { vault } = makeVault(t, { now: () => new Date(trustedNow.getTime()) });
  assert.throws(() => vault.reserve(reservation({
    expires_at: trustedNow.toISOString(),
  })), /expires_at must be in the future/);
  assert.throws(() => vault.reserve(reservation({
    expires_at: new Date(trustedNow.getTime() - 1).toISOString(),
  })), /expires_at must be in the future/);
  const admitted = vault.reserve(reservation({
    expires_at: new Date(trustedNow.getTime() + 1).toISOString(),
  }));
  assert.equal(admitted.expires_at, new Date(trustedNow.getTime() + 1).toISOString());

  const hostFutureButTrustedPast = new Date(Date.now() + 60 * 60_000).toISOString();
  assert.throws(() => vault.reserve(reservation({
    expires_at: hostFutureButTrustedPast,
  })), /expires_at must be in the future/);
});

test("expired physical reservations are durably purged before reporting capacity", (t) => {
  let current = new Date();
  const { root, vault } = makeVault(t, { now: () => new Date(current.getTime()) });
  const expiresAt = new Date(current.getTime() + 60_000).toISOString();
  vault.reserve(reservation({ byte_ceiling: 32, expires_at: expiresAt }));
  assert.equal(fs.readdirSync(path.join(root, "objects")).length, 1);
  current = new Date(current.getTime() + 120_000);
  assert.equal(vault.usage().active_reservations, 0);
  assert.equal(fs.readdirSync(path.join(root, "objects")).length, 0);
  const persisted = JSON.parse(fs.readFileSync(path.join(root, "index.json"), "utf8")).payload;
  assert.deepEqual(persisted.reservations, {});
});

test("the monotonic index anchor stores only an encrypted recovery snapshot", (t) => {
  const { indexStateAnchor, vault } = makeVault(t);
  ingest(vault, "anchor-confidentiality-sentinel", {
    source_ref: "provider:confidential-source",
  });
  const serialized = JSON.stringify(indexStateAnchor.peekStates());
  assert.match(serialized, /encrypted_index/);
  assert.doesNotMatch(serialized, /encoded_index|anchor-confidentiality-sentinel|confidential-source|task-1|attempt-1/);
});

test("an index mirror EIO after the anchor commit cannot strand or delete a durable reservation", (t) => {
  const { root, vault } = makeVault(t);
  const indexPath = path.join(root, "index.json");
  const originalRename = fs.renameSync;
  let injected = false;
  fs.renameSync = function injectedRename(source, destination) {
    if (!injected && destination === indexPath && path.basename(source).startsWith(".index.json.")) {
      injected = true;
      const error = new Error("injected local index mirror EIO");
      error.code = "EIO";
      throw error;
    }
    return originalRename.apply(this, arguments);
  };
  let reserved;
  try {
    reserved = vault.reserve(reservation({ byte_ceiling: 8 }));
  } finally {
    fs.renameSync = originalRename;
  }
  assert.equal(injected, true);
  assert.match(reserved.reservation_handle, PUBLIC_RESERVATION_HANDLE_RE);
  assert.equal(vault.usage().active_reservations, 1);
  assert.equal(fs.readdirSync(path.join(root, "objects")).length, 1);
  const descriptor = vault.ingest({
    reservation_handle: reserved.reservation_handle,
    metadata: metadata(),
    plaintext: Buffer.from("durable"),
  });
  assert.equal(vault.inspect(descriptor.artifact_handle).byte_length, 7);
});

test("committed-but-unacknowledged anchor mutations reconcile idempotent reserve and ingest results", (t) => {
  const { indexStateAnchor, vault } = makeVault(t);
  const request = reservation({ byte_ceiling: 16 });
  indexStateAnchor.armCommitThenReadFailure();
  const reserved = vault.reserve(request);
  assert.deepEqual(vault.reserve(request), reserved);

  const artifactMetadata = metadata();
  indexStateAnchor.armCommitThenReadFailure();
  const descriptor = vault.ingest({
    reservation_handle: reserved.reservation_handle,
    metadata: artifactMetadata,
    plaintext: Buffer.from("ambiguous-commit"),
  });
  assert.deepEqual(vault.ingest({
    reservation_handle: reserved.reservation_handle,
    metadata: artifactMetadata,
    plaintext: Buffer.from("ambiguous-commit"),
  }), descriptor);
  assert.equal(vault.inspect(descriptor.artifact_handle).byte_length, "ambiguous-commit".length);
});

test("failed post-commit compaction remains charged at its physical allocation", (t) => {
  const { vault } = makeVault(t, { quotaBytes: 140 * 1024 });
  const reserved = vault.reserve(reservation({ byte_ceiling: 1 }));
  const originalTruncate = fs.ftruncateSync;
  let injected = false;
  fs.ftruncateSync = function injectedTruncate() {
    if (!injected) {
      injected = true;
      const error = new Error("injected ciphertext compaction EIO");
      error.code = "EIO";
      throw error;
    }
    return originalTruncate.apply(this, arguments);
  };
  try {
    vault.ingest({
      reservation_handle: reserved.reservation_handle,
      metadata: metadata(),
      plaintext: Buffer.from("x"),
    });
  } finally {
    fs.ftruncateSync = originalTruncate;
  }
  assert.equal(injected, true);
  assert.ok(vault.usage().active_bytes > 128 * 1024);
  assert.throws(() => vault.reserve(reservation({ byte_ceiling: 1 })), /quota is exhausted/);
});

test("index/ciphertext tampering and symlink or hardlink substitution are rejected", (t) => {
  const { parent, root, vault } = makeVault(t);
  const descriptor = ingest(vault, "classified");
  const indexPath = path.join(root, "index.json");
  const committedIndex = fs.readFileSync(indexPath, "utf8");
  const index = JSON.parse(fs.readFileSync(indexPath, "utf8"));
  index.payload.generation += 1;
  fs.writeFileSync(indexPath, JSON.stringify(index));
  assert.equal(vault.inspect(descriptor.artifact_handle).byte_length, "classified".length);
  assert.equal(
    fs.readFileSync(indexPath, "utf8"),
    committedIndex,
    "an authenticated external snapshot repairs a corrupt local mirror",
  );

  const secondRoot = path.join(parent, "second");
  const secondKey = crypto.randomBytes(32);
  const secondVaultId = `vault:v1:${crypto.randomBytes(32).toString("base64url")}`;
  const secondVaultSlot = `vault-slot:v1:${crypto.randomBytes(32).toString("base64url")}`;
  const secondBackupKeyCustody = makeBackupKeyCustody({
    vaultId: secondVaultId,
    vaultSlot: secondVaultSlot,
  });
  t.after(() => secondBackupKeyCustody.destroy());
  const second = createArtifactVault({
    root: secondRoot,
    sessionNucleusHash: SESSION_HASH,
    vaultId: secondVaultId,
    vaultSlot: secondVaultSlot,
    createNew: true,
    masterKey: secondKey,
    backupKeyCustody: secondBackupKeyCustody.port,
    deletionLedgerAnchor: makeDeletionLedgerAnchor(),
    indexStateAnchor: makeIndexStateAnchor(),
    quotaBytes: 512 * 1024,
    minFreeBytes: 0,
  });
  secondKey.fill(0);
  t.after(() => second.destroy());
  const secondDescriptor = ingest(second, "secret");
  const blobName = fs.readdirSync(path.join(secondRoot, "objects"))[0];
  const blobPath = path.join(secondRoot, "objects", blobName);
  const hardlinkPath = path.join(secondRoot, "objects", "alias.json");
  fs.linkSync(blobPath, hardlinkPath);
  assert.throws(() => {
    const registry = createTestTransformRegistry(t, [{
      manifest: {
        version: 1,
        tool_id: "identity",
        tool_version: "1.0.0",
        input_data_classes: ["credential_secret"],
        output_data_classes: ["credential_secret"],
        parameters: {},
        max_input_handles: 1,
        max_input_bytes: 32,
        max_output_artifacts: 1,
        max_output_bytes: 32,
      },
    }]);
    const outputReservation = second.reserve(reservation({ byte_ceiling: 32 }));
    runTransform({
      registry,
      registry_digest: registry.registry_digest,
      vault: second,
      transform_attempt_ref: transformAttemptRef("hardlink"),
      tool_id: "identity",
      tool_digest: registry.manifest("identity").tool_digest,
      input_handles: [secondDescriptor.artifact_handle],
      outputs: [{ reservation_handle: outputReservation.reservation_handle, metadata: metadata() }],
    });
  }, /single-link regular file/);
});

test("reference-aware cryptographic erasure leaves an auditable opaque receipt", (t) => {
  const { root, vault } = makeVault(t);
  const descriptor = ingest(vault, "erase-me");
  vault.addReference(descriptor.artifact_handle, "evidence:row-1");
  assert.throws(() => vault.erase(descriptor.artifact_handle, "retention:operator"), /still referenced/);
  vault.removeReference(descriptor.artifact_handle, "evidence:row-1");
  const receipt = vault.erase(descriptor.artifact_handle, "retention:operator");
  assert.equal(receipt.deletion_kind, "managed_cryptographic_erasure");
  assert.match(receipt.deletion_receipt, /^[a-f0-9]{64}$/);
  assert.deepEqual(receipt.current_store_erasure, {
    status: "committed",
    erasure_kind: "deletion_ledger_key_unreachability",
    ciphertext_deleted: true,
  });
  assert.equal(receipt.external_backup_key_revocation.status, "completed");
  assert.equal(receipt.external_backup_key_revocation.revocation_policy, REVOCATION_POLICY);
  assert.equal(receipt.external_backup_key_revocation.revoked_archive_count, 0);
  assert.equal(receipt.external_backup_key_revocation.production_ready, false);
  assert.equal(receipt.external_backup_key_revocation.hil_verified, false);
  assert.deepEqual(receipt.backup_media_erasure, {
    status: "not_attested",
    physically_destroyed: false,
  });
  assert.throws(() => vault.inspect(descriptor.artifact_handle), /erased/);
  assert.equal(fs.readdirSync(path.join(root, "objects")).length, 0);
  const rawIndex = fs.readFileSync(path.join(root, "index.json"), "utf8");
  assert.ok(!rawIndex.includes("erase-me"));
  assert.ok(!rawIndex.includes("wrapped_data_key"));
});

test("index and deletion lifecycle writes honor their exact configured read ceilings", (t) => {
  const trustedNow = new Date("2030-01-01T00:00:00.000Z");
  const clock = () => new Date(trustedNow.getTime());
  const reservationRequest = reservation({
    reservation_ref: "reservation:lifecycle-index-boundary",
    byte_ceiling: 8,
    expires_at: new Date(trustedNow.getTime() + 60_000).toISOString(),
  });

  const indexBaseline = makeVault(t, { now: clock });
  indexBaseline.vault.reserve(reservationRequest);
  const indexCeiling = fs.statSync(path.join(indexBaseline.root, "index.json")).size;

  const indexExact = makeVault(t, { now: clock, indexEncodedBytesCeiling: indexCeiling });
  indexExact.vault.reserve(reservationRequest);
  assert.equal(fs.statSync(path.join(indexExact.root, "index.json")).size, indexCeiling);
  assert.equal(indexExact.vault.usage().active_reservations, 1);

  const indexBelow = makeVault(t, { now: clock, indexEncodedBytesCeiling: indexCeiling - 1 });
  const indexBefore = fs.readFileSync(path.join(indexBelow.root, "index.json"));
  const indexAnchorBefore = indexBelow.indexStateAnchor.peekStates();
  assert.throws(
    () => indexBelow.vault.reserve(reservationRequest),
    /index mutation exceeds its configured read ceiling/,
  );
  assert.deepEqual(fs.readFileSync(path.join(indexBelow.root, "index.json")), indexBefore);
  assert.deepEqual(indexBelow.indexStateAnchor.peekStates(), indexAnchorBefore);
  assert.deepEqual(fs.readdirSync(path.join(indexBelow.root, "objects")), []);

  const ingestOverrides = {
    retention_expires_at: new Date(trustedNow.getTime() + 120_000).toISOString(),
  };
  const reserveOverrides = {
    reservation_ref: "reservation:lifecycle-deletion-boundary",
    expires_at: new Date(trustedNow.getTime() + 60_000).toISOString(),
  };
  const deletionBaseline = makeVault(t, { now: clock });
  const baselineArtifact = ingest(
    deletionBaseline.vault,
    "boundary",
    ingestOverrides,
    reserveOverrides,
  );
  deletionBaseline.vault.erase(baselineArtifact.artifact_handle, "retention:boundary");
  const deletionCeiling = fs.statSync(
    path.join(deletionBaseline.root, "deletion-ledger.json"),
  ).size;

  const deletionExact = makeVault(t, {
    now: clock,
    deletionLedgerEncodedBytesCeiling: deletionCeiling,
  });
  const exactArtifact = ingest(deletionExact.vault, "boundary", ingestOverrides, reserveOverrides);
  deletionExact.vault.erase(exactArtifact.artifact_handle, "retention:boundary");
  assert.equal(
    fs.statSync(path.join(deletionExact.root, "deletion-ledger.json")).size,
    deletionCeiling,
  );
  assert.throws(() => deletionExact.vault.inspect(exactArtifact.artifact_handle), /erased/);

  const deletionBelow = makeVault(t, {
    now: clock,
    deletionLedgerEncodedBytesCeiling: deletionCeiling - 1,
  });
  const retainedArtifact = ingest(deletionBelow.vault, "boundary", ingestOverrides, reserveOverrides);
  const ledgerPath = path.join(deletionBelow.root, "deletion-ledger.json");
  const ledgerBefore = fs.readFileSync(ledgerPath);
  const deletionAnchorBefore = deletionBelow.deletionLedgerAnchor.peekStates();
  assert.throws(
    () => deletionBelow.vault.erase(retainedArtifact.artifact_handle, "retention:boundary"),
    /deletion ledger lacks reserved capacity for exact external retirement evidence/,
  );
  assert.equal(deletionBelow.backupKeyCustodyFixture.metrics.retire_effects, 0);
  assert.equal(
    deletionBelow.backupKeyCustodyFixture.retirements.has(retainedArtifact.artifact_handle),
    false,
  );
  assert.deepEqual(fs.readFileSync(ledgerPath), ledgerBefore);
  assert.deepEqual(deletionBelow.deletionLedgerAnchor.peekStates(), deletionAnchorBefore);
  assert.equal(deletionBelow.vault.inspect(retainedArtifact.artifact_handle).byte_length, 8);
  assert.equal(fs.readdirSync(path.join(deletionBelow.root, "objects")).length, 1);
});

test("an existing vault never regenerates or rolls back deletion state or its authenticated index", (t) => {
  const {
    backupRoot,
    backupKeyCustody,
    deletionLedgerAnchor,
    indexStateAnchor,
    reopenKey,
    root,
    vaultId,
    vaultSlot,
    vault,
  } = makeVault(t);
  const descriptor = ingest(vault, "must-not-resurrect");
  const backupPath = path.join(backupRoot, "pre-erasure.json");
  const backupDescriptor = openBackupFile(t, backupPath);
  const backup = vault.createBackup(backupDescriptor);
  const genesisLedger = fs.readFileSync(path.join(root, "deletion-ledger.json"));
  vault.erase(descriptor.artifact_handle, "retention:test");
  fs.writeFileSync(path.join(root, "deletion-ledger.json"), genesisLedger, { mode: 0o600 });
  assert.throws(() => vault.restoreBackup(backupDescriptor, {
    expected_backup_ref: backup.backup_ref,
  }), /revoked|rolled back|conflicts with its external anchor/);
  vault.destroy();
  fs.unlinkSync(path.join(root, "deletion-ledger.json"));
  assert.throws(() => createArtifactVault({
    root,
    sessionNucleusHash: SESSION_HASH,
    vaultId,
    vaultSlot,
    masterKey: reopenKey,
    backupKeyCustody,
    deletionLedgerAnchor,
    indexStateAnchor,
    minFreeBytes: 0,
  }), /missing its deletion ledger/);
  reopenKey.fill(0);

  const second = makeVault(t);
  const secondDescriptor = ingest(second.vault, "index-must-not-regenerate");
  second.vault.destroy();
  fs.unlinkSync(path.join(second.root, "index.json"));
  const reopened = createArtifactVault({
    root: second.root,
    sessionNucleusHash: SESSION_HASH,
    vaultId: second.vaultId,
    vaultSlot: second.vaultSlot,
    masterKey: second.reopenKey,
    backupKeyCustody: second.backupKeyCustody,
    deletionLedgerAnchor: second.deletionLedgerAnchor,
    indexStateAnchor: second.indexStateAnchor,
    minFreeBytes: 0,
  });
  t.after(() => reopened.destroy());
  assert.equal(
    reopened.inspect(secondDescriptor.artifact_handle).byte_length,
    "index-must-not-regenerate".length,
  );
  assert.equal(fs.existsSync(path.join(second.root, "index.json")), true);
  second.reopenKey.fill(0);
});

test("an externally enrolled vault slot rejects local identity drift and full-root re-enrollment", (t) => {
  const setup = makeVault(t);
  const descriptor = ingest(setup.vault, "externally-anchored-state");
  assert.equal(setup.vault.inspect(descriptor.artifact_handle).byte_length, 25);
  const anchoredBeforeWipe = setup.indexStateAnchor.peekStates();
  assert.equal(anchoredBeforeWipe.length, 1);
  assert.ok(anchoredBeforeWipe[0].generation > 0);

  setup.vault.destroy();
  const metadataPath = path.join(setup.root, "vault.json");
  const metadata = fs.readFileSync(metadataPath, "utf8");
  const driftedMetadata = JSON.parse(metadata);
  driftedMetadata.vault_slot = `vault-slot:v1:${crypto.randomBytes(32).toString("base64url")}`;
  fs.writeFileSync(metadataPath, `${JSON.stringify(driftedMetadata)}\n`, { mode: 0o600 });
  assert.throws(() => createArtifactVault({
    root: setup.root,
    sessionNucleusHash: SESSION_HASH,
    vaultId: setup.vaultId,
    vaultSlot: setup.vaultSlot,
    masterKey: setup.reopenKey,
    backupKeyCustody: setup.backupKeyCustody,
    deletionLedgerAnchor: setup.deletionLedgerAnchor,
    indexStateAnchor: setup.indexStateAnchor,
    minFreeBytes: 0,
  }), /does not match the externally enrolled vault identity and slot/);
  fs.writeFileSync(metadataPath, metadata, { mode: 0o600 });

  fs.rmSync(setup.root, { recursive: true, force: true });
  const erasedRootOptions = {
    root: setup.root,
    sessionNucleusHash: SESSION_HASH,
    vaultId: setup.vaultId,
    vaultSlot: setup.vaultSlot,
    masterKey: setup.reopenKey,
    backupKeyCustody: setup.backupKeyCustody,
    deletionLedgerAnchor: setup.deletionLedgerAnchor,
    indexStateAnchor: setup.indexStateAnchor,
    minFreeBytes: 0,
  };
  assert.throws(
    () => createArtifactVault(erasedRootOptions),
    /vault root is absent; explicit createNew enrollment is required/,
  );
  assert.throws(
    () => createArtifactVault({ ...erasedRootOptions, createNew: true }),
    /vault slot is already externally enrolled/,
  );
  assert.throws(() => createArtifactVault({
    ...erasedRootOptions,
    vaultId: `vault:v1:${crypto.randomBytes(32).toString("base64url")}`,
    createNew: true,
  }), /belongs to another vault|vault slot is already externally enrolled/);
  assert.deepEqual(setup.indexStateAnchor.peekStates(), anchoredBeforeWipe);
  assert.equal(fs.existsSync(path.join(setup.root, "vault.json")), false);
});

test("external backup-key custody is a closed operator-only non-production capability", (t) => {
  const setup = makeVault(t);
  const mainSurface = require("../packages/bob-artifact-vault/index.js");
  const workerSurface = require("../packages/bob-artifact-vault/worker.js");
  const operatorSurface = require("../packages/bob-artifact-vault/operator.js");
  assert.equal(mainSurface.createOperatorBackupKeyCustodyPort, undefined);
  assert.equal(workerSurface.createOperatorBackupKeyCustodyPort, undefined);
  assert.equal(typeof operatorSurface.createOperatorBackupKeyCustodyPort, "function");
  assert.equal(Object.isFrozen(setup.backupKeyCustody), true);
  assert.deepEqual(Object.keys(setup.backupKeyCustody).sort(), [
    "backup_media_erasure_attested",
    "custody_binding_digest",
    "custody_epoch",
    "custody_id",
    "hil_verified",
    "production_ready",
    "revocation_policy",
    "session_nucleus_hash",
    "vault_id",
    "vault_slot",
    "version",
  ]);
  assert.equal(setup.backupKeyCustody.production_ready, false);
  assert.equal(setup.backupKeyCustody.hil_verified, false);
  assert.equal(setup.backupKeyCustody.backup_media_erasure_attested, false);
  assert.equal(setup.backupKeyCustody.revocation_policy, REVOCATION_POLICY);
  assert.equal(
    Object.keys(setup.backupKeyCustody).some((field) => /^(?:raw|master|archive)_key/u.test(field)),
    false,
  );
  for (const forbidden of [
    "seal_archive",
    "open_archive",
    "acquire_restore_fence",
    "read_restore_fence",
    "release_restore_fence",
    "retire_artifact",
    "read_archive_state",
    "read_artifact_retirement",
    "resolve_current_custody",
  ]) assert.equal(setup.backupKeyCustody[forbidden], undefined);

  const reopenKey = Buffer.from(setup.reopenKey);
  t.after(() => reopenKey.fill(0));
  const base = {
    root: setup.root,
    sessionNucleusHash: SESSION_HASH,
    vaultId: setup.vaultId,
    vaultSlot: setup.vaultSlot,
    masterKey: reopenKey,
    deletionLedgerAnchor: setup.deletionLedgerAnchor,
    indexStateAnchor: setup.indexStateAnchor,
    minFreeBytes: 0,
  };
  assert.throws(
    () => createArtifactVault({ ...base, backupKeyCustody: { ...setup.backupKeyCustody } }),
    /private branded operator-only custody port/,
  );
  assert.throws(
    () => createArtifactVault({
      ...base,
      backupKeyCustody: new Proxy(setup.backupKeyCustody, {}),
    }),
    /private branded operator-only custody port/,
  );
  assert.throws(
    () => createArtifactVault({
      ...base,
      root: path.join(setup.parent, "cross-vault"),
      vaultId: `vault:v1:${crypto.randomBytes(32).toString("base64url")}`,
      backupKeyCustody: setup.backupKeyCustody,
      createNew: true,
    }),
    /belongs to another vault/,
  );
});

test("custody resolver drift, Promise, thenable, and Proxy results fail before archive effects", (t) => {
  const setup = makeVault(t);
  ingest(setup.vault, "custody-resolver-sentinel");
  const createDestination = (label) => openBackupFile(
    t,
    path.join(setup.backupRoot, `${label}.json`),
  );

  setup.backupKeyCustodyFixture.control.custody_epoch = 2;
  assert.throws(
    () => setup.vault.createBackup(createDestination("stale-epoch")),
    /custody_epoch drifted/,
  );
  setup.backupKeyCustodyFixture.control.custody_epoch = 1;

  setup.backupKeyCustodyFixture.control.resolve_hook = (state) => Promise.resolve(state);
  assert.throws(
    () => setup.vault.createBackup(createDestination("promise-current")),
    /synchronously without a Proxy, Promise, or thenable/,
  );
  setup.backupKeyCustodyFixture.control.resolve_hook = () => ({ then() {} });
  assert.throws(
    () => setup.vault.createBackup(createDestination("thenable-current")),
    /synchronously without a Proxy, Promise, or thenable/,
  );
  const priorThen = Object.getOwnPropertyDescriptor(Object.prototype, "then");
  Object.defineProperty(Object.prototype, "then", {
    configurable: true,
    value() {},
  });
  try {
    setup.backupKeyCustodyFixture.control.resolve_hook = (state) => state;
    assert.throws(
      () => setup.vault.createBackup(createDestination("inherited-thenable-current")),
      /synchronously without a Proxy, Promise, or thenable/,
    );
  } finally {
    if (priorThen) Object.defineProperty(Object.prototype, "then", priorThen);
    else delete Object.prototype.then;
  }
  setup.backupKeyCustodyFixture.control.resolve_hook = (state) => new Proxy(state, {});
  assert.throws(
    () => setup.vault.createBackup(createDestination("proxy-current")),
    /synchronously without a Proxy, Promise, or thenable/,
  );
  setup.backupKeyCustodyFixture.control.resolve_hook = null;
  assert.equal(setup.backupKeyCustodyFixture.metrics.seal_effects, 0);
});

test("external archive sealing reconciles a lost acknowledgement without exposing or repeating keys", (t) => {
  const setup = makeVault(t);
  ingest(setup.vault, "external-custody-confidentiality-sentinel", {
    source_ref: "provider:external-custody-sentinel",
  });
  setup.backupKeyCustodyFixture.control.seal_lost_ack_once = true;
  const backupPath = path.join(setup.backupRoot, "lost-seal-ack.json");
  const descriptor = openBackupFile(t, backupPath);
  const receipt = setup.vault.createBackup(descriptor);
  assert.equal(setup.backupKeyCustodyFixture.metrics.seal_effects, 1);
  assert.equal(receipt.external_backup_key_state, "active");
  assert.equal(receipt.production_ready, false);
  assert.equal(receipt.hil_verified, false);
  assert.equal(setup.vault.verifyBackup(descriptor).verified, true);

  const serialized = fs.readFileSync(backupPath, "utf8");
  assert.doesNotMatch(
    serialized,
    /external-custody-confidentiality-sentinel|external-custody-sentinel|wrapped_data_key|master_key|archive_key|raw_key/,
  );
  const archive = JSON.parse(serialized);
  assert.deepEqual(Object.keys(archive).sort(), ["external_custody_envelope", "version"]);
  assert.deepEqual(Object.keys(archive.external_custody_envelope).sort(), [
    "artifact_inventory_digest",
    "backup_digest",
    "backup_ref",
    "custody_epoch",
    "custody_format",
    "custody_id",
    "revocation_effect_ref",
    "revoked_at",
    "seal_effect_ref",
    "seal_ref",
    "sealed_archive",
    "sealed_archive_digest",
    "session_nucleus_hash",
    "status",
    "vault_id",
    "vault_slot",
    "version",
  ]);
});

test("durable seal intent survives lost acknowledgement, readback outage, and process restart", (t) => {
  const setup = makeVault(t);
  ingest(setup.vault, "durable-seal-restart");
  const backupPath = path.join(setup.backupRoot, "durable-seal-restart.json");
  const descriptor = openBackupFile(t, backupPath);
  setup.backupKeyCustodyFixture.control.seal_lost_ack_once = true;
  setup.backupKeyCustodyFixture.control.read_archive_hook = (output) => {
    if (output) throw new Error("injected post-seal readback outage");
    return output;
  };
  assert.throws(
    () => setup.vault.createBackup(descriptor),
    /archive-state readback is unavailable/,
  );
  assert.equal(setup.backupKeyCustodyFixture.metrics.seal_effects, 1);
  const sealedBackupRef = [...setup.backupKeyCustodyFixture.archives.keys()][0];
  const preparedIndex = JSON.parse(fs.readFileSync(path.join(setup.root, "index.json"), "utf8"));
  assert.equal(
    preparedIndex.payload.backup_custody.archives[sealedBackupRef].state,
    "prepared",
  );
  assert.equal(fs.readdirSync(path.join(setup.root, "backup-intents")).length, 1);

  setup.vault.destroy();
  setup.backupKeyCustodyFixture.control.read_archive_hook = null;
  const reopened = reopenVault(t, setup);
  const receipt = reopened.createBackup(descriptor);
  assert.equal(receipt.backup_ref, sealedBackupRef);
  assert.equal(setup.backupKeyCustodyFixture.metrics.seal_effects, 1);
  assert.equal(reopened.verifyBackup(descriptor).verified, true);
  assert.deepEqual(fs.readdirSync(path.join(setup.root, "backup-intents")), []);
});

test("post-seal publication failure retries the same envelope without resealing", (t) => {
  const setup = makeVault(t);
  ingest(setup.vault, "publication-retry");
  const descriptor = openBackupFile(
    t,
    path.join(setup.backupRoot, "publication-retry.json"),
  );
  const originalWrite = fs.writeSync;
  let failed = false;
  fs.writeSync = function failFirstPublication(fd) {
    if (!failed && fd === descriptor) {
      failed = true;
      throw new Error("injected publication failure");
    }
    return originalWrite.apply(this, arguments);
  };
  try {
    assert.throws(() => setup.vault.createBackup(descriptor), /injected publication failure/);
  } finally {
    fs.writeSync = originalWrite;
  }
  assert.equal(failed, true);
  assert.equal(setup.backupKeyCustodyFixture.metrics.seal_effects, 1);
  assert.equal(fs.fstatSync(descriptor).size, 0);
  const sealedIndex = JSON.parse(
    fs.readFileSync(path.join(setup.root, "index.json"), "utf8"),
  ).payload;
  const sealedIntent = Object.values(sealedIndex.backup_custody.archives)[0];
  assert.equal(sealedIntent.state, "sealed");
  assert.equal(sealedIntent.payload_file_digest, null);
  assert.deepEqual(fs.readdirSync(path.join(setup.root, "backup-intents")), []);
  const receipt = setup.vault.createBackup(descriptor);
  assert.equal(setup.backupKeyCustodyFixture.metrics.seal_effects, 1);
  assert.equal(setup.vault.verifyBackup(descriptor).backup_ref, receipt.backup_ref);
});

test("a lost prepared payload reconciles its durable seal and rebinds a replacement destination", (t) => {
  const setup = makeVault(t);
  ingest(setup.vault, "prepared-payload-loss-recovery");
  const originalPath = path.join(setup.backupRoot, "lost-prepared-destination.json");
  const originalDescriptor = openBackupFile(t, originalPath);
  setup.backupKeyCustodyFixture.control.seal_lost_ack_once = true;
  setup.backupKeyCustodyFixture.control.read_archive_hook = (output) => {
    if (output) throw new Error("injected post-seal readback outage");
    return output;
  };
  assert.throws(
    () => setup.vault.createBackup(originalDescriptor),
    /archive-state readback is unavailable/,
  );
  const backupRef = [...setup.backupKeyCustodyFixture.archives.keys()][0];
  const prepared = JSON.parse(
    fs.readFileSync(path.join(setup.root, "index.json"), "utf8"),
  ).payload.backup_custody.archives[backupRef];
  assert.equal(prepared.state, "prepared");
  const stagedPayload = fs.readdirSync(path.join(setup.root, "backup-intents"));
  assert.equal(stagedPayload.length, 1);
  fs.unlinkSync(path.join(setup.root, "backup-intents", stagedPayload[0]));
  fs.closeSync(originalDescriptor);
  fs.unlinkSync(originalPath);

  setup.backupKeyCustodyFixture.control.read_archive_hook = null;
  setup.vault.destroy();
  const reopened = reopenVault(t, setup);
  const reconciled = JSON.parse(
    fs.readFileSync(path.join(setup.root, "index.json"), "utf8"),
  ).payload.backup_custody.archives[backupRef];
  assert.equal(reconciled.state, "sealed");
  assert.equal(reconciled.payload_file_digest, null);
  assert.deepEqual(fs.readdirSync(path.join(setup.root, "backup-intents")), []);

  const replacementDescriptor = openBackupFile(
    t,
    path.join(setup.backupRoot, "replacement-destination.json"),
  );
  const receipt = reopened.createBackup(replacementDescriptor);
  assert.equal(receipt.backup_ref, backupRef);
  assert.equal(setup.backupKeyCustodyFixture.metrics.seal_effects, 1);
  assert.equal(reopened.verifyBackup(replacementDescriptor).backup_ref, backupRef);
});

test("a definitively uncommitted or crash-orphaned backup payload is removed before sealing", (t) => {
  const setup = makeVault(t);
  ingest(setup.vault, "unrooted-backup-intent");
  const descriptor = openBackupFile(t, path.join(setup.backupRoot, "unrooted-intent.json"));
  setup.indexStateAnchor.rejectNextCommit();
  assert.throws(
    () => setup.vault.createBackup(descriptor),
    /index state anchor compare-and-set failed/,
  );
  assert.equal(setup.backupKeyCustodyFixture.metrics.seal_effects, 0);
  assert.deepEqual(fs.readdirSync(path.join(setup.root, "backup-intents")), []);
  const index = JSON.parse(fs.readFileSync(path.join(setup.root, "index.json"), "utf8")).payload;
  assert.deepEqual(index.backup_custody.archives, {});

  fs.writeFileSync(
    path.join(setup.root, "backup-intents", "crash-orphan.json"),
    "opaque-encrypted-orphan",
    { mode: 0o600 },
  );
  setup.vault.destroy();
  const reopened = reopenVault(t, setup);
  assert.deepEqual(fs.readdirSync(path.join(setup.root, "backup-intents")), []);
  assert.equal(reopened.inspect(Object.keys(index.records)[0]).byte_length, 22);
});

test("startup reconciliation cannot delete another process's staged backup payload", (t) => {
  const setup = makeVault(t);
  ingest(setup.vault, "cross-process-staged-backup");
  const descriptor = openBackupFile(
    t,
    path.join(setup.backupRoot, "cross-process-staged-backup.json"),
  );
  let sawStagedPayload = false;
  setup.indexStateAnchor.runBeforeNextCommit(() => {
    const contenderKey = Buffer.from(setup.reopenKey);
    let contender = null;
    try {
      contender = createArtifactVault({
        root: setup.root,
        sessionNucleusHash: SESSION_HASH,
        vaultId: setup.vaultId,
        vaultSlot: setup.vaultSlot,
        masterKey: contenderKey,
        backupKeyCustody: setup.backupKeyCustody,
        deletionLedgerAnchor: setup.deletionLedgerAnchor,
        indexStateAnchor: setup.indexStateAnchor,
        minFreeBytes: 0,
      });
      assert.throws(() => contender.usage(), /vault is locked/);
    } finally {
      if (contender) contender.destroy();
      contenderKey.fill(0);
    }
    const stagedPayloads = fs.readdirSync(path.join(setup.root, "backup-intents"));
    assert.equal(stagedPayloads.length, 1);
    sawStagedPayload = true;
  });

  const receipt = setup.vault.createBackup(descriptor);
  assert.equal(sawStagedPayload, true);
  assert.equal(setup.backupKeyCustodyFixture.metrics.seal_effects, 1);
  assert.equal(setup.vault.verifyBackup(descriptor).backup_ref, receipt.backup_ref);
  assert.deepEqual(fs.readdirSync(path.join(setup.root, "backup-intents")), []);
});

test("erasure reconciles an externally sealed prepared intent before member retirement", (t) => {
  const setup = makeVault(t);
  const artifact = ingest(setup.vault, "erase-prepared-external-seal");
  const descriptor = openBackupFile(
    t,
    path.join(setup.backupRoot, "erase-prepared-external-seal.json"),
  );
  setup.backupKeyCustodyFixture.control.seal_lost_ack_once = true;
  setup.backupKeyCustodyFixture.control.read_archive_hook = (output) => {
    if (output) throw new Error("injected post-seal readback outage");
    return output;
  };
  assert.throws(
    () => setup.vault.createBackup(descriptor),
    /archive-state readback is unavailable/,
  );
  assert.equal(setup.backupKeyCustodyFixture.metrics.seal_effects, 1);
  setup.backupKeyCustodyFixture.control.read_archive_hook = null;

  const receipt = setup.vault.erase(artifact.artifact_handle, "retention:prepared-seal");
  assert.equal(receipt.external_backup_key_revocation.revoked_archive_count, 1);
  assert.equal(setup.backupKeyCustodyFixture.metrics.retire_effects, 1);
  assert.deepEqual(fs.readdirSync(path.join(setup.root, "backup-intents")), []);
  const index = JSON.parse(fs.readFileSync(path.join(setup.root, "index.json"), "utf8")).payload;
  const archive = Object.values(index.backup_custody.archives)[0];
  assert.equal(archive.state, "revoked");
  assert.equal(archive.payload_file_digest, null);
  assert.throws(() => setup.vault.inspect(artifact.artifact_handle), /erased/);
});

test("whole-archive revocation is monotonic, response-loss safe, and blocks old media", (t) => {
  const setup = makeVault(t);
  const erased = ingest(setup.vault, "erase-across-backups");
  const firstPath = path.join(setup.backupRoot, "member-one.json");
  const firstDescriptor = openBackupFile(t, firstPath);
  setup.vault.createBackup(firstDescriptor);
  const retained = ingest(setup.vault, "retain-after-erasure");
  const secondPath = path.join(setup.backupRoot, "member-two.json");
  const secondDescriptor = openBackupFile(t, secondPath);
  setup.vault.createBackup(secondDescriptor);

  setup.backupKeyCustodyFixture.control.retire_lost_ack_once = true;
  const receipt = setup.vault.erase(erased.artifact_handle, "retention:whole-archive");
  assert.equal(setup.backupKeyCustodyFixture.metrics.retire_effects, 1);
  assert.equal(receipt.external_backup_key_revocation.revoked_archive_count, 2);
  assert.equal(receipt.external_backup_key_revocation.revocation_policy, REVOCATION_POLICY);
  assert.deepEqual(receipt.backup_media_erasure, {
    status: "not_attested",
    physically_destroyed: false,
  });
  assert.equal(fs.existsSync(firstPath), true);
  assert.equal(fs.existsSync(secondPath), true);
  assert.throws(() => setup.vault.verifyBackup(firstDescriptor), /external backup key is revoked/);
  assert.throws(() => setup.vault.verifyBackup(secondDescriptor), /external backup key is revoked/);

  const retry = setup.vault.erase(erased.artifact_handle, "retention:whole-archive");
  assert.equal(retry.deletion_receipt, receipt.deletion_receipt);
  assert.equal(setup.backupKeyCustodyFixture.metrics.retire_effects, 1);

  const postPath = path.join(setup.backupRoot, "post-retirement.json");
  const postDescriptor = openBackupFile(t, postPath);
  const post = setup.vault.createBackup(postDescriptor);
  assert.equal(post.artifact_count, 1);
  assert.equal(setup.vault.verifyBackup(postDescriptor).verified, true);
  assert.equal(setup.vault.inspect(retained.artifact_handle).byte_length, 20);
});

test("retirement rejects an externally omitted member against the anchored archive registry", (t) => {
  const setup = makeVault(t);
  const artifact = ingest(setup.vault, "registry-completeness");
  for (const label of ["registry-one", "registry-two"]) {
    setup.vault.createBackup(openBackupFile(
      t,
      path.join(setup.backupRoot, `${label}.json`),
    ));
  }
  let completeRetirement = null;
  setup.backupKeyCustodyFixture.control.retire_hook = (output, request) => {
    completeRetirement = cloneJson(output);
    const forged = {
      ...cloneJson(output),
      revoked_archives: output.revoked_archives.slice(0, 1),
    };
    forged.revoked_archives_digest = digest(canonicalJson(forged.revoked_archives));
    forged.retirement_receipt = "e".repeat(64);
    setup.backupKeyCustodyFixture.retirements.set(request.artifact_handle, cloneJson(forged));
    return forged;
  };
  const ledgerPath = path.join(setup.root, "deletion-ledger.json");
  const ledgerBefore = fs.readFileSync(ledgerPath);
  assert.throws(
    () => setup.vault.erase(artifact.artifact_handle, "retention:registry-completeness"),
    /does not cover the exact member archive registry/,
  );
  assert.deepEqual(fs.readFileSync(ledgerPath), ledgerBefore);
  assert.equal(setup.backupKeyCustodyFixture.metrics.retire_effects, 1);
  assert.throws(
    () => setup.vault.inspect(artifact.artifact_handle),
    /pending cryptographic-erasure intent/,
  );

  setup.backupKeyCustodyFixture.retirements.set(
    artifact.artifact_handle,
    completeRetirement,
  );
  setup.backupKeyCustodyFixture.control.retire_hook = null;
  const receipt = setup.vault.erase(
    artifact.artifact_handle,
    "retention:registry-completeness",
  );
  assert.equal(receipt.external_backup_key_revocation.revoked_archive_count, 2);
  assert.equal(setup.backupKeyCustodyFixture.metrics.retire_effects, 1);
});

test("per-artifact archive admission is bounded before a sixty-fifth seal effect", (t) => {
  const setup = makeVault(t);
  ingest(setup.vault, "bounded-member-registry");
  for (let index = 0; index < MAX_MEMBER_ARCHIVES_PER_ARTIFACT; index += 1) {
    setup.vault.createBackup(openBackupFile(
      t,
      path.join(setup.backupRoot, `bounded-${index}.json`),
    ));
  }
  assert.equal(
    setup.backupKeyCustodyFixture.metrics.seal_effects,
    MAX_MEMBER_ARCHIVES_PER_ARTIFACT,
  );
  const overflow = openBackupFile(t, path.join(setup.backupRoot, "bounded-overflow.json"));
  assert.throws(
    () => setup.vault.createBackup(overflow),
    /bounded backup membership registry/,
  );
  assert.equal(fs.fstatSync(overflow).size, 0);
  assert.equal(
    setup.backupKeyCustodyFixture.metrics.seal_effects,
    MAX_MEMBER_ARCHIVES_PER_ARTIFACT,
  );
});

test("external retirement or archive-state rollback invalidates the deletion ledger read", (t) => {
  const setup = makeVault(t);
  const artifact = ingest(setup.vault, "external-rollback");
  const backupDescriptor = openBackupFile(t, path.join(setup.backupRoot, "rollback.json"));
  const backup = setup.vault.createBackup(backupDescriptor);
  setup.vault.erase(artifact.artifact_handle, "retention:rollback");

  const retirement = setup.backupKeyCustodyFixture.retirements.get(artifact.artifact_handle);
  setup.backupKeyCustodyFixture.retirements.delete(artifact.artifact_handle);
  assert.throws(
    () => setup.vault.erase(artifact.artifact_handle, "retention:rollback"),
    /retirement state failed exact durable readback/,
  );
  setup.backupKeyCustodyFixture.retirements.set(artifact.artifact_handle, retirement);

  const archive = setup.backupKeyCustodyFixture.archives.get(backup.backup_ref);
  const revokedState = cloneJson(archive.state);
  archive.state = {
    ...archive.state,
    status: "active",
    revocation_effect_ref: null,
    revoked_at: null,
  };
  assert.throws(
    () => setup.vault.erase(artifact.artifact_handle, "retention:rollback"),
    /archive-key revocation failed exact readback/,
  );
  archive.state = revokedState;
  assert.match(
    setup.vault.erase(artifact.artifact_handle, "retention:rollback").deletion_receipt,
    /^[a-f0-9]{64}$/,
  );
});

test("ambiguous retirement readback fails before the deletion ledger and later reconciles once", (t) => {
  const setup = makeVault(t);
  const artifact = ingest(setup.vault, "retirement-readback");
  const backupDescriptor = openBackupFile(t, path.join(setup.backupRoot, "readback.json"));
  setup.vault.createBackup(backupDescriptor);
  setup.backupKeyCustodyFixture.control.retire_lost_ack_once = true;
  let retirementReads = 0;
  setup.backupKeyCustodyFixture.control.read_retirement_hook = (output) => {
    if (!output) return output;
    retirementReads += 1;
    if (retirementReads === 1) return { ...output, retirement_receipt: "0".repeat(64) };
    return output;
  };
  const ledgerPath = path.join(setup.root, "deletion-ledger.json");
  const before = fs.readFileSync(ledgerPath);
  assert.throws(
    () => setup.vault.erase(artifact.artifact_handle, "retention:readback"),
    /failed exact durable readback/,
  );
  assert.deepEqual(fs.readFileSync(ledgerPath), before);
  assert.throws(
    () => setup.vault.inspect(artifact.artifact_handle),
    /pending cryptographic-erasure intent/,
  );
  assert.equal(setup.backupKeyCustodyFixture.metrics.retire_effects, 1);
  const originalRetirement = cloneJson(
    setup.backupKeyCustodyFixture.retirements.get(artifact.artifact_handle),
  );
  assert.throws(
    () => setup.vault.erase(artifact.artifact_handle, "retention:changed-reason"),
    /reason conflicts with its durable intent/,
  );
  assert.equal(setup.backupKeyCustodyFixture.metrics.retire_effects, 1);

  setup.backupKeyCustodyFixture.control.read_retirement_hook = null;
  const receipt = setup.vault.erase(artifact.artifact_handle, "retention:readback");
  assert.equal(receipt.external_backup_key_revocation.revoked_archive_count, 1);
  assert.equal(setup.backupKeyCustodyFixture.metrics.retire_effects, 1);
  const reconciledRetirement = setup.backupKeyCustodyFixture.retirements
    .get(artifact.artifact_handle);
  assert.equal(reconciledRetirement.retired_at, originalRetirement.retired_at);
  assert.equal(
    reconciledRetirement.retirement_effect_ref,
    originalRetirement.retirement_effect_ref,
  );
});

test("a committed deletion receipt reconciles failed index-intent cleanup exactly once", (t) => {
  const setup = makeVault(t);
  const artifact = ingest(setup.vault, "deletion-cleanup-restart");
  setup.vault.createBackup(openBackupFile(
    t,
    path.join(setup.backupRoot, "deletion-cleanup-restart.json"),
  ));
  setup.backupKeyCustodyFixture.control.retire_hook = (output) => {
    setup.indexStateAnchor.rejectNextCommit();
    return output;
  };
  assert.throws(
    () => setup.vault.erase(artifact.artifact_handle, "retention:cleanup-restart"),
    /index state anchor compare-and-set failed/,
  );
  assert.equal(setup.backupKeyCustodyFixture.metrics.retire_effects, 1);
  const stranded = JSON.parse(fs.readFileSync(path.join(setup.root, "index.json"), "utf8"))
    .payload;
  assert.ok(stranded.records[artifact.artifact_handle]);
  assert.ok(stranded.backup_custody.deletion_intents[artifact.artifact_handle]);
  const ledger = JSON.parse(fs.readFileSync(
    path.join(setup.root, "deletion-ledger.json"),
    "utf8",
  )).payload;
  assert.ok(ledger.entries[artifact.artifact_handle]);

  setup.backupKeyCustodyFixture.control.retire_hook = null;
  const receipt = setup.vault.erase(artifact.artifact_handle, "retention:cleanup-restart");
  assert.equal(receipt.external_backup_key_revocation.revoked_archive_count, 1);
  assert.equal(setup.backupKeyCustodyFixture.metrics.retire_effects, 1);
  const reconciled = JSON.parse(fs.readFileSync(path.join(setup.root, "index.json"), "utf8"))
    .payload;
  assert.equal(reconciled.records[artifact.artifact_handle], undefined);
  assert.equal(reconciled.backup_custody.deletion_intents[artifact.artifact_handle], undefined);
  assert.equal(
    Object.values(reconciled.backup_custody.archives)[0].state,
    "revoked",
  );
});

test("cross-vault, tampered, Proxy, Promise, thenable, and revoked custody envelopes fail closed", (t) => {
  const setup = makeVault(t);
  ingest(setup.vault, "hostile-envelope");
  const backupPath = path.join(setup.backupRoot, "hostile.json");
  const descriptor = openBackupFile(t, backupPath);
  const receipt = setup.vault.createBackup(descriptor);

  const other = makeVault(t);
  assert.throws(() => other.vault.verifyBackup(descriptor), /belongs to another vault|binding mismatch/);

  setup.backupKeyCustodyFixture.control.read_archive_hook = (output) => (
    output ? new Proxy(output, {}) : output
  );
  assert.throws(
    () => setup.vault.verifyBackup(descriptor),
    /synchronously without a Proxy, Promise, or thenable/,
  );
  setup.backupKeyCustodyFixture.control.read_archive_hook = (output) => (
    output ? Promise.resolve(output) : output
  );
  assert.throws(
    () => setup.vault.verifyBackup(descriptor),
    /synchronously without a Proxy, Promise, or thenable/,
  );
  setup.backupKeyCustodyFixture.control.read_archive_hook = (output) => (
    output ? { then() {} } : output
  );
  assert.throws(
    () => setup.vault.verifyBackup(descriptor),
    /synchronously without a Proxy, Promise, or thenable/,
  );
  setup.backupKeyCustodyFixture.control.read_archive_hook = null;

  const archive = JSON.parse(fs.readFileSync(backupPath, "utf8"));
  archive.external_custody_envelope.backup_digest = "0".repeat(64);
  fs.writeFileSync(backupPath, canonicalJson(archive), { mode: 0o600 });
  assert.throws(() => setup.vault.verifyBackup(descriptor), /replayed, or tampered|binding mismatch/);

  // Restore the exact externally issued envelope only to demonstrate that its
  // later replay is denied after member-artifact retirement.
  const issued = cloneJson(setup.backupKeyCustodyFixture.archives.get(receipt.backup_ref).state);
  fs.ftruncateSync(descriptor, 0);
  const restoredArchive = Buffer.from(`${canonicalJson({
    version: 1,
    external_custody_envelope: issued,
  })}\n`);
  fs.writeSync(descriptor, restoredArchive, 0, restoredArchive.length, 0);
  setup.vault.erase(
    Object.keys(JSON.parse(fs.readFileSync(path.join(setup.root, "index.json"), "utf8")).payload.records)[0],
    "retention:replay",
  );
  assert.throws(() => setup.vault.verifyBackup(descriptor), /external backup key is revoked/);
});

test("every malformed open wrapper zeroizes its returned plaintext buffer", (t) => {
  const setup = makeVault(t);
  ingest(setup.vault, "open-zeroization");
  const descriptor = openBackupFile(t, path.join(setup.backupRoot, "open-zeroization.json"));
  setup.vault.createBackup(descriptor);

  let malformedPlaintext = null;
  setup.backupKeyCustodyFixture.control.open_hook = (output) => {
    malformedPlaintext = output.plaintext_archive;
    return { ...output, version: 2 };
  };
  assert.throws(() => setup.vault.verifyBackup(descriptor), /plaintext is invalid/);
  assert.ok(malformedPlaintext);
  assert.equal(malformedPlaintext.every((byte) => byte === 0), true);

  let functionPlaintext = null;
  setup.backupKeyCustodyFixture.control.open_hook = (output) => {
    functionPlaintext = output.plaintext_archive;
    const response = function malformedOpenResponse() {};
    Object.assign(response, output);
    return response;
  };
  assert.throws(
    () => setup.vault.verifyBackup(descriptor),
    /backup archive open response must be a non-Proxy object/,
  );
  assert.ok(functionPlaintext);
  assert.equal(functionPlaintext.every((byte) => byte === 0), true);
});

test("backup verification detects corruption before recovery", (t) => {
  const { backupRoot, root, vault } = makeVault(t);
  const descriptor = ingest(vault, "backup-me");
  assert.throws(() => vault.createBackup(path.join(root, "index.json")), /open file descriptor/);
  const linkedPath = path.join(backupRoot, "linked-empty.json");
  const linkedDescriptor = openBackupFile(t, linkedPath);
  fs.linkSync(linkedPath, path.join(backupRoot, "linked-alias.json"));
  assert.throws(() => vault.createBackup(linkedDescriptor), /single-link regular file/);
  const backupPath = path.join(backupRoot, "vault-backup.json");
  const backupDescriptor = openBackupFile(t, backupPath);
  const receipt = vault.createBackup(backupDescriptor);
  assert.match(receipt.backup_ref, /^backup:v1:[A-Za-z0-9_-]{43}$/);
  assert.equal(vault.verifyBackup(backupDescriptor).verified, true);
  vault.addReference(descriptor.artifact_handle, "evidence:live-reference");
  assert.throws(() => vault.restoreBackup(backupDescriptor, {
    expected_backup_ref: receipt.backup_ref,
    allow_replace: true,
  }), /live evidence references/);
  vault.removeReference(descriptor.artifact_handle, "evidence:live-reference");
  const backup = JSON.parse(fs.readFileSync(backupPath, "utf8"));
  backup.external_custody_envelope.sealed_archive = Buffer.from(
    "corrupt archive ciphertext",
  ).toString("base64");
  fs.writeFileSync(backupPath, JSON.stringify(backup));
  assert.throws(
    () => vault.verifyBackup(backupDescriptor),
    /does not match its digest|replayed, or tampered/,
  );
});

test("backup destination races expose only an outer-encrypted archive", (t) => {
  const { backupRoot, vault } = makeVault(t);
  ingest(vault, "backup-confidentiality-sentinel", {
    source_ref: "provider:backup-confidential-source",
  });

  const publicPath = path.join(backupRoot, "public-mode.json");
  const publicDescriptor = openBackupFile(t, publicPath);
  fs.chmodSync(publicPath, 0o644);
  assert.throws(
    () => vault.createBackup(publicDescriptor),
    /inaccessible to group or other users/,
  );

  const racedPath = path.join(backupRoot, "raced.json");
  const racedAlias = path.join(backupRoot, "raced-alias.json");
  const racedDescriptor = openBackupFile(t, racedPath);
  const originalWrite = fs.writeSync;
  let linked = false;
  fs.writeSync = function linkBeforeFirstBackupByte(descriptor) {
    if (!linked && descriptor === racedDescriptor) {
      fs.linkSync(racedPath, racedAlias);
      linked = true;
    }
    return originalWrite.apply(this, arguments);
  };
  try {
    assert.throws(() => vault.createBackup(racedDescriptor), /identity changed/);
  } finally {
    fs.writeSync = originalWrite;
  }
  assert.equal(linked, true);
  const leakedArchive = fs.readFileSync(racedAlias, "utf8");
  assert.doesNotMatch(
    leakedArchive,
    /backup-confidentiality-sentinel|backup-confidential-source|task-1|attempt-1|wrapped_data_key/,
  );
  assert.ok(JSON.parse(leakedArchive).external_custody_envelope);
});

test("backup verification decrypts nested blobs instead of trusting only the archive MAC", (t) => {
  const { backupRoot, root, vault } = makeVault(t);
  ingest(vault, "must-remain-recoverable");
  const blobPath = path.join(root, "objects", fs.readdirSync(path.join(root, "objects"))[0]);
  const envelope = JSON.parse(fs.readFileSync(blobPath, "utf8"));
  envelope.ciphertext = Buffer.from("corrupt nested ciphertext").toString("base64");
  fs.writeFileSync(blobPath, JSON.stringify(envelope), { mode: 0o600 });
  const backupPath = path.join(backupRoot, "corrupt-source-backup.json");
  const backupDescriptor = openBackupFile(t, backupPath);
  vault.createBackup(backupDescriptor);
  assert.throws(() => vault.verifyBackup(backupDescriptor), /authenticated decryption/);
});

test("authenticated recovery validates nested ciphertext and atomically selects a new generation", (t) => {
  const { backupRoot, root, vault } = makeVault(t);
  const retained = ingest(vault, "recover-me");
  const erased = ingest(vault, "do-not-resurrect");
  const preErasurePath = path.join(backupRoot, "recovery", "pre-erasure.json");
  const preErasureDescriptor = openBackupFile(t, preErasurePath);
  const preErasureBackup = vault.createBackup(preErasureDescriptor);
  const erasure = vault.erase(erased.artifact_handle, "recovery:prepare");
  assert.equal(erasure.external_backup_key_revocation.status, "completed");
  assert.equal(erasure.external_backup_key_revocation.revoked_archive_count, 1);
  assert.equal(erasure.backup_media_erasure.status, "not_attested");
  assert.throws(
    () => vault.verifyBackup(preErasureDescriptor),
    /external backup key is revoked/,
    "whole-archive key revocation prevents selective recovery from old media",
  );

  const backupPath = path.join(backupRoot, "recovery", "post-erasure.json");
  const backupDescriptor = openBackupFile(t, backupPath);
  const backup = vault.createBackup(backupDescriptor);
  assert.notEqual(backup.backup_ref, preErasureBackup.backup_ref);

  const retainedIndex = JSON.parse(fs.readFileSync(path.join(root, "index.json"), "utf8")).payload;
  fs.unlinkSync(path.join(
    root,
    retainedIndex.object_generation,
    `${retainedIndex.records[retained.artifact_handle].blob_id}.json`,
  ));

  // A post-erasure archive contains only retained artifacts. The revoked old
  // archive remains unusable even with its media and the vault master key.
  fs.writeFileSync(path.join(root, "index.json"), "{corrupt-index", { mode: 0o600 });
  const recovered = vault.restoreBackup(backupDescriptor, {
    expected_backup_ref: backup.backup_ref,
    allow_replace: true,
  });
  assert.equal(recovered.prior_index_corrupt, false);
  assert.equal(recovered.artifact_count, 1);
  assert.match(recovered.recovery_receipt, /^[a-f0-9]{64}$/);
  assert.equal(vault.inspect(retained.artifact_handle).byte_length, "recover-me".length);
  assert.throws(() => vault.inspect(erased.artifact_handle), /erased/);
  const activeGeneration = JSON.parse(fs.readFileSync(path.join(root, "index.json"), "utf8"))
    .payload.object_generation;
  assert.match(activeGeneration, /^objects-restore-/);
  const gc = vault.collectOrphanObjectGenerations();
  assert.equal(gc.active_generation, activeGeneration);
  assert.ok(gc.removed_generations.includes("objects"));
});

test("restore acquisition lost-ACK resumes after restart with the same durable fence identities", (t) => {
  const setup = makeVault(t);
  ingest(setup.vault, "restore-acquire-restart");
  const descriptor = openBackupFile(
    t,
    path.join(setup.backupRoot, "restore-acquire-restart.json"),
  );
  const backup = setup.vault.createBackup(descriptor);
  setup.backupKeyCustodyFixture.control.acquire_restore_lost_ack_once = true;
  setup.backupKeyCustodyFixture.control.acquire_restore_read_failures_after_effect = 1;
  assert.throws(
    () => setup.vault.restoreBackup(descriptor, {
      expected_backup_ref: backup.backup_ref,
      allow_replace: true,
    }),
    /restore-fence readback is unavailable/,
  );
  assert.equal(setup.backupKeyCustodyFixture.metrics.restore_acquire_effects, 1);
  const prepared = JSON.parse(fs.readFileSync(path.join(setup.root, "index.json"), "utf8"))
    .payload.backup_custody.restore_intents[backup.backup_ref];
  assert.equal(prepared.state, "prepared");
  assert.equal(setup.backupKeyCustodyFixture.restoreFences.get(prepared.restore_ref).status, "active");

  setup.vault.destroy();
  const reopened = reopenVault(t, setup);
  const receipt = reopened.restoreBackup(descriptor, {
    expected_backup_ref: backup.backup_ref,
    allow_replace: true,
  });
  assert.equal(receipt.backup_ref, backup.backup_ref);
  assert.equal(setup.backupKeyCustodyFixture.metrics.restore_acquire_effects, 1);
  assert.equal(setup.backupKeyCustodyFixture.metrics.restore_release_effects, 1);
  const terminal = JSON.parse(fs.readFileSync(path.join(setup.root, "index.json"), "utf8"))
    .payload.backup_custody.restore_intents[backup.backup_ref];
  assert.equal(terminal.state, "released");
  assert.equal(terminal.restore_ref, prepared.restore_ref);
  assert.equal(terminal.acquire_effect_ref, prepared.acquire_effect_ref);
  assert.equal(terminal.release_effect_ref, prepared.release_effect_ref);
  assert.equal(
    setup.backupKeyCustodyFixture.restoreFences.get(prepared.restore_ref).release_effect_ref,
    prepared.release_effect_ref,
  );
});

test("restore release lost-ACK resumes the committed receipt without a second generation", (t) => {
  const setup = makeVault(t);
  ingest(setup.vault, "restore-release-restart");
  const descriptor = openBackupFile(
    t,
    path.join(setup.backupRoot, "restore-release-restart.json"),
  );
  const backup = setup.vault.createBackup(descriptor);
  setup.backupKeyCustodyFixture.control.release_restore_lost_ack_once = true;
  setup.backupKeyCustodyFixture.control.release_restore_read_failures_after_effect = 1;
  assert.throws(
    () => setup.vault.restoreBackup(descriptor, {
      expected_backup_ref: backup.backup_ref,
      allow_replace: true,
    }),
    /restore-fence readback is unavailable/,
  );
  const committedIndex = JSON.parse(fs.readFileSync(path.join(setup.root, "index.json"), "utf8"))
    .payload;
  const committed = committedIndex.backup_custody.restore_intents[backup.backup_ref];
  assert.equal(committed.state, "committed");
  assert.equal(committedIndex.object_generation, committed.restored_generation);
  assert.equal(setup.backupKeyCustodyFixture.metrics.restore_acquire_effects, 1);
  assert.equal(setup.backupKeyCustodyFixture.metrics.restore_release_effects, 1);

  setup.vault.destroy();
  const reopened = reopenVault(t, setup);
  const receipt = reopened.restoreBackup(descriptor, {
    expected_backup_ref: backup.backup_ref,
    allow_replace: true,
  });
  assert.deepEqual(receipt, committed.receipt);
  assert.equal(setup.backupKeyCustodyFixture.metrics.restore_acquire_effects, 1);
  assert.equal(setup.backupKeyCustodyFixture.metrics.restore_release_effects, 1);
  const after = JSON.parse(fs.readFileSync(path.join(setup.root, "index.json"), "utf8")).payload;
  assert.equal(after.object_generation, committed.restored_generation);
  assert.equal(after.backup_custody.restore_intents[backup.backup_ref].state, "released");
  assert.equal(
    fs.readdirSync(setup.root).filter((entry) => entry.startsWith("objects-restore-")).length,
    1,
  );
  assert.deepEqual(reopened.restoreBackup(descriptor, {
    expected_backup_ref: backup.backup_ref,
    allow_replace: true,
  }), receipt);
  assert.equal(setup.backupKeyCustodyFixture.metrics.restore_acquire_effects, 1);
});

test("released restore idempotency expires after a later anchored vault mutation", (t) => {
  const setup = makeVault(t);
  const archived = ingest(setup.vault, "restore-generation-scope");
  const descriptor = openBackupFile(
    t,
    path.join(setup.backupRoot, "restore-generation-scope.json"),
  );
  const backup = setup.vault.createBackup(descriptor);
  const first = setup.vault.restoreBackup(descriptor, {
    expected_backup_ref: backup.backup_ref,
    allow_replace: true,
  });
  const firstTerminalIndex = JSON.parse(
    fs.readFileSync(path.join(setup.root, "index.json"), "utf8"),
  ).payload;
  const firstTerminal = firstTerminalIndex.backup_custody.restore_intents[backup.backup_ref];
  assert.equal(firstTerminal.state, "released");
  assert.equal(firstTerminal.completed_index_generation, firstTerminalIndex.generation);
  assert.deepEqual(setup.vault.restoreBackup(descriptor, {
    expected_backup_ref: backup.backup_ref,
    allow_replace: true,
  }), first);
  assert.equal(setup.backupKeyCustodyFixture.metrics.restore_acquire_effects, 1);
  assert.equal(setup.backupKeyCustodyFixture.metrics.restore_release_effects, 1);

  const postBackup = ingest(setup.vault, "state-created-after-backup");
  const mutatedGeneration = JSON.parse(
    fs.readFileSync(path.join(setup.root, "index.json"), "utf8"),
  ).payload.generation;
  assert.ok(mutatedGeneration > firstTerminal.completed_index_generation);

  const second = setup.vault.restoreBackup(descriptor, {
    expected_backup_ref: backup.backup_ref,
    allow_replace: true,
  });
  assert.notEqual(second.restored_generation, first.restored_generation);
  assert.equal(setup.backupKeyCustodyFixture.metrics.restore_acquire_effects, 2);
  assert.equal(setup.backupKeyCustodyFixture.metrics.restore_release_effects, 2);
  assert.equal(setup.vault.inspect(archived.artifact_handle).byte_length, 24);
  assert.throws(() => setup.vault.inspect(postBackup.artifact_handle), /absent, expired, or erased/);
  const secondTerminalIndex = JSON.parse(
    fs.readFileSync(path.join(setup.root, "index.json"), "utf8"),
  ).payload;
  const secondTerminal = secondTerminalIndex.backup_custody.restore_intents[backup.backup_ref];
  assert.equal(secondTerminal.completed_index_generation, secondTerminalIndex.generation);
  assert.notEqual(secondTerminal.restore_ref, firstTerminal.restore_ref);

  assert.deepEqual(setup.vault.restoreBackup(descriptor, {
    expected_backup_ref: backup.backup_ref,
    allow_replace: true,
  }), second);
  assert.equal(setup.backupKeyCustodyFixture.metrics.restore_acquire_effects, 2);
  assert.equal(setup.backupKeyCustodyFixture.metrics.restore_release_effects, 2);
});

test("released restore receipt does not mask physical loss in the current generation", (t) => {
  const setup = makeVault(t);
  const archived = ingest(setup.vault, "restore-after-physical-loss");
  const descriptor = openBackupFile(
    t,
    path.join(setup.backupRoot, "restore-after-physical-loss.json"),
  );
  const backup = setup.vault.createBackup(descriptor);
  const first = setup.vault.restoreBackup(descriptor, {
    expected_backup_ref: backup.backup_ref,
    allow_replace: true,
  });
  const damaged = JSON.parse(
    fs.readFileSync(path.join(setup.root, "index.json"), "utf8"),
  ).payload;
  fs.unlinkSync(path.join(
    setup.root,
    damaged.object_generation,
    `${damaged.records[archived.artifact_handle].blob_id}.json`,
  ));

  const second = setup.vault.restoreBackup(descriptor, {
    expected_backup_ref: backup.backup_ref,
    allow_replace: true,
  });
  assert.notEqual(second.restored_generation, first.restored_generation);
  assert.equal(setup.backupKeyCustodyFixture.metrics.restore_acquire_effects, 2);
  assert.equal(setup.backupKeyCustodyFixture.metrics.restore_release_effects, 2);
  assert.equal(setup.vault.inspect(archived.artifact_handle).byte_length, 27);
  assert.deepEqual(setup.vault.restoreBackup(descriptor, {
    expected_backup_ref: backup.backup_ref,
    allow_replace: true,
  }), second);
  assert.equal(setup.backupKeyCustodyFixture.metrics.restore_acquire_effects, 2);
  assert.equal(setup.backupKeyCustodyFixture.metrics.restore_release_effects, 2);
});

test("committed restore recovery does not terminalize a receipt over lost physical objects", (t) => {
  const setup = makeVault(t);
  const archived = ingest(setup.vault, "committed-restore-physical-loss");
  const descriptor = openBackupFile(
    t,
    path.join(setup.backupRoot, "committed-restore-physical-loss.json"),
  );
  const backup = setup.vault.createBackup(descriptor);
  setup.backupKeyCustodyFixture.control.release_restore_lost_ack_once = true;
  setup.backupKeyCustodyFixture.control.release_restore_read_failures_after_effect = 1;
  assert.throws(
    () => setup.vault.restoreBackup(descriptor, {
      expected_backup_ref: backup.backup_ref,
      allow_replace: true,
    }),
    /restore-fence readback is unavailable/,
  );
  const committedIndex = JSON.parse(
    fs.readFileSync(path.join(setup.root, "index.json"), "utf8"),
  ).payload;
  const committed = committedIndex.backup_custody.restore_intents[backup.backup_ref];
  assert.equal(committed.state, "committed");
  fs.unlinkSync(path.join(
    setup.root,
    committedIndex.object_generation,
    `${committedIndex.records[archived.artifact_handle].blob_id}.json`,
  ));

  setup.vault.destroy();
  const reopened = reopenVault(t, setup);
  const repaired = reopened.restoreBackup(descriptor, {
    expected_backup_ref: backup.backup_ref,
    allow_replace: true,
  });
  assert.notEqual(repaired.restored_generation, committed.restored_generation);
  assert.equal(setup.backupKeyCustodyFixture.metrics.restore_acquire_effects, 2);
  assert.equal(setup.backupKeyCustodyFixture.metrics.restore_release_effects, 2);
  assert.equal(reopened.inspect(archived.artifact_handle).byte_length, 31);
});

test("active restore fencing blocks all member retirement before mutation", (t) => {
  const setup = makeVault(t);
  const artifact = ingest(setup.vault, "restore-retirement-fence");
  const descriptors = ["fence-member-one", "fence-member-two"].map((label) => {
    const descriptor = openBackupFile(t, path.join(setup.backupRoot, `${label}.json`));
    setup.vault.createBackup(descriptor);
    return descriptor;
  });
  const memberRegistry = [...setup.backupKeyCustodyFixture.archives.values()]
    .map((record) => memberArchiveProjection(record.state))
    .sort((left, right) => left.backup_ref.localeCompare(right.backup_ref));
  let activeReads = 0;
  let retirementBlocked = false;
  setup.backupKeyCustodyFixture.control.read_restore_hook = (output) => {
    if (output && output.status === "active") {
      activeReads += 1;
      if (activeReads === 2) {
        assert.throws(
          () => retireArtifactBackupKeys(setup.backupKeyCustody, {
            artifact_handle: artifact.artifact_handle,
            reason_ref: "retention:during-restore",
            requested_at: "2030-01-01T00:00:00.000Z",
            retirement_effect_ref: `backup-effect:v1:${crypto.randomBytes(32).toString("base64url")}`,
            member_archive_registry: memberRegistry,
          }),
          /outcome is absent or ambiguous/,
        );
        retirementBlocked = true;
      }
    }
    return output;
  };
  const sourceArchive = JSON.parse(fs.readFileSync(
    path.join(setup.backupRoot, "fence-member-two.json"),
    "utf8",
  )).external_custody_envelope;
  const receipt = setup.vault.restoreBackup(descriptors[1], {
    expected_backup_ref: sourceArchive.backup_ref,
    allow_replace: true,
  });
  assert.equal(receipt.backup_ref, sourceArchive.backup_ref);
  assert.equal(retirementBlocked, true);
  assert.equal(setup.backupKeyCustodyFixture.metrics.retire_effects, 0);
  assert.equal(setup.backupKeyCustodyFixture.retirements.size, 0);
  assert.equal(
    [...setup.backupKeyCustodyFixture.archives.values()]
      .every((record) => record.state.status === "active"),
    true,
  );
  assert.equal(
    [...setup.backupKeyCustodyFixture.restoreFences.values()]
      .every((fence) => fence.status === "released"),
    true,
  );
});

test("restore fence loss before commit leaves the selected object generation unchanged", (t) => {
  const setup = makeVault(t);
  ingest(setup.vault, "restore-fence-loss");
  const descriptor = openBackupFile(t, path.join(setup.backupRoot, "restore-fence-loss.json"));
  const backup = setup.vault.createBackup(descriptor);
  const before = JSON.parse(fs.readFileSync(path.join(setup.root, "index.json"), "utf8")).payload;
  let activeReads = 0;
  setup.backupKeyCustodyFixture.control.read_restore_hook = (output, request) => {
    if (output && output.status === "active") {
      activeReads += 1;
      if (activeReads === 3) {
        setup.backupKeyCustodyFixture.restoreFences.delete(request.restore_ref);
        return null;
      }
    }
    return output;
  };
  assert.throws(
    () => setup.vault.restoreBackup(descriptor, {
      expected_backup_ref: backup.backup_ref,
      allow_replace: true,
    }),
    /restore fence is absent or no longer active/,
  );
  const after = JSON.parse(fs.readFileSync(path.join(setup.root, "index.json"), "utf8")).payload;
  assert.equal(after.object_generation, before.object_generation);
  assert.equal(after.backup_custody.restore_intents[backup.backup_ref], undefined);
  assert.equal(setup.backupKeyCustodyFixture.restoreFences.size, 0);
  assert.equal(
    fs.readdirSync(setup.root).some((entry) => entry.startsWith("objects-restore-")),
    false,
  );
});

test("restore fsyncs the new generation parent before anchored selection", (t) => {
  const setup = makeVault(t);
  ingest(setup.vault, "restore-parent-durability");
  const descriptor = openBackupFile(t, path.join(setup.backupRoot, "restore-parent-fsync.json"));
  const backup = setup.vault.createBackup(descriptor);
  const originalOpen = fs.openSync;
  const originalFsync = fs.fsyncSync;
  const originalClose = fs.closeSync;
  const rootDescriptors = new Set();
  let rootFsyncCount = 0;
  let rootFsyncCountAtAcquisition = null;
  let activeReads = 0;
  let checkedBeforeCommit = false;
  fs.openSync = function trackRootDirectoryOpen(filePath) {
    const opened = originalOpen.apply(this, arguments);
    if (filePath === setup.root) rootDescriptors.add(opened);
    return opened;
  };
  fs.fsyncSync = function trackRootDirectoryFsync(opened) {
    if (rootDescriptors.has(opened)) rootFsyncCount += 1;
    return originalFsync.apply(this, arguments);
  };
  fs.closeSync = function forgetRootDirectoryDescriptor(opened) {
    rootDescriptors.delete(opened);
    return originalClose.apply(this, arguments);
  };
  setup.backupKeyCustodyFixture.control.read_restore_hook = (output) => {
    if (output && output.status === "active") {
      activeReads += 1;
      if (activeReads === 1) rootFsyncCountAtAcquisition = rootFsyncCount;
      if (activeReads === 3) {
        assert.ok(rootFsyncCount > rootFsyncCountAtAcquisition);
        checkedBeforeCommit = true;
      }
    }
    return output;
  };
  try {
    setup.vault.restoreBackup(descriptor, {
      expected_backup_ref: backup.backup_ref,
      allow_replace: true,
    });
  } finally {
    setup.backupKeyCustodyFixture.control.read_restore_hook = null;
    fs.openSync = originalOpen;
    fs.fsyncSync = originalFsync;
    fs.closeSync = originalClose;
  }
  assert.equal(checkedBeforeCommit, true);
});

test("transform registries require immutable operator-enrolled policy capabilities", (t) => {
  const enrollment = createTestTransformPolicy(t);
  const workerSurface = require("../packages/bob-artifact-vault/worker.js");
  assert.equal(workerSurface.createOperatorTransformPolicyAuthority, undefined);
  assert.equal(workerSurface.enrollOperatorTransformPolicy, undefined);
  const definition = [{
    implementation_module: enrollment.implementationModule,
    manifest: {
      version: 1,
      tool_id: "identity",
      tool_version: "1.0.0",
      implementation_digest: enrollment.implementationDigest,
      handler_export: "identityTransform",
      input_data_classes: ["credential_secret"],
      output_data_classes: ["credential_secret"],
      parameters: {},
      max_input_handles: 1,
      max_input_bytes: 64,
      max_output_artifacts: 1,
      max_output_bytes: 64,
    },
  }];
  assert.equal(Object.isFrozen(enrollment.authority), true);
  assert.deepEqual(Reflect.ownKeys(enrollment.authority).sort(), [
    "authority_digest",
    "authority_id",
    "version",
  ]);
  assert.equal(Object.isFrozen(enrollment.policy), true);
  assert.deepEqual(Reflect.ownKeys(enrollment.policy).sort(), [
    "policy_authority_digest",
    "policy_authority_id",
    "policy_digest",
    "policy_epoch",
    "policy_id",
    "version",
  ]);
  const publicCapabilities = JSON.stringify({
    authority: enrollment.authority,
    policy: enrollment.policy,
  });
  assert.equal(publicCapabilities.includes(enrollment.implementationRoot), false);
  assert.equal(publicCapabilities.includes(enrollment.implementationDigest), false);
  assert.equal(publicCapabilities.includes("resolve_current_policy"), false);
  assert.throws(
    () => enrollOperatorTransformPolicy(
      enrollment.enrollmentRequest(),
      Object.freeze({ ...enrollment.authority }),
    ),
    /private branded operator capability/,
  );
  const substitutedAuthority = createOperatorTransformPolicyAuthority({
    version: 1,
    authority_id: enrollment.authority.authority_id,
    resolve_current_policy: enrollment.authorityInput.resolve_current_policy,
  });
  assert.throws(
    () => enrollOperatorTransformPolicy(enrollment.enrollmentRequest(), substitutedAuthority),
    /does not match its pinned authority/,
  );
  assert.throws(
    () => createTransformRegistry(definition, Object.freeze({ ...enrollment.policy })),
    /private branded operator-enrolled capability/,
  );
  assert.throws(() => createTransformRegistry(definition, {
    trusted_implementation_root: enrollment.implementationRoot,
    trusted_implementation_digests: [enrollment.implementationDigest],
  }), /private branded operator-enrolled capability/);

  const registry = createTransformRegistry(definition, enrollment.policy);
  assert.equal(registry.transform_policy_digest, enrollment.policy.policy_digest);
  assert.equal(registry.transform_policy_id, enrollment.policy.policy_id);
  assert.equal(registry.transform_policy_epoch, 1);
  assert.equal(registry.transform_policy_authority_digest, enrollment.authority.authority_digest);
  assert.equal(JSON.stringify(registry).includes(enrollment.implementationRoot), false);

  enrollment.authorityInput.resolve_current_policy = () => {
    throw new Error("caller mutation must not replace the enrolled resolver");
  };
  assert.doesNotThrow(() => createTransformRegistry(definition, enrollment.policy));

  enrollment.control.current.policy_epoch = 2;
  assert.throws(
    () => createTransformRegistry(definition, enrollment.policy),
    /stale relative to the current policy epoch/,
  );
  assert.throws(
    () => runTransform({ registry, registry_digest: registry.registry_digest }),
    /stale relative to the current policy epoch/,
  );
  const successorPolicy = enrollOperatorTransformPolicy(
    enrollment.enrollmentRequest(),
    enrollment.authority,
  );
  const successorRegistry = createTransformRegistry(definition, successorPolicy);
  assert.notEqual(successorRegistry.registry_digest, registry.registry_digest);
  assert.equal(successorRegistry.transform_policy_epoch, 2);

  enrollment.control.current.status = "revoked";
  assert.throws(
    () => enrollOperatorTransformPolicy(enrollment.enrollmentRequest(), enrollment.authority),
    /refuses a revoked policy/,
  );
  assert.throws(
    () => createTransformRegistry(definition, successorPolicy),
    /policy is revoked/,
  );
  assert.throws(
    () => runTransform({ registry: successorRegistry, registry_digest: successorRegistry.registry_digest }),
    /policy is revoked/,
  );
  enrollment.control.current.status = "trusted";

  for (const [mode, pattern] of [
    ["outage", /resolver is unavailable/],
    ["async", /must return synchronously/],
    ["malformed", /returned malformed state/],
    ["substitute", /substituted a different policy identity/],
  ]) {
    enrollment.control.mode = mode;
    assert.throws(
      () => runTransform({
        registry: successorRegistry,
        registry_digest: successorRegistry.registry_digest,
      }),
      pattern,
    );
  }
  enrollment.control.mode = "current";

  enrollment.control.current.trusted_implementation_digests = ["0".repeat(64)];
  assert.throws(
    () => runTransform({ registry: successorRegistry, registry_digest: successorRegistry.registry_digest }),
    /implementation_allowlist_digest binding drifted/,
  );
  enrollment.control.current.trusted_implementation_digests = [enrollment.implementationDigest];

  fs.renameSync(enrollment.implementationRoot, `${enrollment.implementationRoot}.retired`);
  fs.mkdirSync(enrollment.implementationRoot, { mode: 0o700 });
  assert.throws(
    () => createTransformRegistry(definition, successorPolicy),
    /root_binding_digest binding drifted/,
  );
  assert.throws(
    () => runTransform({
      registry: successorRegistry,
      registry_digest: successorRegistry.registry_digest,
    }),
    /root_binding_digest binding drifted/,
  );
});

test("allowlisted transforms are handle-in/handle-out and bind tool provenance", (t) => {
  const { vault } = makeVault(t);
  const source = ingest(vault, "opaque-input");
  const registry = createTestTransformRegistry(t, [{
    manifest: {
      version: 1,
      tool_id: "reverse-bytes",
      tool_version: "1.0.0",
      input_data_classes: ["credential_secret"],
      output_data_classes: ["credential_secret"],
      parameters: {},
      max_input_handles: 1,
      max_input_bytes: 64,
      max_output_artifacts: 1,
      max_output_bytes: 64,
    },
  }]);
  const manifest = registry.manifest("reverse-bytes");
  assert.equal(Object.getOwnPropertySymbols(registry).length, 0);
  const reserved = vault.reserve(reservation({ byte_ceiling: 64 }));
  assert.throws(() => runTransform({
    registry: Object.freeze({ ...registry }),
    registry_digest: registry.registry_digest,
    vault,
    transform_attempt_ref: transformAttemptRef("forged-registry"),
    tool_id: "reverse-bytes",
    tool_digest: manifest.tool_digest,
    input_handles: [source.artifact_handle],
    outputs: [{ reservation_handle: reserved.reservation_handle, metadata: metadata() }],
    parameters: { mode: "reverse" },
  }), /not a transform registry/);
  assert.throws(() => runTransform({
    registry,
    vault,
    transform_attempt_ref: transformAttemptRef("missing-registry-digest"),
    tool_id: "reverse-bytes",
    tool_digest: manifest.tool_digest,
    input_handles: [source.artifact_handle],
    outputs: [{ reservation_handle: reserved.reservation_handle, metadata: metadata() }],
  }), /registry digest is absent/);
  assert.throws(() => runTransform({
    registry,
    registry_digest: registry.registry_digest,
    vault,
    transform_attempt_ref: transformAttemptRef("tool-drift"),
    tool_id: "reverse-bytes",
    tool_digest: "0".repeat(64),
    input_handles: [source.artifact_handle],
    outputs: [{ reservation_handle: reserved.reservation_handle, metadata: metadata() }],
  }), /digest.*drifted/);
  assert.throws(() => runTransform({
    registry,
    registry_digest: registry.registry_digest,
    vault,
    transform_attempt_ref: transformAttemptRef("unknown-parameter"),
    tool_id: "reverse-bytes",
    tool_digest: manifest.tool_digest,
    input_handles: [source.artifact_handle],
    outputs: [{ reservation_handle: reserved.reservation_handle, metadata: metadata() }],
    parameters: { raw_secret: "opaque-input" },
  }), /unknown keys|direct secret/);
  assert.throws(() => runTransform({
    registry,
    registry_digest: registry.registry_digest,
    vault,
    transform_attempt_ref: transformAttemptRef("bad-enum"),
    tool_id: "reverse-bytes",
    tool_digest: manifest.tool_digest,
    input_handles: [source.artifact_handle],
    outputs: [{ reservation_handle: reserved.reservation_handle, metadata: metadata() }],
    parameters: { mode: "opaque-input" },
  }), /unknown keys/);
  const successfulAttemptRef = transformAttemptRef("reverse");
  const successfulRequest = {
    registry,
    registry_digest: registry.registry_digest,
    vault,
    transform_attempt_ref: successfulAttemptRef,
    tool_id: "reverse-bytes",
    tool_digest: manifest.tool_digest,
    input_handles: [source.artifact_handle],
    outputs: [{ reservation_handle: reserved.reservation_handle, metadata: metadata() }],
    parameters: {},
  };
  const result = runTransform(successfulRequest);
  assert.deepEqual(Object.keys(result).sort(), [
    "input_handle_count",
    "output_handle_count",
    "outputs",
    "status",
    "tool_digest",
    "tool_id",
    "tool_version",
  ]);
  assert.match(result.outputs[0].artifact_handle, PUBLIC_ARTIFACT_HANDLE_RE);
  assert.doesNotMatch(JSON.stringify(result), /opaque-input|tupni-euqapo/);
  vault.erase(source.artifact_handle, "transform:source-retired-before-retry");
  const reconciled = runTransform(successfulRequest);
  assert.deepEqual(reconciled.outputs, result.outputs);

  const reversedSource = ingest(vault, "tupni-euqapo");
  assert.equal(vault.compare(result.outputs[0].artifact_handle, reversedSource.artifact_handle).equal, true);
  const { tool_digest: _toolDigest, ...baseManifest } = registry.manifest("reverse-bytes");
  assert.throws(
    () => createTestTransformRegistry(t, [{
      manifest: {
        ...baseManifest,
        tool_id: "bad",
        parameters: { candidate: { kind: "string", required: true } },
      },
    }]),
    /kind is not registered/,
  );
});

test("transform batches commit atomically and release reservations on pre-commit failure", (t) => {
  const { root, vault } = makeVault(t);
  const source = ingest(vault, "source-for-rollback");
  const definition = {
    manifest: {
      version: 1,
      tool_id: "two-output-transform",
      tool_version: "1.0.0",
      input_data_classes: ["credential_secret"],
      output_data_classes: ["credential_secret"],
      parameters: {},
      max_input_handles: 1,
      max_input_bytes: 64,
      max_output_artifacts: 2,
      max_output_bytes: 64,
    },
  };
  const registry = createTestTransformRegistry(t, [definition]);
  const first = vault.reserve(reservation({ byte_ceiling: 16 }));
  const second = vault.reserve(reservation({ byte_ceiling: 16 }));
  assert.throws(() => runTransform({
    registry,
    registry_digest: registry.registry_digest,
    vault,
    transform_attempt_ref: transformAttemptRef("rollback"),
    tool_id: definition.manifest.tool_id,
    tool_digest: registry.manifest(definition.manifest.tool_id).tool_digest,
    input_handles: [source.artifact_handle],
    outputs: [
      { reservation_handle: first.reservation_handle, metadata: metadata() },
      {
        reservation_handle: second.reservation_handle,
        metadata: metadata({ media_type: "application/json" }),
      },
    ],
  }), /content type does not match/);
  assert.equal(vault.usage().active_artifacts, 1, "only the input artifact remains");
  assert.equal(vault.usage().active_reservations, 0, "unused output reservations were released");

  const atomicFirst = vault.reserve(reservation({ byte_ceiling: 16 }));
  const atomicSecond = vault.reserve(reservation({ byte_ceiling: 16 }));
  const liveIndex = JSON.parse(fs.readFileSync(path.join(root, "index.json"), "utf8")).payload;
  const firstBlobPath = path.join(
    root,
    liveIndex.object_generation,
    `${liveIndex.reservations[atomicFirst.reservation_handle].blob_id}.json`,
  );
  const secondBlobPath = path.join(
    root,
    liveIndex.object_generation,
    `${liveIndex.reservations[atomicSecond.reservation_handle].blob_id}.json`,
  );
  fs.unlinkSync(secondBlobPath);
  fs.symlinkSync(firstBlobPath, secondBlobPath);
  assert.throws(() => runTransform({
    registry,
    registry_digest: registry.registry_digest,
    vault,
    transform_attempt_ref: transformAttemptRef("atomic-write-failure"),
    tool_id: definition.manifest.tool_id,
    tool_digest: registry.manifest(definition.manifest.tool_id).tool_digest,
    input_handles: [source.artifact_handle],
    outputs: [
      { reservation_handle: atomicFirst.reservation_handle, metadata: metadata() },
      { reservation_handle: atomicSecond.reservation_handle, metadata: metadata() },
    ],
  }), /single-link regular file/);
  assert.equal(vault.usage().active_artifacts, 1, "a failed multi-object write exposes no partial batch");
  assert.equal(vault.usage().active_reservations, 0, "failed atomic batch reservations are reconciled");

});

test("active-generation orphan collection and stale-lock recovery are explicit and auditable", (t) => {
  const setup = makeVault(t);
  const { root, vault } = setup;
  const retained = ingest(vault, "retained");
  const orphanBlobId = "f".repeat(64);
  const orphanPath = path.join(root, "objects", `${orphanBlobId}.json`);
  fs.writeFileSync(orphanPath, "orphan ciphertext from a pre-index crash", { mode: 0o600 });
  const swept = vault.collectOrphanCiphertexts({ reason_ref: "recovery:test-sweep" });
  assert.equal(swept.removed_ciphertexts, 1);
  assert.match(swept.removed_inventory_digest, /^[a-f0-9]{64}$/);
  assert.match(swept.collection_receipt, /^[a-f0-9]{64}$/);
  assert.equal(fs.existsSync(orphanPath), false);
  assert.equal(vault.inspect(retained.artifact_handle).byte_length, "retained".length);

  const acquiredAt = new Date(Date.now() - 60_000).toISOString();
  const deadPid = 2_147_483_647;
  const lockPath = path.join(root, ".vault.lock");
  fs.writeFileSync(lockPath, `${JSON.stringify({ pid: deadPid, acquired_at: acquiredAt })}\n`, { mode: 0o600 });
  assert.throws(() => vault.recoverStaleLock({
    expected_pid: deadPid,
    expected_acquired_at: new Date(Date.now() - 120_000).toISOString(),
    evidence_ref: "evidence:wrong-observation",
  }), /does not match/);
  const recovered = vault.recoverStaleLock({
    expected_pid: deadPid,
    expected_acquired_at: acquiredAt,
    evidence_ref: "evidence:operator-observation",
  });
  assert.equal(recovered.dead_owner_pid, deadPid);
  assert.match(recovered.recovery_receipt, /^[a-f0-9]{64}$/);
  assert.equal(fs.existsSync(lockPath), false);

  const secondAcquiredAt = new Date(Date.now() - 30_000).toISOString();
  fs.writeFileSync(
    lockPath,
    `${JSON.stringify({ pid: deadPid, acquired_at: secondAcquiredAt })}\n`,
    { mode: 0o600 },
  );
  const publicationSibling = path.join(root, `..vault.lock.publish.${process.pid}.crash-window`);
  fs.linkSync(lockPath, publicationSibling);
  vault.destroy();
  const reopened = reopenVault(t, setup);
  assert.throws(() => reopened.usage(), /vault is locked/);
  const repaired = reopened.recoverStaleLock({
    expected_pid: deadPid,
    expected_acquired_at: secondAcquiredAt,
    evidence_ref: "evidence:operator-observed-publication-crash",
  });
  assert.equal(repaired.dead_owner_pid, deadPid);
  assert.equal(fs.existsSync(lockPath), false);
  assert.equal(fs.existsSync(publicationSibling), false);
});

test("raw export exists only behind an authenticated, audience-bound, one-use operator channel", (t) => {
  const { vault } = makeVault(t);
  const descriptor = ingest(vault, "operator-only-plaintext");
  const exportKey = crypto.randomBytes(32);
  const seenNonces = new Set();
  const fixedNow = new Date();
  const channel = createOperatorExportChannel({
    vault,
    exportKey,
    audience: "bob-operator-export",
    now: () => fixedNow,
    consumeNonce(nonce) {
      if (seenNonces.has(nonce)) return false;
      seenNonces.add(nonce);
      return true;
    },
  });
  t.after(() => channel.destroy());
  const unsigned = {
    version: 1,
    artifact_handle: descriptor.artifact_handle,
    audience: "bob-operator-export",
    purpose_ref: "export:incident-review",
    requester_principal_id: "principal:operator-1",
    nonce: `export-nonce:v1:${crypto.randomBytes(32).toString("base64url")}`,
    not_before: new Date(fixedNow.getTime() - 1000).toISOString(),
    expires_at: new Date(fixedNow.getTime() + 30_000).toISOString(),
  };
  const request = signOperatorExportRequest(unsigned, exportKey);
  exportKey.fill(0);
  const exported = channel.exportArtifact(request);
  assert.equal(exported.plaintext.toString("utf8"), "operator-only-plaintext");
  assert.equal(exported.receipt.requester_principal_id, "principal:operator-1");
  assert.match(exported.receipt.receipt_mac, /^[a-f0-9]{64}$/);
  exported.plaintext.fill(0);
  assert.throws(() => channel.exportArtifact(request), /replayed/);

  const wrongKey = crypto.randomBytes(32);
  const wrongRequest = signOperatorExportRequest({
    ...unsigned,
    nonce: `export-nonce:v1:${crypto.randomBytes(32).toString("base64url")}`,
  }, wrongKey);
  wrongKey.fill(0);
  assert.throws(() => channel.exportArtifact(wrongRequest), /authentication failed/);
  assert.equal(typeof vault.exportArtifact, "undefined", "the ordinary vault API has no raw export method");
  channel.destroy();
  const zeroKey = Buffer.alloc(32);
  const postDestroy = signOperatorExportRequest({
    ...unsigned,
    nonce: `export-nonce:v1:${crypto.randomBytes(32).toString("base64url")}`,
  }, zeroKey);
  assert.throws(() => channel.exportArtifact(postDestroy), /channel is destroyed/);
});
