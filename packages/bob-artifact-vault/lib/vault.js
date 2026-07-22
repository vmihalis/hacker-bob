"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const {
  ARTIFACT_VAULT_SCHEMA_VERSION,
  PUBLIC_ARTIFACT_HANDLE_RE,
  PUBLIC_RESERVATION_HANDLE_RE,
  assertClosedObject,
  assertOpaqueRef,
  normalizeArtifactMetadata,
  normalizeReservationRequest,
} = require("./contracts.js");
const {
  MAX_MEMBER_ARCHIVES_PER_ARTIFACT,
  acquireBackupRestoreFence,
  assertBackupKeyRetirementEvidence,
  assertBackupRestoreFence,
  assertOperatorBackupKeyCustodyPort,
  normalizeArtifactInventory,
  normalizeStoredBackupCustodyEnvelope,
  openBackupArchive,
  readBackupArchiveState,
  readBackupRestoreFence,
  releaseBackupRestoreFence,
  retireArtifactBackupKeys,
  sealBackupArchive,
  verifySerializedBackupKeyRetirementEvidence,
} = require("./backup-key-custody.js");

const VAULT_INTERNALS = new WeakMap();
const DEFAULT_QUOTA_BYTES = 64 * 1024 * 1024;
const MAX_QUOTA_BYTES = 128 * 1024 * 1024;
const DEFAULT_MIN_FREE_BYTES = 16 * 1024 * 1024;
const ARTIFACT_LOGICAL_OVERHEAD_BYTES = 4096;
const DEFAULT_MAX_ARTIFACTS = 4096;
const MAX_TRANSFORM_ATTEMPTS = 65_536;
const MAX_TRANSFORM_OUTPUTS = 64;
const MAX_INDEX_ENCODED_BYTES = 32 * 1024 * 1024;
const MAX_DELETION_LEDGER_ENCODED_BYTES = 32 * 1024 * 1024;
const MAX_TRANSFORM_INDEX_RESERVATION_BYTES = 1024 * 1024;
const BLOB_ID_RE = /^[a-f0-9]{64}$/;
const OBJECT_GENERATION_RE = /^objects(?:-[a-z0-9_-]{1,80})?$/;
const BACKUP_REF_RE = /^backup:v1:[A-Za-z0-9_-]{43}$/;
const BACKUP_EFFECT_REF_RE = /^backup-effect:v1:[A-Za-z0-9_-]{43}$/;
const BACKUP_SEAL_REF_RE = /^backup-seal:v1:[A-Za-z0-9_-]{43}$/;
const BACKUP_RESTORE_REF_RE = /^backup-restore:v1:[A-Za-z0-9_-]{43}$/;
const TRANSFORM_BATCH_REF_RE = /^transform-batch:v1:[a-f0-9]{64}$/;
const TRANSFORM_CLAIM_TOKEN_RE = /^transform-claim:v1:[A-Za-z0-9_-]{43}$/;
const VAULT_ID_RE = /^vault:v1:[A-Za-z0-9_-]{43}$/;
const VAULT_SLOT_RE = /^vault-slot:v1:[A-Za-z0-9_-]{43}$/;
const SHA256_RE = /^[a-f0-9]{64}$/;
const MAX_BACKUP_ARCHIVES = 4096;
const BACKUP_INTENT_INDEX_RESERVATION_BYTES = 2048;
const MAX_BACKUP_INTENT_ENCODED_BYTES = 384 * 1024 * 1024;

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value != null && typeof value === "object") {
    const output = Object.create(null);
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

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function randomToken() {
  return crypto.randomBytes(32).toString("base64url");
}

function assertEncodedLifecycleCeiling(encoded, ceiling, label) {
  const byteLength = Buffer.isBuffer(encoded)
    ? encoded.length
    : Buffer.byteLength(encoded, "utf8");
  if (byteLength > ceiling) {
    throw new Error(`${label} exceeds its configured read ceiling`);
  }
  return byteLength;
}

function constantTimeEqual(left, right) {
  if (typeof left !== "string" || typeof right !== "string") return false;
  const leftBuffer = Buffer.from(left, "utf8");
  const rightBuffer = Buffer.from(right, "utf8");
  return leftBuffer.length === rightBuffer.length && crypto.timingSafeEqual(leftBuffer, rightBuffer);
}

function assertPrivateDirectory(root, label = "private directory") {
  fs.mkdirSync(root, { recursive: true, mode: 0o700 });
  const stats = fs.lstatSync(root);
  if (!stats.isDirectory() || stats.isSymbolicLink()) {
    throw new Error(`${label} must be a real directory, not a symlink`);
  }
  fs.chmodSync(root, 0o700);
}

function assertSafeRegularFile(filePath, label, { required = true } = {}) {
  let stats;
  try {
    stats = fs.lstatSync(filePath);
  } catch (error) {
    if (!required && error && error.code === "ENOENT") return null;
    throw error;
  }
  if (!stats.isFile() || stats.isSymbolicLink() || stats.nlink !== 1) {
    throw new Error(`${label} must be a single-link regular file`);
  }
  return stats;
}

function fsyncDirectory(dirPath) {
  const descriptor = fs.openSync(dirPath, fs.constants.O_RDONLY);
  try {
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
}

function writeExclusiveFile(filePath, content, mode = 0o600) {
  const descriptor = fs.openSync(
    filePath,
    fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY | fs.constants.O_NOFOLLOW,
    mode,
  );
  try {
    fs.writeFileSync(descriptor, content);
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
}

function writeAtomicPrivate(filePath, content) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true, mode: 0o700 });
  assertSafeRegularFile(filePath, path.basename(filePath), { required: false });
  const tempPath = path.join(
    path.dirname(filePath),
    `.${path.basename(filePath)}.${process.pid}.${randomToken()}.tmp`,
  );
  try {
    writeExclusiveFile(tempPath, content, 0o600);
    fs.renameSync(tempPath, filePath);
    fs.chmodSync(filePath, 0o600);
    fsyncDirectory(path.dirname(filePath));
  } finally {
    try { fs.unlinkSync(tempPath); } catch {}
  }
}

function repairExclusivePublication(filePath) {
  let stats;
  try {
    stats = fs.lstatSync(filePath);
  } catch (error) {
    if (error && error.code === "ENOENT") return;
    throw error;
  }
  if (!stats.isFile() || stats.isSymbolicLink()) {
    throw new Error(`${path.basename(filePath)} must be a real regular file`);
  }
  if (stats.nlink === 1) return;
  const prefix = `.${path.basename(filePath)}.publish.`;
  let removed = 0;
  for (const entry of fs.readdirSync(path.dirname(filePath))) {
    if (!entry.startsWith(prefix)) continue;
    const candidate = path.join(path.dirname(filePath), entry);
    const candidateStats = fs.lstatSync(candidate);
    if (candidateStats.isFile() && !candidateStats.isSymbolicLink()
      && candidateStats.dev === stats.dev && candidateStats.ino === stats.ino) {
      fs.unlinkSync(candidate);
      removed += 1;
    }
  }
  const after = fs.lstatSync(filePath);
  if (removed === 0 || after.nlink !== 1) {
    throw new Error(`${path.basename(filePath)} has an unexplained hardlink`);
  }
  fsyncDirectory(path.dirname(filePath));
}

function publishExclusivePrivate(filePath, content) {
  const tempPath = path.join(
    path.dirname(filePath),
    `.${path.basename(filePath)}.publish.${process.pid}.${randomToken()}`,
  );
  let published = false;
  try {
    writeExclusiveFile(tempPath, content, 0o600);
    try {
      fs.linkSync(tempPath, filePath);
      published = true;
      fsyncDirectory(path.dirname(filePath));
    } catch (error) {
      if (!error || error.code !== "EEXIST") throw error;
    }
  } finally {
    try { fs.unlinkSync(tempPath); } catch {}
    try { fsyncDirectory(path.dirname(filePath)); } catch {}
  }
  return published;
}

function readPrivateFile(filePath, label, maxBytes) {
  const descriptor = fs.openSync(filePath, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  let output = null;
  try {
    const stats = assertSafeRegularDescriptor(descriptor, label);
    if (!Number.isSafeInteger(stats.size) || stats.size < 0 || stats.size > maxBytes) {
      throw new Error(`${label} exceeds its byte ceiling`);
    }
    output = Buffer.alloc(stats.size);
    let offset = 0;
    while (offset < output.length) {
      const count = fs.readSync(descriptor, output, offset, output.length - offset, offset);
      if (count === 0) throw new Error(`${label} changed while it was being read`);
      offset += count;
    }
    const after = fs.fstatSync(descriptor);
    const pathState = fs.lstatSync(filePath);
    if (!after.isFile() || after.nlink !== 1
      || after.dev !== stats.dev || after.ino !== stats.ino
      || after.uid !== stats.uid || (after.mode & 0o077) !== 0
      || after.size !== stats.size
      || !pathState.isFile() || pathState.isSymbolicLink() || pathState.nlink !== 1
      || pathState.dev !== after.dev || pathState.ino !== after.ino) {
      throw new Error(`${label} changed while it was being read`);
    }
    const result = output;
    output = null;
    return result;
  } catch (error) {
    if (output) output.fill(0);
    throw error;
  } finally {
    fs.closeSync(descriptor);
  }
}

function assertSafeRegularDescriptor(descriptor, label, { requireEmpty = false } = {}) {
  if (!Number.isSafeInteger(descriptor) || descriptor < 0) {
    throw new Error(`${label} must be an open file descriptor`);
  }
  const stats = fs.fstatSync(descriptor);
  if (!stats.isFile() || stats.nlink !== 1) {
    throw new Error(`${label} must reference a single-link regular file`);
  }
  if ((stats.mode & 0o077) !== 0
    || (typeof process.getuid === "function" && stats.uid !== process.getuid())) {
    throw new Error(`${label} must be owned by this process identity and inaccessible to group or other users`);
  }
  if (requireEmpty && stats.size !== 0) {
    throw new Error(`${label} must be a newly created empty file`);
  }
  return stats;
}

function readPrivateDescriptor(descriptor, label, maxBytes) {
  const stats = assertSafeRegularDescriptor(descriptor, label);
  if (stats.size > maxBytes) throw new Error(`${label} exceeds its byte ceiling`);
  const output = Buffer.alloc(stats.size);
  let offset = 0;
  while (offset < output.length) {
    const count = fs.readSync(descriptor, output, offset, output.length - offset, offset);
    if (count === 0) throw new Error(`${label} changed while it was being read`);
    offset += count;
  }
  const after = fs.fstatSync(descriptor);
  if (after.dev !== stats.dev || after.ino !== stats.ino || after.size !== stats.size) {
    output.fill(0);
    throw new Error(`${label} changed while it was being read`);
  }
  return output;
}

function writePrivateDescriptor(descriptor, content, label) {
  const before = assertSafeRegularDescriptor(descriptor, label, { requireEmpty: true });
  const encoded = Buffer.isBuffer(content) ? content : Buffer.from(content, "utf8");
  let offset = 0;
  while (offset < encoded.length) {
    offset += fs.writeSync(descriptor, encoded, offset, encoded.length - offset, offset);
  }
  fs.ftruncateSync(descriptor, encoded.length);
  fs.fsyncSync(descriptor);
  const after = fs.fstatSync(descriptor);
  if (!after.isFile() || after.nlink !== 1
    || after.dev !== before.dev || after.ino !== before.ino
    || after.uid !== before.uid || (after.mode & 0o077) !== 0
    || after.size !== encoded.length) {
    throw new Error(`${label} identity changed during write`);
  }
}

function deriveKey(masterKey, salt, sessionNucleusHash, vaultId, vaultSlot, label) {
  return Buffer.from(crypto.hkdfSync(
    "sha256",
    masterKey,
    salt,
    Buffer.from(
      `hacker-bob/artifact-vault/v1/${sessionNucleusHash}/${vaultSlot}/${vaultId}/${label}`,
      "utf8",
    ),
    32,
  ));
}

function encryptAead(key, plaintext, aad) {
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, nonce);
  cipher.setAAD(Buffer.from(aad, "utf8"));
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return {
    algorithm: "aes-256-gcm",
    nonce: nonce.toString("base64"),
    ciphertext: ciphertext.toString("base64"),
    tag: cipher.getAuthTag().toString("base64"),
  };
}

function decryptAead(key, envelope, aad, label) {
  if (!envelope || envelope.algorithm !== "aes-256-gcm") {
    throw new Error(`${label} has an unsupported encryption envelope`);
  }
  try {
    const decipher = crypto.createDecipheriv(
      "aes-256-gcm",
      key,
      Buffer.from(envelope.nonce, "base64"),
    );
    decipher.setAAD(Buffer.from(aad, "utf8"));
    decipher.setAuthTag(Buffer.from(envelope.tag, "base64"));
    return Buffer.concat([
      decipher.update(Buffer.from(envelope.ciphertext, "base64")),
      decipher.final(),
    ]);
  } catch {
    throw new Error(`${label} failed authenticated decryption`);
  }
}

function publicDescriptor(record) {
  return Object.freeze({
    artifact_handle: record.artifact_handle,
    data_class: record.metadata.data_class,
    media_type: record.metadata.media_type,
    byte_length: record.byte_length,
    created_at: record.created_at,
    retention_expires_at: record.metadata.retention_expires_at,
    masked_summary: `${record.metadata.data_class} artifact (${record.byte_length} bytes)`,
  });
}

function encodedBlobCeiling(record) {
  const allocatedBytes = Number.isSafeInteger(record.allocated_bytes) && record.allocated_bytes > 0
    ? record.allocated_bytes
    : 0;
  return Math.max(allocatedBytes, record.byte_length * 2 + 64 * 1024, 64 * 1024);
}

function createArtifactVault({
  root,
  sessionNucleusHash,
  vaultId,
  vaultSlot,
  createNew = false,
  masterKey,
  backupKeyCustody,
  deletionLedgerAnchor,
  indexStateAnchor,
  quotaBytes = DEFAULT_QUOTA_BYTES,
  maxArtifacts = DEFAULT_MAX_ARTIFACTS,
  minFreeBytes = DEFAULT_MIN_FREE_BYTES,
  indexEncodedBytesCeiling = MAX_INDEX_ENCODED_BYTES,
  deletionLedgerEncodedBytesCeiling = MAX_DELETION_LEDGER_ENCODED_BYTES,
  now = () => new Date(),
} = {}) {
  if (typeof root !== "string" || !path.isAbsolute(root)) {
    throw new Error("vault root must be an absolute path");
  }
  if (typeof sessionNucleusHash !== "string" || !/^[a-f0-9]{64}$/.test(sessionNucleusHash)) {
    throw new Error("sessionNucleusHash must be a lowercase SHA-256 digest");
  }
  if (typeof vaultId !== "string" || !VAULT_ID_RE.test(vaultId)) {
    throw new Error("vaultId must be an externally enrolled random opaque vault identity");
  }
  if (typeof vaultSlot !== "string" || !VAULT_SLOT_RE.test(vaultSlot)) {
    throw new Error("vaultSlot must be an externally enrolled immutable vault slot");
  }
  if (typeof createNew !== "boolean") {
    throw new Error("createNew must be a boolean");
  }
  if (!Buffer.isBuffer(masterKey) || masterKey.length !== 32) {
    throw new Error("masterKey must be a 32-byte Buffer supplied outside the vault filesystem");
  }
  assertOperatorBackupKeyCustodyPort(backupKeyCustody, {
    vault_id: vaultId,
    vault_slot: vaultSlot,
    session_nucleus_hash: sessionNucleusHash,
  });
  if (!deletionLedgerAnchor || typeof deletionLedgerAnchor.readState !== "function"
    || typeof deletionLedgerAnchor.compareAndSet !== "function") {
    throw new Error("deletionLedgerAnchor must provide external readState and compareAndSet functions");
  }
  if (!indexStateAnchor || typeof indexStateAnchor.readState !== "function"
    || typeof indexStateAnchor.compareAndSet !== "function") {
    throw new Error("indexStateAnchor must provide external readState and compareAndSet functions");
  }
  if (!Number.isSafeInteger(quotaBytes) || quotaBytes < 1 || quotaBytes > MAX_QUOTA_BYTES) {
    throw new Error(`quotaBytes must be a positive safe integer no greater than ${MAX_QUOTA_BYTES}`);
  }
  if (!Number.isSafeInteger(maxArtifacts) || maxArtifacts < 1 || maxArtifacts > DEFAULT_MAX_ARTIFACTS) {
    throw new Error(`maxArtifacts must be between 1 and ${DEFAULT_MAX_ARTIFACTS}`);
  }
  if (!Number.isSafeInteger(minFreeBytes) || minFreeBytes < 0) {
    throw new Error("minFreeBytes must be a non-negative safe integer");
  }
  if (!Number.isSafeInteger(indexEncodedBytesCeiling) || indexEncodedBytesCeiling < 1
    || indexEncodedBytesCeiling > MAX_INDEX_ENCODED_BYTES) {
    throw new Error(`indexEncodedBytesCeiling must be between 1 and ${MAX_INDEX_ENCODED_BYTES}`);
  }
  if (!Number.isSafeInteger(deletionLedgerEncodedBytesCeiling)
    || deletionLedgerEncodedBytesCeiling < 1
    || deletionLedgerEncodedBytesCeiling > MAX_DELETION_LEDGER_ENCODED_BYTES) {
    throw new Error(
      `deletionLedgerEncodedBytesCeiling must be between 1 and ${MAX_DELETION_LEDGER_ENCODED_BYTES}`,
    );
  }
  if (typeof now !== "function") throw new Error("now must be a function");

  if (!fs.existsSync(root) && !createNew) {
    throw new Error("vault root is absent; explicit createNew enrollment is required");
  }
  assertPrivateDirectory(root);
  const metadataPath = path.join(root, "vault.json");
  const indexPath = path.join(root, "index.json");
  const deletionLedgerPath = path.join(root, "deletion-ledger.json");
  const lockPath = path.join(root, ".vault.lock");
  const enrollmentContext = Object.freeze({
    version: ARTIFACT_VAULT_SCHEMA_VERSION,
    vault_id: vaultId,
    vault_slot: vaultSlot,
    session_nucleus_hash: sessionNucleusHash,
  });
  const enrolledIndexState = indexStateAnchor.readState(enrollmentContext);
  const enrolledDeletionState = deletionLedgerAnchor.readState(enrollmentContext);

  function normalizeVaultMetadata(input, label = "vault metadata") {
    assertClosedObject(input, label, [
      "version",
      "vault_id",
      "vault_slot",
      "session_nucleus_hash",
      "kdf_salt",
      "created_at",
    ]);
    const saltBytes = typeof input.kdf_salt === "string"
      ? Buffer.from(input.kdf_salt, "base64")
      : Buffer.alloc(0);
    const saltIsCanonical = saltBytes.length === 32
      && saltBytes.toString("base64") === input.kdf_salt;
    saltBytes.fill(0);
    if (input.version !== ARTIFACT_VAULT_SCHEMA_VERSION
      || input.vault_id !== vaultId
      || input.vault_slot !== vaultSlot
      || input.session_nucleus_hash !== sessionNucleusHash
      || !saltIsCanonical
      || typeof input.created_at !== "string"
      || Number.isNaN(Date.parse(input.created_at))
      || new Date(input.created_at).toISOString() !== input.created_at) {
      throw new Error(`${label} does not match the externally enrolled vault identity and slot`);
    }
    return input;
  }

  const vaultMetadataExisted = fs.existsSync(metadataPath);
  let vaultMetadata;
  if (vaultMetadataExisted) {
    if (createNew && enrolledIndexState != null && enrolledDeletionState != null) {
      throw new Error("createNew cannot replace an existing enrolled vault");
    }
    if (!createNew && (enrolledIndexState == null || enrolledDeletionState == null)) {
      throw new Error("vault slot enrollment is incomplete; explicit createNew enrollment is required");
    }
    repairExclusivePublication(metadataPath);
    vaultMetadata = normalizeVaultMetadata(JSON.parse(
      readPrivateFile(metadataPath, "vault metadata", 64 * 1024).toString("utf8"),
    ));
  } else {
    if (!createNew) {
      throw new Error("vault metadata is absent; explicit createNew enrollment is required");
    }
    if (fs.readdirSync(root).length !== 0) {
      throw new Error("fresh vault enrollment requires an empty private root");
    }
    if (enrolledIndexState != null || enrolledDeletionState != null) {
      throw new Error("vault slot is already externally enrolled; local recovery is required");
    }
    const candidateMetadata = {
      version: ARTIFACT_VAULT_SCHEMA_VERSION,
      vault_id: vaultId,
      vault_slot: vaultSlot,
      session_nucleus_hash: sessionNucleusHash,
      kdf_salt: crypto.randomBytes(32).toString("base64"),
      created_at: now().toISOString(),
    };
    if (publishExclusivePrivate(metadataPath, `${canonicalJson(candidateMetadata)}\n`)) {
      vaultMetadata = candidateMetadata;
    } else {
      repairExclusivePublication(metadataPath);
      vaultMetadata = normalizeVaultMetadata(JSON.parse(readPrivateFile(
        metadataPath,
        "vault metadata",
        64 * 1024,
      ).toString("utf8")), "concurrently published vault metadata");
    }
  }

  const objectRoot = path.join(root, "objects");
  assertPrivateDirectory(objectRoot);
  const backupIntentRoot = path.join(root, "backup-intents");
  assertPrivateDirectory(backupIntentRoot);

  const keyMaterial = Buffer.from(masterKey);
  const salt = Buffer.from(vaultMetadata.kdf_salt, "base64");
  const deriveVaultKey = (label) => deriveKey(
    keyMaterial,
    salt,
    sessionNucleusHash,
    vaultMetadata.vault_id,
    vaultMetadata.vault_slot,
    label,
  );
  const wrapKey = deriveVaultKey("wrap");
  const integrityKey = deriveVaultKey("integrity");
  const comparisonKey = deriveVaultKey("compare");
  const indexKey = deriveVaultKey("index");
  const indexAnchorKey = deriveVaultKey("index-anchor-snapshot");
  const auditKey = deriveVaultKey("audit");
  // This key authenticates the already externally sealed payload. It is not
  // an archive-encryption key and cannot open external custody ciphertext.
  const backupAuthenticationKey = deriveVaultKey("backup");
  const backupIntentKey = deriveVaultKey("backup-intent");
  const providerResponseReceiptKey = deriveVaultKey("provider-response-receipt");
  keyMaterial.fill(0);
  let destroyed = false;
  const providerResponseNativeSinkDrains = new Set();

  function nowIso() {
    const value = now();
    if (!(value instanceof Date) || Number.isNaN(value.getTime())) throw new Error("now returned an invalid Date");
    return value.toISOString();
  }

  function backupDestinationIdentity(stats) {
    return sha256(canonicalJson({
      domain: "hacker-bob/artifact-vault-backup-destination/v1",
      dev: stats.dev.toString(),
      ino: stats.ino.toString(),
      uid: stats.uid.toString(),
    }));
  }

  function backupIntentPath(backupRef) {
    if (typeof backupRef !== "string" || !BACKUP_REF_RE.test(backupRef)) {
      throw new Error("backup intent reference is invalid");
    }
    return path.join(backupIntentRoot, `${sha256(backupRef)}.json`);
  }

  function backupIntentAad(intent) {
    return canonicalJson({
      version: ARTIFACT_VAULT_SCHEMA_VERSION,
      purpose: "durable_backup_seal_intent",
      vault_id: vaultMetadata.vault_id,
      vault_slot: vaultMetadata.vault_slot,
      session_nucleus_hash: sessionNucleusHash,
      backup_ref: intent.backup_ref,
      backup_digest: intent.backup_digest,
      artifact_inventory_digest: intent.artifact_inventory_digest,
      seal_effect_ref: intent.seal_effect_ref,
      destination_identity_digest: intent.destination_identity_digest,
    });
  }

  function writeBackupIntentPayload(intent, serializedBackup) {
    const envelope = encryptAead(backupIntentKey, serializedBackup, backupIntentAad(intent));
    const encoded = Buffer.from(`${canonicalJson(envelope)}\n`, "utf8");
    if (encoded.length > MAX_BACKUP_INTENT_ENCODED_BYTES) {
      encoded.fill(0);
      throw new Error("backup seal intent payload exceeds its encrypted read ceiling");
    }
    const filePath = backupIntentPath(intent.backup_ref);
    try {
      if (!publishExclusivePrivate(filePath, encoded)) {
        throw new Error("backup seal intent payload already exists without a rooted intent");
      }
      return sha256(encoded);
    } finally {
      encoded.fill(0);
    }
  }

  function readBackupIntentPayload(intent) {
    const encoded = readPrivateFile(
      backupIntentPath(intent.backup_ref),
      "backup seal intent payload",
      MAX_BACKUP_INTENT_ENCODED_BYTES,
    );
    try {
      if (sha256(encoded) !== intent.payload_file_digest) {
        throw new Error("backup seal intent payload digest drifted from its anchored intent");
      }
      let envelope;
      try {
        envelope = JSON.parse(encoded.toString("utf8"));
      } catch {
        throw new Error("backup seal intent payload is unreadable or corrupt");
      }
      const plaintext = decryptAead(
        backupIntentKey,
        envelope,
        backupIntentAad(intent),
        "backup seal intent payload",
      );
      if (sha256(plaintext) !== intent.backup_digest) {
        plaintext.fill(0);
        throw new Error("backup seal intent plaintext drifted from its anchored digest");
      }
      return plaintext;
    } finally {
      encoded.fill(0);
    }
  }

  function deleteBackupIntentPayload(intent) {
    const filePath = backupIntentPath(intent.backup_ref);
    const stats = assertSafeRegularFile(filePath, "backup seal intent payload", { required: false });
    if (!stats) return;
    fs.unlinkSync(filePath);
    fsyncDirectory(backupIntentRoot);
  }

  function signIndex(payload) {
    return crypto.createHmac("sha256", indexKey).update(canonicalJson(payload)).digest("hex");
  }

  function encodeIndex(payload) {
    return `${canonicalJson({ payload, mac: signIndex(payload) })}\n`;
  }

  const indexAnchorContext = Object.freeze({
    version: ARTIFACT_VAULT_SCHEMA_VERSION,
    vault_id: vaultMetadata.vault_id,
    vault_slot: vaultMetadata.vault_slot,
    session_nucleus_hash: sessionNucleusHash,
  });

  function indexAnchorSnapshotAad(generation, indexDigest) {
    return canonicalJson({
      ...indexAnchorContext,
      purpose: "encrypted_index_recovery_snapshot",
      generation,
      index_digest: indexDigest,
    });
  }

  function normalizeIndexAnchorEnvelope(input, label) {
    assertClosedObject(input, label, ["algorithm", "nonce", "ciphertext", "tag"]);
    if (input.algorithm !== "aes-256-gcm"
      || typeof input.nonce !== "string" || typeof input.ciphertext !== "string"
      || typeof input.tag !== "string" || input.ciphertext.length > 48 * 1024 * 1024) {
      throw new Error(`${label} is invalid`);
    }
    const nonce = Buffer.from(input.nonce, "base64");
    const ciphertext = Buffer.from(input.ciphertext, "base64");
    const tag = Buffer.from(input.tag, "base64");
    if (nonce.length !== 12 || tag.length !== 16
      || nonce.toString("base64") !== input.nonce
      || ciphertext.toString("base64") !== input.ciphertext
      || tag.toString("base64") !== input.tag) {
      throw new Error(`${label} base64 encoding or AEAD dimensions are invalid`);
    }
    return Object.freeze({
      algorithm: input.algorithm,
      nonce: input.nonce,
      ciphertext: input.ciphertext,
      tag: input.tag,
    });
  }

  function normalizeIndexAnchorState(input, label = "index state anchor") {
    if (input == null) return null;
    assertClosedObject(input, label, [
      "version",
      "vault_id",
      "vault_slot",
      "session_nucleus_hash",
      "generation",
      "index_digest",
      "encrypted_index",
    ]);
    if (input.version !== ARTIFACT_VAULT_SCHEMA_VERSION
      || input.vault_id !== vaultMetadata.vault_id
      || input.vault_slot !== vaultMetadata.vault_slot
      || input.session_nucleus_hash !== sessionNucleusHash
      || !Number.isSafeInteger(input.generation) || input.generation < 0
      || !SHA256_RE.test(input.index_digest || "")) {
      throw new Error(`${label} is invalid or belongs to another vault`);
    }
    const encryptedIndex = normalizeIndexAnchorEnvelope(input.encrypted_index, `${label}.encrypted_index`);
    return Object.freeze({
      version: ARTIFACT_VAULT_SCHEMA_VERSION,
      vault_id: vaultMetadata.vault_id,
      vault_slot: vaultMetadata.vault_slot,
      session_nucleus_hash: sessionNucleusHash,
      generation: input.generation,
      index_digest: input.index_digest,
      encrypted_index: encryptedIndex,
    });
  }

  function readIndexAnchorState() {
    const state = normalizeIndexAnchorState(indexStateAnchor.readState(indexAnchorContext));
    if (state) {
      const snapshot = decryptIndexAnchorSnapshot(state);
      snapshot.fill(0);
    }
    return state;
  }

  function indexAnchorStateFor(generation, encoded) {
    const buffer = Buffer.isBuffer(encoded) ? encoded : Buffer.from(encoded, "utf8");
    const indexDigest = sha256(buffer);
    return Object.freeze({
      version: ARTIFACT_VAULT_SCHEMA_VERSION,
      vault_id: vaultMetadata.vault_id,
      vault_slot: vaultMetadata.vault_slot,
      session_nucleus_hash: sessionNucleusHash,
      generation,
      index_digest: indexDigest,
      encrypted_index: Object.freeze(encryptAead(
        indexAnchorKey,
        buffer,
        indexAnchorSnapshotAad(generation, indexDigest),
      )),
    });
  }

  function decryptIndexAnchorSnapshot(anchor, label = "external index state anchor") {
    const encoded = decryptAead(
      indexAnchorKey,
      anchor.encrypted_index,
      indexAnchorSnapshotAad(anchor.generation, anchor.index_digest),
      `${label} recovery snapshot`,
    );
    if (encoded.length > indexEncodedBytesCeiling || sha256(encoded) !== anchor.index_digest) {
      encoded.fill(0);
      throw new Error(`${label} recovery snapshot digest is invalid`);
    }
    return encoded;
  }

  function indexCommitError(message, outcome, cause) {
    const error = new Error(message, cause ? { cause } : undefined);
    Object.defineProperty(error, "index_commit_outcome", {
      value: outcome,
      enumerable: false,
    });
    return error;
  }

  function commitIndexAnchor(current, next) {
    let committed;
    let commitFailure = null;
    try {
      committed = indexStateAnchor.compareAndSet(Object.freeze({
        version: ARTIFACT_VAULT_SCHEMA_VERSION,
        vault_id: vaultMetadata.vault_id,
        vault_slot: vaultMetadata.vault_slot,
        session_nucleus_hash: sessionNucleusHash,
        expected_generation: current ? current.generation : null,
        expected_index_digest: current ? current.index_digest : null,
        next_state: next,
      }));
    } catch (error) {
      commitFailure = error;
    }
    let observed = null;
    let observationFailure = null;
    try {
      observed = readIndexAnchorState();
    } catch (error) {
      observationFailure = error;
    }
    if (committed !== true && observed && canonicalJson(observed) === canonicalJson(next)) return;
    if (committed !== true) {
      const outcome = committed === false ? "not_committed" : "ambiguous";
      throw indexCommitError(
        outcome === "not_committed"
          ? "external index state anchor compare-and-set failed"
          : "external index state anchor commit outcome is ambiguous",
        outcome,
        commitFailure || observationFailure,
      );
    }
    if (!observed || canonicalJson(observed) !== canonicalJson(next)) {
      throw indexCommitError(
        "external index state anchor publication could not be durably verified",
        "ambiguous",
        observationFailure,
      );
    }
  }

  function signDeletionLedger(payload) {
    return crypto.createHmac("sha256", auditKey).update(canonicalJson(payload)).digest("hex");
  }

  function encodeDeletionLedger(payload) {
    return `${canonicalJson({ payload, mac: signDeletionLedger(payload) })}\n`;
  }

  function emptyDeletionLedger() {
    return {
      version: ARTIFACT_VAULT_SCHEMA_VERSION,
      vault_id: vaultMetadata.vault_id,
      vault_slot: vaultMetadata.vault_slot,
      session_nucleus_hash: sessionNucleusHash,
      generation: 0,
      entries: {},
    };
  }

  const deletionAnchorContext = Object.freeze({
    version: ARTIFACT_VAULT_SCHEMA_VERSION,
    vault_id: vaultMetadata.vault_id,
    vault_slot: vaultMetadata.vault_slot,
    session_nucleus_hash: sessionNucleusHash,
  });

  function normalizeDeletionAnchorState(input, label = "deletion ledger anchor state") {
    if (input == null) return null;
    assertClosedObject(input, label, [
      "version",
      "vault_id",
      "vault_slot",
      "session_nucleus_hash",
      "generation",
      "ledger_digest",
      "receipts",
    ]);
    if (input.version !== ARTIFACT_VAULT_SCHEMA_VERSION
      || input.vault_id !== vaultMetadata.vault_id
      || input.vault_slot !== vaultMetadata.vault_slot
      || input.session_nucleus_hash !== sessionNucleusHash
      || !Number.isSafeInteger(input.generation) || input.generation < 0
      || !SHA256_RE.test(input.ledger_digest || "")
      || !Array.isArray(input.receipts) || input.receipts.length > 1_000_000) {
      throw new Error(`${label} is invalid or belongs to another vault`);
    }
    const receipts = input.receipts.map((receipt, index) => {
      assertClosedObject(receipt, `${label}.receipts[${index}]`, ["artifact_handle", "receipt_mac"]);
      if (!PUBLIC_ARTIFACT_HANDLE_RE.test(receipt.artifact_handle || "")
        || !SHA256_RE.test(receipt.receipt_mac || "")) {
        throw new Error(`${label}.receipts[${index}] is invalid`);
      }
      return Object.freeze({
        artifact_handle: receipt.artifact_handle,
        receipt_mac: receipt.receipt_mac,
      });
    }).sort((left, right) => left.artifact_handle.localeCompare(right.artifact_handle));
    if (new Set(receipts.map((receipt) => receipt.artifact_handle)).size !== receipts.length) {
      throw new Error(`${label}.receipts contains duplicate artifact handles`);
    }
    return Object.freeze({
      version: ARTIFACT_VAULT_SCHEMA_VERSION,
      vault_id: vaultMetadata.vault_id,
      vault_slot: vaultMetadata.vault_slot,
      session_nucleus_hash: sessionNucleusHash,
      generation: input.generation,
      ledger_digest: input.ledger_digest,
      receipts: Object.freeze(receipts),
    });
  }

  function readDeletionAnchorState() {
    return normalizeDeletionAnchorState(deletionLedgerAnchor.readState(deletionAnchorContext));
  }

  function deletionAnchorStateFor(ledger) {
    const receipts = Object.values(ledger.entries)
      .map((receipt) => Object.freeze({
        artifact_handle: receipt.artifact_handle,
        receipt_mac: receipt.receipt_mac,
      }))
      .sort((left, right) => left.artifact_handle.localeCompare(right.artifact_handle));
    return Object.freeze({
      version: ARTIFACT_VAULT_SCHEMA_VERSION,
      vault_id: vaultMetadata.vault_id,
      vault_slot: vaultMetadata.vault_slot,
      session_nucleus_hash: sessionNucleusHash,
      generation: ledger.generation,
      ledger_digest: sha256(encodeDeletionLedger(ledger)),
      receipts: Object.freeze(receipts),
    });
  }

  function commitDeletionAnchor(current, next) {
    const committed = deletionLedgerAnchor.compareAndSet(Object.freeze({
      version: ARTIFACT_VAULT_SCHEMA_VERSION,
      vault_id: vaultMetadata.vault_id,
      vault_slot: vaultMetadata.vault_slot,
      session_nucleus_hash: sessionNucleusHash,
      expected_generation: current ? current.generation : null,
      expected_ledger_digest: current ? current.ledger_digest : null,
      next_state: next,
    }));
    const observed = readDeletionAnchorState();
    if (committed !== true && observed && canonicalJson(observed) === canonicalJson(next)) {
      return;
    }
    if (committed !== true) {
      throw new Error("external deletion ledger anchor compare-and-set failed");
    }
    if (!observed || canonicalJson(observed) !== canonicalJson(next)) {
      throw new Error("external deletion ledger anchor did not durably publish the requested state");
    }
  }

  function synchronizeDeletionAnchor(ledger) {
    const desired = deletionAnchorStateFor(ledger);
    const current = readDeletionAnchorState();
    if (!current) {
      if (ledger.generation !== 0 || desired.receipts.length !== 0) {
        throw new Error("external deletion ledger anchor is missing for a non-genesis ledger");
      }
      commitDeletionAnchor(null, desired);
      return;
    }
    const desiredByHandle = new Map(desired.receipts.map((receipt) => [receipt.artifact_handle, receipt.receipt_mac]));
    for (const receipt of current.receipts) {
      if (desiredByHandle.get(receipt.artifact_handle) !== receipt.receipt_mac) {
        throw new Error("vault deletion ledger was rolled back or forked behind its external anchor");
      }
    }
    if (desired.generation < current.generation || desired.receipts.length < current.receipts.length) {
      throw new Error("vault deletion ledger generation was rolled back behind its external anchor");
    }
    if (desired.generation === current.generation) {
      if (canonicalJson(desired) !== canonicalJson(current)) {
        throw new Error("vault deletion ledger conflicts with its external anchor");
      }
      return;
    }
    if (desired.generation !== current.generation + 1
      || desired.receipts.length !== current.receipts.length + 1) {
      throw new Error("vault deletion ledger advanced outside the single-entry commit protocol");
    }
    commitDeletionAnchor(current, desired);
  }

  // Validate every extant half of the external enrollment before genesis can
  // mutate either half. This prevents a partial slot owned by another vault,
  // or a corrupt encrypted index anchor, from being paired with new state.
  readIndexAnchorState();
  readDeletionAnchorState();

  if (!fs.existsSync(deletionLedgerPath)) {
    const anchorState = readDeletionAnchorState();
    if (anchorState || fs.existsSync(indexPath)) {
      throw new Error("existing vault is missing its deletion ledger; operator recovery is required");
    }
    const encodedGenesisLedger = encodeDeletionLedger(emptyDeletionLedger());
    assertEncodedLifecycleCeiling(
      encodedGenesisLedger,
      deletionLedgerEncodedBytesCeiling,
      "vault deletion ledger genesis",
    );
    publishExclusivePrivate(deletionLedgerPath, encodedGenesisLedger);
  }
  repairExclusivePublication(deletionLedgerPath);

  function readDeletionLedger(index = null) {
    let wrapper;
    try {
      wrapper = JSON.parse(readPrivateFile(
        deletionLedgerPath,
        "vault deletion ledger",
        deletionLedgerEncodedBytesCeiling,
      ).toString("utf8"));
    } catch (error) {
      throw new Error(`vault deletion ledger is unreadable or corrupt: ${error.message}`);
    }
    if (!wrapper || typeof wrapper !== "object" || Array.isArray(wrapper)
      || !wrapper.payload || typeof wrapper.mac !== "string"
      || !constantTimeEqual(wrapper.mac, signDeletionLedger(wrapper.payload))) {
      throw new Error("vault deletion ledger authentication failed");
    }
    const payload = wrapper.payload;
    if (payload.version !== ARTIFACT_VAULT_SCHEMA_VERSION
      || payload.vault_id !== vaultMetadata.vault_id
      || payload.vault_slot !== vaultMetadata.vault_slot
      || payload.session_nucleus_hash !== sessionNucleusHash
      || !Number.isSafeInteger(payload.generation)
      || payload.entries == null || typeof payload.entries !== "object" || Array.isArray(payload.entries)) {
      throw new Error("vault deletion ledger schema or session binding is invalid");
    }
    for (const [handle, receipt] of Object.entries(payload.entries)) {
      if (!PUBLIC_ARTIFACT_HANDLE_RE.test(handle) || !receipt
        || receipt.artifact_handle !== handle || typeof receipt.receipt_mac !== "string") {
        throw new Error("vault deletion ledger contains an invalid receipt");
      }
      const { receipt_mac: receiptMac, ...receiptPayload } = receipt;
      assertClosedObject(receiptPayload, `vault deletion receipt ${handle}`, [
        "version",
        "artifact_handle",
        "session_nucleus_hash",
        "deleted_at",
        "reason_ref",
        "prior_record_digest",
        "deletion_kind",
        "current_store_erasure_kind",
        "external_backup_key_retirement",
        "backup_media_erasure_status",
      ]);
      if (receiptPayload.version !== ARTIFACT_VAULT_SCHEMA_VERSION
        || receiptPayload.session_nucleus_hash !== sessionNucleusHash
        || !SHA256_RE.test(receiptPayload.prior_record_digest || "")
        || receiptPayload.deletion_kind !== "managed_cryptographic_erasure"
        || receiptPayload.current_store_erasure_kind !== "deletion_ledger_key_unreachability"
        || receiptPayload.backup_media_erasure_status !== "not_attested") {
        throw new Error("vault deletion ledger contains an invalid erasure distinction");
      }
      if (typeof receiptPayload.deleted_at !== "string"
        || Number.isNaN(Date.parse(receiptPayload.deleted_at))
        || new Date(receiptPayload.deleted_at).toISOString() !== receiptPayload.deleted_at) {
        throw new Error("vault deletion ledger contains a non-canonical deletion timestamp");
      }
      assertOpaqueRef(receiptPayload.reason_ref, "vault deletion receipt reason_ref");
      const expected = crypto.createHmac("sha256", auditKey)
        .update(canonicalJson(receiptPayload))
        .digest("hex");
      if (!constantTimeEqual(receiptMac, expected)) {
        throw new Error("vault deletion ledger receipt authentication failed");
      }
      verifySerializedBackupKeyRetirementEvidence(
        backupKeyCustody,
        receiptPayload.external_backup_key_retirement,
        handle,
      );
      if (receiptPayload.external_backup_key_retirement.reason_ref
          !== receiptPayload.reason_ref
        || receiptPayload.external_backup_key_retirement.retired_at
          !== receiptPayload.deleted_at) {
        throw new Error("vault deletion receipt relabels external retirement reason or time");
      }
    }
    if (index) assertDeletionLedgerCustodyRoots(payload, index);
    synchronizeDeletionAnchor(payload);
    return payload;
  }

  function writeDeletionLedger(ledger) {
    const candidate = {
      ...ledger,
      generation: ledger.generation + 1,
    };
    const encoded = encodeDeletionLedger(candidate);
    assertEncodedLifecycleCeiling(
      encoded,
      deletionLedgerEncodedBytesCeiling,
      "vault deletion ledger mutation",
    );
    writeAtomicPrivate(deletionLedgerPath, encoded);
    synchronizeDeletionAnchor(candidate);
  }

  function emptyIndex() {
    return {
      version: ARTIFACT_VAULT_SCHEMA_VERSION,
      vault_id: vaultMetadata.vault_id,
      vault_slot: vaultMetadata.vault_slot,
      session_nucleus_hash: sessionNucleusHash,
      generation: 0,
      object_generation: "objects",
      reservations: {},
      records: {},
      references: {},
      reservation_outcomes: {},
      batches: {},
      backup_custody: {
        version: ARTIFACT_VAULT_SCHEMA_VERSION,
        archives: {},
        deletion_intents: {},
        restore_intents: {},
      },
      tombstones: [],
    };
  }

  if (!fs.existsSync(indexPath)) {
    if (!readIndexAnchorState()) {
      const encodedGenesisIndex = encodeIndex(emptyIndex());
      assertEncodedLifecycleCeiling(
        encodedGenesisIndex,
        indexEncodedBytesCeiling,
        "vault index genesis",
      );
      publishExclusivePrivate(indexPath, encodedGenesisIndex);
    }
  }
  repairExclusivePublication(indexPath);
  // Initializing the external anchor last makes local genesis resumable while
  // ensuring any completed vault can never silently regenerate deleted state.
  readDeletionLedger();

  function isCanonicalTimestamp(value) {
    return typeof value === "string"
      && !Number.isNaN(Date.parse(value))
      && new Date(value).toISOString() === value;
  }

  function migrateLegacyTransformAttempt(batchRef, batch, label) {
    if (!batch || batch.state != null) return batch;
    if (batch.version !== ARTIFACT_VAULT_SCHEMA_VERSION
      || batch.batch_ref !== batchRef
      || !SHA256_RE.test(batch.binding_digest || "")
      || !Array.isArray(batch.artifact_handles)
      || batch.artifact_handles.length < 1
      || batch.artifact_handles.length > MAX_TRANSFORM_OUTPUTS
      || new Set(batch.artifact_handles).size !== batch.artifact_handles.length
      || batch.artifact_handles.some((handle) => !PUBLIC_ARTIFACT_HANDLE_RE.test(handle))
      || !isCanonicalTimestamp(batch.committed_at)) {
      throw new Error(`${label} transform batch index contains an invalid legacy entry`);
    }
    return {
      version: ARTIFACT_VAULT_SCHEMA_VERSION,
      batch_ref: batchRef,
      binding_digest: batch.binding_digest,
      state: "committed",
      claim_token_digest: sha256(`legacy-transform-claim\0${batchRef}\0${batch.binding_digest}`),
      output_count: batch.artifact_handles.length,
      claimed_at: batch.committed_at,
      committed_at: batch.committed_at,
      failed_at: null,
      failure_digest: null,
      failure_kind: null,
      adjudication_ref: null,
      input_handles: [],
      deletion_ledger_generation_at_claim: 0,
      output_reservation_handles: [],
      output_metadata_digests: [],
      artifact_handles: [...batch.artifact_handles],
      reserved_index_bytes: 0,
    };
  }

  function memberArchiveProjection(archive) {
    return Object.freeze({
      backup_ref: archive.backup_ref,
      backup_digest: archive.backup_digest,
      artifact_inventory_digest: archive.artifact_inventory_digest,
      seal_effect_ref: archive.seal_effect_ref,
      seal_ref: archive.seal_ref,
      sealed_archive_digest: archive.sealed_archive_digest,
    });
  }

  function ensureBackupCustodyIndex(payload, label, {
    allow_next_completed_generation: allowNextCompletedGeneration = false,
  } = {}) {
    if (payload.backup_custody == null) {
      payload.backup_custody = {
        version: ARTIFACT_VAULT_SCHEMA_VERSION,
        archives: {},
        deletion_intents: {},
        restore_intents: {},
      };
    }
    const custody = payload.backup_custody;
    if (custody && typeof custody === "object" && !Array.isArray(custody)
      && custody.restore_intents == null) custody.restore_intents = {};
    if (!custody || typeof custody !== "object" || Array.isArray(custody)
      || custody.version !== ARTIFACT_VAULT_SCHEMA_VERSION
      || !custody.archives || typeof custody.archives !== "object"
      || Array.isArray(custody.archives)
      || !custody.deletion_intents || typeof custody.deletion_intents !== "object"
      || Array.isArray(custody.deletion_intents)
      || !custody.restore_intents || typeof custody.restore_intents !== "object"
      || Array.isArray(custody.restore_intents)
      || Object.keys(custody.archives).length > MAX_BACKUP_ARCHIVES
      || Object.keys(custody.deletion_intents).length > maxArtifacts
      || Object.keys(custody.restore_intents).length > MAX_BACKUP_ARCHIVES
      || Object.values(custody.restore_intents)
        .filter((intent) => intent && intent.state !== "released").length > 1) {
      throw new Error(`${label} backup custody index is invalid`);
    }
    const membershipCounts = new Map();
    const destinationIdentities = new Set();
    for (const [backupRef, archive] of Object.entries(custody.archives)) {
      if (!BACKUP_REF_RE.test(backupRef) || !archive || typeof archive !== "object"
        || Array.isArray(archive)
        || archive.version !== ARTIFACT_VAULT_SCHEMA_VERSION
        || archive.backup_ref !== backupRef
        || !["prepared", "sealed", "published", "revoked"].includes(archive.state)
        || !SHA256_RE.test(archive.backup_digest || "")
        || !SHA256_RE.test(archive.artifact_inventory_digest || "")
        || !BACKUP_EFFECT_REF_RE.test(archive.seal_effect_ref || "")
        || !SHA256_RE.test(archive.destination_identity_digest || "")
        || !isCanonicalTimestamp(archive.created_at)
        || !Number.isSafeInteger(archive.reserved_index_bytes)
        || archive.reserved_index_bytes < 0
        || archive.reserved_index_bytes > BACKUP_INTENT_INDEX_RESERVATION_BYTES) {
        throw new Error(`${label} backup custody archive entry is invalid`);
      }
      if (destinationIdentities.has(archive.destination_identity_digest)) {
        throw new Error(`${label} backup custody archive reuses a destination identity`);
      }
      destinationIdentities.add(archive.destination_identity_digest);
      const inventory = normalizeArtifactInventory(
        archive.artifact_inventory,
        `${label} backup custody archive ${backupRef} inventory`,
      );
      if (canonicalJson(inventory) !== canonicalJson(archive.artifact_inventory)
        || sha256(canonicalJson(inventory)) !== archive.artifact_inventory_digest) {
        throw new Error(`${label} backup custody archive inventory binding is invalid`);
      }
      if (archive.state === "prepared") {
        if (!SHA256_RE.test(archive.payload_file_digest || "")
          || archive.reserved_index_bytes !== BACKUP_INTENT_INDEX_RESERVATION_BYTES
          || archive.seal_ref !== null || archive.custody_format !== null
          || archive.sealed_archive_digest !== null
          || archive.revocation_effect_ref !== null || archive.revoked_at !== null) {
          throw new Error(`${label} prepared backup custody archive is invalid`);
        }
      } else {
        if (!BACKUP_SEAL_REF_RE.test(archive.seal_ref || "")
          || typeof archive.custody_format !== "string"
          || !/^[a-z][a-z0-9._-]{0,127}$/.test(archive.custody_format)
          || !SHA256_RE.test(archive.sealed_archive_digest || "")
          || archive.reserved_index_bytes !== 0
          || archive.payload_file_digest !== null) {
          throw new Error(`${label} terminal backup custody archive is invalid`);
        }
        if (archive.state === "revoked") {
          if (!BACKUP_EFFECT_REF_RE.test(archive.revocation_effect_ref || "")
            || !isCanonicalTimestamp(archive.revoked_at)) {
            throw new Error(`${label} revoked backup custody archive is invalid`);
          }
        } else if (archive.revocation_effect_ref !== null || archive.revoked_at !== null) {
          throw new Error(`${label} active backup custody archive has revocation fields`);
        }
      }
      for (const artifact of inventory) {
        const count = (membershipCounts.get(artifact.artifact_handle) || 0) + 1;
        if (count > MAX_MEMBER_ARCHIVES_PER_ARTIFACT) {
          throw new Error(`${label} artifact exceeds its bounded backup membership registry`);
        }
        membershipCounts.set(artifact.artifact_handle, count);
      }
    }
    for (const [artifactHandle, intent] of Object.entries(custody.deletion_intents)) {
      assertClosedObject(intent, `${label} backup custody deletion intent ${artifactHandle}`, [
        "version",
        "artifact_handle",
        "reason_ref",
        "requested_at",
        "prior_record_digest",
        "retirement_effect_ref",
        "member_archive_registry",
        "member_archive_registry_digest",
        "deletion_ledger_generation",
        "projected_ledger_encoded_bytes",
      ]);
      if (!PUBLIC_ARTIFACT_HANDLE_RE.test(artifactHandle)
        || intent.version !== ARTIFACT_VAULT_SCHEMA_VERSION
        || intent.artifact_handle !== artifactHandle
        || !SHA256_RE.test(intent.prior_record_digest || "")
        || !BACKUP_EFFECT_REF_RE.test(intent.retirement_effect_ref || "")
        || !isCanonicalTimestamp(intent.requested_at)
        || !SHA256_RE.test(intent.member_archive_registry_digest || "")
        || !Number.isSafeInteger(intent.deletion_ledger_generation)
        || intent.deletion_ledger_generation < 0
        || !Number.isSafeInteger(intent.projected_ledger_encoded_bytes)
        || intent.projected_ledger_encoded_bytes < 1
        || intent.projected_ledger_encoded_bytes > deletionLedgerEncodedBytesCeiling) {
        throw new Error(`${label} backup custody deletion intent is invalid`);
      }
      assertOpaqueRef(intent.reason_ref, `${label} backup custody deletion intent reason_ref`);
      const registry = intent.member_archive_registry;
      if (!Array.isArray(registry)
        || registry.length > MAX_MEMBER_ARCHIVES_PER_ARTIFACT
        || new Set(registry.map((entry) => entry && entry.backup_ref)).size !== registry.length
        || sha256(canonicalJson(registry)) !== intent.member_archive_registry_digest) {
        throw new Error(`${label} backup custody deletion intent registry is invalid`);
      }
      const expectedRegistry = Object.values(custody.archives)
        .filter((archive) => archive.state !== "prepared"
          && archive.artifact_inventory.some((entry) => entry.artifact_handle === artifactHandle))
        .map(memberArchiveProjection)
        .sort((left, right) => left.backup_ref.localeCompare(right.backup_ref));
      if (canonicalJson(registry) !== canonicalJson(expectedRegistry)) {
        throw new Error(`${label} backup custody deletion intent drifted from its rooted membership`);
      }
    }
    for (const [backupRef, intent] of Object.entries(custody.restore_intents)) {
      assertClosedObject(intent, `${label} backup custody restore intent ${backupRef}`, [
        "version",
        "state",
        "backup_ref",
        "backup_digest",
        "artifact_inventory_digest",
        "seal_effect_ref",
        "seal_ref",
        "source_identity_digest",
        "restore_ref",
        "acquire_effect_ref",
        "release_effect_ref",
        "requested_at",
        "restored_generation",
        "allow_replace",
        "allow_corrupt_index",
        "completed_index_generation",
        "receipt",
      ]);
      if (!BACKUP_REF_RE.test(backupRef)
        || intent.version !== ARTIFACT_VAULT_SCHEMA_VERSION
        || !["prepared", "committed", "released"].includes(intent.state)
        || intent.backup_ref !== backupRef
        || !SHA256_RE.test(intent.backup_digest || "")
        || !SHA256_RE.test(intent.artifact_inventory_digest || "")
        || !BACKUP_EFFECT_REF_RE.test(intent.seal_effect_ref || "")
        || !BACKUP_SEAL_REF_RE.test(intent.seal_ref || "")
        || !SHA256_RE.test(intent.source_identity_digest || "")
        || !BACKUP_RESTORE_REF_RE.test(intent.restore_ref || "")
        || !BACKUP_EFFECT_REF_RE.test(intent.acquire_effect_ref || "")
        || !BACKUP_EFFECT_REF_RE.test(intent.release_effect_ref || "")
        || !isCanonicalTimestamp(intent.requested_at)
        || !/^objects-restore-[a-f0-9]{24}$/.test(intent.restored_generation || "")
        || typeof intent.allow_replace !== "boolean"
        || typeof intent.allow_corrupt_index !== "boolean"
        || (intent.state === "released"
          ? (!Number.isSafeInteger(intent.completed_index_generation)
            || intent.completed_index_generation < 1
            || (intent.completed_index_generation > payload.generation
              && (!allowNextCompletedGeneration
                || intent.completed_index_generation !== payload.generation + 1)))
          : intent.completed_index_generation !== null)) {
        throw new Error(`${label} backup custody restore intent is invalid`);
      }
      const archive = custody.archives[backupRef];
      if (!archive || archive.state === "prepared"
        || archive.backup_digest !== intent.backup_digest
        || archive.artifact_inventory_digest !== intent.artifact_inventory_digest
        || archive.seal_effect_ref !== intent.seal_effect_ref
        || archive.seal_ref !== intent.seal_ref) {
        throw new Error(`${label} backup custody restore intent is not rooted in an exact archive`);
      }
      if (intent.state === "prepared") {
        if (intent.receipt !== null) {
          throw new Error(`${label} prepared backup custody restore intent has a receipt`);
        }
        continue;
      }
      assertClosedObject(intent.receipt, `${label} backup custody restore receipt`, [
        "version",
        "backup_ref",
        "restored_at",
        "restored_generation",
        "prior_index_corrupt",
        "replaced_live_state",
        "artifact_count",
        "recovery_receipt",
      ]);
      const { recovery_receipt: recoveryReceipt, ...receiptPayload } = intent.receipt;
      const receiptIsCurrentRestore = intent.state === "committed"
        || (intent.state === "released"
          && intent.completed_index_generation === payload.generation);
      if (intent.receipt.version !== ARTIFACT_VAULT_SCHEMA_VERSION
        || intent.receipt.backup_ref !== backupRef
        || intent.receipt.restored_at !== intent.requested_at
        || intent.receipt.restored_generation !== intent.restored_generation
        || typeof intent.receipt.prior_index_corrupt !== "boolean"
        || typeof intent.receipt.replaced_live_state !== "boolean"
        || !Number.isSafeInteger(intent.receipt.artifact_count)
        || intent.receipt.artifact_count < 0
        || intent.receipt.artifact_count > maxArtifacts
        || !SHA256_RE.test(recoveryReceipt || "")
        || !constantTimeEqual(
          recoveryReceipt,
          crypto.createHmac("sha256", auditKey)
            .update(canonicalJson(receiptPayload))
            .digest("hex"),
        )
        || (receiptIsCurrentRestore
          && (payload.object_generation !== intent.restored_generation
            || Object.keys(payload.records).length !== intent.receipt.artifact_count))) {
        throw new Error(`${label} committed backup custody restore receipt is invalid`);
      }
    }
    return custody;
  }

  function assertDeletionLedgerCustodyRoots(ledger, index) {
    const custody = ensureBackupCustodyIndex(index, "vault deletion ledger custody root");
    for (const [artifactHandle, receipt] of Object.entries(ledger.entries)) {
      const rootedRegistry = Object.values(custody.archives)
        .filter((archive) => archive.state !== "prepared"
          && archive.artifact_inventory.some((entry) => entry.artifact_handle === artifactHandle))
        .map(memberArchiveProjection)
        .sort((left, right) => left.backup_ref.localeCompare(right.backup_ref));
      const retirement = receipt.external_backup_key_retirement;
      const observedRegistry = retirement.revoked_archives.map((archive) => ({
        backup_ref: archive.backup_ref,
        backup_digest: archive.backup_digest,
        artifact_inventory_digest: archive.artifact_inventory_digest,
        seal_effect_ref: archive.seal_effect_ref,
        seal_ref: archive.seal_ref,
        sealed_archive_digest: archive.sealed_archive_digest,
      })).sort((left, right) => left.backup_ref.localeCompare(right.backup_ref));
      const rootedDigest = sha256(canonicalJson(rootedRegistry));
      if (retirement.member_archive_registry_digest !== rootedDigest
        || canonicalJson(observedRegistry) !== canonicalJson(rootedRegistry)) {
        throw new Error("vault deletion receipt is not complete for its independently rooted backup registry");
      }
    }
  }

  function validateBatchIndex(payload, label, options) {
    ensureBackupCustodyIndex(payload, label, options);
    if (payload.batches == null) payload.batches = {};
    if (typeof payload.batches !== "object" || Array.isArray(payload.batches)
      || Object.keys(payload.batches).length > MAX_TRANSFORM_ATTEMPTS) {
      throw new Error(`${label} transform batch index is invalid`);
    }
    const claimedArtifactHandles = new Set();
    for (const [batchRef, inputBatch] of Object.entries(payload.batches)) {
      const batch = migrateLegacyTransformAttempt(batchRef, inputBatch, label);
      if (batch !== inputBatch) payload.batches[batchRef] = batch;
      if (!TRANSFORM_BATCH_REF_RE.test(batchRef) || !batch
        || batch.version !== ARTIFACT_VAULT_SCHEMA_VERSION
        || batch.batch_ref !== batchRef
        || !SHA256_RE.test(batch.binding_digest || "")
        || !["claimed", "committed", "failed"].includes(batch.state)
        || !SHA256_RE.test(batch.claim_token_digest || "")
        || !Number.isSafeInteger(batch.output_count)
        || batch.output_count < 1
        || batch.output_count > MAX_TRANSFORM_OUTPUTS
        || !isCanonicalTimestamp(batch.claimed_at)
        || !Array.isArray(batch.input_handles)
        || batch.input_handles.length > 64
        || new Set(batch.input_handles).size !== batch.input_handles.length
        || batch.input_handles.some((handle) => !PUBLIC_ARTIFACT_HANDLE_RE.test(handle))
        || !Number.isSafeInteger(batch.deletion_ledger_generation_at_claim)
        || batch.deletion_ledger_generation_at_claim < 0
        || !Array.isArray(batch.output_reservation_handles)
        || batch.output_reservation_handles.length > MAX_TRANSFORM_OUTPUTS
        || new Set(batch.output_reservation_handles).size !== batch.output_reservation_handles.length
        || batch.output_reservation_handles.some((handle) => !PUBLIC_RESERVATION_HANDLE_RE.test(handle))
        || !Array.isArray(batch.output_metadata_digests)
        || batch.output_metadata_digests.length > MAX_TRANSFORM_OUTPUTS
        || batch.output_metadata_digests.some((digest) => !SHA256_RE.test(digest || ""))
        || !Array.isArray(batch.artifact_handles)
        || batch.artifact_handles.length > MAX_TRANSFORM_OUTPUTS
        || new Set(batch.artifact_handles).size !== batch.artifact_handles.length
        || batch.artifact_handles.some((handle) => !PUBLIC_ARTIFACT_HANDLE_RE.test(handle))
        || !Number.isSafeInteger(batch.reserved_index_bytes)
        || batch.reserved_index_bytes < 0
        || batch.reserved_index_bytes > MAX_TRANSFORM_INDEX_RESERVATION_BYTES) {
        throw new Error(`${label} transform batch index contains an invalid entry`);
      }
      if (batch.state === "claimed") {
        if (batch.input_handles.length < 1
          || batch.output_reservation_handles.length !== batch.output_count
          || batch.output_metadata_digests.length !== batch.output_count
          || batch.artifact_handles.length !== 0
          || batch.committed_at !== null || batch.failed_at !== null
          || batch.failure_digest !== null || batch.failure_kind !== null
          || batch.adjudication_ref !== null
          || batch.reserved_index_bytes < 1) {
          throw new Error(`${label} claimed transform attempt has invalid terminal fields`);
        }
      } else if (batch.state === "committed") {
        if (batch.artifact_handles.length !== batch.output_count
          || !isCanonicalTimestamp(batch.committed_at)
          || batch.failed_at !== null || batch.failure_digest !== null
          || batch.failure_kind !== null || batch.adjudication_ref !== null
          || batch.reserved_index_bytes !== 0) {
          throw new Error(`${label} committed transform attempt has invalid terminal fields`);
        }
        for (const artifactHandle of batch.artifact_handles) {
          if (claimedArtifactHandles.has(artifactHandle)) {
            throw new Error(`${label} transform batch index has a multiply claimed artifact`);
          }
          claimedArtifactHandles.add(artifactHandle);
        }
      } else if (!isCanonicalTimestamp(batch.failed_at)
        || batch.committed_at !== null || batch.artifact_handles.length !== 0
        || !SHA256_RE.test(batch.failure_digest || "")
        || typeof batch.failure_kind !== "string"
        || !/^[a-z][a-z0-9._-]{0,63}$/.test(batch.failure_kind)
        || (batch.adjudication_ref !== null
          && (typeof batch.adjudication_ref !== "string"
            || !/^[a-z][a-z0-9._-]{0,63}:[A-Za-z0-9][A-Za-z0-9._:-]{0,190}$/.test(batch.adjudication_ref)))
        || batch.reserved_index_bytes !== 0) {
        throw new Error(`${label} failed transform attempt has invalid terminal fields`);
      }
      if (batch.state !== "committed" && batch.artifact_handles.length !== 0) {
        throw new Error(`${label} non-committed transform attempt claims output artifacts`);
      }
      if (batch.state === "committed") {
        for (const artifactHandle of batch.artifact_handles) {
          if (!PUBLIC_ARTIFACT_HANDLE_RE.test(artifactHandle)) {
            throw new Error(`${label} committed transform attempt has an invalid output handle`);
          }
        }
      }
    }
    if (payload.reservation_outcomes == null) payload.reservation_outcomes = {};
    if (typeof payload.reservation_outcomes !== "object"
      || Array.isArray(payload.reservation_outcomes)
      || Object.keys(payload.reservation_outcomes).length > 1_000_000) {
      throw new Error(`${label} reservation outcome index is invalid`);
    }
    for (const [reservationHandle, outcome] of Object.entries(payload.reservation_outcomes)) {
      if (!PUBLIC_RESERVATION_HANDLE_RE.test(reservationHandle) || !outcome
        || outcome.version !== ARTIFACT_VAULT_SCHEMA_VERSION
        || outcome.reservation_handle !== reservationHandle
        || !["consumed", "released", "expired"].includes(outcome.state)
        || !SHA256_RE.test(outcome.binding_digest || "")
        || typeof outcome.reservation_ref !== "string"
        || typeof outcome.terminal_at !== "string"
        || Number.isNaN(Date.parse(outcome.terminal_at))
        || new Date(outcome.terminal_at).toISOString() !== outcome.terminal_at) {
        throw new Error(`${label} reservation outcome index contains an invalid entry`);
      }
      if (outcome.state === "consumed"
        && !PUBLIC_ARTIFACT_HANDLE_RE.test(outcome.artifact_handle || "")) {
        throw new Error(`${label} consumed reservation outcome has an invalid artifact handle`);
      }
      if (outcome.state !== "consumed" && outcome.artifact_handle != null) {
        throw new Error(`${label} terminal reservation outcome has an unexpected artifact handle`);
      }
    }
  }

  function parseIndexBuffer(encoded, label = "vault index") {
    let wrapper;
    try {
      wrapper = JSON.parse(encoded.toString("utf8"));
    } catch (error) {
      throw new Error(`${label} is unreadable or corrupt: ${error.message}`);
    }
    if (!wrapper || typeof wrapper !== "object" || Array.isArray(wrapper)
      || !wrapper.payload || typeof wrapper.mac !== "string"
      || !constantTimeEqual(wrapper.mac, signIndex(wrapper.payload))) {
      throw new Error(`${label} authentication failed`);
    }
    const payload = wrapper.payload;
    if (payload.version !== ARTIFACT_VAULT_SCHEMA_VERSION
      || payload.vault_id !== vaultMetadata.vault_id
      || payload.vault_slot !== vaultMetadata.vault_slot
      || payload.session_nucleus_hash !== sessionNucleusHash
      || !Number.isSafeInteger(payload.generation)
      || typeof payload.object_generation !== "string"
      || !OBJECT_GENERATION_RE.test(payload.object_generation)
      || !payload.reservations || !payload.records || !payload.references
      || !Array.isArray(payload.tombstones)) {
      throw new Error("vault index schema or session binding is invalid");
    }
    // v1 vaults created before atomic transform batches did not carry this
    // map. Its absence is the sole in-version migration; any present value is
    // validated as authenticated state before use.
    validateBatchIndex(payload, "vault");
    return payload;
  }

  function readIndex() {
    const anchor = readIndexAnchorState();
    let encoded;
    let payload;
    try {
      encoded = readPrivateFile(indexPath, "vault index", indexEncodedBytesCeiling);
      payload = parseIndexBuffer(encoded);
    } catch (localError) {
      if (!anchor) throw localError;
      encoded = decryptIndexAnchorSnapshot(anchor);
      try {
        payload = parseIndexBuffer(encoded, "externally anchored vault index");
      } catch (error) {
        encoded.fill(0);
        throw error;
      }
      if (payload.generation !== anchor.generation
        || sha256(encoded) !== anchor.index_digest) {
        encoded.fill(0);
        throw new Error("external index state anchor contains an inconsistent snapshot");
      }
      writeAtomicPrivate(indexPath, encoded);
    }
    const localState = indexAnchorStateFor(payload.generation, encoded);
    if (!anchor) {
      const isGenesis = payload.generation === 0
        && Object.keys(payload.reservations).length === 0
        && Object.keys(payload.records).length === 0
        && Object.keys(payload.references).length === 0
        && Object.keys(payload.batches).length === 0
        && payload.tombstones.length === 0;
      if (!isGenesis) {
        throw new Error("external index state anchor is missing for a non-genesis index");
      }
      commitIndexAnchor(null, localState);
      return payload;
    }
    if (localState.index_digest !== anchor.index_digest
      || localState.generation !== anchor.generation) {
      if (anchor.generation > localState.generation) {
        const anchoredEncoded = decryptIndexAnchorSnapshot(anchor);
        let anchoredPayload;
        try {
          anchoredPayload = parseIndexBuffer(anchoredEncoded, "externally anchored vault index");
        } catch (error) {
          anchoredEncoded.fill(0);
          throw error;
        }
        if (anchoredPayload.generation !== anchor.generation
          || sha256(anchoredEncoded) !== anchor.index_digest) {
          anchoredEncoded.fill(0);
          throw new Error("external index state anchor contains an inconsistent snapshot");
        }
        writeAtomicPrivate(indexPath, anchoredEncoded);
        return anchoredPayload;
      }
      throw new Error("vault index was rolled back or forked behind its external anchor");
    }
    return payload;
  }

  function pruneBatches(index) {
    if (index.batches == null) index.batches = {};
    // Attempt bindings are permanent replay fences. Retention may remove an
    // output record, but never the fact that this attempt already executed.
  }

  function reservedTransformIndexBytes(index) {
    let total = 0;
    for (const attempt of Object.values(index.batches || {})) {
      if (attempt.state !== "claimed") continue;
      if (total > Number.MAX_SAFE_INTEGER - attempt.reserved_index_bytes) {
        throw new Error("transform attempt index reservations exceed safe accounting");
      }
      total += attempt.reserved_index_bytes;
    }
    const custody = ensureBackupCustodyIndex(index, "vault capacity projection");
    for (const archive of Object.values(custody.archives)) {
      if (total > Number.MAX_SAFE_INTEGER - archive.reserved_index_bytes) {
        throw new Error("backup custody index reservations exceed safe accounting");
      }
      total += archive.reserved_index_bytes;
    }
    return total;
  }

  function reconcileBackupIntentFiles(index) {
    const custody = ensureBackupCustodyIndex(index, "backup intent recovery");
    const expected = new Map();
    for (const archive of Object.values(custody.archives)) {
      if (archive.state !== "prepared") continue;
      expected.set(path.basename(backupIntentPath(archive.backup_ref)), archive);
    }
    let directoryChanged = false;
    let indexChanged = false;
    const rootedPayloadsToDelete = new Set();
    for (const entry of fs.readdirSync(backupIntentRoot)) {
      const filePath = path.join(backupIntentRoot, entry);
      const archive = expected.get(entry);
      if (!archive) {
        assertSafeRegularFile(filePath, "unrooted backup intent payload");
        fs.unlinkSync(filePath);
        directoryChanged = true;
        continue;
      }
      const encoded = readPrivateFile(
        filePath,
        "rooted backup intent payload",
        MAX_BACKUP_INTENT_ENCODED_BYTES,
      );
      try {
        if (sha256(encoded) !== archive.payload_file_digest) {
          rootedPayloadsToDelete.add(filePath);
          continue;
        }
      } finally {
        encoded.fill(0);
      }
      expected.delete(entry);
    }

    // A missing/corrupt prepared payload is not automatically fatal. The
    // independently durable custodian may already hold the exact seal after a
    // crash or lost acknowledgement. Reconcile that effect before either
    // advancing to sealed or discarding a definitively effect-free intent.
    for (const [entry, archive] of expected) {
      const observed = readBackupArchiveState(backupKeyCustody, {
        backup_ref: archive.backup_ref,
        backup_digest: archive.backup_digest,
        artifact_inventory_digest: archive.artifact_inventory_digest,
        seal_effect_ref: archive.seal_effect_ref,
      });
      if (!observed) {
        delete custody.archives[archive.backup_ref];
      } else {
        archive.state = observed.status === "active" ? "sealed" : "revoked";
        archive.reserved_index_bytes = 0;
        archive.payload_file_digest = null;
        archive.seal_ref = observed.seal_ref;
        archive.custody_format = observed.custody_format;
        archive.sealed_archive_digest = observed.sealed_archive_digest;
        archive.revocation_effect_ref = observed.revocation_effect_ref;
        archive.revoked_at = observed.revoked_at;
      }
      indexChanged = true;
      const filePath = path.join(backupIntentRoot, entry);
      if (fs.existsSync(filePath)) rootedPayloadsToDelete.add(filePath);
    }
    if (indexChanged) writeIndex(index);
    for (const filePath of rootedPayloadsToDelete) {
      const stats = assertSafeRegularFile(filePath, "reconciled backup intent payload", {
        required: false,
      });
      if (!stats) continue;
      fs.unlinkSync(filePath);
      directoryChanged = true;
    }
    if (directoryChanged) fsyncDirectory(backupIntentRoot);
  }

  function objectRootFor(index, { create = false } = {}) {
    if (!index || typeof index.object_generation !== "string"
      || !OBJECT_GENERATION_RE.test(index.object_generation)) {
      throw new Error("vault object generation is invalid");
    }
    const generationRoot = path.join(root, index.object_generation);
    if (create) assertPrivateDirectory(generationRoot);
    else {
      const stats = fs.lstatSync(generationRoot);
      if (!stats.isDirectory() || stats.isSymbolicLink()) {
        throw new Error("vault object generation must be a real directory");
      }
    }
    return generationRoot;
  }

  function writeIndex(index, {
    allow_restore_intent_mutation: allowRestoreIntentMutation = false,
    allow_next_completed_generation: allowNextCompletedGeneration = false,
  } = {}) {
    const priorGeneration = index.generation;
    try {
      validateBatchIndex(index, "vault commit", {
        allow_next_completed_generation: allowNextCompletedGeneration,
      });
    } catch (error) {
      throw indexCommitError(`vault index mutation is invalid: ${error.message}`, "not_committed", error);
    }
    if (!allowRestoreIntentMutation
      && Object.values(index.backup_custody.restore_intents)
        .some((intent) => intent.state !== "released")) {
      throw indexCommitError(
        "vault mutation is blocked by a pending backup-restore custody intent",
        "not_committed",
      );
    }
    let current;
    try {
      current = readIndexAnchorState();
    } catch (error) {
      throw indexCommitError("external index state anchor is unreadable before commit", "not_committed", error);
    }
    if (!current || current.generation !== priorGeneration) {
      throw indexCommitError("vault index anchor is absent or stale before commit", "not_committed");
    }
    index.generation = priorGeneration + 1;
    const encoded = Buffer.from(encodeIndex(index), "utf8");
    const reservedIndexBytes = reservedTransformIndexBytes(index);
    if (encoded.length > indexEncodedBytesCeiling
      || reservedIndexBytes > indexEncodedBytesCeiling - encoded.length) {
      index.generation = priorGeneration;
      throw indexCommitError(
        "vault index mutation exceeds its configured read ceiling after transform attempt reservations",
        "not_committed",
      );
    }
    const next = indexAnchorStateFor(index.generation, encoded);
    try {
      commitIndexAnchor(current, next);
    } catch (error) {
      if (error.index_commit_outcome === "not_committed") index.generation = priorGeneration;
      throw error;
    }
    try {
      writeAtomicPrivate(indexPath, encoded);
      return Object.freeze({ committed: true, local_mirror_synced: true });
    } catch (error) {
      // The external anchor is the durable commit point. A failed local mirror
      // must never turn a committed mutation into an apparent failure that a
      // caller could compensate by deleting its newly reachable objects.
      return Object.freeze({
        committed: true,
        local_mirror_synced: false,
        local_mirror_error: error.message || String(error),
      });
    }
  }

  // Initializing the index anchor after the parser exists completes resumable
  // genesis and makes all subsequent index mutations anchor-first. Startup
  // reconciliation participates in the same cross-process exclusion as every
  // operation so it cannot delete another process's pre-anchor staged payload.
  // A held lock skips startup cleanup so the returned operator object can still
  // perform explicit stale-lock recovery after a crashed owner.
  tryWithLock(() => reconcileBackupIntentFiles(readIndex()));

  function tryWithLock(callback) {
    const lockPayload = `${canonicalJson({ pid: process.pid, acquired_at: nowIso() })}\n`;
    if (!publishExclusivePrivate(lockPath, lockPayload)) {
      return Object.freeze({ acquired: false, value: undefined });
    }
    try {
      return Object.freeze({ acquired: true, value: callback() });
    } finally {
      try { fs.unlinkSync(lockPath); } catch {}
    }
  }

  function withLock(callback) {
    const result = tryWithLock(callback);
    if (!result.acquired) {
      throw new Error("vault is locked; recovery is operator-owned");
    }
    return result.value;
  }

  function reservationBindingDigest(request) {
    return sha256(canonicalJson(request));
  }

  function reservationIdentity(request) {
    const binding = canonicalJson({
      version: ARTIFACT_VAULT_SCHEMA_VERSION,
      session_nucleus_hash: sessionNucleusHash,
      reservation_ref: request.reservation_ref,
    });
    const derive = (label, encoding) => crypto.createHmac("sha256", auditKey)
      .update(label)
      .update("\0")
      .update(binding)
      .digest(encoding);
    return Object.freeze({
      reservation_handle: `vault-reservation:v1:${derive("reservation-handle", "base64url")}`,
      artifact_handle: `artifact:v1:${derive("artifact-handle", "base64url")}`,
      blob_id: derive("blob-id", "hex"),
    });
  }

  function reservationResponse(reservationHandle, byteCeiling, expiresAt) {
    return Object.freeze({
      reservation_handle: reservationHandle,
      byte_ceiling: byteCeiling,
      expires_at: expiresAt,
    });
  }

  function terminalReservationOutcome(reservation, state, terminalAt, artifactHandle = null) {
    const outcome = {
      version: ARTIFACT_VAULT_SCHEMA_VERSION,
      reservation_handle: reservation.reservation_handle,
      reservation_ref: reservation.reservation_ref,
      binding_digest: reservation.reservation_binding_digest,
      state,
      terminal_at: terminalAt,
    };
    if (artifactHandle != null) outcome.artifact_handle = artifactHandle;
    return outcome;
  }

  function claimedAttemptPinningOutputReservation(index, reservationHandle) {
    return Object.values(index.batches || {}).find(
      (attempt) => attempt.state === "claimed"
        && attempt.output_reservation_handles.includes(reservationHandle),
    ) || null;
  }

  function purgeExpiredReservations(index, timestampMs) {
    const purged = [];
    for (const [handle, reservation] of Object.entries(index.reservations)) {
      if (claimedAttemptPinningOutputReservation(index, handle)) continue;
      if (Date.parse(reservation.expires_at) <= timestampMs) {
        purged.push(reservation);
        delete index.reservations[handle];
        index.reservation_outcomes[handle] = terminalReservationOutcome(
          reservation,
          "expired",
          new Date(timestampMs).toISOString(),
        );
      }
    }
    return purged;
  }

  function commitExpiredReservationPurge(index, timestampMs) {
    const purged = purgeExpiredReservations(index, timestampMs);
    if (purged.length === 0) return 0;
    writeIndex(index);
    const currentObjectRoot = objectRootFor(index);
    for (const reservation of purged) {
      if (!BLOB_ID_RE.test(reservation.blob_id || "")) continue;
      try { fs.unlinkSync(path.join(currentObjectRoot, `${reservation.blob_id}.json`)); } catch {}
    }
    try { fsyncDirectory(currentObjectRoot); } catch {}
    return purged.length;
  }

  function logicalUsage(index) {
    const activeBytes = Object.values(index.records)
      .reduce((total, record) => total + Math.max(
        record.byte_length + ARTIFACT_LOGICAL_OVERHEAD_BYTES,
        Number.isSafeInteger(record.allocated_bytes) ? record.allocated_bytes : 0,
      ), 0);
    const reservedBytes = Object.values(index.reservations)
      .reduce((total, reservation) => total + Math.max(
        reservation.byte_ceiling + ARTIFACT_LOGICAL_OVERHEAD_BYTES,
        Number.isSafeInteger(reservation.allocated_bytes) ? reservation.allocated_bytes : 0,
      ), 0);
    return { activeBytes, reservedBytes, total: activeBytes + reservedBytes };
  }

  function physicalReservationBytes(byteCeiling) {
    return Math.ceil(byteCeiling * 4 / 3) + 128 * 1024;
  }

  function assertDiskCapacity(byteCeiling) {
    const stats = fs.statfsSync(root);
    const available = Number(stats.bavail) * Number(stats.bsize);
    const required = physicalReservationBytes(byteCeiling) + minFreeBytes;
    if (!Number.isFinite(available) || available < required) {
      throw new Error("vault has insufficient free capacity for the requested reservation");
    }
  }

  function preallocatePrivateFile(filePath, byteLength) {
    const descriptor = fs.openSync(
      filePath,
      fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY | fs.constants.O_NOFOLLOW,
      0o600,
    );
    const chunkSize = 64 * 1024;
    try {
      let written = 0;
      while (written < byteLength) {
        const chunk = crypto.randomBytes(Math.min(chunkSize, byteLength - written));
        try {
          fs.writeSync(descriptor, chunk, 0, chunk.length, written);
        } finally {
          chunk.fill(0);
        }
        written += chunk.length;
      }
      fs.fsyncSync(descriptor);
    } finally {
      fs.closeSync(descriptor);
    }
  }

  function overwritePreallocatedFile(filePath, content, allocatedBytes) {
    const stats = assertSafeRegularFile(filePath, "reserved vault object");
    if (!Number.isSafeInteger(allocatedBytes) || allocatedBytes < content.length
      || stats.size < allocatedBytes) {
      throw new Error("reserved vault object lost its physical allocation");
    }
    const descriptor = fs.openSync(filePath, fs.constants.O_RDWR | fs.constants.O_NOFOLLOW);
    const padding = Buffer.alloc(64 * 1024, 0x20);
    try {
      fs.writeSync(descriptor, content, 0, content.length, 0);
      let offset = content.length;
      while (offset < allocatedBytes) {
        const length = Math.min(padding.length, allocatedBytes - offset);
        fs.writeSync(descriptor, padding, 0, length, offset);
        offset += length;
      }
      fs.fsyncSync(descriptor);
    } finally {
      padding.fill(0);
      fs.closeSync(descriptor);
    }
  }

  function compactCommittedBlobs(index, entries) {
    const priorAllocatedBytes = entries.map(({ record }) => record.allocated_bytes);
    try {
      for (const { blob_path: blobPath, encoded_length: encodedLength } of entries) {
        const descriptor = fs.openSync(blobPath, fs.constants.O_RDWR | fs.constants.O_NOFOLLOW);
        try {
          const before = fs.fstatSync(descriptor);
          if (!before.isFile() || before.nlink !== 1) {
            throw new Error("committed vault ciphertext must remain a single-link regular file");
          }
          fs.ftruncateSync(descriptor, encodedLength);
          fs.fsyncSync(descriptor);
          const after = fs.fstatSync(descriptor);
          if (!after.isFile() || after.nlink !== 1
            || after.dev !== before.dev || after.ino !== before.ino
            || after.size !== encodedLength) {
            throw new Error("committed vault ciphertext changed during compaction");
          }
        } finally {
          fs.closeSync(descriptor);
        }
      }
      fsyncDirectory(objectRootFor(index));
    } catch {
      // The index continues to charge the preallocated physical size. Failed
      // compaction can reduce capacity but cannot be used to overcommit disk.
      return false;
    }
    for (let entryIndex = 0; entryIndex < entries.length; entryIndex += 1) {
      entries[entryIndex].record.allocated_bytes = entries[entryIndex].encoded_length;
    }
    try {
      writeIndex(index);
      return true;
    } catch {
      for (let entryIndex = 0; entryIndex < entries.length; entryIndex += 1) {
        entries[entryIndex].record.allocated_bytes = priorAllocatedBytes[entryIndex];
      }
      return false;
    }
  }

  function reserve(input) {
    const request = normalizeReservationRequest(input);
    if (request.session_nucleus_hash !== sessionNucleusHash) {
      throw new Error("reservation session nucleus does not match this vault");
    }
    return withLock(() => {
      const index = readIndex();
      const purgeTimestamp = Date.parse(nowIso());
      commitExpiredReservationPurge(index, purgeTimestamp);
      const admissionTimestamp = Math.max(purgeTimestamp, Date.parse(nowIso()));
      if (Date.parse(request.expires_at) <= admissionTimestamp) {
        throw new Error("reservation_request.expires_at must be in the future");
      }
      const admittedAt = new Date(admissionTimestamp).toISOString();
      const identity = reservationIdentity(request);
      const bindingDigest = reservationBindingDigest(request);
      const existing = index.reservations[identity.reservation_handle];
      if (existing) {
        if (existing.reservation_binding_digest !== bindingDigest) {
          throw new Error("reservation_ref was reused with a different reservation binding");
        }
        return reservationResponse(
          identity.reservation_handle,
          existing.byte_ceiling,
          existing.expires_at,
        );
      }
      const priorRecord = Object.values(index.records)
        .find((record) => record.ingest_reservation_handle === identity.reservation_handle);
      if (priorRecord) {
        if (priorRecord.reservation_binding_digest !== bindingDigest) {
          throw new Error("reservation_ref was reused with a different committed artifact binding");
        }
        return reservationResponse(
          identity.reservation_handle,
          priorRecord.reservation_byte_ceiling,
          priorRecord.reservation_expires_at,
        );
      }
      const priorOutcome = index.reservation_outcomes[identity.reservation_handle];
      if (priorOutcome) {
        if (priorOutcome.binding_digest !== bindingDigest) {
          throw new Error("reservation_ref was reused with a different terminal reservation binding");
        }
        throw new Error(`reservation is terminal and cannot be recreated: ${priorOutcome.state}`);
      }
      const usage = logicalUsage(index);
      if (Object.keys(index.records).length + Object.keys(index.reservations).length >= maxArtifacts) {
        throw new Error("vault artifact/reservation count ceiling is exhausted");
      }
      const requestedAllocation = physicalReservationBytes(request.byte_ceiling);
      if (usage.total + Math.max(
        request.byte_ceiling + ARTIFACT_LOGICAL_OVERHEAD_BYTES,
        requestedAllocation,
      ) > quotaBytes) {
        throw new Error("vault logical quota is exhausted");
      }
      assertDiskCapacity(request.byte_ceiling);
      const handle = identity.reservation_handle;
      const artifactHandle = identity.artifact_handle;
      const blobId = identity.blob_id;
      const allocatedBytes = requestedAllocation;
      const currentObjectRoot = objectRootFor(index);
      const blobPath = path.join(currentObjectRoot, `${blobId}.json`);
      try {
        const orphan = assertSafeRegularFile(blobPath, "orphaned deterministic reservation object", {
          required: false,
        });
        if (orphan) {
          fs.unlinkSync(blobPath);
          fsyncDirectory(currentObjectRoot);
        }
      } catch (error) {
        if (!error || error.code !== "ENOENT") throw error;
      }
      preallocatePrivateFile(blobPath, allocatedBytes);
      index.reservations[handle] = {
        ...request,
        reservation_handle: handle,
        reservation_binding_digest: bindingDigest,
        artifact_handle: artifactHandle,
        blob_id: blobId,
        allocated_bytes: allocatedBytes,
        created_at: admittedAt,
      };
      try {
        writeIndex(index);
      } catch (error) {
        let durable = null;
        try {
          const reconciled = readIndex();
          durable = Boolean(reconciled.reservations[handle]
            && reconciled.reservations[handle].blob_id === blobId);
        } catch {}
        if (durable === true) {
          return reservationResponse(handle, request.byte_ceiling, request.expires_at);
        }
        if (durable === false) {
          try { fs.unlinkSync(blobPath); } catch {}
        }
        throw error;
      }
      return reservationResponse(handle, request.byte_ceiling, request.expires_at);
    });
  }

  function releaseReservation(reservationHandle, reasonRef) {
    if (typeof reservationHandle !== "string" || !PUBLIC_RESERVATION_HANDLE_RE.test(reservationHandle)) {
      throw new Error("reservation_handle is invalid");
    }
    const normalizedReason = assertOpaqueRef(reasonRef, "reason_ref");
    return withLock(() => {
      const index = readIndex();
      if (claimedAttemptPinningOutputReservation(index, reservationHandle)) {
        throw new Error("reservation is pinned as output of a claimed transform attempt");
      }
      const reservation = index.reservations[reservationHandle];
      if (!reservation) {
        const outcome = index.reservation_outcomes[reservationHandle];
        if (outcome && outcome.state === "released") {
          if (outcome.reason_ref !== normalizedReason) {
            throw new Error("released reservation reason binding does not match the retry");
          }
          return Object.freeze({
            reservation_handle: reservationHandle,
            released_at: outcome.terminal_at,
            release_receipt: outcome.release_receipt,
          });
        }
        throw new Error("reservation is absent, expired, consumed, or already released");
      }
      const receiptPayload = {
        version: ARTIFACT_VAULT_SCHEMA_VERSION,
        reservation_handle: reservationHandle,
        session_nucleus_hash: sessionNucleusHash,
        task_id: reservation.task_id,
        attempt_id: reservation.attempt_id,
        released_at: nowIso(),
        reason_ref: normalizedReason,
      };
      const releaseReceipt = crypto.createHmac("sha256", auditKey)
        .update(canonicalJson(receiptPayload))
        .digest("hex");
      delete index.reservations[reservationHandle];
      index.reservation_outcomes[reservationHandle] = {
        ...terminalReservationOutcome(reservation, "released", receiptPayload.released_at),
        reason_ref: normalizedReason,
        release_receipt: releaseReceipt,
      };
      try {
        writeIndex(index);
      } catch (error) {
        try {
          const outcome = readIndex().reservation_outcomes[reservationHandle];
          if (outcome && outcome.state === "released"
            && outcome.release_receipt === releaseReceipt) {
            return Object.freeze({
              reservation_handle: reservationHandle,
              released_at: outcome.terminal_at,
              release_receipt: outcome.release_receipt,
            });
          }
        } catch {}
        throw error;
      }
      if (BLOB_ID_RE.test(reservation.blob_id || "")) {
        try {
          fs.unlinkSync(path.join(objectRootFor(index), `${reservation.blob_id}.json`));
          fsyncDirectory(objectRootFor(index));
        } catch {}
      }
      return Object.freeze({
        reservation_handle: reservationHandle,
        released_at: receiptPayload.released_at,
        release_receipt: releaseReceipt,
      });
    });
  }

  function artifactAad(record) {
    return canonicalJson({
      version: record.version,
      artifact_handle: record.artifact_handle,
      session_nucleus_hash: sessionNucleusHash,
      metadata: record.metadata,
      byte_length: record.byte_length,
      created_at: record.created_at,
    });
  }

  function keyedContentToken(key, dataClass, plaintext) {
    const contentDigest = sha256(plaintext);
    return crypto.createHmac("sha256", key)
      .update(dataClass)
      .update("\0")
      .update(contentDigest)
      .digest("base64url");
  }

  function reconcileCommittedIngest(index, reservationHandle, metadata, plaintext) {
    const record = Object.values(index.records)
      .find((candidate) => candidate.ingest_reservation_handle === reservationHandle);
    if (!record) return null;
    const integrityToken = keyedContentToken(integrityKey, metadata.data_class, plaintext);
    if (canonicalJson(record.metadata) !== canonicalJson(metadata)
      || record.byte_length !== plaintext.length
      || !constantTimeEqual(record.integrity_token, integrityToken)) {
      throw new Error("reservation was consumed by a different committed artifact binding");
    }
    return record;
  }

  function ingestInternal(
    { reservation_handle: reservationHandle, metadata: rawMetadata, plaintext },
    { allow_empty_provider_response: allowEmptyProviderResponse = false } = {},
  ) {
    if (typeof reservationHandle !== "string" || !PUBLIC_RESERVATION_HANDLE_RE.test(reservationHandle)) {
      throw new Error("reservation_handle is invalid");
    }
    if (!Buffer.isBuffer(plaintext)
        || (!allowEmptyProviderResponse && plaintext.length < 1)) {
      throw new Error("plaintext must be a non-empty explicit Buffer");
    }
    const metadata = normalizeArtifactMetadata(rawMetadata);
    if (metadata.transform_provenance != null) {
      throw new Error("ordinary vault ingest cannot mint transform provenance");
    }
    if (metadata.session_nucleus_hash !== sessionNucleusHash) {
      throw new Error("artifact session nucleus does not match this vault");
    }
    return withLock(() => {
      const index = readIndex();
      commitExpiredReservationPurge(index, Date.parse(nowIso()));
      if (claimedAttemptPinningOutputReservation(index, reservationHandle)) {
        throw new Error("reservation is pinned as output of a claimed transform attempt");
      }
      const reservation = index.reservations[reservationHandle];
      if (!reservation) {
        const committed = reconcileCommittedIngest(index, reservationHandle, metadata, plaintext);
        if (committed) return publicDescriptor(committed);
        throw new Error("reservation is absent, expired, or already consumed");
      }
      if (reservation.task_id !== metadata.task_id || reservation.attempt_id !== metadata.attempt_id) {
        throw new Error("artifact task/attempt does not match its reservation");
      }
      if (plaintext.length > reservation.byte_ceiling) {
        throw new Error("artifact exceeds its pre-stimulus byte reservation");
      }
      if (Date.parse(metadata.retention_expires_at) <= Date.parse(nowIso())) {
        throw new Error("artifact retention must extend beyond ingest time");
      }

      const artifactHandle = reservation.artifact_handle;
      const blobId = reservation.blob_id;
      if (!PUBLIC_ARTIFACT_HANDLE_RE.test(artifactHandle || "") || !BLOB_ID_RE.test(blobId || "")) {
        throw new Error("reservation artifact allocation is corrupt");
      }
      const createdAt = nowIso();
      const record = {
        version: ARTIFACT_VAULT_SCHEMA_VERSION,
        artifact_handle: artifactHandle,
        ingest_reservation_handle: reservationHandle,
        reservation_ref: reservation.reservation_ref,
        reservation_binding_digest: reservation.reservation_binding_digest,
        reservation_byte_ceiling: reservation.byte_ceiling,
        reservation_expires_at: reservation.expires_at,
        blob_id: blobId,
        metadata,
        byte_length: plaintext.length,
        allocated_bytes: reservation.allocated_bytes,
        created_at: createdAt,
        integrity_token: keyedContentToken(integrityKey, metadata.data_class, plaintext),
      };
      record.comparison_token = keyedContentToken(comparisonKey, metadata.data_class, plaintext);
      const dataKey = crypto.randomBytes(32);
      try {
        record.wrapped_data_key = encryptAead(
          wrapKey,
          dataKey,
          canonicalJson({ artifact_handle: artifactHandle, session_nucleus_hash: sessionNucleusHash }),
        );
        const blobEnvelope = encryptAead(dataKey, plaintext, artifactAad(record));
        const currentObjectRoot = objectRootFor(index);
        const blobPath = path.join(currentObjectRoot, `${blobId}.json`);
        const encodedBlob = Buffer.from(`${canonicalJson(blobEnvelope)}\n`, "utf8");
        overwritePreallocatedFile(blobPath, encodedBlob, reservation.allocated_bytes);
        fsyncDirectory(currentObjectRoot);
        try {
          index.records[artifactHandle] = record;
          index.references[artifactHandle] = [];
          delete index.reservations[reservationHandle];
          index.reservation_outcomes[reservationHandle] = terminalReservationOutcome(
            reservation,
            "consumed",
            createdAt,
            artifactHandle,
          );
          writeIndex(index);
          compactCommittedBlobs(index, [{
            record,
            blob_path: blobPath,
            encoded_length: encodedBlob.length,
          }]);
        } catch (error) {
          try {
            const committed = reconcileCommittedIngest(
              readIndex(),
              reservationHandle,
              metadata,
              plaintext,
            );
            if (committed) return publicDescriptor(committed);
          } catch (reconciliationError) {
            if (reconciliationError.message
              === "reservation was consumed by a different committed artifact binding") {
              throw reconciliationError;
            }
          }
          throw error;
        }
      } finally {
        dataKey.fill(0);
      }
      return publicDescriptor(record);
    });
  }

  function ingest(input) {
    return ingestInternal(input);
  }

  function ingestProviderResponse(input) {
    return ingestInternal(input, { allow_empty_provider_response: true });
  }

  function validateTransformBatchIdentity(batchRef, bindingDigest) {
    if (typeof batchRef !== "string" || !TRANSFORM_BATCH_REF_RE.test(batchRef)) {
      throw new Error("transform batch_ref is invalid");
    }
    if (typeof bindingDigest !== "string" || !SHA256_RE.test(bindingDigest)) {
      throw new Error("transform batch binding_digest is invalid");
    }
  }

  function validateTransformClaimToken(claimToken) {
    if (typeof claimToken !== "string" || !TRANSFORM_CLAIM_TOKEN_RE.test(claimToken)) {
      throw new Error("transform claim token is invalid");
    }
    return claimToken;
  }

  function transformAttempt(index, batchRef, bindingDigest) {
    const attempt = index.batches[batchRef];
    if (!attempt) return null;
    if (!constantTimeEqual(attempt.binding_digest, bindingDigest)) {
      throw new Error("transform batch reference was reused with a different binding");
    }
    return attempt;
  }

  function retainedTransformOutputs(index, attempt) {
    if (attempt.state !== "committed") return null;
    if (attempt.artifact_handles.some((handle) => !index.records[handle])) return null;
    return Object.freeze(attempt.artifact_handles.map(
      (handle) => publicDescriptor(getRecord(index, handle)),
    ));
  }

  function transformAttemptView(index, batchRef, bindingDigest) {
    const attempt = transformAttempt(index, batchRef, bindingDigest);
    if (!attempt) return null;
    const outputs = retainedTransformOutputs(index, attempt);
    return Object.freeze({
      batch_ref: batchRef,
      binding_digest: bindingDigest,
      status: attempt.state,
      claimed_at: attempt.claimed_at,
      committed_at: attempt.committed_at,
      failed_at: attempt.failed_at,
      failure_digest: attempt.failure_digest,
      failure_kind: attempt.failure_kind,
      adjudication_ref: attempt.adjudication_ref,
      outputs_retained: outputs != null,
      outputs,
    });
  }

  function committedBatch(index, batchRef, bindingDigest) {
    const batch = transformAttempt(index, batchRef, bindingDigest);
    if (!batch) return null;
    if (batch.state !== "committed") return null;
    const outputs = retainedTransformOutputs(index, batch);
    if (!outputs) {
      throw new Error("transform batch already committed but one or more outputs are no longer retained");
    }
    return Object.freeze({
      batch_ref: batchRef,
      committed_at: batch.committed_at,
      outputs,
    });
  }

  function inspectTransformBatch(batchRef, bindingDigest) {
    validateTransformBatchIdentity(batchRef, bindingDigest);
    return committedBatch(readIndex(), batchRef, bindingDigest);
  }

  function inspectTransformAttempt(batchRef, bindingDigest) {
    validateTransformBatchIdentity(batchRef, bindingDigest);
    return transformAttemptView(readIndex(), batchRef, bindingDigest);
  }

  function transformClaimResult(token, view) {
    return Object.freeze({
      ...view,
      claim_token: token,
    });
  }

  function terminalTransformError(view) {
    if (view.status === "committed") {
      if (!view.outputs_retained) {
        return new Error("transform attempt is committed and fenced but its outputs are no longer retained");
      }
      return null;
    }
    if (view.status === "claimed") {
      return new Error("transform attempt is already durably claimed; operator adjudication is required after a crash");
    }
    return new Error("transform attempt is permanently failed and cannot be retried");
  }

  function reserveTransformTerminalIndexBytes(index, attempt, outputs, timestamp) {
    const claimedEncodedLength = Buffer.byteLength(encodeIndex(index), "utf8");
    const terminalIndex = JSON.parse(JSON.stringify(index));
    const terminalAttempt = terminalIndex.batches[attempt.batch_ref];
    const artifactHandles = [];
    for (let outputIndex = 0; outputIndex < outputs.length; outputIndex += 1) {
      const output = outputs[outputIndex];
      const reservation = terminalIndex.reservations[output.reservation_handle];
      const artifactHandle = reservation.artifact_handle;
      const record = {
        version: ARTIFACT_VAULT_SCHEMA_VERSION,
        artifact_handle: artifactHandle,
        ingest_reservation_handle: output.reservation_handle,
        reservation_ref: reservation.reservation_ref,
        reservation_binding_digest: reservation.reservation_binding_digest,
        reservation_byte_ceiling: reservation.byte_ceiling,
        reservation_expires_at: reservation.expires_at,
        blob_id: reservation.blob_id,
        metadata: output.metadata,
        byte_length: reservation.byte_ceiling,
        allocated_bytes: reservation.allocated_bytes,
        created_at: timestamp,
        integrity_token: "A".repeat(43),
        comparison_token: "A".repeat(43),
        wrapped_data_key: {
          algorithm: "aes-256-gcm",
          nonce: "A".repeat(16),
          ciphertext: "A".repeat(44),
          tag: "A".repeat(24),
        },
      };
      terminalIndex.records[artifactHandle] = record;
      terminalIndex.references[artifactHandle] = [];
      delete terminalIndex.reservations[output.reservation_handle];
      terminalIndex.reservation_outcomes[output.reservation_handle] = terminalReservationOutcome(
        reservation,
        "consumed",
        timestamp,
        artifactHandle,
      );
      artifactHandles.push(artifactHandle);
    }
    terminalAttempt.state = "committed";
    terminalAttempt.artifact_handles = artifactHandles;
    terminalAttempt.committed_at = timestamp;
    terminalAttempt.reserved_index_bytes = 0;
    validateBatchIndex(terminalIndex, "transform terminal capacity projection");
    const terminalEncodedLength = Buffer.byteLength(encodeIndex(terminalIndex), "utf8");
    if (terminalEncodedLength > indexEncodedBytesCeiling) {
      throw new Error("transform terminal index exceeds its configured read ceiling before execution");
    }
    const measuredDelta = Math.max(0, terminalEncodedLength - claimedEncodedLength);
    const reservedBytes = measuredDelta + 4096;
    if (reservedBytes > MAX_TRANSFORM_INDEX_RESERVATION_BYTES) {
      throw new Error("transform terminal index expansion exceeds its admission bound");
    }
    return reservedBytes;
  }

  function claimTransformAttempt({
    batch_ref: batchRef,
    binding_digest: bindingDigest,
    input_handles: inputHandles,
    outputs,
  }) {
    validateTransformBatchIdentity(batchRef, bindingDigest);
    if (!Array.isArray(inputHandles) || inputHandles.length < 1 || inputHandles.length > 64
      || new Set(inputHandles).size !== inputHandles.length
      || inputHandles.some((handle) => typeof handle !== "string"
        || !PUBLIC_ARTIFACT_HANDLE_RE.test(handle))) {
      throw new Error("transform input_handles must contain between 1 and 64 unique artifact handles");
    }
    if (!Array.isArray(outputs) || outputs.length < 1 || outputs.length > MAX_TRANSFORM_OUTPUTS) {
      throw new Error(`transform claim outputs must contain between 1 and ${MAX_TRANSFORM_OUTPUTS} bindings`);
    }
    const normalizedOutputs = outputs.map((output, outputIndex) => {
      assertClosedObject(output, `transform claim outputs[${outputIndex}]`, ["reservation_handle", "metadata"]);
      if (typeof output.reservation_handle !== "string"
        || !PUBLIC_RESERVATION_HANDLE_RE.test(output.reservation_handle)) {
        throw new Error(`transform claim outputs[${outputIndex}].reservation_handle is invalid`);
      }
      const metadata = normalizeArtifactMetadata(
        output.metadata,
        `transform claim outputs[${outputIndex}].metadata`,
      );
      if (metadata.session_nucleus_hash !== sessionNucleusHash) {
        throw new Error("transform claim output session nucleus does not match this vault");
      }
      return Object.freeze({ reservation_handle: output.reservation_handle, metadata });
    });
    if (new Set(normalizedOutputs.map((output) => output.reservation_handle)).size
      !== normalizedOutputs.length) {
      throw new Error("transform claim output reservation handles must be unique");
    }
    const outputCount = normalizedOutputs.length;
    return withLock(() => {
      const index = readIndex();
      const priorView = transformAttemptView(index, batchRef, bindingDigest);
      if (priorView) {
        const terminalError = terminalTransformError(priorView);
        if (terminalError) throw terminalError;
        return priorView;
      }
      if (Object.keys(index.batches).length >= MAX_TRANSFORM_ATTEMPTS) {
        throw new Error("transform attempt fence capacity is exhausted before execution");
      }
      const claimedAt = nowIso();
      const deletionLedger = readDeletionLedger(index);
      for (const inputHandle of inputHandles) {
        if (deletionLedger.entries[inputHandle]) {
          throw new Error("transform input artifact was cryptographically erased before claim");
        }
        getRecord(index, inputHandle);
      }
      for (const [outputIndex, output] of normalizedOutputs.entries()) {
        const reservation = index.reservations[output.reservation_handle];
        if (!reservation) {
          throw new Error(`transform claim output reservation ${outputIndex} is absent or terminal`);
        }
        if (reservation.task_id !== output.metadata.task_id
          || reservation.attempt_id !== output.metadata.attempt_id) {
          throw new Error(`transform claim output ${outputIndex} task/attempt does not match its reservation`);
        }
        if (Date.parse(reservation.expires_at) <= Date.parse(claimedAt)) {
          throw new Error(`transform claim output reservation ${outputIndex} is expired`);
        }
        if (Date.parse(output.metadata.retention_expires_at) <= Date.parse(claimedAt)) {
          throw new Error(`transform claim output ${outputIndex} retention expires before execution`);
        }
      }
      const claimToken = `transform-claim:v1:${randomToken()}`;
      const claimTokenDigest = sha256(claimToken);
      index.batches[batchRef] = {
        version: ARTIFACT_VAULT_SCHEMA_VERSION,
        batch_ref: batchRef,
        binding_digest: bindingDigest,
        state: "claimed",
        claim_token_digest: claimTokenDigest,
        output_count: outputCount,
        claimed_at: claimedAt,
        committed_at: null,
        failed_at: null,
        failure_digest: null,
        failure_kind: null,
        adjudication_ref: null,
        input_handles: [...inputHandles],
        deletion_ledger_generation_at_claim: deletionLedger.generation,
        output_reservation_handles: normalizedOutputs.map((output) => output.reservation_handle),
        output_metadata_digests: normalizedOutputs.map((output) => sha256(canonicalJson(output.metadata))),
        artifact_handles: [],
        reserved_index_bytes: 1,
      };
      index.batches[batchRef].reserved_index_bytes = reserveTransformTerminalIndexBytes(
        index,
        index.batches[batchRef],
        normalizedOutputs,
        claimedAt,
      );
      try {
        writeIndex(index);
      } catch (error) {
        try {
          const reconciledIndex = readIndex();
          const reconciled = transformAttempt(reconciledIndex, batchRef, bindingDigest);
          if (reconciled && reconciled.state === "claimed"
            && constantTimeEqual(reconciled.claim_token_digest, claimTokenDigest)) {
            return transformClaimResult(
              claimToken,
              transformAttemptView(reconciledIndex, batchRef, bindingDigest),
            );
          }
        } catch (reconciliationError) {
          Object.defineProperty(error, "transform_claim_reconciliation_error", {
            value: reconciliationError.message || String(reconciliationError),
            enumerable: false,
          });
        }
        throw error;
      }
      return transformClaimResult(
        claimToken,
        transformAttemptView(index, batchRef, bindingDigest),
      );
    });
  }

  function terminalizeClaimedOutputReservations(index, attempt, terminalAt, reasonRef) {
    const blobPaths = [];
    for (const reservationHandle of attempt.output_reservation_handles) {
      const reservation = index.reservations[reservationHandle];
      if (!reservation) {
        const outcome = index.reservation_outcomes[reservationHandle];
        if (!outcome || !["released", "expired"].includes(outcome.state)) {
          throw new Error("claimed transform output reservation disappeared without a safe terminal outcome");
        }
        continue;
      }
      const receiptPayload = {
        version: ARTIFACT_VAULT_SCHEMA_VERSION,
        reservation_handle: reservationHandle,
        session_nucleus_hash: sessionNucleusHash,
        task_id: reservation.task_id,
        attempt_id: reservation.attempt_id,
        released_at: terminalAt,
        reason_ref: reasonRef,
      };
      const releaseReceipt = crypto.createHmac("sha256", auditKey)
        .update(canonicalJson(receiptPayload))
        .digest("hex");
      delete index.reservations[reservationHandle];
      index.reservation_outcomes[reservationHandle] = {
        ...terminalReservationOutcome(reservation, "released", terminalAt),
        reason_ref: reasonRef,
        release_receipt: releaseReceipt,
      };
      if (BLOB_ID_RE.test(reservation.blob_id || "")) {
        blobPaths.push(path.join(objectRootFor(index), `${reservation.blob_id}.json`));
      }
    }
    return blobPaths;
  }

  function deleteTerminalizedReservationBlobs(index, blobPaths) {
    if (blobPaths.length === 0) return;
    for (const blobPath of blobPaths) {
      try { fs.unlinkSync(blobPath); } catch {}
    }
    try { fsyncDirectory(objectRootFor(index)); } catch {}
  }

  function failTransformAttempt({
    batch_ref: batchRef,
    binding_digest: bindingDigest,
    claim_token: claimToken,
    failure_digest: failureDigest,
    failure_kind: failureKind,
  }) {
    validateTransformBatchIdentity(batchRef, bindingDigest);
    validateTransformClaimToken(claimToken);
    if (!SHA256_RE.test(failureDigest || "")) {
      throw new Error("transform failure_digest is invalid");
    }
    if (typeof failureKind !== "string" || !/^[a-z][a-z0-9._-]{0,63}$/.test(failureKind)) {
      throw new Error("transform failure_kind is invalid");
    }
    const claimTokenDigest = sha256(claimToken);
    return withLock(() => {
      const index = readIndex();
      const attempt = transformAttempt(index, batchRef, bindingDigest);
      if (!attempt) throw new Error("transform attempt claim is absent");
      if (attempt.state === "committed") return transformAttemptView(index, batchRef, bindingDigest);
      if (attempt.state === "failed") {
        if (!constantTimeEqual(attempt.failure_digest, failureDigest)
          || attempt.failure_kind !== failureKind) {
          throw new Error("transform attempt already failed under a different terminal binding");
        }
        return transformAttemptView(index, batchRef, bindingDigest);
      }
      if (!constantTimeEqual(attempt.claim_token_digest, claimTokenDigest)) {
        throw new Error("transform attempt claim token does not own this attempt");
      }
      const failedAt = nowIso();
      const releasedBlobPaths = terminalizeClaimedOutputReservations(
        index,
        attempt,
        failedAt,
        "transform:precommit-failure",
      );
      attempt.state = "failed";
      attempt.failed_at = failedAt;
      attempt.failure_digest = failureDigest;
      attempt.failure_kind = failureKind;
      attempt.reserved_index_bytes = 0;
      let terminalIndex = index;
      try {
        writeIndex(index);
      } catch (error) {
        try {
          const reconciledIndex = readIndex();
          const reconciled = transformAttempt(reconciledIndex, batchRef, bindingDigest);
          if (reconciled && reconciled.state === "failed"
            && constantTimeEqual(reconciled.failure_digest, failureDigest)
            && reconciled.failure_kind === failureKind) {
            terminalIndex = reconciledIndex;
          } else if (reconciled && reconciled.state === "committed") {
            return transformAttemptView(reconciledIndex, batchRef, bindingDigest);
          } else {
            throw error;
          }
        } catch (reconciliationError) {
          Object.defineProperty(error, "transform_failure_reconciliation_error", {
            value: reconciliationError.message || String(reconciliationError),
            enumerable: false,
          });
        }
        if (terminalIndex === index) throw error;
      }
      deleteTerminalizedReservationBlobs(terminalIndex, releasedBlobPaths);
      return transformAttemptView(terminalIndex, batchRef, bindingDigest);
    });
  }

  function adjudicateTransformAttempt(input) {
    assertClosedObject(input, "transform attempt adjudication", [
      "batch_ref",
      "binding_digest",
      "expected_claimed_at",
      "evidence_ref",
      "verdict",
    ]);
    validateTransformBatchIdentity(input.batch_ref, input.binding_digest);
    if (!isCanonicalTimestamp(input.expected_claimed_at)) {
      throw new Error("transform attempt adjudication expected_claimed_at is invalid");
    }
    const evidenceRef = assertOpaqueRef(input.evidence_ref, "transform attempt adjudication evidence_ref");
    if (input.verdict !== "terminal_failed") {
      throw new Error("transform attempt adjudication verdict must be terminal_failed");
    }
    const failureDigest = sha256(canonicalJson({
      version: ARTIFACT_VAULT_SCHEMA_VERSION,
      batch_ref: input.batch_ref,
      binding_digest: input.binding_digest,
      expected_claimed_at: input.expected_claimed_at,
      evidence_ref: evidenceRef,
      verdict: input.verdict,
    }));
    return withLock(() => {
      const index = readIndex();
      const attempt = transformAttempt(index, input.batch_ref, input.binding_digest);
      const releaseReason = "transform:operator-crash-adjudication";
      const releasedBlobPaths = [];
      if (!attempt) throw new Error("transform attempt claim is absent");
      if (attempt.claimed_at !== input.expected_claimed_at) {
        throw new Error("transform attempt adjudication does not bind the observed claim");
      }
      if (attempt.state === "committed") {
        throw new Error("committed transform attempt cannot be adjudicated as failed");
      }
      if (attempt.state === "claimed") {
        const failedAt = nowIso();
        releasedBlobPaths.push(...terminalizeClaimedOutputReservations(
          index,
          attempt,
          failedAt,
          releaseReason,
        ));
        attempt.state = "failed";
        attempt.failed_at = failedAt;
        attempt.failure_digest = failureDigest;
        attempt.failure_kind = "operator_crash_adjudication";
        attempt.adjudication_ref = evidenceRef;
        attempt.reserved_index_bytes = 0;
        try {
          writeIndex(index);
        } catch (error) {
          try {
            const reconciled = transformAttempt(readIndex(), input.batch_ref, input.binding_digest);
            if (!reconciled || reconciled.state !== "failed"
              || !constantTimeEqual(reconciled.failure_digest, failureDigest)) throw error;
          } catch (reconciliationError) {
            Object.defineProperty(error, "transform_adjudication_reconciliation_error", {
              value: reconciliationError.message || String(reconciliationError),
              enumerable: false,
            });
            throw error;
          }
        }
      } else if (!constantTimeEqual(attempt.failure_digest, failureDigest)
        || attempt.adjudication_ref !== evidenceRef) {
        throw new Error("transform attempt already has a different terminal adjudication");
      }
      const terminal = transformAttempt(index, input.batch_ref, input.binding_digest);
      let releasedOutputReservations = 0;
      for (const reservationHandle of terminal.output_reservation_handles) {
        const outcome = index.reservation_outcomes[reservationHandle];
        if (!outcome || !["released", "expired"].includes(outcome.state)) {
          throw new Error("adjudicated transform output reservation lacks a safe terminal outcome");
        }
        if (outcome.state === "released" && outcome.reason_ref === releaseReason) {
          releasedOutputReservations += 1;
        }
      }
      deleteTerminalizedReservationBlobs(index, releasedBlobPaths);
      const receiptPayload = {
        version: ARTIFACT_VAULT_SCHEMA_VERSION,
        batch_ref: input.batch_ref,
        binding_digest: input.binding_digest,
        claimed_at: terminal.claimed_at,
        failed_at: terminal.failed_at,
        evidence_ref: evidenceRef,
        verdict: "terminal_failed",
        output_reservation_count: terminal.output_reservation_handles.length,
        released_output_reservations: releasedOutputReservations,
      };
      return Object.freeze({
        ...receiptPayload,
        adjudication_receipt: crypto.createHmac("sha256", auditKey)
          .update(canonicalJson(receiptPayload))
          .digest("hex"),
      });
    });
  }

  function ingestTransformBatch({
    batch_ref: batchRef,
    binding_digest: bindingDigest,
    claim_token: claimToken,
    entries,
  }) {
    validateTransformBatchIdentity(batchRef, bindingDigest);
    validateTransformClaimToken(claimToken);
    if (!Array.isArray(entries) || entries.length < 1 || entries.length > MAX_TRANSFORM_OUTPUTS) {
      throw new Error(`transform batch entries must contain between 1 and ${MAX_TRANSFORM_OUTPUTS} outputs`);
    }
    const normalizedEntries = entries.map((entry, entryIndex) => {
      assertClosedObject(
        entry,
        `transform batch entries[${entryIndex}]`,
        ["reservation_handle", "metadata", "plaintext"],
      );
      if (typeof entry.reservation_handle !== "string"
        || !PUBLIC_RESERVATION_HANDLE_RE.test(entry.reservation_handle)) {
        throw new Error(`transform batch entries[${entryIndex}].reservation_handle is invalid`);
      }
      if (!Buffer.isBuffer(entry.plaintext) || entry.plaintext.length < 1) {
        throw new Error(`transform batch entries[${entryIndex}].plaintext must be a non-empty Buffer`);
      }
      const metadata = normalizeArtifactMetadata(
        entry.metadata,
        `transform batch entries[${entryIndex}].metadata`,
      );
      if (metadata.session_nucleus_hash !== sessionNucleusHash) {
        throw new Error("transform batch artifact session nucleus does not match this vault");
      }
      return { reservation_handle: entry.reservation_handle, metadata, plaintext: entry.plaintext };
    });
    if (new Set(normalizedEntries.map((entry) => entry.reservation_handle)).size
      !== normalizedEntries.length) {
      throw new Error("transform batch reservation handles must be unique");
    }

    return withLock(() => {
      const index = readIndex();
      const prior = committedBatch(index, batchRef, bindingDigest);
      if (prior) return prior;
      const attempt = transformAttempt(index, batchRef, bindingDigest);
      if (!attempt) throw new Error("transform attempt must be durably claimed before batch ingest");
      if (attempt.state === "failed") {
        throw new Error("permanently failed transform attempt cannot commit outputs");
      }
      if (attempt.state !== "claimed") throw new Error("transform attempt state cannot commit outputs");
      if (!constantTimeEqual(attempt.claim_token_digest, sha256(claimToken))) {
        throw new Error("transform attempt claim token does not own batch ingest");
      }
      if (attempt.output_count !== normalizedEntries.length) {
        throw new Error("transform batch output count differs from its durable claim");
      }
      for (let entryIndex = 0; entryIndex < normalizedEntries.length; entryIndex += 1) {
        const entry = normalizedEntries[entryIndex];
        if (attempt.output_reservation_handles[entryIndex] !== entry.reservation_handle
          || !constantTimeEqual(
            attempt.output_metadata_digests[entryIndex],
            sha256(canonicalJson(entry.metadata)),
          )) {
          throw new Error("transform batch output binding differs from its durable claim");
        }
      }
      const inputHandlesDigest = sha256(canonicalJson({
        version: ARTIFACT_VAULT_SCHEMA_VERSION,
        input_handles: attempt.input_handles,
      }));
      for (const entry of normalizedEntries) {
        const provenance = entry.metadata.transform_provenance;
        if (!provenance
          || provenance.batch_ref !== batchRef
          || !constantTimeEqual(provenance.input_handles_digest, inputHandlesDigest)
          || provenance.input_handle_count !== attempt.input_handles.length) {
          throw new Error("transform batch provenance does not bind its durable attempt and input handles");
        }
      }
      const deletionLedger = readDeletionLedger(index);
      if (deletionLedger.generation < attempt.deletion_ledger_generation_at_claim) {
        throw new Error("transform deletion ledger generation regressed behind its durable claim");
      }
      for (const inputHandle of attempt.input_handles) {
        if (deletionLedger.entries[inputHandle] || !index.records[inputHandle]) {
          throw new Error("transform input pin was erased or lost before output commit");
        }
      }

      const timestamp = nowIso();
      const records = [];
      const encodedBlobs = [];
      const currentObjectRoot = objectRootFor(index);
      try {
      for (const [entryIndex, entry] of normalizedEntries.entries()) {
        const reservation = index.reservations[entry.reservation_handle];
        if (!reservation) {
          throw new Error(`transform batch reservation ${entryIndex} is absent, expired, or already consumed`);
        }
        if (Date.parse(reservation.expires_at) <= Date.parse(timestamp)) {
          throw new Error(`transform batch reservation ${entryIndex} is expired`);
        }
        if (reservation.task_id !== entry.metadata.task_id
          || reservation.attempt_id !== entry.metadata.attempt_id) {
          throw new Error(`transform batch artifact ${entryIndex} task/attempt does not match its reservation`);
        }
        if (entry.plaintext.length > reservation.byte_ceiling) {
          throw new Error(`transform batch artifact ${entryIndex} exceeds its pre-stimulus byte reservation`);
        }
        if (Date.parse(entry.metadata.retention_expires_at) <= Date.parse(timestamp)) {
          throw new Error(`transform batch artifact ${entryIndex} retention must extend beyond ingest time`);
        }
        const artifactHandle = reservation.artifact_handle;
        const blobId = reservation.blob_id;
        if (!PUBLIC_ARTIFACT_HANDLE_RE.test(artifactHandle || "") || !BLOB_ID_RE.test(blobId || "")) {
          throw new Error(`transform batch reservation ${entryIndex} artifact allocation is corrupt`);
        }
        const record = {
          version: ARTIFACT_VAULT_SCHEMA_VERSION,
          artifact_handle: artifactHandle,
          ingest_reservation_handle: entry.reservation_handle,
          reservation_ref: reservation.reservation_ref,
          reservation_binding_digest: reservation.reservation_binding_digest,
          reservation_byte_ceiling: reservation.byte_ceiling,
          reservation_expires_at: reservation.expires_at,
          blob_id: blobId,
          metadata: entry.metadata,
          byte_length: entry.plaintext.length,
          allocated_bytes: reservation.allocated_bytes,
          created_at: timestamp,
          integrity_token: keyedContentToken(integrityKey, entry.metadata.data_class, entry.plaintext),
          comparison_token: keyedContentToken(comparisonKey, entry.metadata.data_class, entry.plaintext),
        };
        const dataKey = crypto.randomBytes(32);
        try {
          record.wrapped_data_key = encryptAead(
            wrapKey,
            dataKey,
            canonicalJson({ artifact_handle: artifactHandle, session_nucleus_hash: sessionNucleusHash }),
          );
          encodedBlobs.push({
            blob_path: path.join(currentObjectRoot, `${blobId}.json`),
            allocated_bytes: reservation.allocated_bytes,
            encoded: Buffer.from(`${canonicalJson(encryptAead(dataKey, entry.plaintext, artifactAad(record)))}\n`, "utf8"),
          });
        } finally {
          dataKey.fill(0);
        }
        records.push(record);
      }

      // Ciphertexts may be overwritten independently, but none becomes a
      // reachable artifact until the one authenticated index replacement
      // below commits every output and consumes every reservation together.
      for (const blob of encodedBlobs) {
        overwritePreallocatedFile(blob.blob_path, blob.encoded, blob.allocated_bytes);
      }
      fsyncDirectory(currentObjectRoot);
      for (let entryIndex = 0; entryIndex < normalizedEntries.length; entryIndex += 1) {
        const entry = normalizedEntries[entryIndex];
        const record = records[entryIndex];
        index.records[record.artifact_handle] = record;
        index.references[record.artifact_handle] = [];
        const reservation = index.reservations[entry.reservation_handle];
        delete index.reservations[entry.reservation_handle];
        index.reservation_outcomes[entry.reservation_handle] = terminalReservationOutcome(
          reservation,
          "consumed",
          timestamp,
          record.artifact_handle,
        );
      }
      attempt.state = "committed";
      attempt.artifact_handles = records.map((record) => record.artifact_handle);
      attempt.committed_at = timestamp;
      attempt.reserved_index_bytes = 0;
      writeIndex(index);
      compactCommittedBlobs(index, encodedBlobs.map((blob, entryIndex) => ({
        record: records[entryIndex],
        blob_path: blob.blob_path,
        encoded_length: blob.encoded.length,
      })));
      return committedBatch(index, batchRef, bindingDigest);
      } finally {
        for (const blob of encodedBlobs) blob.encoded.fill(0);
      }
    });
  }

  function getRecord(index, artifactHandle, { allowDeleted = false } = {}) {
    if (typeof artifactHandle !== "string" || !PUBLIC_ARTIFACT_HANDLE_RE.test(artifactHandle)) {
      throw new Error("artifact_handle is invalid");
    }
    const record = index.records[artifactHandle];
    if (!record) throw new Error("artifact_handle is absent, expired, or erased");
    if (!allowDeleted
      && ensureBackupCustodyIndex(index, "artifact read").deletion_intents[artifactHandle]) {
      throw new Error("artifact_handle has a pending cryptographic-erasure intent");
    }
    if (!allowDeleted && readDeletionLedger(index).entries[artifactHandle]) {
      throw new Error("artifact_handle is cryptographically erased");
    }
    if (!BLOB_ID_RE.test(record.blob_id || "")) throw new Error("artifact record blob identity is corrupt");
    return record;
  }

  function inspect(artifactHandle) {
    return publicDescriptor(getRecord(readIndex(), artifactHandle));
  }

  function compare(leftHandle, rightHandle) {
    const index = readIndex();
    const left = getRecord(index, leftHandle);
    const right = getRecord(index, rightHandle);
    return Object.freeze({
      equal: constantTimeEqual(left.comparison_token, right.comparison_token),
      comparison_scope: "engagement",
    });
  }

  function materialize(artifactHandle) {
    const index = readIndex();
    const record = getRecord(index, artifactHandle);
    const wrapAad = canonicalJson({
      artifact_handle: artifactHandle,
      session_nucleus_hash: sessionNucleusHash,
    });
    const dataKey = decryptAead(wrapKey, record.wrapped_data_key, wrapAad, "wrapped data key");
    try {
      const blobPath = path.join(objectRootFor(index), `${record.blob_id}.json`);
      let envelope;
      try {
        envelope = JSON.parse(readPrivateFile(
          blobPath,
          "vault ciphertext",
          encodedBlobCeiling(record),
        ).toString("utf8"));
      } catch (error) {
        throw new Error(`vault ciphertext is unreadable or corrupt: ${error.message}`);
      }
      const plaintext = decryptAead(dataKey, envelope, artifactAad(record), "vault ciphertext");
      const integrityToken = keyedContentToken(
        integrityKey,
        record.metadata.data_class,
        plaintext,
      );
      if (plaintext.length !== record.byte_length
        || !constantTimeEqual(integrityToken, record.integrity_token)) {
        plaintext.fill(0);
        throw new Error("vault plaintext integrity validation failed");
      }
      return { plaintext, metadata: record.metadata };
    } finally {
      dataKey.fill(0);
    }
  }

  function addReference(artifactHandle, reference) {
    const normalizedRef = assertOpaqueRef(reference, "reference");
    return withLock(() => {
      const index = readIndex();
      getRecord(index, artifactHandle);
      const refs = index.references[artifactHandle] || [];
      if (!refs.includes(normalizedRef)) refs.push(normalizedRef);
      refs.sort();
      index.references[artifactHandle] = refs;
      writeIndex(index);
      return Object.freeze({ artifact_handle: artifactHandle, reference_count: refs.length });
    });
  }

  function removeReference(artifactHandle, reference) {
    const normalizedRef = assertOpaqueRef(reference, "reference");
    return withLock(() => {
      const index = readIndex();
      getRecord(index, artifactHandle);
      const refs = (index.references[artifactHandle] || []).filter((item) => item !== normalizedRef);
      index.references[artifactHandle] = refs;
      writeIndex(index);
      return Object.freeze({ artifact_handle: artifactHandle, reference_count: refs.length });
    });
  }

  function archiveStateExpected(archive) {
    return Object.freeze({
      backup_ref: archive.backup_ref,
      backup_digest: archive.backup_digest,
      artifact_inventory_digest: archive.artifact_inventory_digest,
      seal_effect_ref: archive.seal_effect_ref,
    });
  }

  function reconcileArtifactArchiveRegistry(index, artifactHandle) {
    const custody = ensureBackupCustodyIndex(index, "artifact retirement");
    let changed = false;
    const deleteAfterCommit = [];
    for (const [backupRef, archive] of Object.entries(custody.archives)) {
      if (!archive.artifact_inventory.some((entry) => entry.artifact_handle === artifactHandle)) {
        continue;
      }
      const observed = readBackupArchiveState(
        backupKeyCustody,
        archiveStateExpected(archive),
      );
      if (!observed) {
        if (archive.state !== "prepared") {
          throw new Error("rooted member archive is absent from external custody");
        }
        delete custody.archives[backupRef];
        deleteAfterCommit.push(archive);
        changed = true;
        continue;
      }
      if ((archive.seal_ref && archive.seal_ref !== observed.seal_ref)
        || (archive.sealed_archive_digest
          && archive.sealed_archive_digest !== observed.sealed_archive_digest)) {
        throw new Error("rooted member archive drifted from external custody");
      }
      if (archive.state === "prepared") {
        archive.state = observed.status === "revoked" ? "revoked" : "sealed";
        archive.reserved_index_bytes = 0;
        archive.seal_ref = observed.seal_ref;
        archive.custody_format = observed.custody_format;
        archive.sealed_archive_digest = observed.sealed_archive_digest;
        archive.revocation_effect_ref = observed.revocation_effect_ref;
        archive.revoked_at = observed.revoked_at;
        archive.payload_file_digest = null;
        deleteAfterCommit.push(archive);
        changed = true;
      } else if (observed.status === "revoked" && archive.state !== "revoked") {
        archive.state = "revoked";
        archive.revocation_effect_ref = observed.revocation_effect_ref;
        archive.revoked_at = observed.revoked_at;
        archive.payload_file_digest = null;
        deleteAfterCommit.push(archive);
        changed = true;
      } else if (observed.status !== (archive.state === "revoked" ? "revoked" : "active")) {
        throw new Error("rooted member archive state was rolled back");
      }
    }
    if (changed) {
      writeIndex(index);
      for (const archive of deleteAfterCommit) deleteBackupIntentPayload(archive);
    }
    return Object.values(custody.archives)
      .filter((archive) => archive.state !== "prepared"
        && archive.artifact_inventory.some((entry) => entry.artifact_handle === artifactHandle))
      .map(memberArchiveProjection)
      .sort((left, right) => left.backup_ref.localeCompare(right.backup_ref));
  }

  function assertDeletionRetirementCapacity(ledger, validatedRecord, deletionIntent, custody) {
    const currentRecordDigest = sha256(canonicalJson(validatedRecord));
    if (deletionIntent.prior_record_digest !== currentRecordDigest) {
      throw new Error("pending artifact retirement record conflicts with its durable intent");
    }
    const revokedArchives = deletionIntent.member_archive_registry.map((member) => {
      const archive = custody.archives[member.backup_ref];
      const alreadyRevoked = archive.state === "revoked";
      return {
        ...member,
        revocation_effect_ref: alreadyRevoked
          ? archive.revocation_effect_ref
          : deletionIntent.retirement_effect_ref,
        revoked_at: alreadyRevoked ? archive.revoked_at : deletionIntent.requested_at,
        revocation_receipt: "0".repeat(64),
      };
    });
    const externalRetirement = {
      version: ARTIFACT_VAULT_SCHEMA_VERSION,
      status: "retired",
      custody_id: backupKeyCustody.custody_id,
      custody_epoch: backupKeyCustody.custody_epoch,
      vault_id: vaultMetadata.vault_id,
      vault_slot: vaultMetadata.vault_slot,
      session_nucleus_hash: sessionNucleusHash,
      artifact_handle: deletionIntent.artifact_handle,
      reason_ref: deletionIntent.reason_ref,
      retirement_effect_ref: deletionIntent.retirement_effect_ref,
      retired_at: deletionIntent.requested_at,
      revocation_policy: "whole_archive_key_on_member_erasure",
      member_archive_registry_digest: deletionIntent.member_archive_registry_digest,
      revoked_archives: revokedArchives,
      revoked_archives_digest: sha256(canonicalJson(revokedArchives)),
      active_archive_count: 0,
      retirement_receipt: "0".repeat(64),
      production_ready: false,
      hil_verified: false,
      backup_media_erasure_attested: false,
    };
    const receiptPayload = {
      version: ARTIFACT_VAULT_SCHEMA_VERSION,
      artifact_handle: deletionIntent.artifact_handle,
      session_nucleus_hash: sessionNucleusHash,
      deleted_at: deletionIntent.requested_at,
      reason_ref: deletionIntent.reason_ref,
      prior_record_digest: deletionIntent.prior_record_digest,
      deletion_kind: "managed_cryptographic_erasure",
      current_store_erasure_kind: "deletion_ledger_key_unreachability",
      external_backup_key_retirement: externalRetirement,
      backup_media_erasure_status: "not_attested",
    };
    const projectedLedger = JSON.parse(JSON.stringify(ledger));
    projectedLedger.entries[deletionIntent.artifact_handle] = {
      ...receiptPayload,
      receipt_mac: "0".repeat(64),
    };
    projectedLedger.generation += 1;
    const projectedEncodedBytes = Buffer.byteLength(encodeDeletionLedger(projectedLedger), "utf8");
    if (projectedEncodedBytes > deletionLedgerEncodedBytesCeiling) {
      throw new Error(
        "deletion ledger lacks reserved capacity for exact external retirement evidence",
      );
    }
    return projectedEncodedBytes;
  }

  function eraseArtifactLocked(index, artifactHandle, reasonRef, deletedAt) {
    if (Object.values(ensureBackupCustodyIndex(index, "artifact retirement").restore_intents)
      .some((intent) => intent.state !== "released")) {
      throw new Error("artifact retirement is blocked by a pending backup-restore custody intent");
    }
    const pinningAttempt = Object.values(index.batches || {}).find(
      (attempt) => attempt.state === "claimed" && attempt.input_handles.includes(artifactHandle),
    );
    if (pinningAttempt) {
      throw new Error("artifact is pinned by a claimed transform attempt and requires terminal adjudication");
    }
    const ledger = readDeletionLedger(index);
    let receipt = ledger.entries[artifactHandle] || null;
    const record = index.records[artifactHandle] || null;
    if (!receipt) {
      const validatedRecord = getRecord(index, artifactHandle, { allowDeleted: true });
      const references = index.references[artifactHandle] || [];
      if (references.length > 0) throw new Error("artifact is still referenced and cannot be erased");
      const custody = ensureBackupCustodyIndex(index, "artifact retirement");
      const conflictingIntent = Object.keys(custody.deletion_intents)
        .find((pendingHandle) => pendingHandle !== artifactHandle);
      if (conflictingIntent) {
        throw new Error("artifact retirement is blocked by another pending deletion-ledger reservation");
      }
      let deletionIntent = custody.deletion_intents[artifactHandle] || null;
      if (!deletionIntent) {
        const memberArchiveRegistry = reconcileArtifactArchiveRegistry(index, artifactHandle);
        deletionIntent = {
          version: ARTIFACT_VAULT_SCHEMA_VERSION,
          artifact_handle: artifactHandle,
          reason_ref: reasonRef,
          requested_at: deletedAt,
          prior_record_digest: sha256(canonicalJson(validatedRecord)),
          retirement_effect_ref: `backup-effect:v1:${randomToken()}`,
          member_archive_registry: memberArchiveRegistry,
          member_archive_registry_digest: sha256(canonicalJson(memberArchiveRegistry)),
          deletion_ledger_generation: ledger.generation,
          projected_ledger_encoded_bytes: 0,
        };
        deletionIntent.projected_ledger_encoded_bytes = assertDeletionRetirementCapacity(
          ledger,
          validatedRecord,
          deletionIntent,
          custody,
        );
        custody.deletion_intents[artifactHandle] = deletionIntent;
        writeIndex(index);
      } else if (deletionIntent.reason_ref !== reasonRef) {
        throw new Error("pending artifact retirement reason conflicts with its durable intent");
      } else {
        if (deletionIntent.deletion_ledger_generation !== ledger.generation) {
          throw new Error("pending artifact retirement lost its deletion-ledger capacity reservation");
        }
        const projectedEncodedBytes = assertDeletionRetirementCapacity(
          ledger,
          validatedRecord,
          deletionIntent,
          custody,
        );
        if (projectedEncodedBytes !== deletionIntent.projected_ledger_encoded_bytes) {
          throw new Error("pending artifact retirement capacity projection drifted from its durable intent");
        }
      }
      const externalBackupKeyRetirement = retireArtifactBackupKeys(backupKeyCustody, {
        artifact_handle: artifactHandle,
        reason_ref: deletionIntent.reason_ref,
        requested_at: deletionIntent.requested_at,
        retirement_effect_ref: deletionIntent.retirement_effect_ref,
        member_archive_registry: deletionIntent.member_archive_registry,
      });
      assertBackupKeyRetirementEvidence(
        backupKeyCustody,
        externalBackupKeyRetirement,
        artifactHandle,
      );
      const receiptPayload = {
        version: ARTIFACT_VAULT_SCHEMA_VERSION,
        artifact_handle: artifactHandle,
        session_nucleus_hash: sessionNucleusHash,
        deleted_at: deletionIntent.requested_at,
        reason_ref: deletionIntent.reason_ref,
        prior_record_digest: sha256(canonicalJson(validatedRecord)),
        deletion_kind: "managed_cryptographic_erasure",
        current_store_erasure_kind: "deletion_ledger_key_unreachability",
        external_backup_key_retirement: externalBackupKeyRetirement,
        backup_media_erasure_status: "not_attested",
      };
      receipt = {
        ...receiptPayload,
        receipt_mac: crypto.createHmac("sha256", auditKey)
          .update(canonicalJson(receiptPayload))
          .digest("hex"),
      };
      ledger.entries[artifactHandle] = receipt;
      // The deletion ledger commits first. Every read consults it, so a crash
      // before index cleanup still makes the wrapped DEK unreachable.
      writeDeletionLedger(ledger);
    } else {
      const custody = ensureBackupCustodyIndex(index, "artifact retirement reconciliation");
      const rootedRegistry = Object.values(custody.archives)
        .filter((archive) => archive.state !== "prepared"
          && archive.artifact_inventory.some((entry) => entry.artifact_handle === artifactHandle))
        .map(memberArchiveProjection)
        .sort((left, right) => left.backup_ref.localeCompare(right.backup_ref));
      const reconciledExternalRetirement = retireArtifactBackupKeys(backupKeyCustody, {
        artifact_handle: artifactHandle,
        reason_ref: receipt.reason_ref,
        requested_at: receipt.deleted_at,
        retirement_effect_ref: receipt.external_backup_key_retirement.retirement_effect_ref,
        member_archive_registry: rootedRegistry,
      });
      if (canonicalJson(reconciledExternalRetirement)
        !== canonicalJson(receipt.external_backup_key_retirement)) {
        throw new Error("external backup-key retirement drifted behind the deletion ledger");
      }
    }
    const custody = ensureBackupCustodyIndex(index, "artifact retirement commit");
    let indexChanged = false;
    const backupPayloadsToDelete = [];
    for (const summary of receipt.external_backup_key_retirement.revoked_archives) {
      const archive = custody.archives[summary.backup_ref];
      if (!archive) throw new Error("retirement evidence references an unrooted archive");
      if (archive.state !== "revoked"
        || archive.payload_file_digest !== null
        || archive.revocation_effect_ref !== summary.revocation_effect_ref
        || archive.revoked_at !== summary.revoked_at) indexChanged = true;
      archive.state = "revoked";
      archive.reserved_index_bytes = 0;
      archive.payload_file_digest = null;
      archive.revocation_effect_ref = summary.revocation_effect_ref;
      archive.revoked_at = summary.revoked_at;
      backupPayloadsToDelete.push(archive);
    }
    if (custody.deletion_intents[artifactHandle]) {
      delete custody.deletion_intents[artifactHandle];
      indexChanged = true;
    }
    if (record) {
      delete index.records[artifactHandle];
      delete index.references[artifactHandle];
      pruneBatches(index);
      if (!index.tombstones.some((entry) => entry.artifact_handle === artifactHandle)) {
        index.tombstones.push(receipt);
        while (index.tombstones.length > maxArtifacts) index.tombstones.shift();
      }
      indexChanged = true;
    }
    if (indexChanged) writeIndex(index);
    for (const archive of backupPayloadsToDelete) deleteBackupIntentPayload(archive);
    let ciphertext_deleted = true;
    if (record) {
      try {
        const currentObjectRoot = objectRootFor(index);
        fs.unlinkSync(path.join(currentObjectRoot, `${record.blob_id}.json`));
        fsyncDirectory(currentObjectRoot);
      } catch (error) {
        if (!error || error.code !== "ENOENT") ciphertext_deleted = false;
      }
    }
    return Object.freeze({
      artifact_handle: artifactHandle,
      deletion_kind: receipt.deletion_kind,
      deleted_at: receipt.deleted_at,
      ciphertext_deleted,
      deletion_receipt: receipt.receipt_mac,
      current_store_erasure: Object.freeze({
        status: "committed",
        erasure_kind: receipt.current_store_erasure_kind,
        ciphertext_deleted,
      }),
      external_backup_key_revocation: Object.freeze({
        status: "completed",
        custody_id: receipt.external_backup_key_retirement.custody_id,
        custody_epoch: receipt.external_backup_key_retirement.custody_epoch,
        revocation_policy: receipt.external_backup_key_retirement.revocation_policy,
        revoked_archive_count: receipt.external_backup_key_retirement.revoked_archives.length,
        retirement_effect_ref: receipt.external_backup_key_retirement.retirement_effect_ref,
        retirement_receipt: receipt.external_backup_key_retirement.retirement_receipt,
        production_ready: false,
        hil_verified: false,
      }),
      backup_media_erasure: Object.freeze({
        status: receipt.backup_media_erasure_status,
        physically_destroyed: false,
      }),
    });
  }

  function erase(artifactHandle, reasonRef) {
    const normalizedReason = assertOpaqueRef(reasonRef, "reason_ref");
    return withLock(() => eraseArtifactLocked(readIndex(), artifactHandle, normalizedReason, nowIso()));
  }

  function collectExpired({ reason_ref: reasonRef = "retention:expired" } = {}) {
    const normalizedReason = assertOpaqueRef(reasonRef, "reason_ref");
    const candidates = [];
    const index = readIndex();
    const timestamp = Date.parse(nowIso());
    for (const [handle, record] of Object.entries(index.records)) {
      if (Date.parse(record.metadata.retention_expires_at) <= timestamp
        && (index.references[handle] || []).length === 0) {
        candidates.push(handle);
      }
    }
    const receipts = [];
    for (const handle of candidates) receipts.push(erase(handle, normalizedReason));
    return Object.freeze({ collected: receipts.length, receipts: Object.freeze(receipts) });
  }

  function usage() {
    return withLock(() => {
      const index = readIndex();
      commitExpiredReservationPurge(index, Date.parse(nowIso()));
      const totals = logicalUsage(index);
      return Object.freeze({
        quota_bytes: quotaBytes,
        artifact_logical_overhead_bytes: ARTIFACT_LOGICAL_OVERHEAD_BYTES,
        max_artifacts: maxArtifacts,
        active_bytes: totals.activeBytes,
        reserved_bytes: totals.reservedBytes,
        available_bytes: quotaBytes - totals.total,
        active_artifacts: Object.keys(index.records).length,
        active_reservations: Object.keys(index.reservations).length,
      });
    });
  }

  function createBackup(destinationDescriptor) {
    return withLock(() => {
      const destinationStats = assertSafeRegularDescriptor(
        destinationDescriptor,
        "vault backup destination",
      );
      const destinationIdentityDigest = backupDestinationIdentity(destinationStats);
      let index = readIndex();
      reconcileBackupIntentFiles(index);
      let custody = ensureBackupCustodyIndex(index, "vault backup");
      if (Object.values(custody.restore_intents)
        .some((restoreIntent) => restoreIntent.state !== "released")) {
        throw new Error("vault backup is blocked by a pending backup-restore custody intent");
      }
      if (Object.keys(custody.deletion_intents).length > 0) {
        throw new Error("vault backup is blocked by a pending cryptographic-erasure intent");
      }
      let intent = Object.values(custody.archives).find(
        (archive) => archive.destination_identity_digest === destinationIdentityDigest,
      ) || null;
      let rebindPendingIntent = false;
      let serializedBackup = null;
      let artifactCount;

      if (!intent) {
        const pendingIntents = Object.values(custody.archives)
          .filter((archive) => ["prepared", "sealed"].includes(archive.state));
        if (pendingIntents.length > 1) {
          throw new Error("multiple pending backup intents require their original destinations");
        }
        if (pendingIntents.length === 1) {
          if (destinationStats.size !== 0) {
            throw new Error("replacement backup destination must be a newly created empty file");
          }
          intent = pendingIntents[0];
          rebindPendingIntent = true;
        }
      }

      if (!intent) {
        if (destinationStats.size !== 0) {
          throw new Error("vault backup destination must be a newly created empty file");
        }
        if (Object.keys(custody.archives).length >= MAX_BACKUP_ARCHIVES) {
          throw new Error("vault backup archive registry is full");
        }
        const authenticatedIndex = JSON.parse(JSON.stringify(index));
        // Custody control state is authoritative in the live externally
        // anchored index and is never restored from the archive it governs.
        delete authenticatedIndex.backup_custody;
        const deletionLedger = readDeletionLedger(index);
        for (const artifactHandle of Object.keys(deletionLedger.entries)) {
          delete authenticatedIndex.records[artifactHandle];
          delete authenticatedIndex.references[artifactHandle];
        }
        pruneBatches(authenticatedIndex);
        authenticatedIndex.tombstones = Object.values(deletionLedger.entries)
          .sort((left, right) => left.deleted_at.localeCompare(right.deleted_at))
          .slice(-maxArtifacts);
        const indexWrapper = {
          payload: authenticatedIndex,
          mac: signIndex(authenticatedIndex),
        };
        const objects = {};
        const currentObjectRoot = objectRootFor(indexWrapper.payload);
        for (const record of Object.values(indexWrapper.payload.records)) {
          if (!BLOB_ID_RE.test(record.blob_id || "")) {
            throw new Error("vault index contains an invalid blob identity");
          }
          const blobPath = path.join(currentObjectRoot, `${record.blob_id}.json`);
          objects[record.blob_id] = readPrivateFile(
            blobPath,
            "vault ciphertext",
            encodedBlobCeiling(record),
          ).toString("base64");
        }
        const payload = {
          version: ARTIFACT_VAULT_SCHEMA_VERSION,
          backup_ref: `backup:v1:${randomToken()}`,
          vault_id: vaultMetadata.vault_id,
          vault_slot: vaultMetadata.vault_slot,
          session_nucleus_hash: sessionNucleusHash,
          created_at: nowIso(),
          index: indexWrapper,
          objects,
        };
        const backup = {
          payload,
          mac: crypto.createHmac("sha256", backupAuthenticationKey)
            .update(canonicalJson(payload))
            .digest("hex"),
        };
        serializedBackup = Buffer.from(canonicalJson(backup), "utf8");
        const inventory = normalizeArtifactInventory(
          Object.entries(indexWrapper.payload.records).map(([artifactHandle, record]) => ({
            artifact_handle: artifactHandle,
            record_digest: sha256(canonicalJson(record)),
          })),
        );
        for (const member of inventory) {
          const existingCount = Object.values(custody.archives).filter(
            (archive) => archive.artifact_inventory.some(
              (entry) => entry.artifact_handle === member.artifact_handle,
            ),
          ).length;
          if (existingCount >= MAX_MEMBER_ARCHIVES_PER_ARTIFACT) {
            serializedBackup.fill(0);
            throw new Error("artifact reached its bounded backup membership registry");
          }
        }
        const prepared = {
          version: ARTIFACT_VAULT_SCHEMA_VERSION,
          state: "prepared",
          backup_ref: payload.backup_ref,
          backup_digest: sha256(serializedBackup),
          artifact_inventory: inventory,
          artifact_inventory_digest: sha256(canonicalJson(inventory)),
          seal_effect_ref: `backup-effect:v1:${randomToken()}`,
          created_at: payload.created_at,
          destination_identity_digest: destinationIdentityDigest,
          payload_file_digest: null,
          reserved_index_bytes: BACKUP_INTENT_INDEX_RESERVATION_BYTES,
          seal_ref: null,
          custody_format: null,
          sealed_archive_digest: null,
          revocation_effect_ref: null,
          revoked_at: null,
        };
        try {
          prepared.payload_file_digest = writeBackupIntentPayload(prepared, serializedBackup);
          custody.archives[prepared.backup_ref] = prepared;
          writeIndex(index);
        } catch (error) {
          if (error.index_commit_outcome === "not_committed") {
            delete custody.archives[prepared.backup_ref];
            try { deleteBackupIntentPayload(prepared); } catch {}
          }
          serializedBackup.fill(0);
          throw error;
        }
        intent = prepared;
        artifactCount = inventory.length;
      } else {
        artifactCount = intent.artifact_inventory.length;
        if (intent.state === "revoked") {
          throw new Error("vault backup destination belongs to a revoked archive");
        }
        if (intent.state === "published") {
          if (destinationStats.size < 1) {
            throw new Error("published vault backup destination was truncated");
          }
          const verified = loadVerifiedBackup(destinationDescriptor);
          if (verified.backup.payload.backup_ref !== intent.backup_ref) {
            throw new Error("published vault backup destination drifted from its intent");
          }
          return Object.freeze({
            backup_ref: intent.backup_ref,
            artifact_count: artifactCount,
            created_at: intent.created_at,
            external_backup_key_state: "active",
            custody_id: backupKeyCustody.custody_id,
            custody_epoch: backupKeyCustody.custody_epoch,
            production_ready: false,
            hil_verified: false,
          });
        }
        if (intent.state === "prepared") serializedBackup = readBackupIntentPayload(intent);
      }

      try {
        const externalCustodyEnvelope = intent.state === "prepared"
          ? sealBackupArchive(backupKeyCustody, {
            backup_ref: intent.backup_ref,
            seal_effect_ref: intent.seal_effect_ref,
            plaintext_archive: serializedBackup,
            artifact_inventory: intent.artifact_inventory,
          })
          : readBackupArchiveState(backupKeyCustody, {
            backup_ref: intent.backup_ref,
            backup_digest: intent.backup_digest,
            artifact_inventory_digest: intent.artifact_inventory_digest,
            seal_effect_ref: intent.seal_effect_ref,
          });
        if (!externalCustodyEnvelope || externalCustodyEnvelope.status !== "active"
          || (intent.seal_ref && externalCustodyEnvelope.seal_ref !== intent.seal_ref)
          || (intent.sealed_archive_digest
            && externalCustodyEnvelope.sealed_archive_digest !== intent.sealed_archive_digest)) {
          throw new Error("durable backup seal intent is absent, revoked, or drifted");
        }
        if (intent.state === "prepared") {
          intent.state = "sealed";
          intent.reserved_index_bytes = 0;
          intent.payload_file_digest = null;
          intent.seal_ref = externalCustodyEnvelope.seal_ref;
          intent.custody_format = externalCustodyEnvelope.custody_format;
          intent.sealed_archive_digest = externalCustodyEnvelope.sealed_archive_digest;
          writeIndex(index);
          deleteBackupIntentPayload(intent);
        }
        if (rebindPendingIntent) {
          intent.destination_identity_digest = destinationIdentityDigest;
          writeIndex(index);
          rebindPendingIntent = false;
        }
        const outerArchive = `${canonicalJson({
          version: ARTIFACT_VAULT_SCHEMA_VERSION,
          external_custody_envelope: externalCustodyEnvelope,
        })}\n`;
        const currentDestination = fs.fstatSync(destinationDescriptor);
        if (currentDestination.size === 0) {
          writePrivateDescriptor(
            destinationDescriptor,
            outerArchive,
            "vault backup destination",
          );
        } else {
          const existingBytes = readPrivateDescriptor(
            destinationDescriptor,
            "vault backup destination",
            384 * 1024 * 1024,
          );
          try {
            if (existingBytes.toString("utf8") !== outerArchive) {
              throw new Error("vault backup destination conflicts with its durable seal intent");
            }
          } finally {
            existingBytes.fill(0);
          }
        }
        intent.state = "published";
        writeIndex(index);
        deleteBackupIntentPayload(intent);
        return Object.freeze({
          backup_ref: intent.backup_ref,
          artifact_count: artifactCount,
          created_at: intent.created_at,
          external_backup_key_state: "active",
          custody_id: externalCustodyEnvelope.custody_id,
          custody_epoch: externalCustodyEnvelope.custody_epoch,
          production_ready: false,
          hil_verified: false,
        });
      } finally {
        if (serializedBackup) serializedBackup.fill(0);
      }
    });
  }

  function validateEncodedRecord(record, encoded, label) {
    let envelope;
    try {
      envelope = JSON.parse(encoded.toString("utf8"));
    } catch {
      throw new Error(`${label} contains malformed ciphertext JSON`);
    }
    const wrapAad = canonicalJson({
      artifact_handle: record.artifact_handle,
      session_nucleus_hash: sessionNucleusHash,
    });
    const dataKey = decryptAead(wrapKey, record.wrapped_data_key, wrapAad, `${label} wrapped data key`);
    try {
      const plaintext = decryptAead(dataKey, envelope, artifactAad(record), `${label} ciphertext`);
      try {
        const integrityToken = keyedContentToken(
          integrityKey,
          record.metadata.data_class,
          plaintext,
        );
        if (plaintext.length !== record.byte_length
          || !constantTimeEqual(integrityToken, record.integrity_token)) {
          throw new Error(`${label} plaintext integrity validation failed`);
        }
      } finally {
        plaintext.fill(0);
      }
    } finally {
      dataKey.fill(0);
    }
  }

  function currentObjectInventoryIsReadable(index) {
    try {
      const currentObjectRoot = objectRootFor(index);
      for (const record of Object.values(index.records)) {
        const encoded = readPrivateFile(
          path.join(currentObjectRoot, `${record.blob_id}.json`),
          "current restored vault object",
          encodedBlobCeiling(record),
        );
        try {
          validateEncodedRecord(record, encoded, "current restored vault object");
        } finally {
          encoded.fill(0);
        }
      }
      return true;
    } catch {
      return false;
    }
  }

  function readBackupCustodyEnvelope(sourceDescriptor) {
    const encodedArchive = readPrivateDescriptor(
      sourceDescriptor,
      "vault backup source",
      384 * 1024 * 1024,
    );
    let archive;
    try {
      archive = JSON.parse(encodedArchive.toString("utf8"));
    } catch (error) {
      throw new Error(`vault backup archive is unreadable or corrupt: ${error.message}`);
    } finally {
      encodedArchive.fill(0);
    }
    assertClosedObject(archive, "vault backup archive", ["version", "external_custody_envelope"]);
    if (archive.version !== ARTIFACT_VAULT_SCHEMA_VERSION) {
      throw new Error("vault backup archive schema is unsupported");
    }
    return normalizeStoredBackupCustodyEnvelope(
      archive.external_custody_envelope,
      {
        vault_id: vaultMetadata.vault_id,
        vault_slot: vaultMetadata.vault_slot,
        session_nucleus_hash: sessionNucleusHash,
        custody_id: backupKeyCustody.custody_id,
        custody_epoch: backupKeyCustody.custody_epoch,
      },
    );
  }

  function loadVerifiedBackup(sourceDescriptor, {
    custody_envelope: expectedCustodyEnvelope = null,
    restore_fence: restoreFence = null,
  } = {}) {
    const custodyEnvelope = readBackupCustodyEnvelope(sourceDescriptor);
    if (expectedCustodyEnvelope
      && canonicalJson(custodyEnvelope) !== canonicalJson(expectedCustodyEnvelope)) {
      throw new Error("vault backup source changed behind its durable restore intent");
    }
    const serializedBackup = openBackupArchive(
      backupKeyCustody,
      custodyEnvelope,
      { restore_fence: restoreFence },
    );
    let backup;
    try {
      backup = JSON.parse(serializedBackup.toString("utf8"));
    } catch (error) {
      throw new Error(`vault backup payload is unreadable or corrupt: ${error.message}`);
    } finally {
      serializedBackup.fill(0);
    }
    const expectedMac = backup && backup.payload
      ? crypto.createHmac("sha256", backupAuthenticationKey)
        .update(canonicalJson(backup.payload))
        .digest("hex")
      : "";
    if (!backup || !constantTimeEqual(backup.mac, expectedMac)
      || backup.payload.version !== ARTIFACT_VAULT_SCHEMA_VERSION
      || typeof backup.payload.backup_ref !== "string"
      || !BACKUP_REF_RE.test(backup.payload.backup_ref)
      || backup.payload.backup_ref !== custodyEnvelope.backup_ref
      || backup.payload.vault_id !== vaultMetadata.vault_id
      || backup.payload.vault_slot !== vaultMetadata.vault_slot
      || backup.payload.session_nucleus_hash !== sessionNucleusHash) {
      throw new Error("vault backup authentication or session binding failed");
    }
    const indexWrapper = backup.payload.index;
    if (!indexWrapper || !constantTimeEqual(indexWrapper.mac, signIndex(indexWrapper.payload))) {
      throw new Error("vault backup contains an unauthenticated index");
    }
    if (indexWrapper.payload.version !== ARTIFACT_VAULT_SCHEMA_VERSION
      || indexWrapper.payload.vault_id !== vaultMetadata.vault_id
      || indexWrapper.payload.vault_slot !== vaultMetadata.vault_slot
      || indexWrapper.payload.session_nucleus_hash !== sessionNucleusHash
      || !OBJECT_GENERATION_RE.test(indexWrapper.payload.object_generation || "")
      || !indexWrapper.payload.records || !indexWrapper.payload.references
      || !Array.isArray(indexWrapper.payload.tombstones)) {
      throw new Error("vault backup index schema or session binding is invalid");
    }
    validateBatchIndex(indexWrapper.payload, "vault backup");
    const backupObjectIds = Object.keys(backup.payload.objects || {});
    if (backupObjectIds.length > DEFAULT_MAX_ARTIFACTS) {
      throw new Error("vault backup object inventory exceeds the global artifact bound");
    }
    let aggregateObjectBytes = 0;
    for (const record of Object.values(indexWrapper.payload.records || {})) {
      if (!BLOB_ID_RE.test(record.blob_id || "") || typeof backup.payload.objects[record.blob_id] !== "string") {
        throw new Error("vault backup object inventory is incomplete or malformed");
      }
      const encoded = Buffer.from(backup.payload.objects[record.blob_id], "base64");
      if (encoded.toString("base64") !== backup.payload.objects[record.blob_id]) {
        encoded.fill(0);
        throw new Error("vault backup object inventory has non-canonical base64");
      }
      if (encoded.length > encodedBlobCeiling(record)) {
        encoded.fill(0);
        throw new Error("vault backup object exceeds its bound");
      }
      if (aggregateObjectBytes > MAX_QUOTA_BYTES - encoded.length) {
        encoded.fill(0);
        throw new Error("vault backup aggregate object inventory exceeds the global quota bound");
      }
      aggregateObjectBytes += encoded.length;
      try {
        validateEncodedRecord(record, encoded, "vault backup object");
      } finally {
        encoded.fill(0);
      }
    }
    const expectedBlobIds = Object.values(indexWrapper.payload.records || {})
      .map((record) => record.blob_id)
      .sort();
    const actualBlobIds = Object.keys(backup.payload.objects || {}).sort();
    if (canonicalJson(expectedBlobIds) !== canonicalJson(actualBlobIds)) {
      throw new Error("vault backup object inventory contains missing or unreferenced objects");
    }
    const artifactInventory = normalizeArtifactInventory(
      Object.entries(indexWrapper.payload.records || {}).map(([artifactHandle, record]) => ({
        artifact_handle: artifactHandle,
        record_digest: sha256(canonicalJson(record)),
      })),
      "vault backup artifact inventory",
    );
    if (sha256(canonicalJson(artifactInventory)) !== custodyEnvelope.artifact_inventory_digest) {
      throw new Error("vault backup artifact inventory is not bound by external key custody");
    }
    return Object.freeze({
      backup,
      custody_envelope: custodyEnvelope,
      restore_fence: restoreFence,
    });
  }

  function verifyBackup(sourceDescriptor) {
    const { backup } = loadVerifiedBackup(sourceDescriptor);
    const indexWrapper = backup.payload.index;
    return Object.freeze({
      backup_ref: backup.payload.backup_ref,
      artifact_count: Object.keys(indexWrapper.payload.records || {}).length,
      verified: true,
      external_backup_key_state: "active",
      custody_id: backupKeyCustody.custody_id,
      custody_epoch: backupKeyCustody.custody_epoch,
      production_ready: false,
      hil_verified: false,
    });
  }

  function mergeTransformAttemptLedgers(restoredIndex, currentIndex) {
    restoredIndex.batches = restoredIndex.batches || {};
    if (!currentIndex) return;
    for (const [batchRef, currentAttempt] of Object.entries(currentIndex.batches || {})) {
      const restoredAttempt = restoredIndex.batches[batchRef];
      if (!restoredAttempt) {
        restoredIndex.batches[batchRef] = JSON.parse(JSON.stringify(currentAttempt));
        continue;
      }
      if (!constantTimeEqual(restoredAttempt.binding_digest, currentAttempt.binding_digest)) {
        throw new Error("backup restore transform attempt ledger has a binding conflict");
      }
      if (canonicalJson(restoredAttempt) === canonicalJson(currentAttempt)) continue;
      if (restoredAttempt.state === "claimed"
        && currentAttempt.state !== "claimed"
        && constantTimeEqual(restoredAttempt.claim_token_digest, currentAttempt.claim_token_digest)) {
        restoredIndex.batches[batchRef] = JSON.parse(JSON.stringify(currentAttempt));
        continue;
      }
      throw new Error("backup restore would fork or downgrade a transform attempt fence");
    }
  }

  function assertRestoreIntentEnvelopeBindings(intent, envelope) {
    for (const field of [
      "backup_ref",
      "backup_digest",
      "artifact_inventory_digest",
      "seal_effect_ref",
      "seal_ref",
    ]) {
      if (intent[field] !== envelope[field]) {
        throw new Error(`pending backup restore intent.${field} binding mismatch`);
      }
    }
  }

  function restoreIntentMatchesEnvelope(intent, envelope, sourceIdentityDigest, options) {
    assertRestoreIntentEnvelopeBindings(intent, envelope);
    if (intent.source_identity_digest !== sourceIdentityDigest
      || intent.allow_replace !== options.allow_replace
      || intent.allow_corrupt_index !== options.allow_corrupt_index) {
      throw new Error("pending backup restore intent conflicts with the selected source or recovery flags");
    }
  }

  function restoreFenceForIntent(intent, envelope) {
    return readBackupRestoreFence(backupKeyCustody, envelope, {
      restore_ref: intent.restore_ref,
      acquire_effect_ref: intent.acquire_effect_ref,
    });
  }

  function releaseRestoreFenceForIntent(intent, fence) {
    if (fence.status === "released") {
      if (fence.release_effect_ref !== intent.release_effect_ref) {
        throw new Error("backup restore fence was released under a conflicting durable effect");
      }
      return fence;
    }
    return releaseBackupRestoreFence(backupKeyCustody, fence, {
      release_effect_ref: intent.release_effect_ref,
    });
  }

  function clearRestoreIntent(backupRef, restoreRef, { retain_receipt: retainReceipt = false } = {}) {
    const cleanupIndex = readIndex();
    const cleanupCustody = ensureBackupCustodyIndex(cleanupIndex, "backup restore cleanup");
    const rooted = cleanupCustody.restore_intents[backupRef];
    if (!rooted) return;
    if (rooted.restore_ref !== restoreRef) {
      throw new Error("backup restore cleanup conflicts with a newer durable intent");
    }
    if (retainReceipt) {
      if (rooted.state === "released") return;
      if (rooted.state !== "committed" || !rooted.receipt) {
        throw new Error("backup restore cannot retain a receipt before its generation committed");
      }
      rooted.state = "released";
      rooted.completed_index_generation = cleanupIndex.generation + 1;
    } else {
      if (rooted.state !== "prepared") {
        throw new Error("backup restore cannot discard a committed receipt");
      }
      delete cleanupCustody.restore_intents[backupRef];
    }
    writeIndex(cleanupIndex, {
      allow_restore_intent_mutation: true,
      allow_next_completed_generation: retainReceipt,
    });
  }

  function abandonPreparedRestore(intent, envelope, error, generationRoot = null) {
    try {
      let exactIndex = null;
      try { exactIndex = readIndex(); } catch {}
      const rootedIntent = exactIndex
        && exactIndex.backup_custody.restore_intents[intent.backup_ref];
      let fence = restoreFenceForIntent(intent, envelope);
      if (fence && fence.status === "active") {
        fence = releaseRestoreFenceForIntent(intent, fence);
      }
      if (exactIndex && rootedIntent && rootedIntent.state === "prepared"
        && (!fence || fence.status === "released")) {
        clearRestoreIntent(intent.backup_ref, intent.restore_ref);
      }
      if (generationRoot && exactIndex
        && exactIndex.object_generation !== intent.restored_generation
        && fs.existsSync(generationRoot)) {
        fs.rmSync(generationRoot, { recursive: true, force: true });
      }
    } catch (cleanupError) {
      error.restore_fence_cleanup_error = cleanupError.message;
    }
  }

  function restoreBackup(sourceDescriptor, {
    expected_backup_ref: expectedBackupRef,
    allow_replace: allowReplace = false,
    allow_corrupt_index: allowCorruptIndex = false,
  } = {}) {
    if (typeof expectedBackupRef !== "string" || !BACKUP_REF_RE.test(expectedBackupRef)) {
      throw new Error("expected_backup_ref must be the random opaque backup reference");
    }
    if (typeof allowReplace !== "boolean" || typeof allowCorruptIndex !== "boolean") {
      throw new Error("backup recovery flags must be booleans");
    }
    return withLock(() => {
      const sourceStats = assertSafeRegularDescriptor(sourceDescriptor, "vault backup source");
      const sourceIdentityDigest = backupDestinationIdentity(sourceStats);
      const custodyEnvelope = readBackupCustodyEnvelope(sourceDescriptor);
      if (custodyEnvelope.backup_ref !== expectedBackupRef) {
        throw new Error("backup reference does not match the operator-selected recovery source");
      }

      let currentIndex = null;
      let priorIndexCorrupt = false;
      try {
        currentIndex = readIndex();
      } catch (error) {
        priorIndexCorrupt = true;
        if (!allowCorruptIndex) throw error;
      }
      if (!currentIndex) {
        throw new Error(
          "vault recovery requires the authoritative current index to preserve permanent transform attempt fences",
        );
      }
      let custody = ensureBackupCustodyIndex(currentIndex, "backup restore");
      if (Object.keys(custody.deletion_intents).length > 0) {
        throw new Error("vault recovery refuses while cryptographic erasure holds reserved terminal evidence");
      }
      if (Object.values(custody.archives).some((archive) => ["prepared", "sealed"].includes(archive.state))) {
        throw new Error("vault recovery refuses while backup seal publication is incomplete");
      }
      const conflictingRestore = Object.entries(custody.restore_intents)
        .find(([backupRef, restoreIntent]) => backupRef !== expectedBackupRef
          && restoreIntent.state !== "released");
      if (conflictingRestore) {
        throw new Error("vault recovery is blocked by another durable restore intent");
      }

      let intent = custody.restore_intents[expectedBackupRef] || null;
      if (intent) {
        if (intent.state === "released") {
          assertRestoreIntentEnvelopeBindings(intent, custodyEnvelope);
          const fence = restoreFenceForIntent(intent, custodyEnvelope);
          if (!fence || fence.status !== "released"
            || fence.release_effect_ref !== intent.release_effect_ref) {
            throw new Error("completed backup restore lost its exact released-fence evidence");
          }
          if (intent.completed_index_generation === currentIndex.generation
            && currentObjectInventoryIsReadable(currentIndex)) {
            restoreIntentMatchesEnvelope(intent, custodyEnvelope, sourceIdentityDigest, {
              allow_replace: allowReplace,
              allow_corrupt_index: allowCorruptIndex,
            });
            return Object.freeze(JSON.parse(JSON.stringify(intent.receipt)));
          }
          // A released receipt proves only the operation that completed at its
          // rooted index generation and readable object inventory. Once later
          // state commits or physical objects are lost, the same media begins
          // a new restore with fresh effect and generation identities.
          intent = null;
        } else {
          restoreIntentMatchesEnvelope(intent, custodyEnvelope, sourceIdentityDigest, {
            allow_replace: allowReplace,
            allow_corrupt_index: allowCorruptIndex,
          });
        }
        if (intent && intent.state === "committed") {
          const fence = restoreFenceForIntent(intent, custodyEnvelope);
          if (!fence) throw new Error("committed backup restore lost its durable custody fence state");
          releaseRestoreFenceForIntent(intent, fence);
          const receipt = Object.freeze(JSON.parse(JSON.stringify(intent.receipt)));
          const committedInventoryIsReadable = currentObjectInventoryIsReadable(currentIndex);
          clearRestoreIntent(expectedBackupRef, intent.restore_ref, { retain_receipt: true });
          if (committedInventoryIsReadable) return receipt;
          currentIndex = readIndex();
          custody = ensureBackupCustodyIndex(currentIndex, "backup restore after physical loss");
          intent = null;
        }
        if (intent) {
          const priorFence = restoreFenceForIntent(intent, custodyEnvelope);
          if (priorFence && priorFence.status === "released") {
            if (priorFence.release_effect_ref !== intent.release_effect_ref) {
              throw new Error("prepared backup restore fence was released by a conflicting effect");
            }
            clearRestoreIntent(expectedBackupRef, intent.restore_ref);
            currentIndex = readIndex();
            custody = ensureBackupCustodyIndex(currentIndex, "backup restore restart");
            intent = null;
          }
        }
      }

      if (!intent) {
        if (Object.values(currentIndex.references)
          .some((references) => Array.isArray(references) && references.length > 0)) {
          throw new Error("vault recovery refuses to replace artifacts with live evidence references");
        }
        if (!allowReplace
          && (Object.keys(currentIndex.records).length > 0
            || Object.keys(currentIndex.reservations).length > 0)) {
          throw new Error("vault recovery refuses to replace live artifacts or reservations");
        }
        if (Object.values(currentIndex.batches || {})
          .some((attempt) => attempt.state === "claimed")) {
          throw new Error("vault recovery refuses while a transform attempt holds live input pins");
        }
        const rootedArchive = custody.archives[expectedBackupRef];
        if (!rootedArchive || rootedArchive.state !== "published") {
          throw new Error("vault recovery source is revoked or not in the published anchored archive registry");
        }
        const observedArchive = readBackupArchiveState(backupKeyCustody, {
          backup_ref: custodyEnvelope.backup_ref,
          backup_digest: custodyEnvelope.backup_digest,
          artifact_inventory_digest: custodyEnvelope.artifact_inventory_digest,
          seal_effect_ref: custodyEnvelope.seal_effect_ref,
        });
        if (!observedArchive || observedArchive.status !== "active"
          || observedArchive.seal_ref !== custodyEnvelope.seal_ref
          || observedArchive.sealed_archive_digest !== custodyEnvelope.sealed_archive_digest) {
          throw new Error("external backup key is revoked or drifted before restore intent admission");
        }
        intent = {
          version: ARTIFACT_VAULT_SCHEMA_VERSION,
          state: "prepared",
          backup_ref: expectedBackupRef,
          backup_digest: custodyEnvelope.backup_digest,
          artifact_inventory_digest: custodyEnvelope.artifact_inventory_digest,
          seal_effect_ref: custodyEnvelope.seal_effect_ref,
          seal_ref: custodyEnvelope.seal_ref,
          source_identity_digest: sourceIdentityDigest,
          restore_ref: `backup-restore:v1:${randomToken()}`,
          acquire_effect_ref: `backup-effect:v1:${randomToken()}`,
          release_effect_ref: `backup-effect:v1:${randomToken()}`,
          requested_at: nowIso(),
          restored_generation: `objects-restore-${crypto.randomBytes(12).toString("hex")}`,
          allow_replace: allowReplace,
          allow_corrupt_index: allowCorruptIndex,
          completed_index_generation: null,
          receipt: null,
        };
        custody.restore_intents[expectedBackupRef] = intent;
        writeIndex(currentIndex, { allow_restore_intent_mutation: true });
      }

      let restoreFence;
      try {
        restoreFence = restoreFenceForIntent(intent, custodyEnvelope);
        if (!restoreFence) {
          restoreFence = acquireBackupRestoreFence(backupKeyCustody, custodyEnvelope, {
            restore_ref: intent.restore_ref,
            acquire_effect_ref: intent.acquire_effect_ref,
          });
        }
        if (restoreFence.status !== "active") {
          throw new Error("prepared backup restore does not hold an active custody fence");
        }
      } catch (error) {
        try {
          const observedFence = restoreFenceForIntent(intent, custodyEnvelope);
          if (!observedFence || (observedFence.status === "released"
            && observedFence.release_effect_ref === intent.release_effect_ref)) {
            clearRestoreIntent(expectedBackupRef, intent.restore_ref);
          }
        } catch (cleanupError) {
          error.restore_fence_cleanup_error = cleanupError.message;
        }
        throw error;
      }

      let restoreGenerationRoot = null;
      try {
      let loadedBackup;
      try {
        loadedBackup = loadVerifiedBackup(sourceDescriptor, {
          custody_envelope: custodyEnvelope,
          restore_fence: restoreFence,
        });
      } catch (error) {
        try {
          releaseRestoreFenceForIntent(intent, restoreFence);
          clearRestoreIntent(expectedBackupRef, intent.restore_ref);
        } catch (cleanupError) {
          error.restore_fence_cleanup_error = cleanupError.message;
        }
        throw error;
      }

      const { backup } = loadedBackup;
      const backupIndex = JSON.parse(JSON.stringify(backup.payload.index.payload));
      // Backup media cannot roll back the independently anchored custody
      // registry or its in-flight seal, deletion, and restore intents.
      backupIndex.backup_custody = JSON.parse(JSON.stringify(currentIndex.backup_custody));
      backupIndex.reservation_outcomes = {
        ...(backupIndex.reservation_outcomes || {}),
        ...((currentIndex && currentIndex.reservation_outcomes) || {}),
      };
      mergeTransformAttemptLedgers(backupIndex, currentIndex);
      const deletionLedger = readDeletionLedger(currentIndex);
      for (const artifactHandle of Object.keys(deletionLedger.entries)) {
        delete backupIndex.records[artifactHandle];
        delete backupIndex.references[artifactHandle];
      }
      pruneBatches(backupIndex);
      backupIndex.tombstones = Object.values(deletionLedger.entries)
        .sort((left, right) => left.deleted_at.localeCompare(right.deleted_at))
        .slice(-maxArtifacts);
      backupIndex.reservations = {};
      backupIndex.generation = currentIndex.generation;
      backupIndex.object_generation = intent.restored_generation;
      if (Object.keys(backupIndex.records).length > maxArtifacts) {
        const error = new Error("vault backup exceeds the current artifact count ceiling");
        try {
          releaseRestoreFenceForIntent(intent, restoreFence);
          clearRestoreIntent(expectedBackupRef, intent.restore_ref);
        } catch (cleanupError) {
          error.restore_fence_cleanup_error = cleanupError.message;
        }
        throw error;
      }
      let aggregateObjectBytes = 0;
      for (const record of Object.values(backupIndex.records)) {
        const encoded = Buffer.from(backup.payload.objects[record.blob_id], "base64");
        if (aggregateObjectBytes > quotaBytes - encoded.length) {
          encoded.fill(0);
          const error = new Error("vault backup physical inventory exceeds the current quota");
          try {
            releaseRestoreFenceForIntent(intent, restoreFence);
            clearRestoreIntent(expectedBackupRef, intent.restore_ref);
          } catch (cleanupError) {
            error.restore_fence_cleanup_error = cleanupError.message;
          }
          throw error;
        }
        aggregateObjectBytes += encoded.length;
        record.allocated_bytes = encoded.length;
        encoded.fill(0);
      }
      const restoredUsage = logicalUsage(backupIndex);
      if (restoredUsage.total > quotaBytes || aggregateObjectBytes > quotaBytes) {
        const error = new Error("vault backup logical or physical inventory exceeds the current quota");
        try {
          releaseRestoreFenceForIntent(intent, restoreFence);
          clearRestoreIntent(expectedBackupRef, intent.restore_ref);
        } catch (cleanupError) {
          error.restore_fence_cleanup_error = cleanupError.message;
        }
        throw error;
      }
      const diskStats = fs.statfsSync(root);
      const availableBytes = Number(diskStats.bavail) * Number(diskStats.bsize);
      if (!Number.isFinite(availableBytes)
        || minFreeBytes > Number.MAX_SAFE_INTEGER - aggregateObjectBytes
        || availableBytes < aggregateObjectBytes + minFreeBytes) {
        const error = new Error("vault has insufficient free capacity for backup restore");
        try {
          releaseRestoreFenceForIntent(intent, restoreFence);
          clearRestoreIntent(expectedBackupRef, intent.restore_ref);
        } catch (cleanupError) {
          error.restore_fence_cleanup_error = cleanupError.message;
        }
        throw error;
      }

      const replacedLiveState = Boolean(Object.keys(currentIndex.records).length > 0
        || Object.keys(currentIndex.reservations).length > 0);
      const receiptPayload = {
        version: ARTIFACT_VAULT_SCHEMA_VERSION,
        backup_ref: expectedBackupRef,
        restored_at: intent.requested_at,
        restored_generation: intent.restored_generation,
        prior_index_corrupt: priorIndexCorrupt,
        replaced_live_state: replacedLiveState,
        artifact_count: Object.keys(backupIndex.records).length,
      };
      const receipt = {
        ...receiptPayload,
        recovery_receipt: crypto.createHmac("sha256", auditKey)
          .update(canonicalJson(receiptPayload))
          .digest("hex"),
      };
      const committedIntent = backupIndex.backup_custody.restore_intents[expectedBackupRef];
      committedIntent.state = "committed";
      committedIntent.receipt = receipt;

      const candidateEncoded = Buffer.from(encodeIndex(backupIndex), "utf8");
      try {
        parseIndexBuffer(candidateEncoded, "candidate restored vault index");
        const reservedBytes = reservedTransformIndexBytes(backupIndex);
        if (candidateEncoded.length > indexEncodedBytesCeiling
          || reservedBytes > indexEncodedBytesCeiling - candidateEncoded.length) {
          throw new Error("candidate restored vault index exceeds its configured read ceiling");
        }
      } catch (error) {
        try {
          releaseRestoreFenceForIntent(intent, restoreFence);
          clearRestoreIntent(expectedBackupRef, intent.restore_ref);
        } catch (cleanupError) {
          error.restore_fence_cleanup_error = cleanupError.message;
        }
        throw error;
      } finally {
        candidateEncoded.fill(0);
      }

      const generationRoot = path.join(root, intent.restored_generation);
      restoreGenerationRoot = generationRoot;
      if (fs.existsSync(generationRoot)) {
        const stats = fs.lstatSync(generationRoot);
        if (!stats.isDirectory() || stats.isSymbolicLink()
          || currentIndex.object_generation === intent.restored_generation) {
          throw new Error("prepared backup restore generation is unsafe to reconstruct");
        }
        fs.rmSync(generationRoot, { recursive: true, force: false });
      }
      assertPrivateDirectory(generationRoot);
      // The externally anchored index must never select a generation whose
      // parent directory entry can still disappear after power loss.
      fsyncDirectory(root);
      let generationCommitted = false;
      try {
        for (const record of Object.values(backupIndex.records)) {
          const encoded = Buffer.from(backup.payload.objects[record.blob_id], "base64");
          try {
            const destination = path.join(generationRoot, `${record.blob_id}.json`);
            writeExclusiveFile(destination, encoded, 0o600);
          } finally {
            encoded.fill(0);
          }
        }
        fsyncDirectory(generationRoot);
        // This exact read is the restore linearization point. The external
        // custodian serializes member-key retirement against this active fence
        // through the following anchored index/receipt commit.
        assertBackupRestoreFence(backupKeyCustody, restoreFence, custodyEnvelope);
        try {
          writeIndex(backupIndex, { allow_restore_intent_mutation: true });
          generationCommitted = true;
        } catch (commitError) {
          try {
            const observed = readIndex();
            const observedIntent = observed.backup_custody.restore_intents[expectedBackupRef];
            generationCommitted = observed.object_generation === intent.restored_generation
              && observedIntent && observedIntent.state === "committed"
              && observedIntent.restore_ref === intent.restore_ref;
          } catch (observationError) {
            commitError.restore_commit_observation_error = observationError.message;
          }
          if (!generationCommitted) {
            try {
              releaseRestoreFenceForIntent(intent, restoreFence);
            } catch (releaseError) {
              commitError.restore_fence_release_error = releaseError.message;
            }
            throw commitError;
          }
        }
      } catch (error) {
        if (!generationCommitted) {
          let exactIndex = null;
          try { exactIndex = readIndex(); } catch {}
          if (exactIndex && exactIndex.object_generation !== intent.restored_generation) {
            fs.rmSync(generationRoot, { recursive: true, force: true });
          }
          try {
            let currentFence = restoreFenceForIntent(intent, custodyEnvelope);
            if (currentFence && currentFence.status === "active") {
              currentFence = releaseRestoreFenceForIntent(intent, currentFence);
            }
            if (!currentFence || currentFence.status === "released") {
              clearRestoreIntent(expectedBackupRef, intent.restore_ref);
            }
          } catch (cleanupError) {
            error.restore_fence_cleanup_error = cleanupError.message;
          }
        }
        throw error;
      }

      // The committed intent is retained until release exact-read succeeds. A
      // process loss at either point resumes with the same release effect and
      // returns this same receipt without selecting another generation.
      releaseRestoreFenceForIntent(intent, restoreFence);
      clearRestoreIntent(expectedBackupRef, intent.restore_ref, { retain_receipt: true });
      return Object.freeze(receipt);
      } catch (error) {
        abandonPreparedRestore(intent, custodyEnvelope, error, restoreGenerationRoot);
        throw error;
      }
    });
  }

  function collectOrphanObjectGenerations() {
    return withLock(() => {
      const index = readIndex();
      const removed = [];
      for (const entry of fs.readdirSync(root, { withFileTypes: true })) {
        if (!entry.isDirectory() || !OBJECT_GENERATION_RE.test(entry.name)
          || entry.name === index.object_generation) continue;
        const candidate = path.join(root, entry.name);
        const stats = fs.lstatSync(candidate);
        if (!stats.isDirectory() || stats.isSymbolicLink()) {
          throw new Error("orphan object generation is not a real directory");
        }
        fs.rmSync(candidate, { recursive: true, force: false });
        removed.push(entry.name);
      }
      fsyncDirectory(root);
      return Object.freeze({
        active_generation: index.object_generation,
        removed_generations: Object.freeze(removed.sort()),
      });
    });
  }

  function collectOrphanCiphertexts({ reason_ref: reasonRef = "recovery:orphan-sweep" } = {}) {
    const normalizedReason = assertOpaqueRef(reasonRef, "reason_ref");
    return withLock(() => {
      const index = readIndex();
      const currentObjectRoot = objectRootFor(index);
      const referencedBlobIds = new Set();
      for (const record of Object.values(index.records)) {
        if (!BLOB_ID_RE.test(record.blob_id || "")) {
          throw new Error("vault record contains an invalid blob identity");
        }
        referencedBlobIds.add(record.blob_id);
      }
      for (const reservation of Object.values(index.reservations)) {
        if (!BLOB_ID_RE.test(reservation.blob_id || "")) {
          throw new Error("vault reservation contains an invalid blob identity");
        }
        referencedBlobIds.add(reservation.blob_id);
      }

      const removedBlobIds = [];
      for (const entry of fs.readdirSync(currentObjectRoot, { withFileTypes: true })) {
        const match = /^([a-f0-9]{64})\.json$/.exec(entry.name);
        if (!match) throw new Error("vault object generation contains an unregistered entry");
        const candidate = path.join(currentObjectRoot, entry.name);
        assertSafeRegularFile(candidate, "vault object inventory entry");
        if (referencedBlobIds.has(match[1])) continue;
        fs.unlinkSync(candidate);
        removedBlobIds.push(match[1]);
      }
      fsyncDirectory(currentObjectRoot);
      removedBlobIds.sort();
      const receiptPayload = {
        version: ARTIFACT_VAULT_SCHEMA_VERSION,
        session_nucleus_hash: sessionNucleusHash,
        active_generation: index.object_generation,
        collected_at: nowIso(),
        reason_ref: normalizedReason,
        removed_ciphertexts: removedBlobIds.length,
        removed_inventory_digest: sha256(canonicalJson(removedBlobIds)),
      };
      return Object.freeze({
        active_generation: receiptPayload.active_generation,
        collected_at: receiptPayload.collected_at,
        removed_ciphertexts: receiptPayload.removed_ciphertexts,
        removed_inventory_digest: receiptPayload.removed_inventory_digest,
        collection_receipt: crypto.createHmac("sha256", auditKey)
          .update(canonicalJson(receiptPayload))
          .digest("hex"),
      });
    });
  }

  function recoverStaleLock({
    expected_pid: expectedPid,
    expected_acquired_at: expectedAcquiredAt,
    evidence_ref: evidenceRef,
  } = {}) {
    if (!Number.isSafeInteger(expectedPid) || expectedPid < 1) {
      throw new Error("expected_pid must be a positive safe integer");
    }
    if (typeof expectedAcquiredAt !== "string" || Number.isNaN(Date.parse(expectedAcquiredAt))
      || new Date(expectedAcquiredAt).toISOString() !== expectedAcquiredAt) {
      throw new Error("expected_acquired_at must be a canonical UTC timestamp");
    }
    const normalizedEvidenceRef = assertOpaqueRef(evidenceRef, "evidence_ref");
    repairExclusivePublication(lockPath);
    const initialStats = assertSafeRegularFile(lockPath, "vault recovery lock");
    let initialPayload;
    try {
      initialPayload = JSON.parse(readPrivateFile(lockPath, "vault recovery lock", 4096).toString("utf8"));
    } catch (error) {
      throw new Error(`vault recovery lock is unreadable or corrupt: ${error.message}`);
    }
    assertClosedObject(initialPayload, "vault recovery lock", ["pid", "acquired_at"]);
    if (initialPayload.pid !== expectedPid || initialPayload.acquired_at !== expectedAcquiredAt) {
      throw new Error("vault recovery lock does not match the operator-observed identity");
    }
    let ownerIsDead = false;
    try {
      process.kill(expectedPid, 0);
    } catch (error) {
      if (error && error.code === "ESRCH") ownerIsDead = true;
      else throw new Error("vault lock owner liveness cannot be disproved");
    }
    if (!ownerIsDead) throw new Error("vault lock owner is still live");

    const quarantinePath = path.join(root, `.vault.lock.recovery.${process.pid}.${randomToken()}`);
    fs.renameSync(lockPath, quarantinePath);
    let verified = false;
    try {
      const quarantinedStats = assertSafeRegularFile(quarantinePath, "quarantined vault recovery lock");
      const quarantinedPayload = JSON.parse(readPrivateFile(
        quarantinePath,
        "quarantined vault recovery lock",
        4096,
      ).toString("utf8"));
      if (quarantinedStats.dev !== initialStats.dev || quarantinedStats.ino !== initialStats.ino
        || canonicalJson(quarantinedPayload) !== canonicalJson(initialPayload)) {
        throw new Error("vault recovery lock changed during quarantine");
      }
      verified = true;
    } finally {
      if (!verified) {
        try {
          if (!fs.existsSync(lockPath)) fs.renameSync(quarantinePath, lockPath);
        } catch {}
      }
    }
    fs.unlinkSync(quarantinePath);
    fsyncDirectory(root);
    const receiptPayload = {
      version: ARTIFACT_VAULT_SCHEMA_VERSION,
      session_nucleus_hash: sessionNucleusHash,
      recovered_at: nowIso(),
      dead_owner_pid: expectedPid,
      acquired_at: expectedAcquiredAt,
      evidence_ref: normalizedEvidenceRef,
      lock_identity_digest: sha256(canonicalJson({
        dev: initialStats.dev.toString(),
        ino: initialStats.ino.toString(),
        size: initialStats.size,
        payload: initialPayload,
      })),
    };
    return Object.freeze({
      recovered_at: receiptPayload.recovered_at,
      dead_owner_pid: expectedPid,
      recovery_receipt: crypto.createHmac("sha256", auditKey)
        .update(canonicalJson(receiptPayload))
        .digest("hex"),
    });
  }

  function destroy() {
    let nativeSinkDrainError = null;
    if (!destroyed) {
      const drains = Array.from(providerResponseNativeSinkDrains);
      for (const drain of drains) {
        try {
          drain();
        } catch (error) {
          if (nativeSinkDrainError == null) nativeSinkDrainError = error;
        }
      }
      if (providerResponseNativeSinkDrains.size !== 0 && nativeSinkDrainError == null) {
        nativeSinkDrainError = new Error("native provider response sinks did not drain");
      }
    }
    if (nativeSinkDrainError != null) {
      // Keep the owner and its cleanup capabilities live so the caller can
      // reconcile the staging inode and retry destruction. Reporting success
      // after discarding those capabilities could strand linked plaintext.
      throw new Error("vault destruction could not verify native response sink cleanup", {
        cause: nativeSinkDrainError,
      });
    }
    destroyed = true;
    wrapKey.fill(0);
    integrityKey.fill(0);
    comparisonKey.fill(0);
    indexKey.fill(0);
    indexAnchorKey.fill(0);
    auditKey.fill(0);
    backupAuthenticationKey.fill(0);
    backupIntentKey.fill(0);
    providerResponseReceiptKey.fill(0);
  }

  function assertProviderResponseOwnerLive() {
    if (destroyed) throw new Error("provider response vault owner is destroyed");
  }

  function readProviderResponseReservation(reservationHandle) {
    assertProviderResponseOwnerLive();
    if (typeof reservationHandle !== "string"
      || !PUBLIC_RESERVATION_HANDLE_RE.test(reservationHandle)) {
      throw new Error("provider response reservation_handle is invalid");
    }
    const index = readIndex();
    commitExpiredReservationPurge(index, Date.parse(nowIso()));
    const reservation = index.reservations[reservationHandle];
    if (reservation) {
      return Object.freeze({
        state: "active",
        reservation_handle: reservationHandle,
        reservation_ref: reservation.reservation_ref,
        reservation_binding_digest: reservation.reservation_binding_digest,
        byte_ceiling: reservation.byte_ceiling,
        expires_at: reservation.expires_at,
        task_id: reservation.task_id,
        attempt_id: reservation.attempt_id,
        artifact_handle: reservation.artifact_handle,
        metadata: null,
        byte_length: null,
        integrity_token: null,
        created_at: null,
      });
    }
    const record = Object.values(index.records).find(
      (candidate) => candidate.ingest_reservation_handle === reservationHandle,
    );
    if (!record) return null;
    return Object.freeze({
      state: "committed",
      reservation_handle: reservationHandle,
      reservation_ref: record.reservation_ref,
      reservation_binding_digest: record.reservation_binding_digest,
      byte_ceiling: record.reservation_byte_ceiling,
      expires_at: record.reservation_expires_at,
      task_id: record.metadata.task_id,
      attempt_id: record.metadata.attempt_id,
      artifact_handle: record.artifact_handle,
      metadata: normalizeArtifactMetadata(record.metadata, "provider response committed metadata"),
      byte_length: record.byte_length,
      integrity_token: record.integrity_token,
      created_at: record.created_at,
    });
  }

  const vault = Object.freeze({
    reserve,
    releaseReservation,
    ingest,
    inspect,
    compare,
    addReference,
    removeReference,
    erase,
    collectExpired,
    usage,
    createBackup,
    verifyBackup,
    restoreBackup,
    collectOrphanObjectGenerations,
    collectOrphanCiphertexts,
    recoverStaleLock,
    destroy,
  });
  VAULT_INTERNALS.set(vault, Object.freeze({
    adjudicateTransformAttempt,
    claimTransformAttempt,
    failTransformAttempt,
    materialize,
    inspectTransformBatch,
    inspectTransformAttempt,
    ingestTransformBatch,
    provider_response_owner: Object.freeze({
      version: ARTIFACT_VAULT_SCHEMA_VERSION,
      vault_id: vaultMetadata.vault_id,
      vault_slot: vaultMetadata.vault_slot,
      session_nucleus_hash: sessionNucleusHash,
      receipt_root: path.join(root, "provider-response-receipts"),
      native_response_sink_root: path.join(root, "native-provider-response-sinks"),
      max_receipts: maxArtifacts,
      production_ready: false,
      hardware_access_authorized: false,
      execution_authority: false,
      assert_live: assertProviderResponseOwnerLive,
      authenticate_state(serialized) {
        assertProviderResponseOwnerLive();
        return crypto.createHmac("sha256", providerResponseReceiptKey)
          .update("hacker-bob/provider-response-vault-state/v1\0")
          .update(serialized)
          .digest("hex");
      },
      content_token(metadata, bytes) {
        assertProviderResponseOwnerLive();
        return keyedContentToken(integrityKey, metadata.data_class, bytes);
      },
      ingest(reservationHandle, metadata, bytes) {
        assertProviderResponseOwnerLive();
        return ingestProviderResponse({
          reservation_handle: reservationHandle,
          metadata,
          plaintext: bytes,
        });
      },
      now_iso: nowIso,
      read_reservation: readProviderResponseReservation,
      release_reservation(reservationHandle, reasonRef) {
        assertProviderResponseOwnerLive();
        return releaseReservation(reservationHandle, reasonRef);
      },
      register_native_response_sink_drain(drain) {
        assertProviderResponseOwnerLive();
        if (typeof drain !== "function" || providerResponseNativeSinkDrains.has(drain)) {
          throw new Error("native provider response sink drain registration is invalid");
        }
        providerResponseNativeSinkDrains.add(drain);
      },
      unregister_native_response_sink_drain(drain) {
        if (!providerResponseNativeSinkDrains.delete(drain)) {
          throw new Error("native provider response sink drain is not registered");
        }
      },
      with_lock: withLock,
    }),
  }));
  return vault;
}

function hasVaultWorkerAccess(vault) {
  return VAULT_INTERNALS.has(vault);
}

function getProviderResponseVaultOwner(vault) {
  const internal = VAULT_INTERNALS.get(vault);
  if (!internal || !internal.provider_response_owner) {
    throw new Error("vault lacks provider-response owner access");
  }
  internal.provider_response_owner.assert_live();
  return internal.provider_response_owner;
}

function materializeForWorker(vault, artifactHandle) {
  const internal = VAULT_INTERNALS.get(vault);
  if (!internal) throw new Error("vault lacks worker-only access");
  return internal.materialize(artifactHandle);
}

function claimTransformAttemptForWorker(vault, request) {
  const internal = VAULT_INTERNALS.get(vault);
  if (!internal) throw new Error("vault lacks worker-only access");
  return internal.claimTransformAttempt(request);
}

function failTransformAttemptForWorker(vault, request) {
  const internal = VAULT_INTERNALS.get(vault);
  if (!internal) throw new Error("vault lacks worker-only access");
  return internal.failTransformAttempt(request);
}

function inspectTransformAttemptForWorker(vault, batchRef, bindingDigest) {
  const internal = VAULT_INTERNALS.get(vault);
  if (!internal) throw new Error("vault lacks worker-only access");
  return internal.inspectTransformAttempt(batchRef, bindingDigest);
}

function adjudicateTransformAttemptForOperator(vault, request) {
  const internal = VAULT_INTERNALS.get(vault);
  if (!internal) throw new Error("vault lacks operator adjudication access");
  return internal.adjudicateTransformAttempt(request);
}

function inspectTransformAttemptForOperator(vault, batchRef, bindingDigest) {
  const internal = VAULT_INTERNALS.get(vault);
  if (!internal) throw new Error("vault lacks operator inspection access");
  return internal.inspectTransformAttempt(batchRef, bindingDigest);
}

function inspectTransformBatchForWorker(vault, batchRef, bindingDigest) {
  const internal = VAULT_INTERNALS.get(vault);
  if (!internal) throw new Error("vault lacks worker-only access");
  return internal.inspectTransformBatch(batchRef, bindingDigest);
}

function ingestTransformBatchForWorker(vault, request) {
  const internal = VAULT_INTERNALS.get(vault);
  if (!internal) throw new Error("vault lacks worker-only access");
  return internal.ingestTransformBatch(request);
}

module.exports = {
  adjudicateTransformAttemptForOperator,
  claimTransformAttemptForWorker,
  createArtifactVault,
  failTransformAttemptForWorker,
  hasVaultWorkerAccess,
  ingestTransformBatchForWorker,
  inspectTransformBatchForWorker,
  inspectTransformAttemptForWorker,
  inspectTransformAttemptForOperator,
  getProviderResponseVaultOwner,
  materializeForWorker,
};
