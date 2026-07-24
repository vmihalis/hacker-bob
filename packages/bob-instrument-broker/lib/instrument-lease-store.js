"use strict";

// Plane-PH PH-S7 durable broker-side state store.
//
// This module is deliberately not registered as an MCP tool and must run in the
// broker/worker trust domain, outside the model-facing process. It turns the
// pure records in instrument-lease-contract.js into an encrypted, append-only,
// fsync-before-effect ledger. A separate monotonic state anchor is mandatory:
// filesystem state alone is not accepted as an anti-rollback boundary.

const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { types: utilTypes } = require("node:util");

const arrayIsArray = Array.isArray;
const arrayPrototypeFilter = Array.prototype.filter;
const arrayPrototypeFind = Array.prototype.find;
const arrayPrototypeIncludes = Array.prototype.includes;
const arrayPrototypeJoin = Array.prototype.join;
const arrayPrototypeMap = Array.prototype.map;
const arrayPrototypePush = Array.prototype.push;
const arrayPrototypeSome = Array.prototype.some;
const arrayPrototypeSort = Array.prototype.sort;
const cryptoCreateHash = crypto.createHash;
const cryptoHashDigest = crypto.Hash.prototype.digest;
const cryptoHashUpdate = crypto.Hash.prototype.update;
const dateConstructor = Date;
const dateParse = Date.parse;
const datePrototypeGetTime = Date.prototype.getTime;
const datePrototypeToISOString = Date.prototype.toISOString;
const jsonParse = JSON.parse;
const jsonStringify = JSON.stringify;
const numberIsFinite = Number.isFinite;
const numberIsNaN = Number.isNaN;
const numberIsSafeInteger = Number.isSafeInteger;
const objectEntries = Object.entries;
const objectGetOwnPropertyDescriptors = Object.getOwnPropertyDescriptors;
const objectGetPrototypeOf = Object.getPrototypeOf;
const objectHasOwn = Object.prototype.hasOwnProperty;
const objectPrototype = Object.prototype;
const reflectApply = Reflect.apply;
const reflectOwnKeys = Reflect.ownKeys;
const regexpConstructor = RegExp;
const regexpPrototypeExec = RegExp.prototype.exec;
const utilIsProxy = utilTypes.isProxy;

function hasOwn(value, field) {
  return reflectApply(objectHasOwn, value, [field]);
}

function arrayFilter(value, callback) {
  return reflectApply(arrayPrototypeFilter, value, [callback]);
}

function arrayFind(value, callback) {
  return reflectApply(arrayPrototypeFind, value, [callback]);
}

function arrayIncludes(value, candidate) {
  return reflectApply(arrayPrototypeIncludes, value, [candidate]);
}

function arrayJoin(value, separator) {
  return reflectApply(arrayPrototypeJoin, value, [separator]);
}

function arrayMap(value, callback) {
  return reflectApply(arrayPrototypeMap, value, [callback]);
}

function arrayPush(value, candidate) {
  return reflectApply(arrayPrototypePush, value, [candidate]);
}

function arraySome(value, callback) {
  return reflectApply(arrayPrototypeSome, value, [callback]);
}

function arraySort(value, compare) {
  reflectApply(arrayPrototypeSort, value, compare == null ? [] : [compare]);
  return value;
}

function compareStrings(left, right) {
  if (left === right) return 0;
  return left < right ? -1 : 1;
}

function parseTimestamp(value) {
  return reflectApply(dateParse, dateConstructor, [value]);
}

const {
  acquireInstrumentLease,
  assertAttemptJournalAppend,
  assertDurableOutboxAppend,
  assertOutboxJournalBinding,
  beginInstrumentRestoration,
  fenceInstrumentLease,
  normalizeAttemptJournalEntry,
  normalizeDurableOutboxEntry,
  normalizeEffectDispatchRecord,
  normalizeInstrumentLease,
  normalizeOutboxAcknowledgement,
  normalizeProviderDispatchCredential,
  normalizeProviderDispatchRedemption,
  normalizeSafetySupervisorContract,
  PROVIDER_DISPATCH_CREDENTIAL_DOMAIN,
  providerDispatchFenceBindingDigest,
  isLeaseBlocking,
  releaseInstrumentLease,
  renewInstrumentLease,
} = require("../../../mcp/lib/instrument-lease-contract.js");
const {
  normalizeOpaqueRef,
} = require("../../bob-instrument-contracts/lib/physical-quantities.js");
const {
  assertCurrentPhysicalDispatchAuthority,
  assertPhysicalDispatchAuthorityPort,
} = require("../../../mcp/lib/physical-dispatch-authority.js");
const {
  normalizePhysicalExecutionCompositeBinding,
} = require("./physical-execution-transaction-owner.js");

const STORE_VERSION = 1;
const MAX_EVENTS = 100_000;
const SAFETY_EVENT_RESERVE = 16_384;
const ORDINARY_EVENT_LIMIT = MAX_EVENTS - SAFETY_EVENT_RESERVE;
const MAX_ACTIVE_LEASES = 64;
const MAX_OUTBOX_ENTRIES_PER_ATTEMPT = 64;
const MAX_EVENT_PLAINTEXT_BYTES = 1024 * 1024;
const MAX_EVENT_FILE_BYTES = 2 * 1024 * 1024;
const MAX_METADATA_BYTES = 64 * 1024;
const CHECKPOINT_VERSION = 1;
const LEGACY_CHECKPOINT_PROJECTION_SCHEMA_VERSION = 1;
const CHECKPOINT_PROJECTION_SCHEMA_VERSION = 2;
const EXECUTION_TRANSACTION_READER_SCHEMA_VERSION = 2;
const CHECKPOINT_DOMAIN = "hacker-bob/instrument-lease-checkpoint/v1";
const CHECKPOINT_ENVELOPE_DOMAIN = "hacker-bob/instrument-lease-checkpoint-envelope/v1";
const CHECKPOINT_MODES = Object.freeze(["bounded_checkpoint", "legacy_full_audit"]);
const CHECKPOINT_TAIL_EVENT_LIMIT = 1024;
const CHECKPOINT_INTERVAL_EVENTS = 512;
const MIN_CHECKPOINT_PLAINTEXT_BYTES = 1024;
const MAX_CHECKPOINT_PLAINTEXT_BYTES = 32 * 1024 * 1024;
const MAX_CHECKPOINT_FILE_BYTES = 48 * 1024 * 1024;
const MAX_CHECKPOINTS = MAX_EVENTS + 1;
const MAX_EXECUTION_TRANSACTIONS = 4096;
const EXECUTION_TRANSACTION_PRODUCTION_BLOCKERS = Object.freeze([
  "worst_case_post_arm_capacity_reservation_missing",
  "native_commit_go_attestation_missing",
  "native_effect_arm_attestation_missing",
  "authenticated_native_terminal_origin_missing",
  "external_anchor_implementation_attestation_missing",
  "hardware_in_loop_qualification_missing",
]);
const SHA256_PATTERN = /^[a-f0-9]{64}$/;
const IDENTIFIER_PATTERN = /^[a-z][a-z0-9._-]{0,127}$/;
const TOKEN_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:@-]{0,190}$/;
const DURABLE_INSTRUMENT_LEASE_STORES = new WeakSet();
const DURABLE_INSTRUMENT_LEASE_STORE_STATE = new WeakMap();
const DURABLE_INSTRUMENT_LEASE_BROKER_PORTS = new WeakSet();
const DURABLE_INSTRUMENT_LEASE_BROKER_PORT_STATE = new WeakMap();
const DURABLE_PHYSICAL_EXECUTION_TRANSACTION_PORTS = new WeakSet();
const DURABLE_PHYSICAL_EXECUTION_TRANSACTION_PORT_STATE = new WeakMap();
const DURABLE_PROVIDER_DISPATCH_CREDENTIALS = new WeakSet();
const DURABLE_PROVIDER_DISPATCH_CREDENTIAL_STATE = new WeakMap();
const DURABLE_PROVIDER_DISPATCH_PORTS = new WeakSet();
const DURABLE_PROVIDER_DISPATCH_PORT_STATE = new WeakMap();
const DURABLE_PROVIDER_EFFECT_PERMITS = new WeakSet();
const DURABLE_PROVIDER_EFFECT_PERMIT_STATE = new WeakMap();
const INSTRUMENT_LEASE_CHECKPOINT_PORTS = new WeakSet();
const INSTRUMENT_LEASE_CHECKPOINT_PORT_STATE = new WeakMap();
const INSTRUMENT_LEASE_CHECKPOINT_CAPACITY_ERRORS = new WeakSet();
const RUNTIME_ID_PATTERN = /^physical-runtime:v1:[a-f0-9]{32}$/;
const EVENT_FILE_PATTERN = /^(\d{12})\.event\.json$/;
const CHECKPOINT_FILE_PATTERN = /^(\d{12})\.checkpoint\.json$/;
const EVENT_KINDS = Object.freeze([
  "containment_action_claimed",
  "containment_action_completed",
  "dispatch_committed",
  "dispatch_redeemed",
  "execution_transaction_claimed",
  "execution_transaction_vault_committed",
  "journal_appended",
  "lease_acquired",
  "lease_fenced",
  "lease_released",
  "lease_renewed",
  "lease_restoring",
  "outbox_acknowledged",
  "outbox_appended",
  "outbox_delivery_bound",
  "recovery_launch_claimed",
  "recovery_launch_completed",
  "safety_supervisor_registered",
]);
const CONTAINMENT_RESULT_STATES = Object.freeze([
  "ambiguous",
  "confirmed",
  "failed",
  "unavailable",
]);
const RECOVERY_RESULT_STATES = Object.freeze([
  "ambiguous",
  "failed",
  "launched",
  "unavailable",
]);
const IDEMPOTENT_OUTBOX_RECIPIENT_PORTS = new WeakSet();

function isPlainObject(value) {
  if (value == null || typeof value !== "object" || arrayIsArray(value)
      || utilIsProxy(value)) return false;
  const prototype = objectGetPrototypeOf(value);
  return prototype === objectPrototype || prototype === null;
}

function assertClosedObject(value, label, requiredFields, optionalFields = []) {
  if (!isPlainObject(value)) throw new Error(`${label} must be an object`);
  const descriptors = objectGetOwnPropertyDescriptors(value);
  const keys = reflectOwnKeys(descriptors);
  if (arraySome(keys, (field) => typeof field !== "string")) {
    throw new Error(`${label} cannot contain symbol fields`);
  }
  const allowed = arrayMap(requiredFields, (field) => field);
  for (const field of optionalFields) arrayPush(allowed, field);
  const unknown = arraySort(arrayFilter(keys, (field) => !arrayIncludes(allowed, field)));
  if (unknown.length > 0) {
    throw new Error(`${label} has unknown fields: ${arrayJoin(unknown, ", ")}`);
  }
  const missing = arrayFilter(requiredFields, (field) => !hasOwn(descriptors, field));
  if (missing.length > 0) {
    throw new Error(`${label} is missing fields: ${arrayJoin(missing, ", ")}`);
  }
  if (objectGetPrototypeOf(value) === objectPrototype) {
    const prototypeDescriptors = objectGetOwnPropertyDescriptors(objectPrototype);
    const inheritedOptional = arrayFilter(optionalFields, (field) => (
      !hasOwn(descriptors, field) && hasOwn(prototypeDescriptors, field)
    ));
    if (inheritedOptional.length > 0) {
      throw new Error(
        `${label} cannot inherit optional fields: ${arrayJoin(inheritedOptional, ", ")}`,
      );
    }
  }
  for (const field of keys) {
    const descriptor = descriptors[field];
    if (!descriptor || descriptor.enumerable !== true || !hasOwn(descriptor, "value")) {
      throw new Error(`${label}.${field} must be an enumerable data property`);
    }
  }
  return value;
}

function patternMatches(pattern, value) {
  return reflectApply(regexpPrototypeExec, pattern, [value]) !== null;
}

function canonicalJson(value, depth = 0) {
  if (depth > 64) throw new Error("canonical JSON nesting exceeds 64 levels");
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return jsonStringify(value);
  }
  if (typeof value === "number") {
    if (!numberIsFinite(value) || !numberIsSafeInteger(value)) {
      throw new Error("canonical JSON numbers must be finite safe integers");
    }
    return jsonStringify(value);
  }
  if (value != null && typeof value === "object" && utilIsProxy(value)) {
    throw new Error("canonical JSON rejects proxy values");
  }
  if (arrayIsArray(value)) {
    const descriptors = objectGetOwnPropertyDescriptors(value);
    const keys = reflectOwnKeys(descriptors);
    if (keys.length !== value.length + 1 || !hasOwn(descriptors, "length")) {
      throw new Error("canonical JSON arrays must be dense data arrays");
    }
    const entries = [];
    for (let index = 0; index < value.length; index += 1) {
      const descriptor = descriptors[String(index)];
      if (!descriptor || descriptor.enumerable !== true
          || !hasOwn(descriptor, "value")) {
        throw new Error("canonical JSON arrays must contain only enumerable data entries");
      }
      arrayPush(entries, canonicalJson(descriptor.value, depth + 1));
    }
    return `[${arrayJoin(entries, ",")}]`;
  }
  if (!isPlainObject(value)) throw new Error("canonical JSON accepts only plain JSON values");
  const descriptors = objectGetOwnPropertyDescriptors(value);
  const keys = reflectOwnKeys(descriptors);
  if (arraySome(keys, (key) => typeof key !== "string")) {
    throw new Error("canonical JSON objects cannot contain symbol fields");
  }
  for (const key of keys) {
    const descriptor = descriptors[key];
    if (!descriptor || descriptor.enumerable !== true || !hasOwn(descriptor, "value")) {
      throw new Error("canonical JSON objects must contain only enumerable data properties");
    }
  }
  arraySort(keys);
  return `{${arrayJoin(arrayMap(keys, (key) => (
    `${jsonStringify(key)}:${canonicalJson(descriptors[key].value, depth + 1)}`
  )), ",")}}`;
}

function sha256(value) {
  const hash = reflectApply(cryptoCreateHash, crypto, ["sha256"]);
  reflectApply(cryptoHashUpdate, hash, [value]);
  return reflectApply(cryptoHashDigest, hash, ["hex"]);
}

function canonicalDigest(value) {
  return sha256(Buffer.from(canonicalJson(value), "utf8"));
}

function cloneJson(value) {
  return jsonParse(canonicalJson(value));
}

function createInstrumentLeaseCheckpointAnchorPort({
  portId,
  readState,
  compareAndSet,
  maxCheckpointPlaintextBytes = MAX_CHECKPOINT_PLAINTEXT_BYTES,
} = {}) {
  const plaintextLimit = assertStoreInteger(
    maxCheckpointPlaintextBytes,
    "instrument checkpoint anchor maxCheckpointPlaintextBytes",
    MIN_CHECKPOINT_PLAINTEXT_BYTES,
  );
  if (plaintextLimit > MAX_CHECKPOINT_PLAINTEXT_BYTES) {
    throw new Error(
      `instrument checkpoint anchor maxCheckpointPlaintextBytes cannot exceed ${MAX_CHECKPOINT_PLAINTEXT_BYTES}`,
    );
  }
  const port = Object.freeze({
    version: CHECKPOINT_VERSION,
    port_id: assertStoreIdentifier(portId, "instrument checkpoint anchor port_id"),
    contract: "external-monotonic-checkpoint-cas-v1",
    anchor_assurance: "caller_asserted_callback_unattested",
    max_checkpoint_plaintext_bytes: plaintextLimit,
  });
  if (typeof readState !== "function" || typeof compareAndSet !== "function") {
    throw new Error("instrument checkpoint anchor requires readState and compareAndSet functions");
  }
  INSTRUMENT_LEASE_CHECKPOINT_PORTS.add(port);
  INSTRUMENT_LEASE_CHECKPOINT_PORT_STATE.set(port, Object.freeze({
    readState,
    compareAndSet,
    maxCheckpointPlaintextBytes: plaintextLimit,
  }));
  return port;
}

function assertInstrumentLeaseCheckpointAnchorPort(input) {
  if (!input
      || !INSTRUMENT_LEASE_CHECKPOINT_PORTS.has(input)
      || !INSTRUMENT_LEASE_CHECKPOINT_PORT_STATE.has(input)) {
    throw new Error("instrument checkpoint anchor port must be created by Bob's private factory");
  }
  return input;
}

function createIdempotentOutboxRecipientPort({
  recipientPrincipalId,
  idempotencyDomainDigest,
  deliverOnce,
} = {}) {
  // This brand is a closed integration contract, not proof that arbitrary
  // JavaScript is crash-durable. Production wiring must supply a recipient
  // transaction/ledger that atomically commits its external action and receipt
  // under outbox_entry_digest; an in-memory port is suitable only for mocks.
  const recipient = normalizeOpaqueRef(
    recipientPrincipalId,
    "outbox recipient principal",
    { prefix: "principal" },
  );
  if (typeof idempotencyDomainDigest !== "string"
      || !patternMatches(SHA256_PATTERN, idempotencyDomainDigest)) {
    throw new Error("outbox recipient idempotencyDomainDigest must be a lowercase SHA-256 digest");
  }
  if (typeof deliverOnce !== "function") {
    throw new Error("outbox recipient deliverOnce must be a durable idempotent function");
  }
  const port = Object.freeze({
    recipient_principal_id: recipient,
    idempotency_contract: "atomic-recipient-dedup-by-outbox-digest-v1",
    idempotency_domain_digest: idempotencyDomainDigest,
    async accept(command) {
      assertClosedObject(command, "outbox recipient command", [
        "version", "idempotency_key", "idempotency_domain_digest", "outbox_entry",
      ]);
      if (command.version !== STORE_VERSION
          || command.idempotency_key !== command.outbox_entry.outbox_entry_digest
          || command.idempotency_domain_digest !== idempotencyDomainDigest) {
        throw new Error("outbox recipient command is detached from its idempotency contract");
      }
      const acknowledgement = await deliverOnce(Object.freeze(cloneJson(command)));
      if (!isPlainObject(acknowledgement)
          || acknowledgement.outbox_entry_digest !== command.idempotency_key
          || acknowledgement.recipient_principal_id !== recipient) {
        throw new Error("outbox recipient acknowledgement violates the idempotency binding");
      }
      return acknowledgement;
    },
  });
  IDEMPOTENT_OUTBOX_RECIPIENT_PORTS.add(port);
  return port;
}

function assertCanonicalTimestamp(value, label) {
  const parsed = parseTimestamp(value);
  const canonical = new dateConstructor(value);
  if (typeof value !== "string" || numberIsNaN(parsed)
      || reflectApply(datePrototypeToISOString, canonical, []) !== value) {
    throw new Error(`${label} must be a canonical UTC ISO-8601 timestamp`);
  }
  return value;
}

function assertPrivateDirectory(dirPath) {
  if (!fs.existsSync(dirPath)) fs.mkdirSync(dirPath, { recursive: true, mode: 0o700 });
  const stats = fs.lstatSync(dirPath);
  if (!stats.isDirectory() || stats.isSymbolicLink()) {
    throw new Error(`instrument lease store path must be a real directory: ${dirPath}`);
  }
  if (typeof process.getuid === "function" && stats.uid !== process.getuid()) {
    throw new Error(`instrument lease store directory is not owned by the broker principal: ${dirPath}`);
  }
  if ((stats.mode & 0o077) !== 0) {
    throw new Error(`instrument lease store directory must deny group/other access: ${dirPath}`);
  }
}

function openFlags(base) {
  return base | (fs.constants.O_NOFOLLOW || 0);
}

function readPrivateFile(filePath, label, maxBytes, { allowedLinks = 1 } = {}) {
  let descriptor;
  try {
    descriptor = fs.openSync(filePath, openFlags(fs.constants.O_RDONLY));
    const before = fs.fstatSync(descriptor);
    if (!before.isFile() || before.nlink !== allowedLinks || before.size < 1 || before.size > maxBytes) {
      throw new Error(`${label} is not a bounded private regular file`);
    }
    if (typeof process.getuid === "function" && before.uid !== process.getuid()) {
      throw new Error(`${label} is not owned by the broker principal`);
    }
    if ((before.mode & 0o077) !== 0) throw new Error(`${label} is accessible to group/other principals`);
    const buffer = Buffer.alloc(before.size);
    let offset = 0;
    while (offset < buffer.length) {
      const count = fs.readSync(descriptor, buffer, offset, buffer.length - offset, offset);
      if (count === 0) throw new Error(`${label} was truncated while reading`);
      offset += count;
    }
    const after = fs.fstatSync(descriptor);
    if (after.dev !== before.dev || after.ino !== before.ino || after.size !== before.size
        || after.nlink !== allowedLinks) {
      buffer.fill(0);
      throw new Error(`${label} changed while reading`);
    }
    return buffer;
  } finally {
    if (descriptor != null) fs.closeSync(descriptor);
  }
}

function fsyncDirectory(dirPath) {
  const descriptor = fs.openSync(dirPath, openFlags(fs.constants.O_RDONLY));
  try {
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
}

function writeAll(descriptor, buffer) {
  let offset = 0;
  while (offset < buffer.length) {
    offset += fs.writeSync(descriptor, buffer, offset, buffer.length - offset, offset);
  }
}

function publishExclusiveDurable(filePath, buffer) {
  const dirPath = path.dirname(filePath);
  const baseName = path.basename(filePath);
  const candidatePath = path.join(
    dirPath,
    `.${baseName}.pending-${process.pid}-${crypto.randomBytes(12).toString("hex")}`,
  );
  let descriptor;
  try {
    descriptor = fs.openSync(
      candidatePath,
      openFlags(fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY),
      0o600,
    );
    writeAll(descriptor, buffer);
    fs.fsyncSync(descriptor);
    fs.fchmodSync(descriptor, 0o400);
    fs.fsyncSync(descriptor);
    fs.closeSync(descriptor);
    descriptor = null;
    fs.linkSync(candidatePath, filePath);
    fsyncDirectory(dirPath);
    fs.unlinkSync(candidatePath);
    fsyncDirectory(dirPath);
    return true;
  } catch (error) {
    if (error && error.code === "EEXIST") return false;
    throw error;
  } finally {
    if (descriptor != null) fs.closeSync(descriptor);
    try { fs.unlinkSync(candidatePath); } catch {}
  }
}

function repairPublicationSiblings(dirPath) {
  for (const name of fs.readdirSync(dirPath)) {
    const match = reflectApply(
      regexpPrototypeExec,
      /^\.(.+)\.pending-\d+-[a-f0-9]{24}$/,
      [name],
    );
    if (!match) continue;
    const candidatePath = path.join(dirPath, name);
    const finalPath = path.join(dirPath, match[1]);
    let candidate;
    try {
      candidate = fs.lstatSync(candidatePath);
    } catch {
      continue;
    }
    if (!candidate.isFile() || candidate.isSymbolicLink()) {
      throw new Error(`invalid publication sibling in instrument lease store: ${candidatePath}`);
    }
    let final = null;
    try { final = fs.lstatSync(finalPath); } catch {}
    if (final && final.isFile() && !final.isSymbolicLink()
        && final.dev === candidate.dev && final.ino === candidate.ino) {
      fs.unlinkSync(candidatePath);
      fsyncDirectory(dirPath);
      continue;
    }
    // A candidate with no published sibling was never a commit point. It is
    // safe to remove only while the store-wide lock is held.
    if (!final) {
      fs.unlinkSync(candidatePath);
      fsyncDirectory(dirPath);
      continue;
    }
    throw new Error(`conflicting publication sibling in instrument lease store: ${candidatePath}`);
  }
}

function lockOwnerPath(root, token) {
  return path.join(root, `.instrument-store.lock.${token}.candidate`);
}

function isProcessAlive(pid) {
  if (!numberIsSafeInteger(pid) || pid < 1) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return Boolean(error && error.code === "EPERM");
  }
}

function readLockOwner(lockPath) {
  const buffer = readPrivateFile(lockPath, "instrument lease store lock", MAX_METADATA_BYTES, {
    allowedLinks: 2,
  });
  try {
    const owner = jsonParse(buffer.toString("utf8"));
    assertClosedObject(owner, "instrument lease store lock", [
      "version", "pid", "hostname", "token", "created_at",
    ]);
    if (owner.version !== STORE_VERSION || !numberIsSafeInteger(owner.pid) || owner.pid < 1
        || typeof owner.hostname !== "string" || owner.hostname.length < 1 || owner.hostname.length > 255
        || typeof owner.token !== "string"
        || !patternMatches(/^[a-f0-9]{32}$/, owner.token)) {
      throw new Error("instrument lease store lock owner is invalid");
    }
    assertCanonicalTimestamp(owner.created_at, "instrument lease store lock.created_at");
    return owner;
  } finally {
    buffer.fill(0);
  }
}

function reclaimDeadLocalLock(root, finalLockPath) {
  let before;
  try { before = fs.lstatSync(finalLockPath); } catch { return false; }
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 2) {
    throw new Error("instrument lease store lock publication is corrupt");
  }
  const owner = readLockOwner(finalLockPath);
  if (owner.hostname !== os.hostname()) {
    throw new Error("instrument lease store lock belongs to another host and requires operator recovery");
  }
  if (isProcessAlive(owner.pid)) return false;
  const current = fs.lstatSync(finalLockPath);
  if (current.dev !== before.dev || current.ino !== before.ino || current.nlink !== before.nlink) {
    return false;
  }
  fs.unlinkSync(finalLockPath);
  const candidatePath = lockOwnerPath(root, owner.token);
  try {
    const candidate = fs.lstatSync(candidatePath);
    if (candidate.dev === before.dev && candidate.ino === before.ino) fs.unlinkSync(candidatePath);
  } catch {}
  fsyncDirectory(root);
  return true;
}

function acquireStoreLock(root, nowIso) {
  const finalLockPath = path.join(root, ".instrument-store.lock");
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const token = crypto.randomBytes(16).toString("hex");
    const candidatePath = lockOwnerPath(root, token);
    const owner = {
      version: STORE_VERSION,
      pid: process.pid,
      hostname: os.hostname(),
      token,
      created_at: nowIso(),
    };
    const buffer = Buffer.from(`${canonicalJson(owner)}\n`, "utf8");
    let descriptor;
    let lockPublished = false;
    let lockReturned = false;
    try {
      descriptor = fs.openSync(
        candidatePath,
        openFlags(fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY),
        0o600,
      );
      writeAll(descriptor, buffer);
      fs.fsyncSync(descriptor);
      fs.closeSync(descriptor);
      descriptor = null;
      try {
        fs.linkSync(candidatePath, finalLockPath);
        lockPublished = true;
      } catch (error) {
        if (!error || error.code !== "EEXIST") throw error;
        try { fs.unlinkSync(candidatePath); } catch {}
        if (attempt === 0 && reclaimDeadLocalLock(root, finalLockPath)) continue;
        throw new Error("instrument lease store is busy");
      }
      fsyncDirectory(root);
      const identity = fs.lstatSync(finalLockPath);
      const release = () => {
        let current;
        try { current = fs.lstatSync(finalLockPath); } catch { return; }
        if (current.dev !== identity.dev || current.ino !== identity.ino) return;
        let currentOwner;
        try { currentOwner = readLockOwner(finalLockPath); } catch { return; }
        if (currentOwner.token !== token) return;
        fs.unlinkSync(finalLockPath);
        try {
          const candidate = fs.lstatSync(candidatePath);
          if (candidate.dev === identity.dev && candidate.ino === identity.ino) fs.unlinkSync(candidatePath);
        } catch {}
        fsyncDirectory(root);
      };
      lockReturned = true;
      return release;
    } finally {
      buffer.fill(0);
      if (descriptor != null) fs.closeSync(descriptor);
      if (!lockReturned) {
        if (lockPublished) {
          try {
            const final = fs.lstatSync(finalLockPath);
            const candidate = fs.lstatSync(candidatePath);
            if (final.dev === candidate.dev && final.ino === candidate.ino) {
              fs.unlinkSync(finalLockPath);
            }
          } catch {}
        }
        try { fs.unlinkSync(candidatePath); } catch {}
        try { fsyncDirectory(root); } catch {}
      }
    }
  }
  throw new Error("instrument lease store is busy");
}

function deriveStoreKey(masterKey, salt, sessionNucleusHash, runtimeId) {
  return Buffer.from(crypto.hkdfSync(
    "sha256",
    masterKey,
    salt,
    Buffer.from(`bob-plane-ph-s7:${sessionNucleusHash}:${runtimeId}`, "utf8"),
    32,
  ));
}

function deriveCheckpointKey(masterKey, salt, sessionNucleusHash, runtimeId) {
  return Buffer.from(crypto.hkdfSync(
    "sha256",
    masterKey,
    salt,
    Buffer.from(`bob-plane-ph-s7-checkpoint:${sessionNucleusHash}:${runtimeId}`, "utf8"),
    32,
  ));
}

function checkpointFileName(checkpointGeneration) {
  return `${String(checkpointGeneration).padStart(12, "0")}.checkpoint.json`;
}

function checkpointAnchorBasis({
  runtime_id: runtimeId,
  session_nucleus_hash: sessionNucleusHash,
  checkpoint_generation: checkpointGeneration,
  prior_checkpoint_digest: priorCheckpointDigest,
  event_generation: eventGeneration,
  event_head_digest: eventHeadDigest,
  projection_schema_version: projectionSchemaVersion,
  ciphertext_digest: ciphertextDigest,
  checkpoint_envelope_digest: checkpointEnvelopeDigest,
}) {
  return {
    version: CHECKPOINT_VERSION,
    domain: CHECKPOINT_DOMAIN,
    runtime_id: runtimeId,
    session_nucleus_hash: sessionNucleusHash,
    checkpoint_generation: checkpointGeneration,
    prior_checkpoint_digest: priorCheckpointDigest,
    event_generation: eventGeneration,
    event_head_digest: eventHeadDigest,
    projection_schema_version: projectionSchemaVersion,
    ciphertext_digest: ciphertextDigest,
    checkpoint_envelope_digest: checkpointEnvelopeDigest,
    checkpoint_file: checkpointFileName(checkpointGeneration),
  };
}

function normalizeCheckpointAnchorState(input, metadata, label = "instrument checkpoint anchor") {
  if (input == null) return null;
  assertClosedObject(input, label, [
    "version",
    "domain",
    "runtime_id",
    "session_nucleus_hash",
    "checkpoint_generation",
    "prior_checkpoint_digest",
    "event_generation",
    "event_head_digest",
    "projection_schema_version",
    "ciphertext_digest",
    "checkpoint_envelope_digest",
    "checkpoint_file",
    "checkpoint_anchor_digest",
  ]);
  if (input.version !== CHECKPOINT_VERSION || input.domain !== CHECKPOINT_DOMAIN
      || input.runtime_id !== metadata.runtime_id
      || input.session_nucleus_hash !== metadata.session_nucleus_hash) {
    throw new Error(`${label} belongs to another runtime or schema`);
  }
  const checkpointGeneration = assertStoreInteger(
    input.checkpoint_generation,
    `${label}.checkpoint_generation`,
    1,
  );
  if (checkpointGeneration > MAX_CHECKPOINTS) {
    throw new Error(`${label}.checkpoint_generation exceeds the checkpoint ledger`);
  }
  const priorCheckpointDigest = input.prior_checkpoint_digest == null
    ? null
    : assertStoreDigest(input.prior_checkpoint_digest, `${label}.prior_checkpoint_digest`);
  if ((checkpointGeneration === 1) !== (priorCheckpointDigest === null)) {
    throw new Error(`${label} prior digest does not match its checkpoint generation`);
  }
  const eventGeneration = assertStoreInteger(
    input.event_generation,
    `${label}.event_generation`,
  );
  if (eventGeneration > MAX_EVENTS) throw new Error(`${label}.event_generation exceeds the ledger`);
  const eventHeadDigest = input.event_head_digest == null
    ? null
    : assertStoreDigest(input.event_head_digest, `${label}.event_head_digest`);
  if ((eventGeneration === 0) !== (eventHeadDigest === null)) {
    throw new Error(`${label} event genesis/head binding is invalid`);
  }
  if (!arrayIncludes([
    LEGACY_CHECKPOINT_PROJECTION_SCHEMA_VERSION,
    CHECKPOINT_PROJECTION_SCHEMA_VERSION,
  ], input.projection_schema_version)) {
    throw new Error(`${label}.projection_schema_version is unsupported`);
  }
  if (input.checkpoint_file !== checkpointFileName(checkpointGeneration)) {
    throw new Error(`${label}.checkpoint_file is not generation-derived`);
  }
  const basis = checkpointAnchorBasis({
    runtime_id: input.runtime_id,
    session_nucleus_hash: input.session_nucleus_hash,
    checkpoint_generation: checkpointGeneration,
    prior_checkpoint_digest: priorCheckpointDigest,
    event_generation: eventGeneration,
    event_head_digest: eventHeadDigest,
    projection_schema_version: input.projection_schema_version,
    ciphertext_digest: assertStoreDigest(input.ciphertext_digest, `${label}.ciphertext_digest`),
    checkpoint_envelope_digest: assertStoreDigest(
      input.checkpoint_envelope_digest,
      `${label}.checkpoint_envelope_digest`,
    ),
  });
  const anchorDigest = canonicalDigest(basis);
  if (input.checkpoint_anchor_digest !== anchorDigest) {
    throw new Error(`${label}.checkpoint_anchor_digest is invalid`);
  }
  return Object.freeze({ ...basis, checkpoint_anchor_digest: anchorDigest });
}

function checkpointAad(metadata, fields) {
  return Buffer.from(canonicalJson({
    version: CHECKPOINT_VERSION,
    domain: CHECKPOINT_ENVELOPE_DOMAIN,
    runtime_id: metadata.runtime_id,
    session_nucleus_hash: metadata.session_nucleus_hash,
    checkpoint_generation: fields.checkpoint_generation,
    prior_checkpoint_digest: fields.prior_checkpoint_digest,
    event_generation: fields.event_generation,
    event_head_digest: fields.event_head_digest,
    projection_schema_version: fields.projection_schema_version,
  }), "utf8");
}

function createCheckpointCapacityError(message, {
  actualBytes = null,
  limitBytes,
} = {}) {
  const error = new Error(message);
  Object.defineProperties(error, {
    checkpoint_capacity_outcome: {
      value: "exhausted",
      enumerable: false,
    },
    checkpoint_plaintext_bytes: {
      value: actualBytes,
      enumerable: false,
    },
    checkpoint_plaintext_limit_bytes: {
      value: limitBytes,
      enumerable: false,
    },
  });
  INSTRUMENT_LEASE_CHECKPOINT_CAPACITY_ERRORS.add(error);
  return error;
}

function assertCheckpointCapacityError(input) {
  if (!(input instanceof Error)
      || !INSTRUMENT_LEASE_CHECKPOINT_CAPACITY_ERRORS.has(input)) {
    throw new Error("instrument checkpoint failure is not a Bob capacity outcome");
  }
  return input;
}

function encodeCheckpointPlaintext(checkpointPayload, plaintextLimit) {
  const plaintext = Buffer.from(canonicalJson(checkpointPayload), "utf8");
  if (plaintext.length > plaintextLimit) {
    const actualBytes = plaintext.length;
    plaintext.fill(0);
    throw createCheckpointCapacityError(
      `instrument checkpoint plaintext exceeds ${plaintextLimit} bytes`,
      { actualBytes, limitBytes: plaintextLimit },
    );
  }
  return plaintext;
}

function encryptCheckpoint(
  checkpointKey,
  metadata,
  fields,
  checkpointPayload,
  plaintextLimit = MAX_CHECKPOINT_PLAINTEXT_BYTES,
) {
  const plaintext = encodeCheckpointPlaintext(checkpointPayload, plaintextLimit);
  const nonce = crypto.randomBytes(12);
  let ciphertext;
  let tag;
  try {
    const cipher = crypto.createCipheriv("aes-256-gcm", checkpointKey, nonce);
    cipher.setAAD(checkpointAad(metadata, fields));
    ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    tag = cipher.getAuthTag();
  } finally {
    plaintext.fill(0);
  }
  const envelopeBasis = {
    version: CHECKPOINT_VERSION,
    domain: CHECKPOINT_ENVELOPE_DOMAIN,
    algorithm: "aes-256-gcm",
    runtime_id: metadata.runtime_id,
    session_nucleus_hash: metadata.session_nucleus_hash,
    checkpoint_generation: fields.checkpoint_generation,
    prior_checkpoint_digest: fields.prior_checkpoint_digest,
    event_generation: fields.event_generation,
    event_head_digest: fields.event_head_digest,
    projection_schema_version: fields.projection_schema_version,
    nonce: nonce.toString("base64"),
    ciphertext: ciphertext.toString("base64"),
    ciphertext_digest: sha256(ciphertext),
    tag: tag.toString("base64"),
  };
  return Object.freeze({
    ...envelopeBasis,
    checkpoint_envelope_digest: canonicalDigest(envelopeBasis),
  });
}

function decryptCheckpoint(checkpointKey, metadata, anchor, envelope, label) {
  assertClosedObject(envelope, label, [
    "version",
    "domain",
    "algorithm",
    "runtime_id",
    "session_nucleus_hash",
    "checkpoint_generation",
    "prior_checkpoint_digest",
    "event_generation",
    "event_head_digest",
    "projection_schema_version",
    "nonce",
    "ciphertext",
    "ciphertext_digest",
    "tag",
    "checkpoint_envelope_digest",
  ]);
  const exact = {
    version: CHECKPOINT_VERSION,
    domain: CHECKPOINT_ENVELOPE_DOMAIN,
    algorithm: "aes-256-gcm",
    runtime_id: metadata.runtime_id,
    session_nucleus_hash: metadata.session_nucleus_hash,
    checkpoint_generation: anchor.checkpoint_generation,
    prior_checkpoint_digest: anchor.prior_checkpoint_digest,
    event_generation: anchor.event_generation,
    event_head_digest: anchor.event_head_digest,
    projection_schema_version: anchor.projection_schema_version,
  };
  for (const [field, expected] of objectEntries(exact)) {
    if (envelope[field] !== expected) throw new Error(`${label}.${field} anchor binding drift`);
  }
  const envelopeBasis = { ...envelope };
  delete envelopeBasis.checkpoint_envelope_digest;
  if (canonicalDigest(envelopeBasis) !== envelope.checkpoint_envelope_digest
      || envelope.checkpoint_envelope_digest !== anchor.checkpoint_envelope_digest) {
    throw new Error(`${label} digest is invalid`);
  }
  const nonce = Buffer.from(envelope.nonce, "base64");
  const ciphertext = Buffer.from(envelope.ciphertext, "base64");
  const tag = Buffer.from(envelope.tag, "base64");
  if (nonce.length !== 12 || tag.length !== 16
      || nonce.toString("base64") !== envelope.nonce
      || ciphertext.toString("base64") !== envelope.ciphertext
      || tag.toString("base64") !== envelope.tag
      || sha256(ciphertext) !== envelope.ciphertext_digest
      || envelope.ciphertext_digest !== anchor.ciphertext_digest) {
    throw new Error(`${label} encoding or ciphertext digest is invalid`);
  }
  let plaintext;
  try {
    const decipher = crypto.createDecipheriv("aes-256-gcm", checkpointKey, nonce);
    decipher.setAAD(checkpointAad(metadata, anchor));
    decipher.setAuthTag(tag);
    plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    if (plaintext.length > MAX_CHECKPOINT_PLAINTEXT_BYTES) {
      throw new Error("decrypted checkpoint exceeds its plaintext ceiling");
    }
    return jsonParse(plaintext.toString("utf8"));
  } catch (error) {
    throw new Error(`${label} authentication failed`, { cause: error });
  } finally {
    if (plaintext) plaintext.fill(0);
  }
}

function encryptEvent(key, metadata, event) {
  const plaintext = Buffer.from(canonicalJson(event), "utf8");
  if (plaintext.length > MAX_EVENT_PLAINTEXT_BYTES) {
    plaintext.fill(0);
    throw new Error(`instrument lease event exceeds ${MAX_EVENT_PLAINTEXT_BYTES} bytes`);
  }
  const nonce = crypto.randomBytes(12);
  const aad = Buffer.from(canonicalJson({
    version: STORE_VERSION,
    runtime_id: metadata.runtime_id,
    session_nucleus_hash: metadata.session_nucleus_hash,
    generation: event.generation,
  }), "utf8");
  const cipher = crypto.createCipheriv("aes-256-gcm", key, nonce);
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  plaintext.fill(0);
  const envelopePayload = {
    version: STORE_VERSION,
    algorithm: "aes-256-gcm",
    generation: event.generation,
    nonce: nonce.toString("base64"),
    ciphertext: ciphertext.toString("base64"),
    tag: tag.toString("base64"),
  };
  return Object.freeze({
    ...envelopePayload,
    envelope_digest: canonicalDigest(envelopePayload),
  });
}

function decryptEvent(key, metadata, envelope, label) {
  assertClosedObject(envelope, label, [
    "version", "algorithm", "generation", "nonce", "ciphertext", "tag", "envelope_digest",
  ]);
  if (envelope.version !== STORE_VERSION || envelope.algorithm !== "aes-256-gcm"
      || !numberIsSafeInteger(envelope.generation) || envelope.generation < 1
      || !patternMatches(SHA256_PATTERN, envelope.envelope_digest || "")) {
    throw new Error(`${label} is invalid`);
  }
  const envelopePayload = {
    version: envelope.version,
    algorithm: envelope.algorithm,
    generation: envelope.generation,
    nonce: envelope.nonce,
    ciphertext: envelope.ciphertext,
    tag: envelope.tag,
  };
  if (canonicalDigest(envelopePayload) !== envelope.envelope_digest) {
    throw new Error(`${label} digest is invalid`);
  }
  const nonce = Buffer.from(envelope.nonce, "base64");
  const ciphertext = Buffer.from(envelope.ciphertext, "base64");
  const tag = Buffer.from(envelope.tag, "base64");
  if (nonce.length !== 12 || tag.length !== 16
      || nonce.toString("base64") !== envelope.nonce
      || ciphertext.toString("base64") !== envelope.ciphertext
      || tag.toString("base64") !== envelope.tag) {
    throw new Error(`${label} encoding is invalid`);
  }
  const aad = Buffer.from(canonicalJson({
    version: STORE_VERSION,
    runtime_id: metadata.runtime_id,
    session_nucleus_hash: metadata.session_nucleus_hash,
    generation: envelope.generation,
  }), "utf8");
  let plaintext;
  try {
    const decipher = crypto.createDecipheriv("aes-256-gcm", key, nonce);
    decipher.setAAD(aad);
    decipher.setAuthTag(tag);
    plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    if (plaintext.length > MAX_EVENT_PLAINTEXT_BYTES) throw new Error("decrypted event exceeds byte ceiling");
    return jsonParse(plaintext.toString("utf8"));
  } catch (error) {
    throw new Error(`${label} authentication failed`, { cause: error });
  } finally {
    if (plaintext) plaintext.fill(0);
  }
}

function normalizeMetadata(input, sessionNucleusHash, runtimeId) {
  assertClosedObject(input, "instrument lease store metadata", [
    "version", "runtime_id", "session_nucleus_hash", "kdf_salt", "created_at",
  ]);
  if (input.version !== STORE_VERSION || input.runtime_id !== runtimeId
      || !patternMatches(RUNTIME_ID_PATTERN, input.runtime_id || "")
      || input.session_nucleus_hash !== sessionNucleusHash) {
    throw new Error("instrument lease store metadata does not match the requested runtime");
  }
  const salt = Buffer.from(input.kdf_salt, "base64");
  if (salt.length !== 32 || salt.toString("base64") !== input.kdf_salt) {
    throw new Error("instrument lease store metadata KDF salt is invalid");
  }
  assertCanonicalTimestamp(input.created_at, "instrument lease store metadata.created_at");
  return Object.freeze(cloneJson(input));
}

function normalizeAnchorState(input, metadata) {
  if (input == null) return null;
  assertClosedObject(input, "instrument lease external anchor", [
    "version", "runtime_id", "session_nucleus_hash", "generation", "head_event_digest",
  ], ["minimum_reader_schema_version"]);
  if (input.version !== STORE_VERSION || input.runtime_id !== metadata.runtime_id
      || input.session_nucleus_hash !== metadata.session_nucleus_hash
      || !numberIsSafeInteger(input.generation) || input.generation < 0 || input.generation > MAX_EVENTS) {
    throw new Error("instrument lease external anchor belongs to another runtime or is invalid");
  }
  if ((input.generation === 0) !== (input.head_event_digest === null)) {
    throw new Error("instrument lease external anchor genesis/head binding is invalid");
  }
  if (input.generation > 0
      && !patternMatches(SHA256_PATTERN, input.head_event_digest || "")) {
    throw new Error("instrument lease external anchor head digest is invalid");
  }
  const minimumReaderSchemaVersion = input.minimum_reader_schema_version == null
    ? LEGACY_CHECKPOINT_PROJECTION_SCHEMA_VERSION
    : assertStoreInteger(
      input.minimum_reader_schema_version,
      "instrument lease external anchor.minimum_reader_schema_version",
      LEGACY_CHECKPOINT_PROJECTION_SCHEMA_VERSION,
    );
  if (minimumReaderSchemaVersion > EXECUTION_TRANSACTION_READER_SCHEMA_VERSION) {
    throw new Error("instrument lease external anchor requires an unsupported reader schema");
  }
  const normalized = cloneJson(input);
  if (minimumReaderSchemaVersion > LEGACY_CHECKPOINT_PROJECTION_SCHEMA_VERSION) {
    normalized.minimum_reader_schema_version = minimumReaderSchemaVersion;
  }
  return Object.freeze(normalized);
}

function anchorReaderSchema(anchor) {
  return anchor && anchor.minimum_reader_schema_version != null
    ? anchor.minimum_reader_schema_version
    : LEGACY_CHECKPOINT_PROJECTION_SCHEMA_VERSION;
}

function projectionReaderSchema(projection) {
  return projection.executionTransactionSchemaActivated
    ? EXECUTION_TRANSACTION_READER_SCHEMA_VERSION
    : LEGACY_CHECKPOINT_PROJECTION_SCHEMA_VERSION;
}

function anchorState(
  metadata,
  generation,
  headEventDigest,
  minimumReaderSchemaVersion = LEGACY_CHECKPOINT_PROJECTION_SCHEMA_VERSION,
) {
  const value = {
    version: STORE_VERSION,
    runtime_id: metadata.runtime_id,
    session_nucleus_hash: metadata.session_nucleus_hash,
    generation,
    head_event_digest: headEventDigest,
  };
  if (minimumReaderSchemaVersion > LEGACY_CHECKPOINT_PROJECTION_SCHEMA_VERSION) {
    value.minimum_reader_schema_version = minimumReaderSchemaVersion;
  }
  return Object.freeze(value);
}

function anchorContext(metadata) {
  return Object.freeze({
    version: STORE_VERSION,
    runtime_id: metadata.runtime_id,
    session_nucleus_hash: metadata.session_nucleus_hash,
  });
}

function sameJson(left, right) {
  return canonicalJson(left) === canonicalJson(right);
}

function createEmptyProjection() {
  return {
    generation: 0,
    head_event_digest: null,
    last_recorded_at: null,
    leases: new Map(),
    journalHeads: new Map(),
    dispatches: new Map(),
    dispatchSourceJournals: new Map(),
    dispatchCommitAnchors: new Map(),
    dispatchRedemptions: new Map(),
    outboxHeads: new Map(),
    outboxEntries: new Map(),
    outboxDeliveries: new Map(),
    acknowledgements: new Map(),
    safetySupervisorContracts: new Map(),
    containmentActions: new Map(),
    recoveryLaunches: new Map(),
    executionTransactionClaims: new Map(),
    executionTransactionVaultCommits: new Map(),
    executionTransactionVaultArtifacts: new Map(),
    executionTransactionVaultReceipts: new Map(),
    executionTransactionLineages: new Map(),
    executionTransactionKeys: new Map(),
    executionTransactionAttempts: new Map(),
    executionTransactionLeases: new Map(),
    executionTransactionAdmissions: new Map(),
    executionTransactionSchemaActivated: false,
    eventKeys: new Set(),
    eventDigests: new Map(),
  };
}

function cloneProjection(projection) {
  return {
    generation: projection.generation,
    head_event_digest: projection.head_event_digest,
    last_recorded_at: projection.last_recorded_at,
    leases: new Map(projection.leases),
    journalHeads: new Map(projection.journalHeads),
    dispatches: new Map(projection.dispatches),
    dispatchSourceJournals: new Map(projection.dispatchSourceJournals),
    dispatchCommitAnchors: new Map(projection.dispatchCommitAnchors),
    dispatchRedemptions: new Map(projection.dispatchRedemptions),
    outboxHeads: new Map(projection.outboxHeads),
    outboxEntries: new Map(projection.outboxEntries),
    outboxDeliveries: new Map(projection.outboxDeliveries),
    acknowledgements: new Map(projection.acknowledgements),
    safetySupervisorContracts: new Map(projection.safetySupervisorContracts),
    containmentActions: new Map(projection.containmentActions),
    recoveryLaunches: new Map(projection.recoveryLaunches),
    executionTransactionClaims: new Map(projection.executionTransactionClaims),
    executionTransactionVaultCommits: new Map(projection.executionTransactionVaultCommits),
    executionTransactionVaultArtifacts: new Map(projection.executionTransactionVaultArtifacts),
    executionTransactionVaultReceipts: new Map(projection.executionTransactionVaultReceipts),
    executionTransactionLineages: new Map(projection.executionTransactionLineages),
    executionTransactionKeys: new Map(projection.executionTransactionKeys),
    executionTransactionAttempts: new Map(projection.executionTransactionAttempts),
    executionTransactionLeases: new Map(projection.executionTransactionLeases),
    executionTransactionAdmissions: new Map(projection.executionTransactionAdmissions),
    executionTransactionSchemaActivated: projection.executionTransactionSchemaActivated,
    eventKeys: new Set(projection.eventKeys),
    eventDigests: new Map(projection.eventDigests),
  };
}

function isSafetyCriticalEvent(kind, payload) {
  if (arrayIncludes([
    "lease_fenced",
    "lease_released",
    "lease_restoring",
    "outbox_acknowledged",
    "outbox_delivery_bound",
    "safety_supervisor_registered",
    "containment_action_claimed",
    "containment_action_completed",
    "dispatch_redeemed",
    "execution_transaction_vault_committed",
    "recovery_launch_claimed",
    "recovery_launch_completed",
  ], kind)) {
    return true;
  }
  if (kind === "outbox_appended") return true;
  if (kind !== "journal_appended" || !isPlainObject(payload)) return false;
  return arrayIncludes([
    "ambiguous_effect",
    "effect_recorded",
    "irreversible_authorized",
    "quarantined",
    "reconciled_no_effect",
    "restored",
    "restoring",
    "running",
    "stop_acked",
    "stop_forced",
    "stop_requested",
    "unknown_effect",
  ], payload.state);
}

function requireLease(projection, leaseId, label) {
  const lease = projection.leases.get(leaseId);
  if (!lease) throw new Error(`${label} refers to an unknown lease`);
  return lease;
}

function assertEventNotBefore(event, timestamp, label) {
  if (parseTimestamp(event.recorded_at) < parseTimestamp(timestamp)) {
    throw new Error(`instrument lease store event predates ${label}`);
  }
}

function assertLeaseLiveWindow(event, lease, label) {
  if (lease.state !== "held") {
    throw new Error(`${label} requires the current lease to remain held`);
  }
  assertEventNotBefore(event, lease.updated_at, "current lease state");
  if (parseTimestamp(event.recorded_at) >= parseTimestamp(lease.heartbeat_deadline)) {
    throw new Error(`${label} is past the current lease heartbeat deadline`);
  }
  if (parseTimestamp(event.recorded_at) >= parseTimestamp(lease.expires_at)) {
    throw new Error(`${label} is past the current lease expiry`);
  }
}

function assertLeaseEffectWindow(event, lease, label) {
  assertLeaseLiveWindow(event, lease, label);
  if (parseTimestamp(event.recorded_at) < parseTimestamp(lease.effect_not_before)) {
    throw new Error(`${label} predates the immutable lease effect window`);
  }
  if (parseTimestamp(event.recorded_at) >= parseTimestamp(lease.effect_deadline)) {
    throw new Error(`${label} is past the immutable lease effect deadline`);
  }
}

function assertStoreDigest(value, label) {
  if (typeof value !== "string" || !patternMatches(SHA256_PATTERN, value)) {
    throw new Error(`${label} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function assertStoreIdentifier(value, label) {
  if (typeof value !== "string" || !patternMatches(IDENTIFIER_PATTERN, value)) {
    throw new Error(`${label} must be a lowercase identifier`);
  }
  return value;
}

function assertStoreInteger(value, label, minimum = 0) {
  if (!numberIsSafeInteger(value) || value < minimum) {
    throw new Error(`${label} must be a safe integer >= ${minimum}`);
  }
  return value;
}

function assertStoreToken(value, label) {
  if (typeof value !== "string" || !patternMatches(TOKEN_PATTERN, value)) {
    throw new Error(`${label} must be a bounded opaque token`);
  }
  return value;
}

function normalizeProviderDispatchPortEnrollment(input, label) {
  assertClosedObject(input, label, [
    "provider_id",
    "provider_descriptor_digest",
    "execution_principal_id",
    "instrument_refs",
    "authority_port",
  ]);
  if (!arrayIsArray(input.instrument_refs)
      || input.instrument_refs.length < 1
      || input.instrument_refs.length > 256) {
    throw new Error(`${label}.instrument_refs must contain 1-256 entries`);
  }
  const instrumentRefs = arrayMap(input.instrument_refs, (entry, index) => normalizeOpaqueRef(
    entry,
    `${label}.instrument_refs[${index}]`,
    { prefix: "instrument" },
  ));
  if (new Set(instrumentRefs).size !== instrumentRefs.length) {
    throw new Error(`${label}.instrument_refs cannot contain duplicates`);
  }
  return Object.freeze({
    provider_id: assertStoreIdentifier(input.provider_id, `${label}.provider_id`),
    provider_descriptor_digest: assertStoreDigest(
      input.provider_descriptor_digest,
      `${label}.provider_descriptor_digest`,
    ),
    execution_principal_id: normalizeOpaqueRef(
      input.execution_principal_id,
      `${label}.execution_principal_id`,
      { prefix: "principal" },
    ),
    instrument_refs: Object.freeze(arraySort([...instrumentRefs])),
    authority_port: assertPhysicalDispatchAuthorityPort(input.authority_port),
  });
}

function normalizeProviderDispatchExpectedState(input, label) {
  assertClosedObject(input, label, [
    "attempt_ref",
    "instrument_ref",
    "operation_id",
    "provider_id",
    "provider_descriptor_digest",
    "dispatch_journal_ref",
    "provider_request_digest",
    "expected_state",
    "expected_sequence",
  ]);
  if (input.expected_state !== "prepared") {
    throw new Error(`${label}.expected_state must be prepared`);
  }
  return Object.freeze({
    attempt_ref: normalizeOpaqueRef(input.attempt_ref, `${label}.attempt_ref`, { prefix: "attempt" }),
    instrument_ref: normalizeOpaqueRef(
      input.instrument_ref,
      `${label}.instrument_ref`,
      { prefix: "instrument" },
    ),
    operation_id: assertStoreToken(input.operation_id, `${label}.operation_id`),
    provider_id: assertStoreIdentifier(input.provider_id, `${label}.provider_id`),
    provider_descriptor_digest: assertStoreDigest(
      input.provider_descriptor_digest,
      `${label}.provider_descriptor_digest`,
    ),
    dispatch_journal_ref: normalizeOpaqueRef(
      input.dispatch_journal_ref,
      `${label}.dispatch_journal_ref`,
      { prefix: "journal-entry" },
    ),
    provider_request_digest: assertStoreDigest(
      input.provider_request_digest,
      `${label}.provider_request_digest`,
    ),
    expected_state: "prepared",
    expected_sequence: assertStoreInteger(input.expected_sequence, `${label}.expected_sequence`),
  });
}

function projectJournalExecutionLineage(journal, label, { required = false } = {}) {
  if (!journal || typeof journal !== "object") {
    throw new Error(`${label} requires a durable attempt journal`);
  }
  const hasExperimentPlan = hasOwn(journal, "experiment_plan_hash");
  const hasExecutionLineage = hasOwn(journal, "execution_lineage_digest");
  if (hasExperimentPlan !== hasExecutionLineage) {
    throw new Error(`${label} execution lineage binding is incomplete`);
  }
  if (!hasExperimentPlan) {
    if (required) throw new Error(`${label} requires precommitted execution lineage`);
    return Object.freeze({});
  }
  return Object.freeze({
    experiment_plan_hash: assertStoreDigest(
      journal.experiment_plan_hash,
      `${label}.experiment_plan_hash`,
    ),
    execution_lineage_digest: assertStoreDigest(
      journal.execution_lineage_digest,
      `${label}.execution_lineage_digest`,
    ),
  });
}

function createProviderDispatchCredentialProjection(metadata, dispatch, lease, journal, anchor) {
  const executionLineage = projectJournalExecutionLineage(
    journal,
    "provider dispatch credential journal",
  );
  const fenceBindingDigest = providerDispatchFenceBindingDigest({
    runtime_id: metadata.runtime_id,
    session_nucleus_hash: metadata.session_nucleus_hash,
    attempt_ref: dispatch.attempt_ref,
    instrument_ref: dispatch.instrument_ref,
    execution_principal_id: lease.execution_principal_id,
    lease_id: dispatch.lease_id,
    fencing_token: dispatch.fencing_token,
    fencing_generation: dispatch.fencing_generation,
    execution_request_digest: dispatch.execution_request_digest,
    provider_id: dispatch.provider_id,
    provider_descriptor_digest: dispatch.provider_descriptor_digest,
  });
  return normalizeProviderDispatchCredential({
    version: STORE_VERSION,
    domain: PROVIDER_DISPATCH_CREDENTIAL_DOMAIN,
    credential_ref: `provider-dispatch-credential:${dispatch.dispatch_record_digest.slice(0, 40)}`,
    runtime_id: metadata.runtime_id,
    session_nucleus_hash: metadata.session_nucleus_hash,
    dispatch_record_digest: dispatch.dispatch_record_digest,
    journal_entry_ref: dispatch.journal_entry_ref,
    journal_entry_digest: dispatch.journal_entry_digest,
    attempt_ref: dispatch.attempt_ref,
    instrument_ref: dispatch.instrument_ref,
    execution_principal_id: lease.execution_principal_id,
    lease_id: dispatch.lease_id,
    fencing_generation: dispatch.fencing_generation,
    fence_binding_digest: fenceBindingDigest,
    effect_not_before: lease.effect_not_before,
    effect_deadline: lease.effect_deadline,
    operation_id: dispatch.operation_id,
    execution_request_digest: dispatch.execution_request_digest,
    ...executionLineage,
    provider_id: dispatch.provider_id,
    provider_descriptor_digest: dispatch.provider_descriptor_digest,
    provider_request_digest: dispatch.provider_request_digest,
    provider_state: "prepared",
    provider_sequence: dispatch.provider_sequence,
    store_generation: anchor.generation,
    store_head_event_digest: anchor.head_event_digest,
  });
}

function createPhysicalDispatchAuthorityAssertion(credential, signedGrantDigest, fencingToken) {
  return Object.freeze({
    session_nucleus_hash: credential.session_nucleus_hash,
    signed_grant_digest: assertStoreDigest(
      signedGrantDigest,
      "provider dispatch authority signed_grant_digest",
    ),
    execution_request_digest: credential.execution_request_digest,
    ...projectJournalExecutionLineage(
      credential,
      "provider dispatch authority credential",
      { required: true },
    ),
    execution_principal_id: credential.execution_principal_id,
    attempt_ref: credential.attempt_ref,
    instrument_ref: credential.instrument_ref,
    lease_id: credential.lease_id,
    // The raw fence remains confined to the store/authority closure. It is not
    // projected into the opaque provider credential or attenuated broker snapshot.
    fencing_token: assertStoreToken(
      fencingToken,
      "provider dispatch authority fencing_token",
    ),
    fencing_generation: credential.fencing_generation,
    operation_id: credential.operation_id,
    provider_id: credential.provider_id,
    provider_descriptor_digest: credential.provider_descriptor_digest,
    effect_not_before: credential.effect_not_before,
    effect_deadline: credential.effect_deadline,
  });
}

function assertSupervisorLeaseBinding(contract, lease, label) {
  const bindings = [
    "attempt_ref",
    "instrument_ref",
    "lease_id",
    "fencing_token",
    "fencing_generation",
    "operation_id",
    "execution_request_digest",
  ];
  for (const field of bindings) {
    if (contract[field] !== lease[field]) throw new Error(`${label}.${field} binding drift`);
  }
  if (contract.worker_principal_id !== lease.execution_principal_id) {
    throw new Error(`${label}.worker_principal_id binding drift`);
  }
}

function requireSafetySupervisorContract(projection, digest, label) {
  assertStoreDigest(digest, `${label}.supervisor_contract_digest`);
  const contract = projection.safetySupervisorContracts.get(digest);
  if (!contract) throw new Error(`${label} refers to an unregistered safety supervisor`);
  return contract;
}

function containmentActionKey(supervisorContractDigest, action) {
  return `${supervisorContractDigest}:${action}`;
}

function recoveryLaunchKey(supervisorContractDigest) {
  return supervisorContractDigest;
}

function normalizeContainmentClaimPayload(input, projection, label) {
  assertClosedObject(input, label, [
    "version",
    "supervisor_contract_digest",
    "action",
    "fenced_lease_digest",
    "claim_digest",
  ]);
  if (input.version !== STORE_VERSION) throw new Error(`${label}.version must be ${STORE_VERSION}`);
  const contract = requireSafetySupervisorContract(
    projection,
    input.supervisor_contract_digest,
    label,
  );
  const lease = requireLease(projection, contract.lease_id, label);
  assertSupervisorLeaseBinding(contract, lease, label);
  if (lease.state !== "fenced") throw new Error(`${label} requires the exact lease to be fenced`);
  if (input.fenced_lease_digest !== lease.lease_digest) {
    throw new Error(`${label}.fenced_lease_digest binding drift`);
  }
  if (typeof input.action !== "string"
      || !arrayIncludes(contract.containment_actions, input.action)) {
    throw new Error(`${label}.action is not precommitted by the safety supervisor`);
  }
  const basis = {
    version: STORE_VERSION,
    supervisor_contract_digest: contract.supervisor_contract_digest,
    action: input.action,
    fenced_lease_digest: lease.lease_digest,
  };
  const claimDigest = canonicalDigest(basis);
  if (input.claim_digest !== claimDigest) throw new Error(`${label}.claim_digest is invalid`);
  return Object.freeze({ ...basis, claim_digest: claimDigest });
}

function findClaimByDigest(values, claimDigest) {
  return arrayFind(
    [...values.values()],
    (claim) => claim.claim_digest === claimDigest,
  ) || null;
}

function normalizeSafetyCompletionPayload(input, outcomes, receiptField, label) {
  assertClosedObject(input, label, ["version", "claim_digest", "outcome", receiptField]);
  if (input.version !== STORE_VERSION) throw new Error(`${label}.version must be ${STORE_VERSION}`);
  const claimDigest = assertStoreDigest(input.claim_digest, `${label}.claim_digest`);
  if (typeof input.outcome !== "string" || !arrayIncludes(outcomes, input.outcome)) {
    throw new Error(`${label}.outcome is invalid`);
  }
  const receiptDigest = input[receiptField] == null
    ? null
    : assertStoreDigest(input[receiptField], `${label}.${receiptField}`);
  const successful = input.outcome === "confirmed" || input.outcome === "launched";
  if (successful !== (receiptDigest != null)) {
    throw new Error(`${label}.${input.outcome} receipt binding is invalid`);
  }
  return Object.freeze({
    version: STORE_VERSION,
    claim_digest: claimDigest,
    outcome: input.outcome,
    [receiptField]: receiptDigest,
  });
}

function normalizeRecoveryClaimPayload(input, projection, label) {
  assertClosedObject(input, label, [
    "version",
    "supervisor_contract_digest",
    "verified_bootstrap_digest",
    "claim_digest",
  ]);
  if (input.version !== STORE_VERSION) throw new Error(`${label}.version must be ${STORE_VERSION}`);
  const contract = requireSafetySupervisorContract(
    projection,
    input.supervisor_contract_digest,
    label,
  );
  const lease = requireLease(projection, contract.lease_id, label);
  assertSupervisorLeaseBinding(contract, lease, label);
  if (lease.state !== "fenced") throw new Error(`${label} requires the exact lease to be fenced`);
  const incomplete = arrayFilter(contract.containment_actions, (action) => {
    const state = projection.containmentActions.get(
      containmentActionKey(contract.supervisor_contract_digest, action),
    );
    return !state || state.state !== "completed" || state.outcome !== "confirmed";
  });
  if (incomplete.length > 0) {
    throw new Error(
      `${label} requires confirmed durable containment: ${arrayJoin(incomplete, ", ")}`,
    );
  }
  const basis = {
    version: STORE_VERSION,
    supervisor_contract_digest: contract.supervisor_contract_digest,
    verified_bootstrap_digest: assertStoreDigest(
      input.verified_bootstrap_digest,
      `${label}.verified_bootstrap_digest`,
    ),
  };
  const claimDigest = canonicalDigest(basis);
  if (input.claim_digest !== claimDigest) throw new Error(`${label}.claim_digest is invalid`);
  return Object.freeze({ ...basis, claim_digest: claimDigest });
}

const EXECUTION_TRANSACTION_SINGLE_USE_BINDINGS = Object.freeze([
  "replay_identity_digest",
  "authority_admission_digest",
  "capability_grant_digest",
  "commit_go_digest",
  "dispatch_admission_digest",
  "provider_worker_vault_binding_digest",
  "transaction_capability_digest",
  "resource_admission_digest",
  "resource_fence_digest",
  "native_launch_ticket_digest",
  "worker_launch_digest",
  "worker_fence_digest",
  "vault_ingest_capability_digest",
  "artifact_allocation_digest",
  "vault_reservation_ref",
  "vault_reservation_digest",
]);

function executionTransactionClaimForAttempt(projection, attemptRef) {
  const transactionRef = projection.executionTransactionAttempts.get(attemptRef);
  return transactionRef == null
    ? null
    : projection.executionTransactionClaims.get(transactionRef) || null;
}

function requireExecutionTransactionClaim(projection, transactionRef, label) {
  const claim = projection.executionTransactionClaims.get(transactionRef);
  if (!claim) throw new Error(`${label} refers to an unknown execution transaction`);
  return claim;
}

const EXECUTION_TRANSACTION_VAULT_REQUIRED_FIELDS = Object.freeze([
  "version",
  "kind",
  "transaction_ref",
  "execution_lineage_digest",
  "transaction_key_digest",
  "composite_binding_digest",
  "effect_evidence_digest",
  "effect_disposition",
  "semantic_disposition",
  "vault_artifact_ref",
  "vault_receipt_digest",
  "vault_reservation_ref",
  "vault_reservation_digest",
]);
const EXECUTION_TRANSACTION_VAULT_OPTIONAL_FIELDS = Object.freeze([
  "vault_commit_digest",
]);

function assertExecutionTransactionVaultInputShape(input, label) {
  return assertClosedObject(
    input,
    label,
    EXECUTION_TRANSACTION_VAULT_REQUIRED_FIELDS,
    EXECUTION_TRANSACTION_VAULT_OPTIONAL_FIELDS,
  );
}

function assertExecutionTransactionIdentity(input, claim, label) {
  assertExecutionTransactionVaultInputShape(input, label);
  if (input.version !== STORE_VERSION) throw new Error(`${label}.version must be ${STORE_VERSION}`);
  for (const field of [
    "transaction_ref",
    "execution_lineage_digest",
    "transaction_key_digest",
    "composite_binding_digest",
  ]) {
    if (input[field] !== claim.binding[field]) throw new Error(`${label}.${field} binding drift`);
  }
}

function normalizeExecutionTransactionReadQuery(input, label) {
  assertClosedObject(input, label, [
    "version",
    "kind",
    "transaction_ref",
    "execution_lineage_digest",
    "transaction_key_digest",
    "composite_binding_digest",
  ]);
  if (input.version !== STORE_VERSION
      || input.kind !== "physical_execution_transaction_durable_read") {
    throw new Error(`${label}.version or kind is invalid`);
  }
  return Object.freeze({
    version: STORE_VERSION,
    kind: input.kind,
    transaction_ref: (() => {
      if (typeof input.transaction_ref !== "string"
          || Buffer.byteLength(input.transaction_ref, "utf8") < 1
          || Buffer.byteLength(input.transaction_ref, "utf8") > 512) {
        throw new Error(`${label}.transaction_ref is invalid`);
      }
      return input.transaction_ref;
    })(),
    execution_lineage_digest: assertStoreDigest(
      input.execution_lineage_digest,
      `${label}.execution_lineage_digest`,
    ),
    transaction_key_digest: assertStoreDigest(
      input.transaction_key_digest,
      `${label}.transaction_key_digest`,
    ),
    composite_binding_digest: assertStoreDigest(
      input.composite_binding_digest,
      `${label}.composite_binding_digest`,
    ),
  });
}

function executionTransactionFenceDigest(event, lease, journal) {
  return providerDispatchFenceBindingDigest({
    runtime_id: event.runtime_id,
    session_nucleus_hash: event.session_nucleus_hash,
    attempt_ref: journal.attempt_ref,
    instrument_ref: journal.instrument_ref,
    execution_principal_id: lease.execution_principal_id,
    lease_id: lease.lease_id,
    fencing_token: lease.fencing_token,
    fencing_generation: lease.fencing_generation,
    execution_request_digest: journal.execution_request_digest,
    provider_id: journal.provider_id,
    provider_descriptor_digest: journal.provider_descriptor_digest,
  });
}

function hasActiveLegacyDispatch(projection) {
  for (const dispatch of projection.dispatches.values()) {
    const lease = projection.leases.get(dispatch.lease_id);
    if (!lease || lease.state !== "released") return true;
  }
  return false;
}

function createExecutionTransactionClaim(projection, event, envelopeDigest) {
  const binding = normalizePhysicalExecutionCompositeBinding(event.payload);
  if (binding.session_nucleus_hash !== event.session_nucleus_hash) {
    throw new Error("execution transaction claim session nucleus binding drift");
  }
  if (projection.executionTransactionClaims.size >= MAX_EXECUTION_TRANSACTIONS) {
    throw new Error(`execution transaction count has reached ${MAX_EXECUTION_TRANSACTIONS}`);
  }
  if (!projection.executionTransactionSchemaActivated && hasActiveLegacyDispatch(projection)) {
    throw new Error("execution transaction schema v2 cannot activate over an active legacy effect");
  }
  const lease = projection.leases.get(binding.lease_ref);
  const journal = projection.journalHeads.get(binding.attempt_ref);
  if (!lease || !journal || lease.state !== "held"
      || !arrayIncludes(["precommitted", "admitted"], journal.state)
      || projection.dispatches.has(binding.attempt_ref)
      || projection.dispatchRedemptions.has(binding.attempt_ref)) {
    throw new Error("execution transaction claim requires an undispatched held lease and pre-effect journal");
  }
  for (const [actual, expected, field] of [
    [binding.attempt_ref, lease.attempt_ref, "attempt_ref"],
    [binding.execution_request_digest, lease.execution_request_digest, "execution_request_digest"],
    [binding.lease_digest, lease.lease_digest, "lease_digest"],
    [binding.execution_lineage_digest, journal.execution_lineage_digest, "execution_lineage_digest"],
    [binding.capability_grant_digest, journal.signed_grant_digest, "capability_grant_digest"],
    [binding.cleanup_plan_digest, journal.cleanup_plan_digest, "cleanup_plan_digest"],
    [binding.resource_fence_digest, executionTransactionFenceDigest(event, lease, journal),
      "resource_fence_digest"],
  ]) {
    if (actual !== expected) throw new Error(`execution transaction claim ${field} binding drift`);
  }
  assertExecutionTransactionClaimUnused(projection, binding, "execution transaction claim");
  const basis = {
    version: STORE_VERSION,
    kind: "physical_execution_transaction_durable_claim",
    binding,
    claimed_at: event.recorded_at,
    claim_event_generation: event.generation,
    claim_event_digest: envelopeDigest,
  };
  return Object.freeze({ ...basis, claim_digest: canonicalDigest(basis) });
}

function installExecutionTransactionClaim(projection, claim) {
  const binding = claim.binding;
  projection.executionTransactionClaims.set(binding.transaction_ref, claim);
  projection.executionTransactionLineages.set(
    binding.execution_lineage_digest,
    binding.transaction_ref,
  );
  projection.executionTransactionKeys.set(binding.transaction_key_digest, binding.transaction_ref);
  projection.executionTransactionAttempts.set(binding.attempt_ref, binding.transaction_ref);
  projection.executionTransactionLeases.set(binding.lease_ref, binding.transaction_ref);
  for (const field of EXECUTION_TRANSACTION_SINGLE_USE_BINDINGS) {
    projection.executionTransactionAdmissions.set(
      `${field}:${binding[field]}`,
      binding.transaction_ref,
    );
  }
  projection.executionTransactionSchemaActivated = true;
}

function assertExecutionTransactionClaimUnused(projection, binding, label) {
  for (const [map, key, code] of [
    [projection.executionTransactionClaims, binding.transaction_ref, "transaction_ref"],
    [projection.executionTransactionLineages, binding.execution_lineage_digest,
      "execution_lineage_digest"],
    [projection.executionTransactionKeys, binding.transaction_key_digest,
      "transaction_key_digest"],
    [projection.executionTransactionAttempts, binding.attempt_ref, "attempt_ref"],
    [projection.executionTransactionLeases, binding.lease_ref, "lease_ref"],
  ]) {
    if (map.has(key)) throw new Error(`${label} reuses ${code}`);
  }
  for (const field of EXECUTION_TRANSACTION_SINGLE_USE_BINDINGS) {
    const alias = `${field}:${binding[field]}`;
    if (projection.executionTransactionAdmissions.has(alias)) {
      throw new Error(`${label} reuses ${field}`);
    }
  }
}

function journalEffectDisposition(journal) {
  if (!journal) return null;
  if (arrayIncludes(["effect_recorded", "restored", "irreversible_authorized"], journal.state)
      && journal.effect_disposition === "confirmed_effect") return "recorded";
  if (arrayIncludes(["ambiguous_effect", "quarantined", "unknown_effect"], journal.state)
      && arrayIncludes(["ambiguous", "unknown"], journal.effect_disposition)) return "ambiguous";
  if (journal.state === "quarantined" && journal.effect_disposition === "confirmed_effect") {
    return "recorded";
  }
  return null;
}

function normalizeExecutionTransactionVaultCommit(input, claim, label) {
  assertExecutionTransactionIdentity(input, claim, label);
  if (input.kind !== "physical_execution_transaction_vault_commit") {
    throw new Error(`${label}.kind is invalid`);
  }
  const effectDisposition = input.effect_disposition;
  const semanticDisposition = input.semantic_disposition;
  if (effectDisposition === "recorded") {
    if (!arrayIncludes(["validated_success", "nonsemantic_raw_custody"], semanticDisposition)) {
      throw new Error(`${label}.semantic_disposition is invalid for a recorded effect`);
    }
  } else if (effectDisposition !== "ambiguous"
      || semanticDisposition !== "nonsemantic_raw_custody") {
    throw new Error(`${label} cannot promote an ambiguous effect to semantic success`);
  }
  const binding = claim.binding;
  if (input.vault_reservation_ref !== binding.vault_reservation_ref
      || input.vault_reservation_digest !== binding.vault_reservation_digest) {
    throw new Error(`${label} vault reservation binding drift`);
  }
  const basis = {
    version: STORE_VERSION,
    kind: "physical_execution_transaction_vault_commit",
    transaction_ref: binding.transaction_ref,
    execution_lineage_digest: binding.execution_lineage_digest,
    transaction_key_digest: binding.transaction_key_digest,
    composite_binding_digest: binding.composite_binding_digest,
    effect_evidence_digest: assertStoreDigest(
      input.effect_evidence_digest,
      `${label}.effect_evidence_digest`,
    ),
    effect_disposition: effectDisposition,
    semantic_disposition: semanticDisposition,
    vault_artifact_ref: normalizeOpaqueRef(
      input.vault_artifact_ref,
      `${label}.vault_artifact_ref`,
      { prefix: "artifact" },
    ),
    vault_receipt_digest: assertStoreDigest(
      input.vault_receipt_digest,
      `${label}.vault_receipt_digest`,
    ),
    vault_reservation_ref: binding.vault_reservation_ref,
    vault_reservation_digest: binding.vault_reservation_digest,
  };
  const vaultCommitDigest = canonicalDigest(basis);
  if (input.vault_commit_digest != null
      && input.vault_commit_digest !== vaultCommitDigest) {
    throw new Error(`${label}.vault_commit_digest is invalid`);
  }
  return Object.freeze({ ...basis, vault_commit_digest: vaultCommitDigest });
}

function createExecutionTransactionVaultCommit(projection, event, envelopeDigest) {
  const transactionRef = event.payload && event.payload.transaction_ref;
  const claim = requireExecutionTransactionClaim(
    projection,
    transactionRef,
    "execution transaction vault commit",
  );
  const commit = normalizeExecutionTransactionVaultCommit(
    event.payload,
    claim,
    "execution_transaction_vault_committed.payload",
  );
  if (projection.executionTransactionVaultCommits.has(transactionRef)) {
    throw new Error("execution transaction vault custody is one-shot");
  }
  assertExecutionTransactionVaultOutputUnused(
    projection,
    commit,
    "execution transaction vault custody",
  );
  if (!projection.dispatchRedemptions.has(claim.binding.attempt_ref)) {
    throw new Error("execution transaction vault custody requires a durable dispatch redemption");
  }
  const journal = projection.journalHeads.get(claim.binding.attempt_ref);
  const journalDisposition = journalEffectDisposition(journal);
  if (journalDisposition != null && journalDisposition !== commit.effect_disposition) {
    throw new Error("execution transaction vault custody conflicts with the effect journal");
  }
  const basis = {
    ...commit,
    committed_at: event.recorded_at,
    vault_event_generation: event.generation,
    vault_event_digest: envelopeDigest,
  };
  return Object.freeze({
    ...basis,
    durable_vault_commit_digest: canonicalDigest(basis),
  });
}

function assertExecutionTransactionVaultOutputUnused(projection, commit, label) {
  for (const [map, value, field] of [
    [projection.executionTransactionVaultArtifacts, commit.vault_artifact_ref,
      "vault_artifact_ref"],
    [projection.executionTransactionVaultReceipts, commit.vault_receipt_digest,
      "vault_receipt_digest"],
  ]) {
    if (map.has(value)) throw new Error(`${label} reuses ${field}`);
  }
}

function installExecutionTransactionVaultCommit(projection, commit) {
  projection.executionTransactionVaultCommits.set(commit.transaction_ref, commit);
  projection.executionTransactionVaultArtifacts.set(
    commit.vault_artifact_ref,
    commit.transaction_ref,
  );
  projection.executionTransactionVaultReceipts.set(
    commit.vault_receipt_digest,
    commit.transaction_ref,
  );
}

function assertExecutionTransactionEffectJoin(projection, journal, label) {
  const claim = executionTransactionClaimForAttempt(projection, journal.attempt_ref);
  if (!claim) return;
  const vault = projection.executionTransactionVaultCommits.get(
    claim.binding.transaction_ref,
  );
  const disposition = journalEffectDisposition(journal);
  if (vault && disposition != null && vault.effect_disposition !== disposition) {
    throw new Error(`${label} conflicts with the durable transaction vault fact`);
  }
  if (arrayIncludes(
    ["restoring", "restored", "quarantined", "irreversible_authorized", "unknown_effect"],
    journal.state,
  ) && (!vault || disposition == null)) {
    throw new Error(`${label} requires an exact durable transaction effect/vault join`);
  }
}

function isOutboxEntryExactlyAcknowledged(projection, entry) {
  const delivery = projection.outboxDeliveries.get(entry.outbox_entry_digest);
  const acknowledgement = projection.acknowledgements.get(entry.outbox_entry_digest);
  return delivery != null
    && acknowledgement != null
    && delivery.outbox_entry_ref === entry.outbox_entry_ref
    && acknowledgement.outbox_entry_ref === entry.outbox_entry_ref
    && acknowledgement.recipient_principal_id === delivery.recipient_principal_id;
}

function executionTransactionLedgerState(projection, claim) {
  const attemptRef = claim.binding.attempt_ref;
  const lease = projection.leases.get(claim.binding.lease_ref);
  const journal = projection.journalHeads.get(attemptRef);
  const dispatch = projection.dispatches.get(attemptRef) || null;
  const redemption = projection.dispatchRedemptions.get(attemptRef) || null;
  const vault = projection.executionTransactionVaultCommits.get(
    claim.binding.transaction_ref,
  ) || null;
  const journalDisposition = journalEffectDisposition(journal);
  const effectJoined = vault != null && journalDisposition != null
    && vault.effect_disposition === journalDisposition;
  const leaseTerminal = lease && arrayIncludes(["released", "quarantined"], lease.state);
  const terminalOutbox = leaseTerminal && journal
    ? arrayFind([...projection.outboxEntries.values()], (entry) => (
      entry.attempt_ref === attemptRef
      && entry.source_journal_entry_digest === journal.journal_entry_digest
      && entry.payload_ref === lease.terminal_receipt_ref
      && entry.payload_digest === lease.terminal_receipt_digest
    )) || null
    : null;
  const terminalDelivery = terminalOutbox == null
    ? null
    : projection.outboxDeliveries.get(terminalOutbox.outbox_entry_digest) || null;
  const terminalAcknowledgement = terminalOutbox == null
    ? null
    : projection.acknowledgements.get(terminalOutbox.outbox_entry_digest) || null;
  const pendingAttemptOutboxCount = arrayFilter([...projection.outboxEntries.values()], (entry) => (
    entry.attempt_ref === attemptRef && !isOutboxEntryExactlyAcknowledged(projection, entry)
  )).length;
  const terminalJoined = leaseTerminal && terminalOutbox != null
    && terminalDelivery != null && terminalAcknowledgement != null
    && pendingAttemptOutboxCount === 0;
  let ledgerState = "CLAIMED";
  if (dispatch) ledgerState = "DISPATCH_COMMITTED_NONAUTHORITATIVE_GO_CANDIDATE";
  if (redemption) ledgerState = "DISPATCH_REDEEMED_NONAUTHORITATIVE_ARM_CANDIDATE";
  if (journalDisposition != null && !vault) ledgerState = "EFFECT_FACT_PENDING_VAULT";
  if (vault && journalDisposition == null) ledgerState = "VAULT_FACT_PENDING_EFFECT";
  if (effectJoined) ledgerState = "EFFECT_AND_VAULT_COMMITTED";
  if (effectJoined && (lease.state === "restoring" || journal.state === "restoring")) {
    ledgerState = "RESTORING";
  }
  if (leaseTerminal) ledgerState = terminalJoined
    ? "TERMINAL"
    : "TERMINAL_PENDING_EXACT_OUTBOX_PROJECTION";
  const basis = {
    version: STORE_VERSION,
    kind: "physical_execution_transaction_durable_projection",
    transaction_ref: claim.binding.transaction_ref,
    execution_lineage_digest: claim.binding.execution_lineage_digest,
    transaction_key_digest: claim.binding.transaction_key_digest,
    composite_binding_digest: claim.binding.composite_binding_digest,
    attempt_ref: attemptRef,
    lease_ref: claim.binding.lease_ref,
    claim_digest: claim.claim_digest,
    claim_event_generation: claim.claim_event_generation,
    claim_event_digest: claim.claim_event_digest,
    ledger_state: ledgerState,
    dispatch_record_digest: dispatch == null ? null : dispatch.dispatch_record_digest,
    dispatch_redemption_digest: redemption == null ? null : redemption.redemption_digest,
    effect_evidence_digest: vault == null ? null : vault.effect_evidence_digest,
    effect_disposition: vault == null ? null : vault.effect_disposition,
    semantic_disposition: vault == null ? null : vault.semantic_disposition,
    vault_artifact_ref: vault == null ? null : vault.vault_artifact_ref,
    vault_receipt_digest: vault == null ? null : vault.vault_receipt_digest,
    vault_commit_digest: vault == null ? null : vault.durable_vault_commit_digest,
    journal_entry_digest: journal == null ? null : journal.journal_entry_digest,
    lease_digest: lease == null ? null : lease.lease_digest,
    terminal_receipt_ref: leaseTerminal ? lease.terminal_receipt_ref : null,
    terminal_receipt_digest: leaseTerminal ? lease.terminal_receipt_digest : null,
    terminal_outbox_digest: terminalOutbox == null ? null : terminalOutbox.outbox_entry_digest,
    terminal_acknowledgement_digest: terminalAcknowledgement == null
      ? null
      : terminalAcknowledgement.acknowledgement_digest,
    pending_outbox_count: pendingAttemptOutboxCount,
    authoritative_phase: null,
    automatic_effect_retry_permitted: false,
    provider_effect_execution_permitted: false,
    durability_assurance: "encrypted_append_only_caller_asserted_external_cas_v2",
    durability_attested: false,
    production_blockers: EXECUTION_TRANSACTION_PRODUCTION_BLOCKERS,
    production_ready: false,
    hardware_access_authorized: false,
    execution_authority: false,
  };
  return Object.freeze({ ...basis, projection_digest: canonicalDigest(basis) });
}

function applyEvent(projection, event, envelopeDigest) {
  assertClosedObject(event, "instrument lease store event", [
    "version", "runtime_id", "session_nucleus_hash", "generation", "previous_event_digest",
    "kind", "payload", "recorded_at",
  ]);
  if (event.version !== STORE_VERSION || !arrayIncludes(EVENT_KINDS, event.kind)
      || event.generation !== projection.generation + 1
      || event.previous_event_digest !== projection.head_event_digest) {
    throw new Error(`instrument lease store event ${event.generation} breaks the append-only chain`);
  }
  assertCanonicalTimestamp(event.recorded_at, "instrument lease store event.recorded_at");
  if (projection.last_recorded_at != null
      && parseTimestamp(event.recorded_at) < parseTimestamp(projection.last_recorded_at)) {
    throw new Error("instrument lease store event clock moved backwards");
  }
  const eventKey = `${event.kind}:${canonicalDigest(event.payload)}`;
  if (projection.eventKeys.has(eventKey)) {
    throw new Error(`instrument lease store repeats event ${eventKey}`);
  }

  switch (event.kind) {
    case "execution_transaction_claimed": {
      const claim = createExecutionTransactionClaim(projection, event, envelopeDigest);
      installExecutionTransactionClaim(projection, claim);
      break;
    }
    case "execution_transaction_vault_committed": {
      const commit = createExecutionTransactionVaultCommit(projection, event, envelopeDigest);
      installExecutionTransactionVaultCommit(projection, commit);
      break;
    }
    case "safety_supervisor_registered": {
      const contract = normalizeSafetySupervisorContract(
        event.payload,
        "safety_supervisor_registered.payload",
      );
      const lease = requireLease(projection, contract.lease_id, "safety supervisor registration");
      assertSupervisorLeaseBinding(contract, lease, "safety supervisor registration");
      assertEventNotBefore(event, lease.updated_at, "current lease state");
      const conflicting = arrayFind(
        [...projection.safetySupervisorContracts.values()],
        (candidate) => (
        candidate.lease_id === contract.lease_id
        && candidate.supervisor_contract_digest !== contract.supervisor_contract_digest
      ));
      if (conflicting) {
        throw new Error("instrument lease already has a different safety-supervisor contract");
      }
      if (projection.safetySupervisorContracts.has(contract.supervisor_contract_digest)) {
        throw new Error("safety-supervisor contract is duplicated in the append-only ledger");
      }
      projection.safetySupervisorContracts.set(contract.supervisor_contract_digest, contract);
      break;
    }
    case "containment_action_claimed": {
      const claim = normalizeContainmentClaimPayload(
        event.payload,
        projection,
        "containment_action_claimed.payload",
      );
      const key = containmentActionKey(claim.supervisor_contract_digest, claim.action);
      const claimContract = projection.safetySupervisorContracts.get(claim.supervisor_contract_digest);
      const claimLease = requireLease(projection, claimContract.lease_id, "containment action claim");
      assertEventNotBefore(event, claimLease.updated_at, "fenced lease state");
      if (projection.containmentActions.has(key)) {
        throw new Error("containment action has already been durably claimed");
      }
      projection.containmentActions.set(key, Object.freeze({
        ...claim,
        state: "claimed",
        claimed_at: event.recorded_at,
        outcome: null,
        receipt_digest: null,
        completed_at: null,
      }));
      break;
    }
    case "containment_action_completed": {
      const completion = normalizeSafetyCompletionPayload(
        event.payload,
        CONTAINMENT_RESULT_STATES,
        "receipt_digest",
        "containment_action_completed.payload",
      );
      const prior = findClaimByDigest(projection.containmentActions, completion.claim_digest);
      if (!prior) throw new Error("containment completion refers to an unknown durable claim");
      if (prior.state !== "claimed") {
        throw new Error("containment action already has a terminal durable outcome");
      }
      assertEventNotBefore(event, prior.claimed_at, "containment action claim");
      const key = containmentActionKey(prior.supervisor_contract_digest, prior.action);
      projection.containmentActions.set(key, Object.freeze({
        ...prior,
        state: "completed",
        outcome: completion.outcome,
        receipt_digest: completion.receipt_digest,
        completed_at: event.recorded_at,
      }));
      break;
    }
    case "recovery_launch_claimed": {
      const claim = normalizeRecoveryClaimPayload(
        event.payload,
        projection,
        "recovery_launch_claimed.payload",
      );
      const key = recoveryLaunchKey(claim.supervisor_contract_digest);
      const recoveryContract = projection.safetySupervisorContracts.get(claim.supervisor_contract_digest);
      const recoveryLease = requireLease(projection, recoveryContract.lease_id, "recovery launch claim");
      assertEventNotBefore(event, recoveryLease.updated_at, "fenced lease state");
      if (projection.recoveryLaunches.has(key)) {
        throw new Error("recovery launch has already been durably claimed");
      }
      projection.recoveryLaunches.set(key, Object.freeze({
        ...claim,
        state: "claimed",
        claimed_at: event.recorded_at,
        outcome: null,
        launch_receipt_digest: null,
        completed_at: null,
      }));
      break;
    }
    case "recovery_launch_completed": {
      const completion = normalizeSafetyCompletionPayload(
        event.payload,
        RECOVERY_RESULT_STATES,
        "launch_receipt_digest",
        "recovery_launch_completed.payload",
      );
      const prior = findClaimByDigest(projection.recoveryLaunches, completion.claim_digest);
      if (!prior) throw new Error("recovery completion refers to an unknown durable claim");
      if (prior.state !== "claimed") {
        throw new Error("recovery launch already has a terminal durable outcome");
      }
      assertEventNotBefore(event, prior.claimed_at, "recovery launch claim");
      const key = recoveryLaunchKey(prior.supervisor_contract_digest);
      projection.recoveryLaunches.set(key, Object.freeze({
        ...prior,
        state: "completed",
        outcome: completion.outcome,
        launch_receipt_digest: completion.launch_receipt_digest,
        completed_at: event.recorded_at,
      }));
      break;
    }
    case "lease_acquired": {
      const candidate = normalizeInstrumentLease(event.payload, "lease_acquired.payload");
      assertEventNotBefore(event, candidate.updated_at, "acquired lease state");
      assertLeaseLiveWindow(event, candidate, "lease acquisition");
      const activeLeaseCount = arrayFilter([...projection.leases.values()], (lease) => (
        arrayIncludes(["held", "stop_requested", "fenced", "restoring"], lease.state)
      )).length;
      if (activeLeaseCount >= MAX_ACTIVE_LEASES) {
        throw new Error(`instrument lease store permits at most ${MAX_ACTIVE_LEASES} active leases`);
      }
      if (arraySome(
        [...projection.leases.values()],
        (lease) => lease.attempt_ref === candidate.attempt_ref,
      )) {
        throw new Error(`instrument lease attempt_ref has already been used: ${candidate.attempt_ref}`);
      }
      const accepted = acquireInstrumentLease(candidate, [...projection.leases.values()]);
      projection.leases.set(accepted.lease_id, accepted);
      break;
    }
    case "lease_renewed": {
      const prior = requireLease(projection, event.payload.lease_id, "lease renewal");
      assertLeaseLiveWindow(event, prior, "lease renewal");
      const renewed = renewInstrumentLease(prior, event.payload);
      assertEventNotBefore(event, renewed.updated_at, "renewed lease state");
      projection.leases.set(renewed.lease_id, renewed);
      break;
    }
    case "lease_fenced": {
      const prior = requireLease(projection, event.payload.lease_id, "lease fence");
      const fenced = fenceInstrumentLease(prior, event.payload);
      assertEventNotBefore(event, fenced.updated_at, "fenced lease state");
      projection.leases.set(fenced.lease_id, fenced);
      break;
    }
    case "lease_restoring": {
      const prior = requireLease(projection, event.payload.lease_id, "lease restoration");
      const restoring = beginInstrumentRestoration(prior, event.payload);
      assertEventNotBefore(event, restoring.updated_at, "restoring lease state");
      const transaction = executionTransactionClaimForAttempt(projection, restoring.attempt_ref);
      if (transaction && projection.dispatchRedemptions.has(restoring.attempt_ref)) {
        const journal = projection.journalHeads.get(restoring.attempt_ref);
        assertExecutionTransactionEffectJoin(projection, journal, "lease restoration");
      }
      projection.leases.set(restoring.lease_id, restoring);
      break;
    }
    case "lease_released": {
      const prior = requireLease(projection, event.payload.lease_id, "lease release");
      const released = releaseInstrumentLease(prior, event.payload);
      assertEventNotBefore(event, released.updated_at, "released lease state");
      const journal = projection.journalHeads.get(prior.attempt_ref);
      if (journal) {
        for (const field of [
          "attempt_ref", "instrument_ref", "lease_id", "fencing_token", "fencing_generation",
          "operation_id", "execution_request_digest",
        ]) {
          if (journal[field] !== prior[field]) {
            throw new Error(`terminal journal ${field} is detached from the lease being released`);
          }
        }
      }
      const requiredJournalState = {
        confirmed_no_effect: "reconciled_no_effect",
        restored: "restored",
        quarantined: "quarantined",
        irreversible_authorized: "irreversible_authorized",
        unknown_effect: "unknown_effect",
      }[released.terminal_disposition];
      if (!journal || journal.state !== requiredJournalState) {
        throw new Error(
          `lease release disposition ${released.terminal_disposition} requires terminal journal state ${requiredJournalState}`,
        );
      }
      assertExecutionTransactionEffectJoin(projection, journal, "lease release");
      const terminalProof = arrayFind([...projection.outboxEntries.values()], (entry) => (
        entry.attempt_ref === prior.attempt_ref
        && entry.instrument_ref === prior.instrument_ref
        && entry.lease_id === prior.lease_id
        && entry.fencing_token === prior.fencing_token
        && entry.fencing_generation === prior.fencing_generation
        && entry.operation_id === prior.operation_id
        && entry.execution_request_digest === prior.execution_request_digest
        && entry.source_journal_entry_digest === journal.journal_entry_digest
        && entry.payload_ref === released.terminal_receipt_ref
        && entry.payload_digest === released.terminal_receipt_digest
      ));
      if (!terminalProof) {
        throw new Error("lease release requires a durable terminal receipt in the bound outbox");
      }
      const terminalDelivery = projection.outboxDeliveries.get(terminalProof.outbox_entry_digest);
      if (!terminalDelivery) {
        throw new Error("lease release requires a durable terminal-receipt delivery binding");
      }
      if (terminalDelivery.recipient_principal_id
          !== prior.terminal_receipt_recipient_principal_id) {
        throw new Error("lease release terminal receipt is bound to the wrong authority principal");
      }
      if (terminalDelivery.idempotency_domain_digest
          !== prior.terminal_receipt_idempotency_domain_digest) {
        throw new Error("lease release terminal receipt is bound to an uncommitted dedup domain");
      }
      const terminalAcknowledgement = projection.acknowledgements.get(
        terminalProof.outbox_entry_digest,
      );
      if (!terminalAcknowledgement
          || terminalAcknowledgement.recipient_principal_id
            !== prior.terminal_receipt_recipient_principal_id) {
        throw new Error("lease release requires durable terminal-receipt acceptance by its owner");
      }
      const pendingOutbox = arrayFilter([...projection.outboxEntries.values()], (entry) => (
        entry.attempt_ref === prior.attempt_ref
        && !isOutboxEntryExactlyAcknowledged(projection, entry)
      ));
      if (pendingOutbox.length > 0) {
        throw new Error("lease release requires every durable attempt outbox entry to be acknowledged");
      }
      projection.leases.set(released.lease_id, released);
      break;
    }
    case "journal_appended": {
      const candidate = normalizeAttemptJournalEntry(event.payload, "journal_appended.payload");
      assertEventNotBefore(event, candidate.fsynced_at, "attempt journal fsync claim");
      const lease = requireLease(projection, candidate.lease_id, "attempt journal");
      if (arrayIncludes(["released", "quarantined"], lease.state)) {
        throw new Error("attempt journal cannot advance after terminal lease closure");
      }
      for (const field of [
        "attempt_ref", "instrument_ref", "lease_id", "fencing_token", "fencing_generation",
        "operation_id", "execution_request_digest",
      ]) {
        if (candidate[field] !== lease[field]) throw new Error(`attempt journal ${field} is detached from lease`);
      }
      const prior = projection.journalHeads.get(candidate.attempt_ref);
      const accepted = prior == null
        ? candidate
        : assertAttemptJournalAppend(prior, candidate);
      if (prior == null && candidate.sequence !== 0) {
        throw new Error("first attempt journal entry must be sequence 0");
      }
      if (arrayIncludes(["precommitted", "admitted", "effect_starting"], candidate.state)) {
        assertLeaseLiveWindow(event, lease, `attempt journal state ${candidate.state}`);
      }
      if (arrayIncludes(["running", "effect_recorded"], candidate.state)
          && !projection.dispatches.has(candidate.attempt_ref)) {
        throw new Error(`attempt journal state ${candidate.state} requires a durable dispatch record`);
      }
      if (arrayIncludes(["running", "effect_recorded"], candidate.state)
          && !projection.dispatchRedemptions.has(candidate.attempt_ref)) {
        throw new Error(`attempt journal state ${candidate.state} requires a durable provider redemption`);
      }
      assertExecutionTransactionEffectJoin(projection, candidate, "attempt journal transition");
      projection.journalHeads.set(candidate.attempt_ref, accepted);
      break;
    }
    case "dispatch_committed": {
      const attemptRef = event.payload.attempt_ref;
      if (projection.executionTransactionSchemaActivated
          && !executionTransactionClaimForAttempt(projection, attemptRef)) {
        throw new Error("schema-v2 effect dispatch requires a durable execution transaction claim");
      }
      const journal = projection.journalHeads.get(attemptRef);
      if (!journal) throw new Error("effect dispatch requires an existing attempt journal");
      const dispatch = normalizeEffectDispatchRecord(event.payload, journal);
      assertEventNotBefore(event, dispatch.dispatched_at, "effect dispatch timestamp");
      const lease = requireLease(projection, dispatch.lease_id, "effect dispatch");
      assertLeaseEffectWindow(event, lease, "effect dispatch");
      if (projection.dispatches.has(attemptRef)) {
        throw new Error("effect dispatch is one-shot and has already been committed");
      }
      projection.dispatches.set(attemptRef, dispatch);
      projection.dispatchSourceJournals.set(attemptRef, journal);
      projection.dispatchCommitAnchors.set(attemptRef, Object.freeze({
        generation: event.generation,
        head_event_digest: envelopeDigest,
      }));
      break;
    }
    case "dispatch_redeemed": {
      const candidate = normalizeProviderDispatchRedemption(
        event.payload,
        null,
        "dispatch_redeemed.payload",
      );
      const dispatch = projection.dispatches.get(candidate.attempt_ref);
      if (!dispatch) throw new Error("provider dispatch redemption requires a durable dispatch");
      const commitAnchor = projection.dispatchCommitAnchors.get(candidate.attempt_ref);
      if (!commitAnchor
          || projection.eventDigests.get(commitAnchor.generation) !== commitAnchor.head_event_digest) {
        throw new Error("provider dispatch redemption cannot authenticate its dispatch commit anchor");
      }
      const lease = requireLease(projection, candidate.lease_id, "provider dispatch redemption");
      const journal = projection.journalHeads.get(candidate.attempt_ref);
      if (!journal
          || journal.state !== "effect_starting"
          || journal.provider_state !== "prepared"
          || journal.provider_sequence !== candidate.provider_sequence
          || journal.journal_entry_digest !== candidate.journal_entry_digest) {
        throw new Error("provider dispatch redemption requires the exact effect_starting/prepared journal head");
      }
      const expectedCredential = createProviderDispatchCredentialProjection(
        {
          runtime_id: event.runtime_id,
          session_nucleus_hash: event.session_nucleus_hash,
        },
        dispatch,
        lease,
        journal,
        commitAnchor,
      );
      normalizeProviderDispatchRedemption(
        candidate,
        expectedCredential,
        "dispatch_redeemed.bound_payload",
      );
      if (candidate.redemption_ref
          !== `provider-dispatch-redemption:${candidate.credential_digest.slice(0, 40)}`) {
        throw new Error("provider dispatch redemption reference is not derived from its credential");
      }
      for (const field of [
        "journal_entry_digest",
        "attempt_ref",
        "instrument_ref",
        "lease_id",
        "fencing_generation",
        "operation_id",
        "execution_request_digest",
        "provider_id",
        "provider_descriptor_digest",
        "provider_request_digest",
        "provider_sequence",
      ]) {
        if (candidate[field] !== dispatch[field]) {
          throw new Error(`provider dispatch redemption ${field} binding drift`);
        }
      }
      for (const field of ["experiment_plan_hash", "execution_lineage_digest"]) {
        if (candidate[field] !== journal[field]) {
          throw new Error(`provider dispatch redemption ${field} binding drift`);
        }
      }
      if (candidate.execution_principal_id !== lease.execution_principal_id) {
        throw new Error("provider dispatch redemption execution_principal_id binding drift");
      }
      if (dispatch.fencing_token !== lease.fencing_token
          || dispatch.fencing_generation !== lease.fencing_generation) {
        throw new Error("provider dispatch redemption durable fence binding drift");
      }
      assertEventNotBefore(event, candidate.redeemed_at, "provider dispatch redemption timestamp");
      if (parseTimestamp(candidate.redeemed_at) < parseTimestamp(dispatch.dispatched_at)) {
        throw new Error("provider dispatch redemption predates its durable dispatch");
      }
      assertLeaseEffectWindow(event, lease, "provider dispatch redemption");
      if (projection.dispatchRedemptions.has(candidate.attempt_ref)) {
        throw new Error("provider dispatch credential has already been durably redeemed");
      }
      projection.dispatchRedemptions.set(candidate.attempt_ref, candidate);
      break;
    }
    case "outbox_appended": {
      const candidate = normalizeDurableOutboxEntry(event.payload, "outbox_appended.payload");
      assertEventNotBefore(event, candidate.fsynced_at, "durable outbox fsync claim");
      const lease = requireLease(projection, candidate.lease_id, "durable outbox");
      if (arrayIncludes(["released", "quarantined"], lease.state)) {
        throw new Error("durable outbox cannot grow after terminal lease closure");
      }
      const journal = projection.journalHeads.get(candidate.attempt_ref);
      if (!journal) throw new Error("outbox entry requires an existing attempt journal");
      assertOutboxJournalBinding(candidate, journal);
      const prior = projection.outboxHeads.get(candidate.attempt_ref);
      const accepted = prior == null ? candidate : assertDurableOutboxAppend(prior, candidate);
      if (prior == null && candidate.sequence !== 0) {
        throw new Error("first durable outbox entry must be sequence 0");
      }
      if (candidate.sequence >= MAX_OUTBOX_ENTRIES_PER_ATTEMPT) {
        throw new Error(
          `durable outbox permits at most ${MAX_OUTBOX_ENTRIES_PER_ATTEMPT} entries per attempt`,
        );
      }
      if (projection.outboxEntries.has(accepted.outbox_entry_digest)) {
        throw new Error("durable outbox entry digest has already been used");
      }
      projection.outboxHeads.set(candidate.attempt_ref, accepted);
      projection.outboxEntries.set(accepted.outbox_entry_digest, accepted);
      break;
    }
    case "outbox_acknowledged": {
      if (!isPlainObject(event.payload)) throw new Error("outbox acknowledgement payload must be an object");
      const outbox = projection.outboxEntries.get(event.payload.outbox_entry_digest);
      if (!outbox) throw new Error("outbox acknowledgement refers to an unknown entry");
      const acknowledgement = normalizeOutboxAcknowledgement(event.payload, outbox);
      const deliveryBinding = projection.outboxDeliveries.get(outbox.outbox_entry_digest);
      if (!deliveryBinding) {
        throw new Error("outbox acknowledgement requires a prior durable delivery binding");
      }
      if (acknowledgement.recipient_principal_id !== deliveryBinding.recipient_principal_id) {
        throw new Error("outbox acknowledgement recipient drifts from the durable delivery binding");
      }
      assertEventNotBefore(event, acknowledgement.acknowledged_at, "outbox acknowledgement");
      const prior = projection.acknowledgements.get(outbox.outbox_entry_digest);
      if (prior) throw new Error("outbox entry has already been acknowledged");
      projection.acknowledgements.set(outbox.outbox_entry_digest, acknowledgement);
      break;
    }
    case "outbox_delivery_bound": {
      assertClosedObject(event.payload, "outbox_delivery_bound.payload", [
        "version",
        "outbox_entry_ref",
        "outbox_entry_digest",
        "recipient_principal_id",
        "idempotency_domain_digest",
      ]);
      if (event.payload.version !== STORE_VERSION) {
        throw new Error(`outbox delivery binding version must be ${STORE_VERSION}`);
      }
      const outbox = projection.outboxEntries.get(event.payload.outbox_entry_digest);
      if (!outbox || outbox.outbox_entry_ref !== event.payload.outbox_entry_ref) {
        throw new Error("outbox delivery binding refers to an unknown durable outbox entry");
      }
      const lease = requireLease(projection, outbox.lease_id, "outbox delivery binding");
      if (arrayIncludes(["released", "quarantined"], lease.state)) {
        throw new Error("outbox delivery cannot first bind after terminal lease closure");
      }
      const binding = Object.freeze({
        version: STORE_VERSION,
        outbox_entry_ref: outbox.outbox_entry_ref,
        outbox_entry_digest: outbox.outbox_entry_digest,
        recipient_principal_id: normalizeOpaqueRef(
          event.payload.recipient_principal_id,
          "outbox_delivery_bound.payload.recipient_principal_id",
          { prefix: "principal" },
        ),
        idempotency_domain_digest: (() => {
          if (!patternMatches(
            SHA256_PATTERN,
            event.payload.idempotency_domain_digest || "",
          )) {
            throw new Error("outbox delivery binding idempotency domain digest is invalid");
          }
          return event.payload.idempotency_domain_digest;
        })(),
      });
      const prior = projection.outboxDeliveries.get(outbox.outbox_entry_digest);
      if (prior && !sameJson(prior, binding)) {
        throw new Error("durable outbox entry is already bound to another recipient or dedup domain");
      }
      if (prior) throw new Error("outbox delivery binding is duplicated in the append-only ledger");
      projection.outboxDeliveries.set(outbox.outbox_entry_digest, binding);
      break;
    }
    default:
      throw new Error(`unsupported instrument lease store event kind: ${event.kind}`);
  }
  projection.generation = event.generation;
  projection.head_event_digest = envelopeDigest;
  projection.last_recorded_at = event.recorded_at;
  projection.eventKeys.add(eventKey);
  projection.eventDigests.set(event.generation, envelopeDigest);
  return eventKey;
}

function publicProjection(projection) {
  return Object.freeze({
    projection_schema_version: projection.executionTransactionSchemaActivated
      ? CHECKPOINT_PROJECTION_SCHEMA_VERSION
      : LEGACY_CHECKPOINT_PROJECTION_SCHEMA_VERSION,
    generation: projection.generation,
    head_event_digest: projection.head_event_digest,
    leases: Object.freeze(arrayMap([...projection.leases.values()], cloneJson)),
    journal_heads: Object.freeze(arrayMap([...projection.journalHeads.values()], cloneJson)),
    dispatches: Object.freeze(arrayMap([...projection.dispatches.values()], cloneJson)),
    dispatch_redemptions: Object.freeze(
      arrayMap([...projection.dispatchRedemptions.values()], cloneJson),
    ),
    outbox_heads: Object.freeze(arrayMap([...projection.outboxHeads.values()], cloneJson)),
    outbox_entries: Object.freeze(arrayMap([...projection.outboxEntries.values()], cloneJson)),
    outbox_delivery_bindings: Object.freeze(
      arrayMap([...projection.outboxDeliveries.values()], cloneJson),
    ),
    acknowledgements: Object.freeze(arrayMap([...projection.acknowledgements.values()], cloneJson)),
    safety_supervisor_contracts: Object.freeze(
      arrayMap([...projection.safetySupervisorContracts.values()], cloneJson),
    ),
    containment_action_states: Object.freeze(
      arrayMap([...projection.containmentActions.values()], cloneJson),
    ),
    recovery_launch_states: Object.freeze(
      arrayMap([...projection.recoveryLaunches.values()], cloneJson),
    ),
    execution_transactions: Object.freeze(
      arraySort(
        arrayMap(
          [...projection.executionTransactionClaims.values()],
          (claim) => executionTransactionLedgerState(projection, claim),
        ),
        (left, right) => compareStrings(left.transaction_ref, right.transaction_ref),
      ),
    ),
  });
}

function sortedProjectionValues(values, field) {
  return arraySort(
    arrayMap([...values.values()], cloneJson),
    (left, right) => compareStrings(left[field], right[field]),
  );
}

function checkpointProjectionPayload(projection, metadata, checkpointGeneration, priorCheckpointDigest) {
  const projectionSchemaVersion = projection.executionTransactionSchemaActivated
    ? CHECKPOINT_PROJECTION_SCHEMA_VERSION
    : LEGACY_CHECKPOINT_PROJECTION_SCHEMA_VERSION;
  const basis = {
    version: CHECKPOINT_VERSION,
    domain: CHECKPOINT_DOMAIN,
    projection_schema_version: projectionSchemaVersion,
    runtime_id: metadata.runtime_id,
    session_nucleus_hash: metadata.session_nucleus_hash,
    checkpoint_generation: checkpointGeneration,
    prior_checkpoint_digest: priorCheckpointDigest,
    event_generation: projection.generation,
    event_head_digest: projection.head_event_digest,
    last_recorded_at: projection.last_recorded_at,
    leases: sortedProjectionValues(projection.leases, "lease_id"),
    journal_heads: sortedProjectionValues(projection.journalHeads, "attempt_ref"),
    dispatches: sortedProjectionValues(projection.dispatches, "attempt_ref"),
    dispatch_source_journals: sortedProjectionValues(
      projection.dispatchSourceJournals,
      "attempt_ref",
    ),
    dispatch_commit_anchors: arraySort(
      arrayMap(
        [...projection.dispatchCommitAnchors.entries()],
        ([attemptRef, anchor]) => ({ attempt_ref: attemptRef, ...cloneJson(anchor) }),
      ),
      (left, right) => compareStrings(left.attempt_ref, right.attempt_ref),
    ),
    dispatch_redemptions: sortedProjectionValues(projection.dispatchRedemptions, "attempt_ref"),
    outbox_entries: sortedProjectionValues(projection.outboxEntries, "outbox_entry_digest"),
    outbox_delivery_bindings: sortedProjectionValues(
      projection.outboxDeliveries,
      "outbox_entry_digest",
    ),
    acknowledgements: sortedProjectionValues(projection.acknowledgements, "outbox_entry_digest"),
    safety_supervisor_contracts: sortedProjectionValues(
      projection.safetySupervisorContracts,
      "supervisor_contract_digest",
    ),
    containment_action_states: sortedProjectionValues(projection.containmentActions, "claim_digest"),
    recovery_launch_states: sortedProjectionValues(projection.recoveryLaunches, "claim_digest"),
    event_keys: arraySort([...projection.eventKeys]),
    event_digests: arraySort(
      [...projection.eventDigests.entries()],
      (left, right) => left[0] - right[0],
    ),
  };
  if (projectionSchemaVersion === CHECKPOINT_PROJECTION_SCHEMA_VERSION) {
    basis.execution_transaction_schema_activated = true;
    basis.execution_transaction_claims = sortedProjectionValues(
      projection.executionTransactionClaims,
      "claim_digest",
    );
    basis.execution_transaction_vault_commits = sortedProjectionValues(
      projection.executionTransactionVaultCommits,
      "durable_vault_commit_digest",
    );
  }
  return Object.freeze({ ...basis, projection_digest: canonicalDigest(basis) });
}

function assertCheckpointArray(input, label, maximum = MAX_EVENTS) {
  if (!arrayIsArray(input) || input.length > maximum) {
    throw new Error(`${label} must be an array with at most ${maximum} entries`);
  }
  return input;
}

function checkpointMap(records, label, normalize, keyField) {
  const map = new Map();
  for (const [index, value] of assertCheckpointArray(records, label).entries()) {
    const normalized = normalize(value, `${label}[${index}]`);
    const key = normalized[keyField];
    if (map.has(key)) throw new Error(`${label} repeats ${keyField} ${key}`);
    map.set(key, normalized);
  }
  return map;
}

function countCheckpointEventKeys(projection, kind) {
  const prefix = `${kind}:`;
  let count = 0;
  for (const key of projection.eventKeys) {
    if (key.startsWith(prefix)) count += 1;
  }
  return count;
}

function claimCheckpointSourceEvent(record, generations, digests, generationField, digestField, label) {
  const generation = record[generationField];
  const digest = record[digestField];
  if (generations.has(generation) || digests.has(digest)) {
    throw new Error(`${label} reuses a durable source event`);
  }
  generations.add(generation);
  digests.add(digest);
}

function assertExactRecordBindings(left, right, fields, label) {
  for (const field of fields) {
    if (left[field] !== right[field]) throw new Error(`${label}.${field} binding drift`);
  }
}

function validateCheckpointLeaseHistory(projection) {
  const attempts = new Set();
  const byInstrument = new Map();
  let active = 0;
  for (const lease of projection.leases.values()) {
    if (attempts.has(lease.attempt_ref)) {
      throw new Error("instrument checkpoint repeats a lease attempt_ref");
    }
    attempts.add(lease.attempt_ref);
    if (arrayIncludes(["held", "stop_requested", "fenced", "restoring"], lease.state)) {
      active += 1;
    }
    if (!byInstrument.has(lease.instrument_ref)) byInstrument.set(lease.instrument_ref, []);
    arrayPush(byInstrument.get(lease.instrument_ref), lease);
  }
  if (active > MAX_ACTIVE_LEASES) {
    throw new Error("instrument checkpoint exceeds the active lease ceiling");
  }
  for (const leases of byInstrument.values()) {
    arraySort(leases, (left, right) => left.fencing_generation - right.fencing_generation);
    let blocking = 0;
    for (let index = 0; index < leases.length; index += 1) {
      const lease = leases[index];
      if (lease.fencing_generation !== index + 1) {
        throw new Error("instrument checkpoint lease fencing history is non-contiguous");
      }
      if (isLeaseBlocking(lease)) blocking += 1;
      if (index > 0) {
        const prior = leases[index - 1];
        const boundary = prior.closed_at || prior.expires_at;
        if (parseTimestamp(lease.acquired_at) < parseTimestamp(boundary)) {
          throw new Error("instrument checkpoint lease history overlaps");
        }
      }
    }
    if (blocking > 1 || (blocking === 1 && !isLeaseBlocking(leases[leases.length - 1]))) {
      throw new Error("instrument checkpoint lease history contains an impossible blocking successor");
    }
  }
}

function normalizeCheckpointDeliveryBinding(input, outboxEntries, label) {
  assertClosedObject(input, label, [
    "version",
    "outbox_entry_ref",
    "outbox_entry_digest",
    "recipient_principal_id",
    "idempotency_domain_digest",
  ]);
  if (input.version !== STORE_VERSION) throw new Error(`${label}.version must be ${STORE_VERSION}`);
  const outboxDigest = assertStoreDigest(input.outbox_entry_digest, `${label}.outbox_entry_digest`);
  const outbox = outboxEntries.get(outboxDigest);
  if (!outbox || outbox.outbox_entry_ref !== input.outbox_entry_ref) {
    throw new Error(`${label} refers to an unknown outbox entry`);
  }
  return Object.freeze({
    version: STORE_VERSION,
    outbox_entry_ref: outbox.outbox_entry_ref,
    outbox_entry_digest: outboxDigest,
    recipient_principal_id: normalizeOpaqueRef(
      input.recipient_principal_id,
      `${label}.recipient_principal_id`,
      { prefix: "principal" },
    ),
    idempotency_domain_digest: assertStoreDigest(
      input.idempotency_domain_digest,
      `${label}.idempotency_domain_digest`,
    ),
  });
}

function normalizeCheckpointContainmentState(input, projection, label) {
  assertClosedObject(input, label, [
    "version",
    "supervisor_contract_digest",
    "action",
    "fenced_lease_digest",
    "claim_digest",
    "state",
    "claimed_at",
    "outcome",
    "receipt_digest",
    "completed_at",
  ]);
  if (input.version !== STORE_VERSION) throw new Error(`${label}.version must be ${STORE_VERSION}`);
  const supervisorDigest = assertStoreDigest(
    input.supervisor_contract_digest,
    `${label}.supervisor_contract_digest`,
  );
  const contract = projection.safetySupervisorContracts.get(supervisorDigest);
  if (!contract || typeof input.action !== "string"
      || !arrayIncludes(contract.containment_actions, input.action)) {
    throw new Error(`${label} is detached from its safety supervisor contract`);
  }
  const basis = {
    version: STORE_VERSION,
    supervisor_contract_digest: supervisorDigest,
    action: input.action,
    fenced_lease_digest: assertStoreDigest(input.fenced_lease_digest, `${label}.fenced_lease_digest`),
  };
  const claimDigest = canonicalDigest(basis);
  if (input.claim_digest !== claimDigest) throw new Error(`${label}.claim_digest is invalid`);
  const claimedAt = assertCanonicalTimestamp(input.claimed_at, `${label}.claimed_at`);
  if (input.state === "claimed") {
    if (input.outcome !== null || input.receipt_digest !== null || input.completed_at !== null) {
      throw new Error(`${label}.claimed carries terminal fields`);
    }
    return Object.freeze({
      ...basis,
      claim_digest: claimDigest,
      state: "claimed",
      claimed_at: claimedAt,
      outcome: null,
      receipt_digest: null,
      completed_at: null,
    });
  }
  if (input.state !== "completed") throw new Error(`${label}.state is invalid`);
  const completion = normalizeSafetyCompletionPayload({
    version: STORE_VERSION,
    claim_digest: claimDigest,
    outcome: input.outcome,
    receipt_digest: input.receipt_digest,
  }, CONTAINMENT_RESULT_STATES, "receipt_digest", `${label}.completion`);
  const completedAt = assertCanonicalTimestamp(input.completed_at, `${label}.completed_at`);
  if (parseTimestamp(completedAt) < parseTimestamp(claimedAt)) {
    throw new Error(`${label}.completed_at predates its claim`);
  }
  return Object.freeze({
    ...basis,
    claim_digest: claimDigest,
    state: "completed",
    claimed_at: claimedAt,
    outcome: completion.outcome,
    receipt_digest: completion.receipt_digest,
    completed_at: completedAt,
  });
}

function normalizeCheckpointRecoveryState(input, projection, label) {
  assertClosedObject(input, label, [
    "version",
    "supervisor_contract_digest",
    "verified_bootstrap_digest",
    "claim_digest",
    "state",
    "claimed_at",
    "outcome",
    "launch_receipt_digest",
    "completed_at",
  ]);
  if (input.version !== STORE_VERSION) throw new Error(`${label}.version must be ${STORE_VERSION}`);
  const supervisorDigest = assertStoreDigest(
    input.supervisor_contract_digest,
    `${label}.supervisor_contract_digest`,
  );
  if (!projection.safetySupervisorContracts.has(supervisorDigest)) {
    throw new Error(`${label} is detached from its safety supervisor contract`);
  }
  const basis = {
    version: STORE_VERSION,
    supervisor_contract_digest: supervisorDigest,
    verified_bootstrap_digest: assertStoreDigest(
      input.verified_bootstrap_digest,
      `${label}.verified_bootstrap_digest`,
    ),
  };
  const claimDigest = canonicalDigest(basis);
  if (input.claim_digest !== claimDigest) throw new Error(`${label}.claim_digest is invalid`);
  const claimedAt = assertCanonicalTimestamp(input.claimed_at, `${label}.claimed_at`);
  if (input.state === "claimed") {
    if (input.outcome !== null || input.launch_receipt_digest !== null || input.completed_at !== null) {
      throw new Error(`${label}.claimed carries terminal fields`);
    }
    return Object.freeze({
      ...basis,
      claim_digest: claimDigest,
      state: "claimed",
      claimed_at: claimedAt,
      outcome: null,
      launch_receipt_digest: null,
      completed_at: null,
    });
  }
  if (input.state !== "completed") throw new Error(`${label}.state is invalid`);
  const completion = normalizeSafetyCompletionPayload({
    version: STORE_VERSION,
    claim_digest: claimDigest,
    outcome: input.outcome,
    launch_receipt_digest: input.launch_receipt_digest,
  }, RECOVERY_RESULT_STATES, "launch_receipt_digest", `${label}.completion`);
  const completedAt = assertCanonicalTimestamp(input.completed_at, `${label}.completed_at`);
  if (parseTimestamp(completedAt) < parseTimestamp(claimedAt)) {
    throw new Error(`${label}.completed_at predates its claim`);
  }
  return Object.freeze({
    ...basis,
    claim_digest: claimDigest,
    state: "completed",
    claimed_at: claimedAt,
    outcome: completion.outcome,
    launch_receipt_digest: completion.launch_receipt_digest,
    completed_at: completedAt,
  });
}

function normalizeCheckpointExecutionTransactionClaim(input, projection, metadata, label) {
  assertClosedObject(input, label, [
    "version",
    "kind",
    "binding",
    "claimed_at",
    "claim_event_generation",
    "claim_event_digest",
    "claim_digest",
  ]);
  const binding = normalizePhysicalExecutionCompositeBinding(input.binding);
  if (input.version !== STORE_VERSION
      || input.kind !== "physical_execution_transaction_durable_claim"
      || binding.session_nucleus_hash !== metadata.session_nucleus_hash) {
    throw new Error(`${label} version, kind, or session binding is invalid`);
  }
  const generation = assertStoreInteger(
    input.claim_event_generation,
    `${label}.claim_event_generation`,
    1,
  );
  const eventDigest = assertStoreDigest(input.claim_event_digest, `${label}.claim_event_digest`);
  if (projection.eventDigests.get(generation) !== eventDigest
      || !projection.eventKeys.has(
        `execution_transaction_claimed:${canonicalDigest(binding)}`,
      )) {
    throw new Error(`${label} is detached from its durable source event`);
  }
  const basis = {
    version: STORE_VERSION,
    kind: "physical_execution_transaction_durable_claim",
    binding,
    claimed_at: assertCanonicalTimestamp(input.claimed_at, `${label}.claimed_at`),
    claim_event_generation: generation,
    claim_event_digest: eventDigest,
  };
  const claimDigest = canonicalDigest(basis);
  if (input.claim_digest !== claimDigest) throw new Error(`${label}.claim_digest is invalid`);
  return Object.freeze({ ...basis, claim_digest: claimDigest });
}

function assertCheckpointExecutionTransactionBinding(claim, projection, metadata, label) {
  const binding = claim.binding;
  const lease = projection.leases.get(binding.lease_ref);
  const journal = projection.journalHeads.get(binding.attempt_ref);
  if (!lease || !journal) throw new Error(`${label} has no durable lease/journal binding`);
  for (const [actual, expected, field] of [
    [binding.attempt_ref, lease.attempt_ref, "attempt_ref"],
    [binding.execution_request_digest, lease.execution_request_digest, "execution_request_digest"],
    [binding.execution_lineage_digest, journal.execution_lineage_digest, "execution_lineage_digest"],
    [binding.capability_grant_digest, journal.signed_grant_digest, "capability_grant_digest"],
    [binding.cleanup_plan_digest, journal.cleanup_plan_digest, "cleanup_plan_digest"],
    [binding.resource_fence_digest, executionTransactionFenceDigest({
      runtime_id: metadata.runtime_id,
      session_nucleus_hash: metadata.session_nucleus_hash,
    }, lease, journal), "resource_fence_digest"],
  ]) {
    if (actual !== expected) throw new Error(`${label}.${field} binding drift`);
  }
}

function normalizeCheckpointExecutionTransactionVaultCommit(input, claim, projection, label) {
  assertClosedObject(input, label, [
    "version",
    "kind",
    "transaction_ref",
    "execution_lineage_digest",
    "transaction_key_digest",
    "composite_binding_digest",
    "effect_evidence_digest",
    "effect_disposition",
    "semantic_disposition",
    "vault_artifact_ref",
    "vault_receipt_digest",
    "vault_reservation_ref",
    "vault_reservation_digest",
    "vault_commit_digest",
    "committed_at",
    "vault_event_generation",
    "vault_event_digest",
    "durable_vault_commit_digest",
  ]);
  const commit = normalizeExecutionTransactionVaultCommit({
    version: input.version,
    kind: input.kind,
    transaction_ref: input.transaction_ref,
    execution_lineage_digest: input.execution_lineage_digest,
    transaction_key_digest: input.transaction_key_digest,
    composite_binding_digest: input.composite_binding_digest,
    effect_evidence_digest: input.effect_evidence_digest,
    effect_disposition: input.effect_disposition,
    semantic_disposition: input.semantic_disposition,
    vault_artifact_ref: input.vault_artifact_ref,
    vault_receipt_digest: input.vault_receipt_digest,
    vault_reservation_ref: input.vault_reservation_ref,
    vault_reservation_digest: input.vault_reservation_digest,
    vault_commit_digest: input.vault_commit_digest,
  }, claim, `${label}.commit`);
  const generation = assertStoreInteger(
    input.vault_event_generation,
    `${label}.vault_event_generation`,
    1,
  );
  const eventDigest = assertStoreDigest(input.vault_event_digest, `${label}.vault_event_digest`);
  if (projection.eventDigests.get(generation) !== eventDigest
      || !projection.eventKeys.has(
        `execution_transaction_vault_committed:${canonicalDigest(commit)}`,
      )) {
    throw new Error(`${label} is detached from its durable source event`);
  }
  const basis = {
    ...commit,
    committed_at: assertCanonicalTimestamp(input.committed_at, `${label}.committed_at`),
    vault_event_generation: generation,
    vault_event_digest: eventDigest,
  };
  const durableDigest = canonicalDigest(basis);
  if (input.durable_vault_commit_digest !== durableDigest) {
    throw new Error(`${label}.durable_vault_commit_digest is invalid`);
  }
  return Object.freeze({ ...basis, durable_vault_commit_digest: durableDigest });
}

function assertCheckpointTransactionSourceEvent(
  sourceEventReader,
  metadata,
  expected,
  label,
) {
  if (typeof sourceEventReader !== "function") {
    throw new Error(`${label} source event reader is unavailable`);
  }
  const source = sourceEventReader(expected.generation);
  const event = source && source.event;
  if (!source
      || source.envelope_digest !== expected.envelope_digest
      || !event
      || event.runtime_id !== metadata.runtime_id
      || event.session_nucleus_hash !== metadata.session_nucleus_hash
      || event.generation !== expected.generation
      || event.kind !== expected.kind
      || event.recorded_at !== expected.recorded_at
      || !sameJson(event.payload, expected.payload)) {
    throw new Error(`${label} conflicts with its retained durable source event`);
  }
}

function rebuildCheckpointProjection(payload, metadata, anchor, sourceEventReader) {
  const baseFields = [
    "version",
    "domain",
    "projection_schema_version",
    "runtime_id",
    "session_nucleus_hash",
    "checkpoint_generation",
    "prior_checkpoint_digest",
    "event_generation",
    "event_head_digest",
    "last_recorded_at",
    "leases",
    "journal_heads",
    "dispatches",
    "dispatch_source_journals",
    "dispatch_commit_anchors",
    "dispatch_redemptions",
    "outbox_entries",
    "outbox_delivery_bindings",
    "acknowledgements",
    "safety_supervisor_contracts",
    "containment_action_states",
    "recovery_launch_states",
    "event_keys",
    "event_digests",
    "projection_digest",
  ];
  const schemaVersion = payload && payload.projection_schema_version;
  const v2Fields = [
    "execution_transaction_schema_activated",
    "execution_transaction_claims",
    "execution_transaction_vault_commits",
  ];
  if (!arrayIncludes([
    LEGACY_CHECKPOINT_PROJECTION_SCHEMA_VERSION,
    CHECKPOINT_PROJECTION_SCHEMA_VERSION,
  ], schemaVersion)) {
    throw new Error("instrument checkpoint projection schema is unsupported");
  }
  assertClosedObject(
    payload,
    "instrument checkpoint projection",
    schemaVersion === CHECKPOINT_PROJECTION_SCHEMA_VERSION
      ? [...baseFields, ...v2Fields]
      : baseFields,
  );
  const basis = { ...payload };
  delete basis.projection_digest;
  if (payload.projection_digest !== canonicalDigest(basis)) {
    throw new Error("instrument checkpoint projection digest is invalid");
  }
  for (const [actual, expected, field] of [
    [payload.version, CHECKPOINT_VERSION, "version"],
    [payload.domain, CHECKPOINT_DOMAIN, "domain"],
    [payload.projection_schema_version, anchor.projection_schema_version,
      "projection_schema_version"],
    [payload.runtime_id, metadata.runtime_id, "runtime_id"],
    [payload.session_nucleus_hash, metadata.session_nucleus_hash, "session_nucleus_hash"],
    [payload.checkpoint_generation, anchor.checkpoint_generation, "checkpoint_generation"],
    [payload.prior_checkpoint_digest, anchor.prior_checkpoint_digest, "prior_checkpoint_digest"],
    [payload.event_generation, anchor.event_generation, "event_generation"],
    [payload.event_head_digest, anchor.event_head_digest, "event_head_digest"],
  ]) {
    if (actual !== expected) throw new Error(`instrument checkpoint projection ${field} binding drift`);
  }
  const projection = createEmptyProjection();
  projection.generation = anchor.event_generation;
  projection.head_event_digest = anchor.event_head_digest;
  projection.last_recorded_at = anchor.event_generation === 0
    ? (() => {
      if (payload.last_recorded_at !== null) {
        throw new Error("instrument checkpoint genesis has a recorded timestamp");
      }
      return null;
    })()
    : assertCanonicalTimestamp(payload.last_recorded_at, "instrument checkpoint.last_recorded_at");

  projection.eventKeys = new Set(assertCheckpointArray(payload.event_keys, "checkpoint.event_keys"));
  if (projection.eventKeys.size !== payload.event_keys.length
      || projection.eventKeys.size !== projection.generation) {
    throw new Error("instrument checkpoint event key set is incomplete or duplicated");
  }
  for (const key of projection.eventKeys) {
    if (typeof key !== "string"
        || !patternMatches(
          new regexpConstructor(`^(${arrayJoin(EVENT_KINDS, "|")}):[a-f0-9]{64}$`),
          key,
        )) {
      throw new Error("instrument checkpoint event key is invalid");
    }
  }
  projection.eventDigests = new Map();
  for (const [index, entry] of assertCheckpointArray(
    payload.event_digests,
    "checkpoint.event_digests",
  ).entries()) {
    if (!arrayIsArray(entry) || entry.length !== 2 || entry[0] !== index + 1) {
      throw new Error("instrument checkpoint event digest index is non-contiguous");
    }
    projection.eventDigests.set(entry[0], assertStoreDigest(
      entry[1],
      `checkpoint.event_digests[${index}][1]`,
    ));
  }
  if (projection.eventDigests.size !== projection.generation
      || (projection.generation > 0
        && projection.eventDigests.get(projection.generation) !== projection.head_event_digest)) {
    throw new Error("instrument checkpoint event digest chain does not end at its anchored head");
  }

  projection.leases = checkpointMap(
    payload.leases,
    "checkpoint.leases",
    normalizeInstrumentLease,
    "lease_id",
  );
  validateCheckpointLeaseHistory(projection);
  projection.journalHeads = checkpointMap(
    payload.journal_heads,
    "checkpoint.journal_heads",
    normalizeAttemptJournalEntry,
    "attempt_ref",
  );
  const stableBindings = [
    "attempt_ref", "instrument_ref", "lease_id", "fencing_token", "fencing_generation",
    "operation_id", "execution_request_digest",
  ];
  for (const journal of projection.journalHeads.values()) {
    const lease = projection.leases.get(journal.lease_id);
    if (!lease) throw new Error("instrument checkpoint journal has no lease");
    assertExactRecordBindings(journal, lease, stableBindings, "instrument checkpoint journal");
  }

  projection.dispatchSourceJournals = checkpointMap(
    payload.dispatch_source_journals,
    "checkpoint.dispatch_source_journals",
    normalizeAttemptJournalEntry,
    "attempt_ref",
  );
  projection.dispatches = new Map();
  for (const [index, rawDispatch] of assertCheckpointArray(
    payload.dispatches,
    "checkpoint.dispatches",
  ).entries()) {
    const attemptRef = normalizeOpaqueRef(
      rawDispatch && rawDispatch.attempt_ref,
      `checkpoint.dispatches[${index}].attempt_ref`,
      { prefix: "attempt" },
    );
    const source = projection.dispatchSourceJournals.get(attemptRef);
    if (!source) throw new Error("instrument checkpoint dispatch has no source journal");
    const dispatch = normalizeEffectDispatchRecord(
      rawDispatch,
      source,
      `checkpoint.dispatches[${index}]`,
    );
    if (projection.dispatches.has(attemptRef)) throw new Error("instrument checkpoint repeats a dispatch");
    const lease = projection.leases.get(dispatch.lease_id);
    if (!lease) throw new Error("instrument checkpoint dispatch has no lease");
    const currentJournal = projection.journalHeads.get(attemptRef);
    if (!currentJournal) throw new Error("instrument checkpoint dispatch has no current journal");
    assertExactRecordBindings(dispatch, lease, stableBindings, "instrument checkpoint dispatch");
    assertExactRecordBindings(
      currentJournal,
      dispatch,
      stableBindings,
      "instrument checkpoint dispatch journal",
    );
    if (source.sequence > currentJournal.sequence
        || (source.sequence === currentJournal.sequence
          && source.journal_entry_digest !== currentJournal.journal_entry_digest)) {
      throw new Error("instrument checkpoint dispatch source is ahead of or forked from its journal head");
    }
    projection.dispatches.set(attemptRef, dispatch);
  }
  if (projection.dispatchSourceJournals.size !== projection.dispatches.size) {
    throw new Error("instrument checkpoint has detached dispatch source journals");
  }

  projection.dispatchCommitAnchors = new Map();
  for (const [index, value] of assertCheckpointArray(
    payload.dispatch_commit_anchors,
    "checkpoint.dispatch_commit_anchors",
  ).entries()) {
    assertClosedObject(value, `checkpoint.dispatch_commit_anchors[${index}]`, [
      "attempt_ref", "generation", "head_event_digest",
    ]);
    const attemptRef = normalizeOpaqueRef(
      value.attempt_ref,
      `checkpoint.dispatch_commit_anchors[${index}].attempt_ref`,
      { prefix: "attempt" },
    );
    const generation = assertStoreInteger(
      value.generation,
      `checkpoint.dispatch_commit_anchors[${index}].generation`,
      1,
    );
    const digest = assertStoreDigest(
      value.head_event_digest,
      `checkpoint.dispatch_commit_anchors[${index}].head_event_digest`,
    );
    if (!projection.dispatches.has(attemptRef)
        || projection.eventDigests.get(generation) !== digest
        || projection.dispatchCommitAnchors.has(attemptRef)) {
      throw new Error("instrument checkpoint dispatch commit anchor is detached");
    }
    projection.dispatchCommitAnchors.set(attemptRef, Object.freeze({
      generation,
      head_event_digest: digest,
    }));
  }
  if (projection.dispatchCommitAnchors.size !== projection.dispatches.size) {
    throw new Error("instrument checkpoint is missing a dispatch commit anchor");
  }

  projection.dispatchRedemptions = new Map();
  for (const [index, rawRedemption] of assertCheckpointArray(
    payload.dispatch_redemptions,
    "checkpoint.dispatch_redemptions",
  ).entries()) {
    const attemptRef = normalizeOpaqueRef(
      rawRedemption && rawRedemption.attempt_ref,
      `checkpoint.dispatch_redemptions[${index}].attempt_ref`,
      { prefix: "attempt" },
    );
    const dispatch = projection.dispatches.get(attemptRef);
    if (!dispatch) throw new Error("instrument checkpoint redemption has no dispatch");
    const lease = projection.leases.get(dispatch.lease_id);
    const commitAnchor = projection.dispatchCommitAnchors.get(attemptRef);
    const sourceJournal = projection.dispatchSourceJournals.get(attemptRef);
    const expectedCredential = createProviderDispatchCredentialProjection(
      metadata,
      dispatch,
      lease,
      sourceJournal,
      commitAnchor,
    );
    const redemption = normalizeProviderDispatchRedemption(
      rawRedemption,
      expectedCredential,
      `checkpoint.dispatch_redemptions[${index}]`,
    );
    if (projection.dispatchRedemptions.has(attemptRef)) {
      throw new Error("instrument checkpoint repeats a dispatch redemption");
    }
    projection.dispatchRedemptions.set(attemptRef, redemption);
  }
  for (const journal of projection.journalHeads.values()) {
    if (arrayIncludes(["running", "effect_recorded"], journal.state)
        && (!projection.dispatches.has(journal.attempt_ref)
          || !projection.dispatchRedemptions.has(journal.attempt_ref))) {
      throw new Error("instrument checkpoint journal effect state lacks dispatch authority");
    }
  }

  projection.outboxEntries = checkpointMap(
    payload.outbox_entries,
    "checkpoint.outbox_entries",
    normalizeDurableOutboxEntry,
    "outbox_entry_digest",
  );
  projection.outboxHeads = new Map();
  const outboxByAttempt = new Map();
  for (const outbox of projection.outboxEntries.values()) {
    const lease = projection.leases.get(outbox.lease_id);
    if (!lease) throw new Error("instrument checkpoint outbox entry has no lease");
    const journal = projection.journalHeads.get(outbox.attempt_ref);
    if (!journal) throw new Error("instrument checkpoint outbox entry has no current journal");
    assertExactRecordBindings(outbox, lease, stableBindings, "instrument checkpoint outbox entry");
    assertExactRecordBindings(
      outbox,
      journal,
      stableBindings,
      "instrument checkpoint outbox journal",
    );
    if (!outboxByAttempt.has(outbox.attempt_ref)) outboxByAttempt.set(outbox.attempt_ref, []);
    arrayPush(outboxByAttempt.get(outbox.attempt_ref), outbox);
  }
  for (const entries of outboxByAttempt.values()) {
    arraySort(entries, (left, right) => left.sequence - right.sequence);
    if (entries[0].sequence !== 0 || entries.length > MAX_OUTBOX_ENTRIES_PER_ATTEMPT) {
      throw new Error("instrument checkpoint outbox sequence is invalid");
    }
    let head = entries[0];
    for (let index = 1; index < entries.length; index += 1) {
      head = assertDurableOutboxAppend(head, entries[index]);
    }
    projection.outboxHeads.set(head.attempt_ref, head);
  }

  projection.outboxDeliveries = new Map();
  for (const [index, value] of assertCheckpointArray(
    payload.outbox_delivery_bindings,
    "checkpoint.outbox_delivery_bindings",
  ).entries()) {
    const delivery = normalizeCheckpointDeliveryBinding(
      value,
      projection.outboxEntries,
      `checkpoint.outbox_delivery_bindings[${index}]`,
    );
    if (projection.outboxDeliveries.has(delivery.outbox_entry_digest)) {
      throw new Error("instrument checkpoint repeats an outbox delivery binding");
    }
    projection.outboxDeliveries.set(delivery.outbox_entry_digest, delivery);
  }
  projection.acknowledgements = new Map();
  for (const [index, value] of assertCheckpointArray(
    payload.acknowledgements,
    "checkpoint.acknowledgements",
  ).entries()) {
    const outbox = projection.outboxEntries.get(value && value.outbox_entry_digest);
    if (!outbox) throw new Error("instrument checkpoint acknowledgement has no outbox entry");
    const acknowledgement = normalizeOutboxAcknowledgement(
      value,
      outbox,
      `checkpoint.acknowledgements[${index}]`,
    );
    const delivery = projection.outboxDeliveries.get(outbox.outbox_entry_digest);
    if (!delivery || acknowledgement.recipient_principal_id !== delivery.recipient_principal_id
        || projection.acknowledgements.has(outbox.outbox_entry_digest)) {
      throw new Error("instrument checkpoint acknowledgement is detached or duplicated");
    }
    projection.acknowledgements.set(outbox.outbox_entry_digest, acknowledgement);
  }

  projection.safetySupervisorContracts = checkpointMap(
    payload.safety_supervisor_contracts,
    "checkpoint.safety_supervisor_contracts",
    normalizeSafetySupervisorContract,
    "supervisor_contract_digest",
  );
  const supervisedLeaseIds = new Set();
  for (const contract of projection.safetySupervisorContracts.values()) {
    const lease = projection.leases.get(contract.lease_id);
    if (!lease) throw new Error("instrument checkpoint safety supervisor has no lease");
    if (supervisedLeaseIds.has(contract.lease_id)) {
      throw new Error("instrument checkpoint lease has conflicting safety supervisors");
    }
    supervisedLeaseIds.add(contract.lease_id);
    assertSupervisorLeaseBinding(contract, lease, "instrument checkpoint safety supervisor");
  }
  projection.containmentActions = checkpointMap(
    payload.containment_action_states,
    "checkpoint.containment_action_states",
    (value, label) => normalizeCheckpointContainmentState(value, projection, label),
    "claim_digest",
  );
  for (const state of [...projection.containmentActions.values()]) {
    const key = containmentActionKey(state.supervisor_contract_digest, state.action);
    if (projection.containmentActions.get(state.claim_digest) !== state) continue;
    // Re-key to the runtime's semantic lookup key after duplicate claim-digest
    // validation above.
    projection.containmentActions.delete(state.claim_digest);
    if (projection.containmentActions.has(key)) {
      throw new Error("instrument checkpoint repeats a containment action");
    }
    projection.containmentActions.set(key, state);
  }
  projection.recoveryLaunches = checkpointMap(
    payload.recovery_launch_states,
    "checkpoint.recovery_launch_states",
    (value, label) => normalizeCheckpointRecoveryState(value, projection, label),
    "claim_digest",
  );
  for (const state of [...projection.recoveryLaunches.values()]) {
    projection.recoveryLaunches.delete(state.claim_digest);
    const key = recoveryLaunchKey(state.supervisor_contract_digest);
    if (projection.recoveryLaunches.has(key)) {
      throw new Error("instrument checkpoint repeats a recovery launch");
    }
    projection.recoveryLaunches.set(key, state);
  }
  for (const state of projection.recoveryLaunches.values()) {
    const contract = projection.safetySupervisorContracts.get(
      state.supervisor_contract_digest,
    );
    const incomplete = arrayFilter(contract.containment_actions, (action) => {
      const containment = projection.containmentActions.get(
        containmentActionKey(contract.supervisor_contract_digest, action),
      );
      return !containment
        || containment.state !== "completed"
        || containment.outcome !== "confirmed";
    });
    if (incomplete.length > 0) {
      throw new Error(
        `instrument checkpoint recovery lacks confirmed containment: ${arrayJoin(incomplete, ", ")}`,
      );
    }
  }

  if (schemaVersion === LEGACY_CHECKPOINT_PROJECTION_SCHEMA_VERSION) {
    projection.executionTransactionSchemaActivated = false;
  } else {
    if (payload.execution_transaction_schema_activated !== true) {
      throw new Error("instrument checkpoint schema v2 requires transaction activation");
    }
    const claims = assertCheckpointArray(
      payload.execution_transaction_claims,
      "checkpoint.execution_transaction_claims",
      MAX_EXECUTION_TRANSACTIONS,
    );
    if (claims.length < 1) {
      throw new Error("instrument checkpoint schema v2 requires a durable transaction claim");
    }
    if (countCheckpointEventKeys(projection, "execution_transaction_claimed")
        !== claims.length) {
      throw new Error("instrument checkpoint transaction claim projection is incomplete");
    }
    const transactionSourceGenerations = new Set();
    const transactionSourceDigests = new Set();
    for (const [index, value] of claims.entries()) {
      const claim = normalizeCheckpointExecutionTransactionClaim(
        value,
        projection,
        metadata,
        `checkpoint.execution_transaction_claims[${index}]`,
      );
      assertCheckpointExecutionTransactionBinding(
        claim,
        projection,
        metadata,
        `checkpoint.execution_transaction_claims[${index}]`,
      );
      claimCheckpointSourceEvent(
        claim,
        transactionSourceGenerations,
        transactionSourceDigests,
        "claim_event_generation",
        "claim_event_digest",
        `checkpoint.execution_transaction_claims[${index}]`,
      );
      assertCheckpointTransactionSourceEvent(
        sourceEventReader,
        metadata,
        {
          generation: claim.claim_event_generation,
          envelope_digest: claim.claim_event_digest,
          kind: "execution_transaction_claimed",
          payload: claim.binding,
          recorded_at: claim.claimed_at,
        },
        `checkpoint.execution_transaction_claims[${index}]`,
      );
      assertExecutionTransactionClaimUnused(
        projection,
        claim.binding,
        `checkpoint.execution_transaction_claims[${index}]`,
      );
      installExecutionTransactionClaim(projection, claim);
    }
    const vaultCommits = assertCheckpointArray(
      payload.execution_transaction_vault_commits,
      "checkpoint.execution_transaction_vault_commits",
      MAX_EXECUTION_TRANSACTIONS,
    );
    if (countCheckpointEventKeys(projection, "execution_transaction_vault_committed")
        !== vaultCommits.length) {
      throw new Error("instrument checkpoint transaction vault projection is incomplete");
    }
    for (const [index, value] of vaultCommits.entries()) {
      const claim = requireExecutionTransactionClaim(
        projection,
        value && value.transaction_ref,
        `checkpoint.execution_transaction_vault_commits[${index}]`,
      );
      const commit = normalizeCheckpointExecutionTransactionVaultCommit(
        value,
        claim,
        projection,
        `checkpoint.execution_transaction_vault_commits[${index}]`,
      );
      if (projection.executionTransactionVaultCommits.has(commit.transaction_ref)) {
        throw new Error("instrument checkpoint repeats a transaction vault commit");
      }
      assertExecutionTransactionVaultOutputUnused(
        projection,
        commit,
        `checkpoint.execution_transaction_vault_commits[${index}]`,
      );
      claimCheckpointSourceEvent(
        commit,
        transactionSourceGenerations,
        transactionSourceDigests,
        "vault_event_generation",
        "vault_event_digest",
        `checkpoint.execution_transaction_vault_commits[${index}]`,
      );
      const vaultCommittedAt = commit.committed_at;
      const vaultEventGeneration = commit.vault_event_generation;
      const vaultEventDigest = commit.vault_event_digest;
      const vaultSourcePayload = { ...commit };
      delete vaultSourcePayload.committed_at;
      delete vaultSourcePayload.vault_event_generation;
      delete vaultSourcePayload.vault_event_digest;
      delete vaultSourcePayload.durable_vault_commit_digest;
      assertCheckpointTransactionSourceEvent(
        sourceEventReader,
        metadata,
        {
          generation: vaultEventGeneration,
          envelope_digest: vaultEventDigest,
          kind: "execution_transaction_vault_committed",
          payload: vaultSourcePayload,
          recorded_at: vaultCommittedAt,
        },
        `checkpoint.execution_transaction_vault_commits[${index}]`,
      );
      const journal = projection.journalHeads.get(claim.binding.attempt_ref);
      const disposition = journalEffectDisposition(journal);
      if (disposition != null && disposition !== commit.effect_disposition) {
        throw new Error("instrument checkpoint transaction vault/effect fork");
      }
      installExecutionTransactionVaultCommit(projection, commit);
    }
    for (const journal of projection.journalHeads.values()) {
      assertExecutionTransactionEffectJoin(
        projection,
        journal,
        "instrument checkpoint transaction journal",
      );
    }
  }

  for (const lease of projection.leases.values()) {
    if (!arrayIncludes(["released", "quarantined"], lease.state)) continue;
    const journal = projection.journalHeads.get(lease.attempt_ref);
    const expectedJournalState = {
      confirmed_no_effect: "reconciled_no_effect",
      restored: "restored",
      quarantined: "quarantined",
      irreversible_authorized: "irreversible_authorized",
      unknown_effect: "unknown_effect",
    }[lease.terminal_disposition];
    if (!journal || journal.state !== expectedJournalState) {
      throw new Error("instrument checkpoint terminal lease lacks its terminal journal");
    }
    const proof = arrayFind([...projection.outboxEntries.values()], (entry) => (
      entry.attempt_ref === lease.attempt_ref
      && entry.source_journal_entry_digest === journal.journal_entry_digest
      && entry.payload_ref === lease.terminal_receipt_ref
      && entry.payload_digest === lease.terminal_receipt_digest
    ));
    const delivery = proof && projection.outboxDeliveries.get(proof.outbox_entry_digest);
    const acknowledgement = proof && projection.acknowledgements.get(proof.outbox_entry_digest);
    if (!proof || !delivery || !acknowledgement
        || delivery.recipient_principal_id !== lease.terminal_receipt_recipient_principal_id
        || delivery.idempotency_domain_digest
          !== lease.terminal_receipt_idempotency_domain_digest
        || acknowledgement.recipient_principal_id
          !== lease.terminal_receipt_recipient_principal_id) {
      throw new Error("instrument checkpoint terminal lease lacks its accepted receipt");
    }
    if (arraySome([...projection.outboxEntries.values()], (entry) => (
      entry.attempt_ref === lease.attempt_ref
      && !isOutboxEntryExactlyAcknowledged(projection, entry)
    ))) {
      throw new Error("instrument checkpoint terminal lease retains pending outbox evidence");
    }
  }
  return projection;
}

function createDurableInstrumentLeaseStore({
  root,
  runtimeId,
  sessionNucleusHash,
  masterKey,
  stateAnchor,
  checkpointMode,
  checkpointPort = null,
  checkpointIntervalEvents = CHECKPOINT_INTERVAL_EVENTS,
  now = () => new Date(),
} = {}) {
  if (typeof root !== "string" || !path.isAbsolute(root)) {
    throw new Error("instrument lease store root must be an absolute path");
  }
  if (typeof runtimeId !== "string" || !patternMatches(RUNTIME_ID_PATTERN, runtimeId)) {
    throw new Error(
      "runtimeId must be an externally enrolled physical-runtime:v1 identity; it cannot be generated from local store state",
    );
  }
  if (typeof sessionNucleusHash !== "string"
      || !patternMatches(SHA256_PATTERN, sessionNucleusHash)) {
    throw new Error("sessionNucleusHash must be a lowercase SHA-256 digest");
  }
  if (!Buffer.isBuffer(masterKey) || masterKey.length !== 32) {
    throw new Error("masterKey must be a 32-byte Buffer supplied outside the store filesystem");
  }
  if (!stateAnchor || typeof stateAnchor.readState !== "function"
      || typeof stateAnchor.compareAndSet !== "function") {
    throw new Error("stateAnchor must provide external readState and compareAndSet functions");
  }
  if (!arrayIncludes(CHECKPOINT_MODES, checkpointMode)) {
    throw new Error(`checkpointMode must be one of: ${arrayJoin(CHECKPOINT_MODES, ", ")}`);
  }
  if (checkpointMode === "bounded_checkpoint") {
    assertInstrumentLeaseCheckpointAnchorPort(checkpointPort);
  } else if (checkpointPort != null) {
    // An explicit full audit may be paired with the external port solely to
    // publish/verify a migration checkpoint. Readiness remains false until the
    // same root is reopened in bounded_checkpoint mode.
    assertInstrumentLeaseCheckpointAnchorPort(checkpointPort);
  }
  if (!numberIsSafeInteger(checkpointIntervalEvents)
      || checkpointIntervalEvents < 1
      || checkpointIntervalEvents > CHECKPOINT_INTERVAL_EVENTS) {
    throw new Error(
      `checkpointIntervalEvents must be a safe integer from 1 through ${CHECKPOINT_INTERVAL_EVENTS}`,
    );
  }
  if (typeof now !== "function") throw new Error("now must be a function");

  function nowIso() {
    const value = now();
    if (!(value instanceof dateConstructor)
        || numberIsNaN(reflectApply(datePrototypeGetTime, value, []))) {
      throw new Error("instrument lease store clock returned an invalid Date");
    }
    return reflectApply(datePrototypeToISOString, value, []);
  }

  assertPrivateDirectory(root);
  const eventsRoot = path.join(root, "events");
  assertPrivateDirectory(eventsRoot);
  const checkpointsRoot = checkpointPort != null
    ? path.join(root, "checkpoints")
    : null;
  if (checkpointsRoot != null) assertPrivateDirectory(checkpointsRoot);
  const metadataPath = path.join(root, "runtime.json");
  let metadata;
  if (fs.existsSync(metadataPath)) {
    repairPublicationSiblings(root);
    const buffer = readPrivateFile(metadataPath, "instrument lease store metadata", MAX_METADATA_BYTES);
    try {
      metadata = normalizeMetadata(jsonParse(buffer.toString("utf8")), sessionNucleusHash, runtimeId);
    } finally {
      buffer.fill(0);
    }
  } else {
    if (arraySome(
      fs.readdirSync(eventsRoot),
      (name) => patternMatches(EVENT_FILE_PATTERN, name),
    )) {
      throw new Error("instrument lease events exist without runtime metadata");
    }
    const candidate = {
      version: STORE_VERSION,
      runtime_id: runtimeId,
      session_nucleus_hash: sessionNucleusHash,
      kdf_salt: crypto.randomBytes(32).toString("base64"),
      created_at: nowIso(),
    };
    const encoded = Buffer.from(`${canonicalJson(candidate)}\n`, "utf8");
    const published = publishExclusiveDurable(metadataPath, encoded);
    encoded.fill(0);
    if (!published) {
      const buffer = readPrivateFile(metadataPath, "instrument lease store metadata", MAX_METADATA_BYTES);
      try {
        metadata = normalizeMetadata(jsonParse(buffer.toString("utf8")), sessionNucleusHash, runtimeId);
      } finally {
        buffer.fill(0);
      }
    } else {
      metadata = normalizeMetadata(candidate, sessionNucleusHash, runtimeId);
    }
  }

  const keyMaterial = Buffer.from(masterKey);
  const salt = Buffer.from(metadata.kdf_salt, "base64");
  const storeKey = deriveStoreKey(keyMaterial, salt, sessionNucleusHash, metadata.runtime_id);
  const checkpointKey = checkpointPort != null
    ? deriveCheckpointKey(keyMaterial, salt, sessionNucleusHash, metadata.runtime_id)
    : null;
  let closed = false;
  keyMaterial.fill(0);
  salt.fill(0);
  const context = anchorContext(metadata);
  const checkpointContext = Object.freeze({
    version: CHECKPOINT_VERSION,
    domain: CHECKPOINT_DOMAIN,
    runtime_id: metadata.runtime_id,
    session_nucleus_hash: metadata.session_nucleus_hash,
  });

  function readAnchor() {
    return normalizeAnchorState(stateAnchor.readState(context), metadata);
  }

  function commitAnchor(expected, next) {
    let result;
    let commitError = null;
    try {
      result = stateAnchor.compareAndSet(Object.freeze({
        ...context,
        expected_generation: expected == null ? null : expected.generation,
        expected_head_event_digest: expected == null ? null : expected.head_event_digest,
        next_state: next,
      }));
    } catch (error) {
      commitError = error;
    }
    let observed = null;
    let readError = null;
    try { observed = readAnchor(); } catch (error) { readError = error; }
    if (observed && sameJson(observed, next)) return;
    const pending = result === false && observed && expected && sameJson(observed, expected);
    const error = new Error(
      pending
        ? "instrument lease event is durable locally and pending external anchor reconciliation"
        : "instrument lease external anchor commit outcome is ambiguous",
      { cause: commitError || readError || undefined },
    );
    Object.defineProperty(error, "anchor_commit_outcome", {
      // Once an event file is fsynced, callers must never compensate on a
      // false CAS response: a later reconciliation may still publish that
      // exact tail. "pending" and "ambiguous" are both non-compensable.
      value: pending ? "pending" : "ambiguous",
      enumerable: false,
    });
    throw error;
  }

  const checkpointPortState = checkpointPort != null
    ? INSTRUMENT_LEASE_CHECKPOINT_PORT_STATE.get(checkpointPort)
    : null;
  const checkpointPlaintextLimit = checkpointPortState == null
    ? null
    : checkpointPortState.maxCheckpointPlaintextBytes;
  let cachedCheckpointAnchor = null;
  let checkpointCapacityExhausted = false;
  let checkpointCapacityExhaustedAtEventGeneration = null;

  function callCheckpointPort(method, request) {
    if (!checkpointPortState) throw new Error("instrument checkpoint anchor capability is unavailable");
    const result = checkpointPortState[method](Object.freeze(cloneJson(request)));
    if (result && (typeof result === "object" || typeof result === "function")
        && typeof result.then === "function") {
      throw new Error(`instrument checkpoint anchor ${method} must be synchronous`);
    }
    return result;
  }

  function readCheckpointAnchor() {
    return normalizeCheckpointAnchorState(
      callCheckpointPort("readState", checkpointContext),
      metadata,
    );
  }

  function commitCheckpointAnchor(expected, next) {
    let result;
    let commitError = null;
    try {
      result = callCheckpointPort("compareAndSet", {
        ...checkpointContext,
        expected_checkpoint_generation: expected == null
          ? null
          : expected.checkpoint_generation,
        expected_checkpoint_anchor_digest: expected == null
          ? null
          : expected.checkpoint_anchor_digest,
        next_state: next,
      });
      if (result !== true && result !== false) {
        throw new Error("instrument checkpoint anchor compareAndSet must return a boolean");
      }
    } catch (error) {
      commitError = error;
    }
    let observed = null;
    let readError = null;
    try { observed = readCheckpointAnchor(); } catch (error) { readError = error; }
    if (observed && sameJson(observed, next)) return;
    const pending = readError == null
      && result === false
      && ((observed == null && expected == null)
        || (observed != null && expected != null && sameJson(observed, expected)));
    const error = new Error(
      pending
        ? "instrument checkpoint is durable locally and pending external anchor reconciliation"
        : "instrument checkpoint external anchor commit outcome is ambiguous",
      { cause: commitError || readError || undefined },
    );
    Object.defineProperty(error, "checkpoint_anchor_commit_outcome", {
      value: pending ? "pending" : "ambiguous",
      enumerable: false,
    });
    throw error;
  }

  function readCheckpointFiles() {
    const names = fs.readdirSync(checkpointsRoot);
    const unknown = arrayFilter(
      names,
      (name) => !patternMatches(CHECKPOINT_FILE_PATTERN, name),
    );
    if (unknown.length > 0) {
      throw new Error(
        `instrument checkpoint directory contains unknown entries: ${arrayJoin(arraySort(unknown), ", ")}`,
      );
    }
    const files = arraySort(names);
    if (files.length > MAX_CHECKPOINTS) {
      throw new Error("instrument checkpoint count exceeds the ledger ceiling");
    }
    for (let index = 0; index < files.length; index += 1) {
      if (Number(reflectApply(regexpPrototypeExec, CHECKPOINT_FILE_PATTERN, [files[index]])[1])
          !== index + 1) {
        throw new Error("instrument checkpoint files are missing, duplicated, or non-contiguous");
      }
    }
    return files;
  }

  function readCheckpointEnvelope(checkpointGeneration) {
    const fileName = checkpointFileName(checkpointGeneration);
    const buffer = readPrivateFile(
      path.join(checkpointsRoot, fileName),
      `instrument checkpoint ${fileName}`,
      MAX_CHECKPOINT_FILE_BYTES,
    );
    try {
      return jsonParse(buffer.toString("utf8"));
    } finally {
      buffer.fill(0);
    }
  }

  function checkpointAnchorFromEnvelope(envelope, label) {
    assertClosedObject(envelope, label, [
      "version", "domain", "algorithm", "runtime_id", "session_nucleus_hash",
      "checkpoint_generation", "prior_checkpoint_digest", "event_generation",
      "event_head_digest", "projection_schema_version", "nonce", "ciphertext",
      "ciphertext_digest", "tag", "checkpoint_envelope_digest",
    ]);
    const envelopeBasis = { ...envelope };
    delete envelopeBasis.checkpoint_envelope_digest;
    const envelopeDigest = canonicalDigest(envelopeBasis);
    if (envelope.checkpoint_envelope_digest !== envelopeDigest) {
      throw new Error(`${label}.checkpoint_envelope_digest is invalid`);
    }
    const anchorBasis = checkpointAnchorBasis({
      runtime_id: envelope.runtime_id,
      session_nucleus_hash: envelope.session_nucleus_hash,
      checkpoint_generation: envelope.checkpoint_generation,
      prior_checkpoint_digest: envelope.prior_checkpoint_digest,
      event_generation: envelope.event_generation,
      event_head_digest: envelope.event_head_digest,
      projection_schema_version: envelope.projection_schema_version,
      ciphertext_digest: envelope.ciphertext_digest,
      checkpoint_envelope_digest: envelopeDigest,
    });
    return normalizeCheckpointAnchorState({
      ...anchorBasis,
      checkpoint_anchor_digest: canonicalDigest(anchorBasis),
    }, metadata, `${label}.anchor`);
  }

  function loadCheckpointProjection(anchor) {
    const envelope = readCheckpointEnvelope(anchor.checkpoint_generation);
    const localAnchor = checkpointAnchorFromEnvelope(
      envelope,
      `instrument checkpoint ${anchor.checkpoint_generation}`,
    );
    if (!sameJson(localAnchor, anchor)) {
      throw new Error("local instrument checkpoint conflicts with its external anchor");
    }
    const payload = decryptCheckpoint(
      checkpointKey,
      metadata,
      anchor,
      envelope,
      `instrument checkpoint ${anchor.checkpoint_generation}`,
    );
    return rebuildCheckpointProjection(payload, metadata, anchor, readEventGeneration);
  }

  function assertCheckpointEventBoundary(projection, headAnchor, label) {
    if (projection.generation > headAnchor.generation) {
      throw new Error(`${label} is ahead of the external event anchor`);
    }
    if (projection.generation === 0) {
      if (projection.head_event_digest !== null) throw new Error(`${label} genesis is invalid`);
      return;
    }
    const record = readEventGeneration(projection.generation);
    if (record.envelope_digest !== projection.head_event_digest
        || record.event.recorded_at !== projection.last_recorded_at) {
      throw new Error(`${label} event boundary conflicts with the retained append-only ledger`);
    }
  }

  function reconcileCheckpointAnchor(headAnchor, { loadProjection = false } = {}) {
    const files = readCheckpointFiles();
    let external = readCheckpointAnchor();
    if (cachedCheckpointAnchor != null && external == null) {
      throw new Error("instrument checkpoint external anchor disappeared behind the live cache");
    }
    if (cachedCheckpointAnchor != null && external != null) {
      if (external.checkpoint_generation < cachedCheckpointAnchor.checkpoint_generation) {
        throw new Error("instrument checkpoint external anchor rolled back behind the live cache");
      }
      if (external.checkpoint_generation === cachedCheckpointAnchor.checkpoint_generation
          && external.checkpoint_anchor_digest !== cachedCheckpointAnchor.checkpoint_anchor_digest) {
        throw new Error("instrument checkpoint external anchor forked from the live cache");
      }
    }
    if (external != null && external.checkpoint_generation > files.length) {
      throw new Error("instrument checkpoint files were rolled back behind their external anchor");
    }
    if (cachedCheckpointAnchor != null && external != null
        && external.checkpoint_generation > cachedCheckpointAnchor.checkpoint_generation) {
      let prior = cachedCheckpointAnchor;
      for (let generation = prior.checkpoint_generation + 1;
        generation <= external.checkpoint_generation;
        generation += 1) {
        const envelope = readCheckpointEnvelope(generation);
        const successor = checkpointAnchorFromEnvelope(
          envelope,
          `instrument checkpoint ${generation}`,
        );
        if (successor.checkpoint_generation !== generation
            || successor.prior_checkpoint_digest !== prior.checkpoint_anchor_digest
            || successor.event_generation <= prior.event_generation) {
          throw new Error("instrument checkpoint external anchor advanced across a forked local chain");
        }
        prior = successor;
      }
      if (!sameJson(prior, external)) {
        throw new Error("instrument checkpoint external anchor forked from its local successor chain");
      }
    }
    if (external != null) {
      if (external.event_generation > headAnchor.generation) {
        throw new Error("instrument checkpoint is ahead of the external event anchor");
      }
      const envelope = readCheckpointEnvelope(external.checkpoint_generation);
      const local = checkpointAnchorFromEnvelope(
        envelope,
        `instrument checkpoint ${external.checkpoint_generation}`,
      );
      if (!sameJson(local, external)) {
        throw new Error("instrument checkpoint file fork conflicts with its external anchor");
      }
      if (external.event_generation > 0) {
        const boundary = readEventGeneration(external.event_generation);
        if (boundary.envelope_digest !== external.event_head_digest) {
          throw new Error("instrument checkpoint event boundary conflicts with the retained ledger");
        }
      }
    }
    const externalGeneration = external == null ? 0 : external.checkpoint_generation;
    if (files.length - externalGeneration > 1) {
      throw new Error("instrument checkpoint ledger has multiple unanchored checkpoints");
    }
    if (files.length === externalGeneration + 1) {
      const envelope = readCheckpointEnvelope(files.length);
      const pending = checkpointAnchorFromEnvelope(
        envelope,
        `instrument checkpoint ${files.length}`,
      );
      if (pending.prior_checkpoint_digest
          !== (external == null ? null : external.checkpoint_anchor_digest)
          || pending.event_generation <= (external == null ? -1 : external.event_generation)
          || pending.event_generation > headAnchor.generation) {
        throw new Error("unanchored instrument checkpoint does not extend current durable state");
      }
      const pendingProjection = loadCheckpointProjection(pending);
      assertCheckpointEventBoundary(pendingProjection, headAnchor, "unanchored instrument checkpoint");
      commitCheckpointAnchor(external, pending);
      external = readCheckpointAnchor();
      if (!external || !sameJson(external, pending)) {
        throw new Error("instrument checkpoint external anchor did not retain the reconciled checkpoint");
      }
    }
    cachedCheckpointAnchor = external;
    if (external == null) return Object.freeze({ anchor: null, projection: null });
    const projection = loadProjection ? loadCheckpointProjection(external) : null;
    if (projection) assertCheckpointEventBoundary(projection, headAnchor, "instrument checkpoint");
    return Object.freeze({ anchor: external, projection });
  }

  function readEventFiles() {
    const names = fs.readdirSync(eventsRoot);
    const unknown = arrayFilter(names, (name) => !patternMatches(EVENT_FILE_PATTERN, name));
    if (unknown.length > 0) {
      throw new Error(
        `instrument lease event directory contains unknown entries: ${arrayJoin(arraySort(unknown), ", ")}`,
      );
    }
    const files = arraySort(names);
    if (files.length > MAX_EVENTS) throw new Error(`instrument lease event count exceeds ${MAX_EVENTS}`);
    for (let index = 0; index < files.length; index += 1) {
      const generation = Number(
        reflectApply(regexpPrototypeExec, EVENT_FILE_PATTERN, [files[index]])[1],
      );
      if (generation !== index + 1) {
        throw new Error("instrument lease event files are missing, duplicated, or non-contiguous");
      }
    }
    return files;
  }

  function readEventRecord(fileName) {
    const match = reflectApply(regexpPrototypeExec, EVENT_FILE_PATTERN, [fileName]);
    if (!match) throw new Error(`instrument lease event filename is invalid: ${fileName}`);
    const filePath = path.join(eventsRoot, fileName);
    const buffer = readPrivateFile(filePath, `instrument lease event ${fileName}`, MAX_EVENT_FILE_BYTES);
    try {
      const envelope = jsonParse(buffer.toString("utf8"));
      const event = decryptEvent(storeKey, metadata, envelope, `instrument lease event ${fileName}`);
      const generation = Number(match[1]);
      if (event.runtime_id !== metadata.runtime_id
          || event.session_nucleus_hash !== metadata.session_nucleus_hash
          || event.generation !== generation
          || event.generation !== envelope.generation) {
        throw new Error(`instrument lease event ${fileName} is detached from runtime metadata`);
      }
      return Object.freeze({ event, envelope_digest: envelope.envelope_digest });
    } finally {
      buffer.fill(0);
    }
  }

  function eventFileName(generation) {
    return `${String(generation).padStart(12, "0")}.event.json`;
  }

  function readEventGeneration(generation) {
    if (!numberIsSafeInteger(generation) || generation < 1 || generation > MAX_EVENTS) {
      throw new Error("instrument lease event generation is outside the ledger bounds");
    }
    return readEventRecord(eventFileName(generation));
  }

  function eventGenerationExists(generation) {
    if (!numberIsSafeInteger(generation) || generation < 1 || generation > MAX_EVENTS) return false;
    try {
      const stats = fs.lstatSync(path.join(eventsRoot, eventFileName(generation)));
      return stats.isFile() && !stats.isSymbolicLink();
    } catch (error) {
      if (error && error.code === "ENOENT") return false;
      throw error;
    }
  }

  function replayLocalEvents() {
    const projection = createEmptyProjection();
    const events = [];
    for (const fileName of readEventFiles()) {
      const record = readEventRecord(fileName);
      const eventKey = applyEvent(projection, record.event, record.envelope_digest);
      arrayPush(events, Object.freeze({ ...record, eventKey }));
    }
    return { projection, events };
  }

  function synchronizeAnchor(local) {
    let anchor = readAnchor();
    if (anchor == null) {
      if (local.projection.generation !== 0) {
        throw new Error("instrument lease external anchor is missing for a non-genesis ledger");
      }
      const genesis = anchorState(metadata, 0, null);
      commitAnchor(null, genesis);
      anchor = readAnchor();
    }
    if (!anchor) throw new Error("instrument lease external anchor genesis is unavailable");
    if (anchor.generation > local.projection.generation) {
      throw new Error("instrument lease ledger was rolled back behind its external anchor");
    }
    if (anchor.generation > 0
        && local.events[anchor.generation - 1].envelope_digest !== anchor.head_event_digest) {
      throw new Error("instrument lease ledger fork conflicts with its external anchor");
    }
    if (local.projection.generation - anchor.generation > 1) {
      throw new Error("instrument lease ledger has multiple unanchored events and requires adjudication");
    }
    if (local.projection.generation === anchor.generation + 1) {
      const pending = local.events[anchor.generation];
      if (pending.event.previous_event_digest !== anchor.head_event_digest) {
        throw new Error("unanchored instrument lease event does not extend the external anchor");
      }
      const next = anchorState(
        metadata,
        pending.event.generation,
        pending.envelope_digest,
        projectionReaderSchema(local.projection),
      );
      commitAnchor(anchor, next);
      anchor = readAnchor();
    }
    const expected = anchorState(
      metadata,
      local.projection.generation,
      local.projection.head_event_digest,
      projectionReaderSchema(local.projection),
    );
    if (!anchor || !sameJson(anchor, expected)) {
      throw new Error("instrument lease external anchor does not match the durable local ledger");
    }
    return anchor;
  }

  function publishCheckpoint(projection) {
    if (!checkpointPortState) return null;
    const prior = cachedCheckpointAnchor;
    if (prior != null
        && prior.event_generation === projection.generation
        && prior.event_head_digest === projection.head_event_digest) {
      return prior;
    }
    if (prior != null && projection.generation <= prior.event_generation) {
      throw new Error("instrument checkpoint cannot move its event boundary backwards");
    }
    const checkpointGeneration = prior == null ? 1 : prior.checkpoint_generation + 1;
    const fields = {
      checkpoint_generation: checkpointGeneration,
      prior_checkpoint_digest: prior == null ? null : prior.checkpoint_anchor_digest,
      event_generation: projection.generation,
      event_head_digest: projection.head_event_digest,
      projection_schema_version: projection.executionTransactionSchemaActivated
        ? CHECKPOINT_PROJECTION_SCHEMA_VERSION
        : LEGACY_CHECKPOINT_PROJECTION_SCHEMA_VERSION,
    };
    const payload = checkpointProjectionPayload(
      projection,
      metadata,
      checkpointGeneration,
      fields.prior_checkpoint_digest,
    );
    const envelope = encryptCheckpoint(
      checkpointKey,
      metadata,
      fields,
      payload,
      checkpointPlaintextLimit,
    );
    const anchorBasis = checkpointAnchorBasis({
      runtime_id: metadata.runtime_id,
      session_nucleus_hash: metadata.session_nucleus_hash,
      ...fields,
      projection_schema_version: fields.projection_schema_version,
      ciphertext_digest: envelope.ciphertext_digest,
      checkpoint_envelope_digest: envelope.checkpoint_envelope_digest,
    });
    const next = normalizeCheckpointAnchorState({
      ...anchorBasis,
      checkpoint_anchor_digest: canonicalDigest(anchorBasis),
    }, metadata);
    const encoded = Buffer.from(`${canonicalJson(envelope)}\n`, "utf8");
    if (encoded.length > MAX_CHECKPOINT_FILE_BYTES) {
      const actualBytes = encoded.length;
      encoded.fill(0);
      throw createCheckpointCapacityError(
        `instrument checkpoint file exceeds ${MAX_CHECKPOINT_FILE_BYTES} bytes`,
        { actualBytes, limitBytes: MAX_CHECKPOINT_FILE_BYTES },
      );
    }
    const published = publishExclusiveDurable(
      path.join(checkpointsRoot, next.checkpoint_file),
      encoded,
    );
    encoded.fill(0);
    if (!published) throw new Error("instrument checkpoint generation was concurrently published");
    commitCheckpointAnchor(prior, next);
    cachedCheckpointAnchor = next;
    checkpointCapacityExhausted = false;
    checkpointCapacityExhaustedAtEventGeneration = null;
    return next;
  }

  function markCheckpointCapacityExhausted(error, projection) {
    assertCheckpointCapacityError(error);
    checkpointCapacityExhausted = true;
    checkpointCapacityExhaustedAtEventGeneration = projection.generation;
  }

  function assertCheckpointProjectionCapacity(projection) {
    if (!checkpointPortState) return;
    const prior = cachedCheckpointAnchor;
    if (prior != null
        && prior.event_generation === projection.generation
        && prior.event_head_digest === projection.head_event_digest) {
      return;
    }
    const checkpointGeneration = prior == null ? 1 : prior.checkpoint_generation + 1;
    const projectionSchemaVersion = projection.executionTransactionSchemaActivated
      ? CHECKPOINT_PROJECTION_SCHEMA_VERSION
      : LEGACY_CHECKPOINT_PROJECTION_SCHEMA_VERSION;
    const payload = checkpointProjectionPayload(
      projection,
      metadata,
      checkpointGeneration,
      prior == null ? null : prior.checkpoint_anchor_digest,
    );
    if (payload.projection_schema_version !== projectionSchemaVersion) {
      throw new Error("instrument checkpoint projection schema selection drift");
    }
    const plaintext = encodeCheckpointPlaintext(payload, checkpointPlaintextLimit);
    plaintext.fill(0);
  }

  function publishAutomaticCheckpoint(projection) {
    if (checkpointCapacityExhausted) return null;
    try {
      return publishCheckpoint(projection);
    } catch (error) {
      if (!INSTRUMENT_LEASE_CHECKPOINT_CAPACITY_ERRORS.has(error)) throw error;
      markCheckpointCapacityExhausted(error, projection);
      return null;
    }
  }

  function loadBoundedColdProjection() {
    const eventFiles = readEventFiles();
    let headAnchor = readAnchor();
    if (headAnchor == null) {
      if (eventFiles.length !== 0) {
        throw new Error("instrument lease external anchor is missing for a non-genesis ledger");
      }
      const genesis = anchorState(metadata, 0, null);
      commitAnchor(null, genesis);
      headAnchor = readAnchor();
    }
    if (!headAnchor) throw new Error("instrument lease external anchor genesis is unavailable");
    if (headAnchor.generation > eventFiles.length) {
      throw new Error("instrument lease ledger was rolled back behind its external anchor");
    }
    if (eventFiles.length - headAnchor.generation > 1) {
      throw new Error("instrument lease ledger has multiple unanchored events and requires adjudication");
    }

    const checkpoint = reconcileCheckpointAnchor(headAnchor, { loadProjection: true });
    let projection;
    if (checkpoint.anchor == null) {
      if (headAnchor.generation !== 0) {
        throw new Error("bounded checkpoint recovery requires a current external checkpoint anchor");
      }
      projection = createEmptyProjection();
    } else {
      projection = checkpoint.projection;
    }
    const retainedTail = eventFiles.length - projection.generation;
    if (retainedTail < 0) {
      throw new Error("instrument checkpoint is ahead of the retained append-only event ledger");
    }
    if (retainedTail > CHECKPOINT_TAIL_EVENT_LIMIT) {
      throw new Error(
        `instrument checkpoint tail exceeds ${CHECKPOINT_TAIL_EVENT_LIMIT} events; full audit mode is required`,
      );
    }
    for (let generation = projection.generation + 1;
      generation <= headAnchor.generation;
      generation += 1) {
      const record = readEventGeneration(generation);
      applyEvent(projection, record.event, record.envelope_digest);
    }
    if (projection.generation !== headAnchor.generation
        || projection.head_event_digest !== headAnchor.head_event_digest
        || projectionReaderSchema(projection) !== anchorReaderSchema(headAnchor)) {
      throw new Error("bounded checkpoint tail conflicts with the external event anchor");
    }
    if (headAnchor.generation > 0) {
      const anchoredHead = readEventGeneration(headAnchor.generation);
      if (anchoredHead.envelope_digest !== headAnchor.head_event_digest
          || anchoredHead.event.previous_event_digest
            !== (headAnchor.generation === 1
              ? null
              : projection.eventDigests.get(headAnchor.generation - 1))) {
        throw new Error("bounded checkpoint current head conflicts with its retained event chain");
      }
    }
    if (eventFiles.length === headAnchor.generation + 1) {
      const pending = readEventGeneration(eventFiles.length);
      applyEvent(projection, pending.event, pending.envelope_digest);
      const next = anchorState(
        metadata,
        pending.event.generation,
        pending.envelope_digest,
        projectionReaderSchema(projection),
      );
      commitAnchor(headAnchor, next);
      headAnchor = readAnchor();
      if (!headAnchor || !sameJson(headAnchor, next)) {
        throw new Error("external event anchor did not retain the bounded-recovery tail");
      }
    }
    return { projection, headAnchor };
  }

  // The live worker keeps an authenticated projection so safety reads do not
  // decrypt the complete ledger on every heartbeat. Every use still checks
  // the external event and checkpoint anchors plus their exact retained
  // boundary files. Bounded mode restarts from the encrypted, externally
  // anchored checkpoint and replays at most CHECKPOINT_TAIL_EVENT_LIMIT event
  // files; legacy mode deliberately performs the complete audit replay. This
  // is not compaction: neither mode deletes an event or checkpoint record.
  let cachedProjection = null;

  function refreshCachedProjection() {
    if (cachedProjection == null) {
      if (checkpointMode === "bounded_checkpoint") {
        const bounded = loadBoundedColdProjection();
        cachedProjection = bounded.projection;
        return { projection: cachedProjection };
      }
      const local = replayLocalEvents();
      synchronizeAnchor(local);
      cachedProjection = local.projection;
      return { projection: cachedProjection };
    }

    let anchor = readAnchor();
    if (anchor == null) {
      if (cachedProjection.generation !== 0) {
        throw new Error("instrument lease external anchor is missing for a non-genesis ledger");
      }
      commitAnchor(null, anchorState(metadata, 0, null));
      anchor = readAnchor();
    }
    if (!anchor) throw new Error("instrument lease external anchor genesis is unavailable");
    if (anchor.generation < cachedProjection.generation) {
      throw new Error("instrument lease ledger was rolled back behind its cached external anchor");
    }

    if (anchor.generation > cachedProjection.generation) {
      const refreshed = cloneProjection(cachedProjection);
      for (let generation = refreshed.generation + 1;
        generation <= anchor.generation;
        generation += 1) {
        const record = readEventGeneration(generation);
        applyEvent(refreshed, record.event, record.envelope_digest);
      }
      cachedProjection = refreshed;
    }
    if (cachedProjection.generation !== anchor.generation
        || cachedProjection.head_event_digest !== anchor.head_event_digest
        || projectionReaderSchema(cachedProjection) !== anchorReaderSchema(anchor)) {
      throw new Error("instrument lease cached ledger fork conflicts with its external anchor");
    }
    if (anchor.generation > 0) {
      const anchoredHead = readEventGeneration(anchor.generation);
      if (anchoredHead.envelope_digest !== anchor.head_event_digest
          || anchoredHead.event.previous_event_digest
            !== (anchor.generation === 1
              ? null
              : cachedProjection.eventDigests.get(anchor.generation - 1))) {
        throw new Error("instrument lease cached head file conflicts with its external anchor chain");
      }
    }

    const pendingGeneration = cachedProjection.generation + 1;
    if (eventGenerationExists(pendingGeneration)) {
      if (eventGenerationExists(pendingGeneration + 1)) {
        throw new Error("instrument lease ledger has multiple unanchored events and requires adjudication");
      }
      const pending = readEventGeneration(pendingGeneration);
      const refreshed = cloneProjection(cachedProjection);
      applyEvent(refreshed, pending.event, pending.envelope_digest);
      const next = anchorState(
        metadata,
        pending.event.generation,
        pending.envelope_digest,
        projectionReaderSchema(refreshed),
      );
      commitAnchor(anchor, next);
      anchor = readAnchor();
      if (!anchor || !sameJson(anchor, next)) {
        throw new Error("instrument lease external anchor did not retain the reconciled local tail");
      }
      cachedProjection = refreshed;
    }
    return { projection: cachedProjection };
  }

  function withLockedProjection(callback) {
    if (closed) throw new Error("instrument lease store is closed");
    const release = acquireStoreLock(root, nowIso);
    try {
      repairPublicationSiblings(root);
      // A second store process may crash after fsyncing an event candidate or
      // linking the final event but before removing its publication sibling.
      // Reconcile that bounded publication state under the store-wide lock on
      // every hot use; otherwise a cached peer can publish a different final
      // over an orphan candidate and leave a restart-poisoning conflict.
      repairPublicationSiblings(eventsRoot);
      if (checkpointPortState) {
        repairPublicationSiblings(checkpointsRoot);
      }
      const local = refreshCachedProjection();
      if (checkpointPortState) {
        const head = anchorState(
          metadata,
          local.projection.generation,
          local.projection.head_event_digest,
          projectionReaderSchema(local.projection),
        );
        const checkpoint = reconcileCheckpointAnchor(head);
        if (checkpointMode === "bounded_checkpoint"
            && (checkpoint.anchor == null
            || local.projection.generation - checkpoint.anchor.event_generation
              >= checkpointIntervalEvents)) {
          publishAutomaticCheckpoint(local.projection);
        }
      }
      const startingGeneration = local.projection.generation;
      const result = callback(local);
      if (checkpointMode === "bounded_checkpoint"
          && cachedProjection.generation > startingGeneration
          && cachedProjection.generation
            - (cachedCheckpointAnchor == null ? 0 : cachedCheckpointAnchor.event_generation)
            >= checkpointIntervalEvents) {
        publishAutomaticCheckpoint(cachedProjection);
      }
      return result;
    } finally {
      release();
    }
  }

  // Initialize and reconcile genesis (or one crash-left local commit) before
  // returning a usable store object. Do not leave derived key material live if
  // constructor-time integrity or rollback validation fails.
  try {
    withLockedProjection((local) => local.projection.generation);
  } catch (error) {
    storeKey.fill(0);
    if (checkpointKey) checkpointKey.fill(0);
    throw error;
  }

  function appendEvent(kind, payload) {
    if (!arrayIncludes(EVENT_KINDS, kind)) {
      throw new Error(`unsupported instrument lease event kind: ${kind}`);
    }
    const normalizedPayload = cloneJson(payload);
    const eventKey = `${kind}:${canonicalDigest(normalizedPayload)}`;
    return withLockedProjection((local) => {
      if (local.projection.eventKeys.has(eventKey)) {
        return Object.freeze({
          committed: true,
          already_committed: true,
          projection: publicProjection(local.projection),
        });
      }
      const safetyCriticalEvent = isSafetyCriticalEvent(kind, normalizedPayload);
      if (checkpointMode === "bounded_checkpoint"
          && checkpointCapacityExhausted
          && !safetyCriticalEvent) {
        throw createCheckpointCapacityError(
          "instrument checkpoint capacity is exhausted; ordinary events are refused while the safety reserve remains open",
          { limitBytes: checkpointPlaintextLimit },
        );
      }
      if (local.projection.generation >= MAX_EVENTS) {
        throw new Error(`instrument lease event count has reached ${MAX_EVENTS}`);
      }
      if (!safetyCriticalEvent
          && local.projection.generation >= ORDINARY_EVENT_LIMIT) {
        throw new Error(
          `ordinary instrument lease admission stops at ${ORDINARY_EVENT_LIMIT} events; `
          + `${SAFETY_EVENT_RESERVE} events are reserved for fencing and cleanup`,
        );
      }
      const event = {
        version: STORE_VERSION,
        runtime_id: metadata.runtime_id,
        session_nucleus_hash: metadata.session_nucleus_hash,
        generation: local.projection.generation + 1,
        previous_event_digest: local.projection.head_event_digest,
        kind,
        payload: normalizedPayload,
        recorded_at: nowIso(),
      };
      // Validate the exact event against a replayed projection before bytes are
      // published. This catches stale CAS inputs without leaving residue.
      const validationProjection = cloneProjection(local.projection);
      const envelope = encryptEvent(storeKey, metadata, event);
      applyEvent(validationProjection, event, envelope.envelope_digest);
      if (checkpointMode === "bounded_checkpoint"
          && !safetyCriticalEvent
          && validationProjection.generation
            - (cachedCheckpointAnchor == null ? 0 : cachedCheckpointAnchor.event_generation)
            >= checkpointIntervalEvents) {
        try {
          assertCheckpointProjectionCapacity(validationProjection);
        } catch (error) {
          if (!INSTRUMENT_LEASE_CHECKPOINT_CAPACITY_ERRORS.has(error)) throw error;
          markCheckpointCapacityExhausted(error, local.projection);
          throw error;
        }
      }
      const encoded = Buffer.from(`${canonicalJson(envelope)}\n`, "utf8");
      if (encoded.length > MAX_EVENT_FILE_BYTES) {
        encoded.fill(0);
        throw new Error(`instrument lease event file exceeds ${MAX_EVENT_FILE_BYTES} bytes`);
      }
      const eventPath = path.join(
        eventsRoot,
        `${String(event.generation).padStart(12, "0")}.event.json`,
      );
      const published = publishExclusiveDurable(eventPath, encoded);
      encoded.fill(0);
      if (!published) throw new Error("instrument lease event generation was concurrently published");
      const nextAnchor = anchorState(
        metadata,
        event.generation,
        envelope.envelope_digest,
        projectionReaderSchema(validationProjection),
      );
      const priorAnchor = anchorState(
        metadata,
        local.projection.generation,
        local.projection.head_event_digest,
        projectionReaderSchema(local.projection),
      );
      commitAnchor(priorAnchor, nextAnchor);
      cachedProjection = validationProjection;
      return Object.freeze({
        committed: true,
        already_committed: false,
        projection: publicProjection(validationProjection),
      });
    });
  }

  function findById(values, field, value) {
    return arrayFind(values, (entry) => entry[field] === value) || null;
  }

  function claimExecutionTransaction(bindingInput) {
    const binding = normalizePhysicalExecutionCompositeBinding(bindingInput);
    const outcome = appendEvent("execution_transaction_claimed", binding);
    const transaction = findById(
      outcome.projection.execution_transactions,
      "transaction_ref",
      binding.transaction_ref,
    );
    if (!transaction || transaction.composite_binding_digest !== binding.composite_binding_digest) {
      throw new Error("durable execution transaction claim disappeared after commit");
    }
    return Object.freeze({
      already_committed: outcome.already_committed,
      transaction,
    });
  }

  function commitExecutionTransactionVault(input) {
    assertExecutionTransactionVaultInputShape(
      input,
      "physical_execution_transaction_vault_commit",
    );
    const normalized = withLockedProjection((local) => {
      const transactionRef = input.transaction_ref;
      const claim = requireExecutionTransactionClaim(
        local.projection,
        transactionRef,
        "execution transaction vault commit",
      );
      return normalizeExecutionTransactionVaultCommit(
        input,
        claim,
        "physical_execution_transaction_vault_commit",
      );
    });
    const outcome = appendEvent("execution_transaction_vault_committed", normalized);
    const transaction = findById(
      outcome.projection.execution_transactions,
      "transaction_ref",
      normalized.transaction_ref,
    );
    if (!transaction || transaction.vault_commit_digest == null) {
      throw new Error("durable execution transaction vault fact disappeared after commit");
    }
    return Object.freeze({
      already_committed: outcome.already_committed,
      transaction,
    });
  }

  function readExecutionTransaction(input) {
    const query = normalizeExecutionTransactionReadQuery(
      input,
      "physical_execution_transaction_durable_read",
    );
    return withLockedProjection((local) => {
      const claim = requireExecutionTransactionClaim(
        local.projection,
        query.transaction_ref,
        "physical execution transaction read",
      );
      for (const field of [
        "execution_lineage_digest",
        "transaction_key_digest",
        "composite_binding_digest",
      ]) {
        if (query[field] !== claim.binding[field]) {
          throw new Error(`physical execution transaction read ${field} binding drift`);
        }
      }
      return executionTransactionLedgerState(local.projection, claim);
    });
  }

  function acquireLease(candidate) {
    const normalized = normalizeInstrumentLease(candidate);
    const outcome = appendEvent("lease_acquired", normalized);
    return findById(outcome.projection.leases, "lease_id", normalized.lease_id);
  }

  function mutateLease(kind, request) {
    const outcome = appendEvent(kind, request);
    return findById(outcome.projection.leases, "lease_id", request.lease_id);
  }

  function appendJournal(entry) {
    const normalized = normalizeAttemptJournalEntry(entry);
    const outcome = appendEvent("journal_appended", normalized);
    return findById(outcome.projection.journal_heads, "attempt_ref", normalized.attempt_ref);
  }

  function commitDispatch(record) {
    // Refuse before publishing the one-shot dispatch event. A provider effect
    // credential must be rooted in the experiment and exact compiled-command
    // lineage that were durably precommitted with the attempt.
    const attemptRefDescriptor = record == null
      ? null
      : Object.getOwnPropertyDescriptor(record, "attempt_ref");
    if (!attemptRefDescriptor
        || !hasOwn(attemptRefDescriptor, "value")) {
      throw new Error("provider dispatch commit requires a data-valued attempt_ref");
    }
    const attemptRef = normalizeOpaqueRef(
      attemptRefDescriptor.value,
      "provider dispatch commit attempt_ref",
      { prefix: "attempt" },
    );
    const normalizedRecord = withLockedProjection((local) => {
      const journal = local.projection.journalHeads.get(attemptRef);
      projectJournalExecutionLineage(
        journal,
        "provider dispatch commit journal",
        { required: true },
      );
      return normalizeEffectDispatchRecord(
        record,
        journal,
        "provider dispatch commit record",
      );
    });
    const outcome = appendEvent("dispatch_committed", normalizedRecord);
    const dispatch = findById(
      outcome.projection.dispatches,
      "attempt_ref",
      normalizedRecord.attempt_ref,
    );
    if (outcome.already_committed) {
      return Object.freeze({
        dispatch,
        dispatch_credential: null,
        already_committed: true,
      });
    }
    const lease = findById(outcome.projection.leases, "lease_id", dispatch.lease_id);
    if (!lease) throw new Error("newly committed dispatch lost its durable lease binding");
    const journal = findById(outcome.projection.journal_heads, "attempt_ref", dispatch.attempt_ref);
    if (!journal) throw new Error("newly committed dispatch lost its durable journal binding");
    const dispatchCredential = createProviderDispatchCredentialProjection(
      metadata,
      dispatch,
      lease,
      journal,
      {
        generation: outcome.projection.generation,
        head_event_digest: outcome.projection.head_event_digest,
      },
    );
    DURABLE_PROVIDER_DISPATCH_CREDENTIALS.add(dispatchCredential);
    DURABLE_PROVIDER_DISPATCH_CREDENTIAL_STATE.set(dispatchCredential, Object.freeze({
      store,
      credential_digest: dispatchCredential.credential_digest,
      fencing_token: lease.fencing_token,
      signed_grant_digest: journal.signed_grant_digest,
    }));
    return Object.freeze({
      dispatch,
      dispatch_credential: dispatchCredential,
      already_committed: false,
    });
  }

  function redeemProviderDispatchCredential(credential, enrollment, expected, port) {
    const credentialState = credential == null
      ? null
      : DURABLE_PROVIDER_DISPATCH_CREDENTIAL_STATE.get(credential);
    if (!credential
        || !DURABLE_PROVIDER_DISPATCH_CREDENTIALS.has(credential)
        || !credentialState
        || credentialState.store !== store
        || credentialState.credential_digest !== credential.credential_digest) {
      throw new Error("provider dispatch credential was not issued by this live durable store");
    }
    for (const [actual, wanted, field] of [
      [credential.provider_id, enrollment.provider_id, "provider_id"],
      [credential.provider_descriptor_digest, enrollment.provider_descriptor_digest,
        "provider_descriptor_digest"],
      [credential.execution_principal_id, enrollment.execution_principal_id,
        "execution_principal_id"],
      [credential.attempt_ref, expected.attempt_ref, "attempt_ref"],
      [credential.instrument_ref, expected.instrument_ref, "instrument_ref"],
      [credential.operation_id, expected.operation_id, "operation_id"],
      [credential.provider_id, expected.provider_id, "expected_provider_id"],
      [credential.provider_descriptor_digest, expected.provider_descriptor_digest,
        "expected_provider_descriptor_digest"],
      [credential.journal_entry_ref, expected.dispatch_journal_ref, "journal_entry_ref"],
      [credential.provider_request_digest, expected.provider_request_digest,
        "provider_request_digest"],
      [credential.provider_state, expected.expected_state, "provider_state"],
      [credential.provider_sequence, expected.expected_sequence, "provider_sequence"],
    ]) {
      if (actual !== wanted) throw new Error(`provider dispatch redemption ${field} binding drift`);
    }
    projectJournalExecutionLineage(
      credential,
      "provider dispatch redemption credential",
      { required: true },
    );
    if (!arrayIncludes(enrollment.instrument_refs, credential.instrument_ref)) {
      throw new Error("provider dispatch redemption instrument is outside the enrolled provider port");
    }
    const authorityAssertion = createPhysicalDispatchAuthorityAssertion(
      credential,
      credentialState.signed_grant_digest,
      credentialState.fencing_token,
    );
    // Redemption is a durable election boundary, not the final authority
    // decision. The same assertion is retained privately and rechecked under
    // the store lock immediately before the synchronous provider effect.
    assertCurrentPhysicalDispatchAuthority(enrollment.authority_port, authorityAssertion);
    const { domain: _domain, version: _credentialVersion, ...credentialFields } = credential;
    const redemption = normalizeProviderDispatchRedemption({
      version: STORE_VERSION,
      redemption_ref: `provider-dispatch-redemption:${credential.credential_digest.slice(0, 40)}`,
      ...credentialFields,
      redeemed_at: nowIso(),
    }, credential);
    const outcome = appendEvent("dispatch_redeemed", redemption);
    if (outcome.already_committed) {
      throw new Error("provider dispatch credential has already been durably redeemed");
    }
    const durable = findById(
      outcome.projection.dispatch_redemptions,
      "attempt_ref",
      credential.attempt_ref,
    );
    if (!durable || durable.redemption_digest !== redemption.redemption_digest) {
      throw new Error("provider dispatch redemption disappeared after its durable commit");
    }
    const permit = Object.freeze(Object.create(null));
    DURABLE_PROVIDER_EFFECT_PERMITS.add(permit);
    DURABLE_PROVIDER_EFFECT_PERMIT_STATE.set(permit, {
      consumed: false,
      authority_assertion: authorityAssertion,
      credential_digest: credential.credential_digest,
      dispatch_record_digest: credential.dispatch_record_digest,
      enrollment,
      expected,
      port,
      redemption_digest: durable.redemption_digest,
      store,
    });
    return permit;
  }

  function consumeProviderEffectPermit(permit, callback, port) {
    const permitState = permit == null ? null : DURABLE_PROVIDER_EFFECT_PERMIT_STATE.get(permit);
    if (!permit
        || !DURABLE_PROVIDER_EFFECT_PERMITS.has(permit)
        || !permitState
        || permitState.store !== store
        || permitState.port !== port) {
      throw new Error("provider effect permit was not issued to this provider dispatch port");
    }
    if (permitState.consumed) throw new Error("provider effect permit has already been consumed");
    if (typeof callback !== "function") {
      throw new Error("provider effect permit callback must be a synchronous function");
    }
    if (callback.constructor && callback.constructor.name === "AsyncFunction") {
      throw new Error("provider effect permit callback cannot be async");
    }
    return withLockedProjection((local) => {
      const redemption = local.projection.dispatchRedemptions.get(permitState.expected.attempt_ref);
      if (!redemption || redemption.redemption_digest !== permitState.redemption_digest) {
        throw new Error("provider effect permit lost its durable redemption binding");
      }
      const dispatch = local.projection.dispatches.get(permitState.expected.attempt_ref);
      if (!dispatch || dispatch.dispatch_record_digest !== permitState.dispatch_record_digest) {
        throw new Error("provider effect permit lost its durable dispatch binding");
      }
      const journal = local.projection.journalHeads.get(permitState.expected.attempt_ref);
      if (!journal
          || journal.state !== "effect_starting"
          || journal.journal_entry_ref !== permitState.expected.dispatch_journal_ref
          || journal.provider_state !== "prepared"
          || journal.provider_sequence !== permitState.expected.expected_sequence
          || journal.provider_request_digest !== permitState.expected.provider_request_digest) {
        throw new Error("provider effect permit requires the exact effect_starting/prepared journal head");
      }
      const lease = local.projection.leases.get(dispatch.lease_id);
      if (!lease
          || lease.execution_principal_id !== permitState.enrollment.execution_principal_id
          || lease.instrument_ref !== permitState.expected.instrument_ref
          || lease.fencing_token !== dispatch.fencing_token
          || lease.fencing_generation !== dispatch.fencing_generation) {
        throw new Error("provider effect permit lost its live lease/fence binding");
      }
      assertLeaseEffectWindow(
        { recorded_at: nowIso() },
        lease,
        "provider effect permit consumption",
      );
      const authorityAssertion = permitState.authority_assertion;
      for (const [actual, expectedValue, field] of [
        [authorityAssertion.session_nucleus_hash, metadata.session_nucleus_hash,
          "session_nucleus_hash"],
        [authorityAssertion.signed_grant_digest, journal.signed_grant_digest,
          "signed_grant_digest"],
        [authorityAssertion.execution_request_digest, dispatch.execution_request_digest,
          "execution_request_digest"],
        [authorityAssertion.experiment_plan_hash, journal.experiment_plan_hash,
          "experiment_plan_hash"],
        [authorityAssertion.execution_lineage_digest, journal.execution_lineage_digest,
          "execution_lineage_digest"],
        [authorityAssertion.execution_principal_id, lease.execution_principal_id,
          "execution_principal_id"],
        [authorityAssertion.attempt_ref, dispatch.attempt_ref, "attempt_ref"],
        [authorityAssertion.instrument_ref, lease.instrument_ref, "instrument_ref"],
        [authorityAssertion.lease_id, lease.lease_id, "lease_id"],
        [authorityAssertion.fencing_token, lease.fencing_token, "fencing_token"],
        [authorityAssertion.fencing_token, dispatch.fencing_token,
          "dispatch_fencing_token"],
        [authorityAssertion.fencing_generation, lease.fencing_generation,
          "fencing_generation"],
        [authorityAssertion.operation_id, dispatch.operation_id, "operation_id"],
        [authorityAssertion.provider_id, dispatch.provider_id, "provider_id"],
        [authorityAssertion.provider_descriptor_digest, dispatch.provider_descriptor_digest,
          "provider_descriptor_digest"],
        [authorityAssertion.effect_not_before, lease.effect_not_before, "effect_not_before"],
        [authorityAssertion.effect_deadline, lease.effect_deadline, "effect_deadline"],
      ]) {
        if (actual !== expectedValue) {
          throw new Error(`provider effect permit authority ${field} binding drift`);
        }
      }
      assertCurrentPhysicalDispatchAuthority(
        permitState.enrollment.authority_port,
        authorityAssertion,
      );
      // No await or user hook may occur between this live authority check and
      // callback entry. Real hardware still requires a separately privileged
      // worker that owns the device descriptor; this in-process port is the
      // deterministic contract seam, not an OS isolation boundary.
      permitState.consumed = true;
      const result = callback();
      if (result && (typeof result === "object" || typeof result === "function")
          && typeof result.then === "function") {
        throw new Error("provider effect permit callback must complete synchronously");
      }
      return result;
    });
  }

  function appendOutbox(entry) {
    const normalized = normalizeDurableOutboxEntry(entry);
    const outcome = appendEvent("outbox_appended", normalized);
    return findById(
      outcome.projection.outbox_entries,
      "outbox_entry_digest",
      normalized.outbox_entry_digest,
    );
  }

  function acknowledgeOutbox(acknowledgement) {
    const outcome = appendEvent("outbox_acknowledged", acknowledgement);
    return findById(
      outcome.projection.acknowledgements,
      "outbox_entry_digest",
      acknowledgement.outbox_entry_digest,
    );
  }

  // Delivery is intentionally at-least-once across a crash between recipient
  // acceptance and local acknowledgement. The only accepted recipient port is
  // therefore branded with a mandatory atomic deduplication contract keyed by
  // outbox_entry_digest. A plain callback is rejected; production admission
  // separately attests the recipient transaction implementation.
  async function deliverOutbox(entry, recipientPort) {
    if (!IDEMPOTENT_OUTBOX_RECIPIENT_PORTS.has(recipientPort)) {
      throw new Error("deliverOutbox requires a branded idempotent recipient port");
    }
    const durable = appendOutbox(entry);
    appendEvent("outbox_delivery_bound", {
      version: STORE_VERSION,
      outbox_entry_ref: durable.outbox_entry_ref,
      outbox_entry_digest: durable.outbox_entry_digest,
      recipient_principal_id: recipientPort.recipient_principal_id,
      idempotency_domain_digest: recipientPort.idempotency_domain_digest,
    });
    const snapshotValue = snapshot();
    const priorAck = findById(
      snapshotValue.acknowledgements,
      "outbox_entry_digest",
      durable.outbox_entry_digest,
    );
    if (priorAck) {
      const binding = findById(
        snapshotValue.outbox_delivery_bindings,
        "outbox_entry_digest",
        durable.outbox_entry_digest,
      );
      if (!binding || binding.recipient_principal_id !== recipientPort.recipient_principal_id
          || binding.idempotency_domain_digest !== recipientPort.idempotency_domain_digest) {
        throw new Error("durable acknowledgement is detached from the requested recipient port");
      }
      return priorAck;
    }
    const acknowledgement = await recipientPort.accept({
      version: STORE_VERSION,
      idempotency_key: durable.outbox_entry_digest,
      idempotency_domain_digest: recipientPort.idempotency_domain_digest,
      outbox_entry: durable,
    });
    return acknowledgeOutbox(acknowledgement);
  }

  function registerSafetySupervisor(contractInput) {
    const contract = normalizeSafetySupervisorContract(
      contractInput,
      "instrument lease store safety supervisor",
    );
    const outcome = appendEvent("safety_supervisor_registered", contract);
    return findById(
      outcome.projection.safety_supervisor_contracts,
      "supervisor_contract_digest",
      contract.supervisor_contract_digest,
    );
  }

  function claimContainmentAction(request) {
    assertClosedObject(request, "containment action claim request", [
      "version",
      "supervisor_contract_digest",
      "action",
      "fenced_lease_digest",
    ]);
    const basis = cloneJson(request);
    const payload = { ...basis, claim_digest: canonicalDigest(basis) };
    const outcome = appendEvent("containment_action_claimed", payload);
    const state = findById(
      outcome.projection.containment_action_states,
      "claim_digest",
      payload.claim_digest,
    );
    if (!state) throw new Error("durable containment claim was not projected");
    return Object.freeze({ claimed: !outcome.already_committed, state });
  }

  function completeContainmentAction(request) {
    const outcome = appendEvent("containment_action_completed", request);
    const state = findById(
      outcome.projection.containment_action_states,
      "claim_digest",
      request.claim_digest,
    );
    if (!state || state.state !== "completed") {
      throw new Error("durable containment completion was not projected");
    }
    return state;
  }

  function claimRecoveryLaunch(request) {
    assertClosedObject(request, "recovery launch claim request", [
      "version",
      "supervisor_contract_digest",
      "verified_bootstrap_digest",
    ]);
    const basis = cloneJson(request);
    const payload = { ...basis, claim_digest: canonicalDigest(basis) };
    const outcome = appendEvent("recovery_launch_claimed", payload);
    const state = findById(
      outcome.projection.recovery_launch_states,
      "claim_digest",
      payload.claim_digest,
    );
    if (!state) throw new Error("durable recovery launch claim was not projected");
    return Object.freeze({ claimed: !outcome.already_committed, state });
  }

  function completeRecoveryLaunch(request) {
    const outcome = appendEvent("recovery_launch_completed", request);
    const state = findById(
      outcome.projection.recovery_launch_states,
      "claim_digest",
      request.claim_digest,
    );
    if (!state || state.state !== "completed") {
      throw new Error("durable recovery completion was not projected");
    }
    return state;
  }

  function snapshot() {
    return withLockedProjection((local) => publicProjection(local.projection));
  }

  function readLease(leaseIdInput) {
    const leaseId = assertStoreToken(leaseIdInput, "instrument lease read lease_id");
    return withLockedProjection((local) => {
      const lease = local.projection.leases.get(leaseId);
      return lease == null ? null : Object.freeze(cloneJson(lease));
    });
  }

  function checkpointReadinessUnsafe(projection) {
    const checkpoint = cachedCheckpointAnchor;
    const tailEventCount = checkpoint == null
      ? null
      : projection.generation - checkpoint.event_generation;
    const boundedRecoveryReady = checkpointMode === "bounded_checkpoint"
      && checkpoint != null
      && numberIsSafeInteger(tailEventCount)
      && tailEventCount >= 0
      && tailEventCount <= CHECKPOINT_TAIL_EVENT_LIMIT;
    const common = {
      version: CHECKPOINT_VERSION,
      checkpoint_mode: checkpointMode,
      // The local factory can prove only that callbacks are privately branded
      // inside this process. It cannot attest that their backing CAS is hosted
      // by another principal or survives process/host loss. Higher-level
      // provisioning must turn this contract assertion into production proof.
      production_ready: false,
      bounded_recovery_ready: boundedRecoveryReady,
      anchor_assurance: checkpointPortState == null
        ? "unavailable"
        : "caller_asserted_callback_unattested",
      checkpoint_capacity_state: checkpointPortState == null
        ? "not_configured"
        : (checkpointCapacityExhausted ? "exhausted" : "within_limit"),
      admission_mode: checkpointCapacityExhausted ? "safety_reserve_only" : "normal",
      checkpoint_capacity_exhausted_at_event_generation:
        checkpointCapacityExhaustedAtEventGeneration,
      checkpoint_generation: checkpoint == null ? null : checkpoint.checkpoint_generation,
      checkpoint_event_generation: checkpoint == null ? null : checkpoint.event_generation,
      event_generation: projection.generation,
      tail_event_count: tailEventCount,
      tail_event_limit: CHECKPOINT_TAIL_EVENT_LIMIT,
      checkpoint_interval_events: checkpointIntervalEvents,
      checkpoint_plaintext_limit_bytes: checkpointPlaintextLimit,
    };
    if (checkpointMode !== "bounded_checkpoint") {
      return Object.freeze({
        ...common,
        reason: checkpoint == null
          ? "externally_anchored_encrypted_checkpoint_required"
          : "bounded_checkpoint_mode_required",
      });
    }
    return Object.freeze({
      ...common,
      reason: checkpointCapacityExhausted
        ? "checkpoint_capacity_exhausted"
        : (checkpoint == null
          ? "external_checkpoint_anchor_unavailable"
          : "external_checkpoint_anchor_attestation_required"),
    });
  }

  function checkpointReadiness() {
    return withLockedProjection((local) => {
      if (checkpointPortState && !checkpointCapacityExhausted) {
        try {
          assertCheckpointProjectionCapacity(local.projection);
        } catch (error) {
          if (!INSTRUMENT_LEASE_CHECKPOINT_CAPACITY_ERRORS.has(error)) throw error;
          markCheckpointCapacityExhausted(error, local.projection);
        }
      }
      return checkpointReadinessUnsafe(local.projection);
    });
  }

  function checkpointNow() {
    if (!checkpointPortState) {
      throw new Error("checkpointNow requires an external checkpoint anchor port");
    }
    return withLockedProjection((local) => {
      try {
        publishCheckpoint(local.projection);
      } catch (error) {
        if (!INSTRUMENT_LEASE_CHECKPOINT_CAPACITY_ERRORS.has(error)) throw error;
        markCheckpointCapacityExhausted(error, local.projection);
        throw error;
      }
      return checkpointReadinessUnsafe(local.projection);
    });
  }

  function close() {
    if (closed) return;
    closed = true;
    storeKey.fill(0);
    if (checkpointKey) checkpointKey.fill(0);
  }

  const store = Object.freeze({
    acquireLease,
    appendJournal,
    appendOutbox,
    beginRestoration: (request) => mutateLease("lease_restoring", request),
    claimContainmentAction,
    claimRecoveryLaunch,
    checkpointNow,
    checkpointReadiness,
    close,
    claimExecutionTransaction,
    commitExecutionTransactionVault,
    completeContainmentAction,
    completeRecoveryLaunch,
    commitDispatch,
    deliverOutbox,
    fenceLease: (request) => mutateLease("lease_fenced", request),
    registerSafetySupervisor,
    readExecutionTransaction,
    readLease,
    releaseLease: (request) => mutateLease("lease_released", request),
    renewLease: (request) => mutateLease("lease_renewed", request),
    snapshot,
  });
  DURABLE_INSTRUMENT_LEASE_STORES.add(store);
  DURABLE_INSTRUMENT_LEASE_STORE_STATE.set(store, Object.freeze({
    consumeProviderEffectPermit,
    redeemProviderDispatchCredential,
    runtimeId: metadata.runtime_id,
    sessionNucleusHash: metadata.session_nucleus_hash,
  }));
  return store;
}

function assertDurableInstrumentLeaseStore(input) {
  if (!input || !DURABLE_INSTRUMENT_LEASE_STORES.has(input)) {
    throw new Error("instrument lease store must be created by Bob's durable store factory");
  }
  return input;
}

function assertDurableProviderDispatchCredential(input) {
  if (!input
      || !DURABLE_PROVIDER_DISPATCH_CREDENTIALS.has(input)
      || !DURABLE_PROVIDER_DISPATCH_CREDENTIAL_STATE.has(input)) {
    throw new Error("provider dispatch credential must be issued by a live Bob durable store");
  }
  return input;
}

function createDurablePhysicalExecutionTransactionPort(storeInput) {
  const store = assertDurableInstrumentLeaseStore(storeInput);
  let port;
  port = Object.freeze({
    claim(binding) {
      if (arguments.length !== 1) {
        throw new Error("physical execution transaction port claim requires one binding");
      }
      return store.claimExecutionTransaction(binding);
    },
    commitVault(input) {
      if (arguments.length !== 1) {
        throw new Error("physical execution transaction port commitVault requires one record");
      }
      return store.commitExecutionTransactionVault(input);
    },
    read(input) {
      if (arguments.length !== 1) {
        throw new Error("physical execution transaction port read requires one query");
      }
      return store.readExecutionTransaction(input);
    },
  });
  DURABLE_PHYSICAL_EXECUTION_TRANSACTION_PORTS.add(port);
  DURABLE_PHYSICAL_EXECUTION_TRANSACTION_PORT_STATE.set(port, Object.freeze({ store }));
  return port;
}

function assertDurablePhysicalExecutionTransactionPort(input) {
  if (!input || !DURABLE_PHYSICAL_EXECUTION_TRANSACTION_PORTS.has(input)
      || !DURABLE_PHYSICAL_EXECUTION_TRANSACTION_PORT_STATE.has(input)) {
    throw new Error("physical execution transaction port must attenuate a Bob durable store");
  }
  return input;
}

function createDurableInstrumentProviderDispatchPort(storeInput, enrollmentInput) {
  const store = assertDurableInstrumentLeaseStore(storeInput);
  const storeState = DURABLE_INSTRUMENT_LEASE_STORE_STATE.get(store);
  if (!storeState) throw new Error("durable store provider dispatch state is unavailable");
  const enrollment = normalizeProviderDispatchPortEnrollment(
    enrollmentInput,
    "instrument_provider_dispatch_port_enrollment",
  );
  let port;
  port = Object.freeze({
    consumeEffect(permit, callback) {
      if (arguments.length !== 2) {
        throw new Error("provider dispatch port consumeEffect requires a permit and callback");
      }
      return storeState.consumeProviderEffectPermit(permit, callback, port);
    },
    redeem(credential, expectedInput) {
      if (arguments.length !== 2) {
        throw new Error("provider dispatch port redeem requires a credential and expected state");
      }
      assertDurableProviderDispatchCredential(credential);
      const expected = normalizeProviderDispatchExpectedState(
        expectedInput,
        "provider_dispatch_expected_state",
      );
      return storeState.redeemProviderDispatchCredential(
        credential,
        enrollment,
        expected,
        port,
      );
    },
  });
  DURABLE_PROVIDER_DISPATCH_PORTS.add(port);
  DURABLE_PROVIDER_DISPATCH_PORT_STATE.set(port, Object.freeze({ store, enrollment }));
  return port;
}

function assertDurableInstrumentProviderDispatchPort(input) {
  if (!input
      || !DURABLE_PROVIDER_DISPATCH_PORTS.has(input)
      || !DURABLE_PROVIDER_DISPATCH_PORT_STATE.has(input)) {
    throw new Error("provider dispatch port must be enrolled by a Bob durable store");
  }
  return input;
}

function callSynchronousPortHook(hook, context, label) {
  if (hook == null) return;
  const result = hook(Object.freeze(cloneJson(context)));
  if (result !== undefined) {
    throw new Error(`${label} must return undefined`);
  }
}

function brokerSnapshotProjection(value) {
  if (arrayIsArray(value)) {
    return Object.freeze(arrayMap(value, (entry) => brokerSnapshotProjection(entry)));
  }
  if (!isPlainObject(value)) return value;
  const descriptors = objectGetOwnPropertyDescriptors(value);
  const projected = {};
  for (const field of reflectOwnKeys(descriptors)) {
    if (field === "fencing_token") continue;
    projected[field] = brokerSnapshotProjection(descriptors[field].value);
  }
  return Object.freeze(projected);
}

function createDurableInstrumentLeaseBrokerPort(storeInput, options = {}) {
  const store = assertDurableInstrumentLeaseStore(storeInput);
  assertClosedObject(options, "instrument_lease_broker_port_options", [], ["before_call", "after_call"]);
  for (const field of ["before_call", "after_call"]) {
    if (options[field] != null && typeof options[field] !== "function") {
      throw new Error(`instrument_lease_broker_port_options.${field} must be a function`);
    }
  }
  const methods = {};
  for (const method of ["appendJournal", "commitDispatch", "snapshot"]) {
    methods[method] = (...arguments_) => {
      if (arguments_.length !== (method === "snapshot" ? 0 : 1)) {
        throw new Error(`instrument lease broker port ${method} received an invalid argument count`);
      }
      callSynchronousPortHook(options.before_call, {
        version: STORE_VERSION,
        method,
      }, "instrument lease broker port before_call");
      const rawResult = store[method](...arguments_);
      const result = method === "snapshot" ? brokerSnapshotProjection(rawResult) : rawResult;
      callSynchronousPortHook(options.after_call, {
        version: STORE_VERSION,
        method,
      }, "instrument lease broker port after_call");
      return result;
    };
  }
  const port = Object.freeze(methods);
  DURABLE_INSTRUMENT_LEASE_BROKER_PORTS.add(port);
  DURABLE_INSTRUMENT_LEASE_BROKER_PORT_STATE.set(port, Object.freeze({ store }));
  return port;
}

function assertDurableInstrumentLeaseBrokerPort(input) {
  if (!input || !DURABLE_INSTRUMENT_LEASE_BROKER_PORTS.has(input)
      || !DURABLE_INSTRUMENT_LEASE_BROKER_PORT_STATE.has(input)) {
    throw new Error("instrument lease broker port must attenuate a Bob durable store");
  }
  return input;
}

// Private-owner readback used by physical campaign closure.  The caller cannot
// supply an effect count or a digest: both are recomputed from the live Bob
// store behind the branded broker port.  A quarantined lease remains blocking;
// only the fully released state proves zero active effects for lifecycle
// handoff.
function readDurableInstrumentLeaseBrokerClosureState(portInput) {
  const port = assertDurableInstrumentLeaseBrokerPort(portInput);
  const binding = DURABLE_INSTRUMENT_LEASE_BROKER_PORT_STATE.get(port);
  const storeState = DURABLE_INSTRUMENT_LEASE_STORE_STATE.get(binding.store);
  if (!storeState) throw new Error("instrument lease broker owner state is unavailable");
  const snapshot = binding.store.snapshot();
  const activeAttempts = new Set();
  for (const lease of snapshot.leases) {
    if (lease.state !== "released") activeAttempts.add(lease.attempt_ref);
  }
  const terminalJournalStates = new Set([
    "reconciled_no_effect",
    "restored",
    "irreversible_authorized",
  ]);
  for (const journal of snapshot.journal_heads) {
    if (!terminalJournalStates.has(journal.state)) activeAttempts.add(journal.attempt_ref);
  }
  let nonterminalTransactionCount = 0;
  for (const transaction of snapshot.execution_transactions) {
    if (transaction.ledger_state !== "TERMINAL") {
      nonterminalTransactionCount += 1;
      activeAttempts.add(transaction.attempt_ref);
    }
  }
  let pendingOutboxCount = 0;
  for (const entry of snapshot.outbox_entries) {
    const delivery = arrayFind(snapshot.outbox_delivery_bindings, (candidate) => (
      candidate.outbox_entry_digest === entry.outbox_entry_digest
    ));
    const acknowledgement = arrayFind(snapshot.acknowledgements, (candidate) => (
      candidate.outbox_entry_digest === entry.outbox_entry_digest
    ));
    if (!delivery || !acknowledgement
        || delivery.outbox_entry_ref !== entry.outbox_entry_ref
        || acknowledgement.outbox_entry_ref !== entry.outbox_entry_ref
        || acknowledgement.recipient_principal_id !== delivery.recipient_principal_id) {
      pendingOutboxCount += 1;
      activeAttempts.add(entry.attempt_ref);
    }
  }
  const snapshotDigest = canonicalDigest({
    domain: "hacker-bob/instrument-lease-broker-closure-snapshot/v1",
    runtime_id: storeState.runtimeId,
    session_nucleus_hash: storeState.sessionNucleusHash,
    snapshot,
  });
  const basis = {
    version: STORE_VERSION,
    runtime_id: storeState.runtimeId,
    session_nucleus_hash: storeState.sessionNucleusHash,
    generation: snapshot.generation,
    head_event_digest: snapshot.head_event_digest,
    lease_count: snapshot.leases.length,
    journal_head_count: snapshot.journal_heads.length,
    execution_transaction_count: snapshot.execution_transactions.length,
    nonterminal_execution_transaction_count: nonterminalTransactionCount,
    pending_outbox_count: pendingOutboxCount,
    active_effect_count: activeAttempts.size,
    snapshot_digest: snapshotDigest,
  };
  return Object.freeze({
    ...basis,
    owner_state_digest: canonicalDigest({
      domain: "hacker-bob/instrument-lease-broker-closure-owner-state/v1",
      ...basis,
    }),
  });
}

module.exports = {
  INSTRUMENT_LEASE_CHECKPOINT_FILE_MAX_BYTES: MAX_CHECKPOINT_FILE_BYTES,
  INSTRUMENT_LEASE_CHECKPOINT_PLAINTEXT_MAX_BYTES: MAX_CHECKPOINT_PLAINTEXT_BYTES,
  INSTRUMENT_LEASE_CHECKPOINT_PROJECTION_SCHEMA_VERSION:
    CHECKPOINT_PROJECTION_SCHEMA_VERSION,
  INSTRUMENT_LEASE_CHECKPOINT_TAIL_EVENT_LIMIT: CHECKPOINT_TAIL_EVENT_LIMIT,
  INSTRUMENT_LEASE_STORE_VERSION: STORE_VERSION,
  INSTRUMENT_LEASE_SAFETY_EVENT_RESERVE: SAFETY_EVENT_RESERVE,
  MAX_INSTRUMENT_LEASE_EVENTS: MAX_EVENTS,
  assertDurablePhysicalExecutionTransactionPort,
  assertDurableInstrumentLeaseBrokerPort,
  assertDurableInstrumentLeaseStore,
  assertDurableInstrumentProviderDispatchPort,
  assertDurableProviderDispatchCredential,
  assertInstrumentLeaseCheckpointAnchorPort,
  createDurableInstrumentLeaseBrokerPort,
  createDurableInstrumentLeaseStore,
  createDurableInstrumentProviderDispatchPort,
  createDurablePhysicalExecutionTransactionPort,
  createIdempotentOutboxRecipientPort,
  createInstrumentLeaseCheckpointAnchorPort,
  readDurableInstrumentLeaseBrokerClosureState,
};
