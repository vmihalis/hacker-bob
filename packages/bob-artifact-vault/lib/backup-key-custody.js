"use strict";

const crypto = require("node:crypto");
const { types: utilTypes } = require("node:util");
const {
  ARTIFACT_VAULT_SCHEMA_VERSION,
  PUBLIC_ARTIFACT_HANDLE_RE,
  assertCanonicalTimestamp,
  assertOpaqueRef,
} = require("./contracts.js");

const BACKUP_REF_RE = /^backup:v1:[A-Za-z0-9_-]{43}$/;
const BACKUP_SEAL_REF_RE = /^backup-seal:v1:[A-Za-z0-9_-]{43}$/;
const CUSTODY_ID_RE = /^backup-custody:v1:[A-Za-z0-9_-]{43}$/;
const EFFECT_REF_RE = /^backup-effect:v1:[A-Za-z0-9_-]{43}$/;
const RESTORE_REF_RE = /^backup-restore:v1:[A-Za-z0-9_-]{43}$/;
const SHA256_RE = /^[a-f0-9]{64}$/;
const VAULT_ID_RE = /^vault:v1:[A-Za-z0-9_-]{43}$/;
const VAULT_SLOT_RE = /^vault-slot:v1:[A-Za-z0-9_-]{43}$/;
const FORMAT_RE = /^[a-z][a-z0-9._-]{0,127}$/;
const MAX_ARCHIVE_BYTES = 384 * 1024 * 1024;
const MAX_SEALED_BASE64_LENGTH = Math.ceil(MAX_ARCHIVE_BYTES / 3) * 4 + 4096;
const MAX_ARTIFACTS = 4096;
const MAX_MEMBER_ARCHIVES_PER_ARTIFACT = 64;
const REVOCATION_POLICY = "whole_archive_key_on_member_erasure";

const CUSTODY_PORTS = new WeakSet();
const CUSTODY_PORT_STATE = new WeakMap();
const RETIREMENT_EVIDENCE = new WeakSet();
const RESTORE_FENCE_EVIDENCE = new WeakSet();

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

function randomRef(prefix) {
  return `${prefix}${crypto.randomBytes(32).toString("base64url")}`;
}

function isProxy(value) {
  return value != null && (typeof value === "object" || typeof value === "function")
    && utilTypes.isProxy(value);
}

function assertClosedDataObject(value, label, fields) {
  if (value == null || typeof value !== "object" || Array.isArray(value) || isProxy(value)) {
    throw new Error(`${label} must be a non-Proxy object`);
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new Error(`${label} must be a plain data object`);
  }
  const keys = Reflect.ownKeys(value);
  if (keys.some((key) => typeof key !== "string")
    || canonicalJson([...keys].sort()) !== canonicalJson([...fields].sort())) {
    throw new Error(`${label} must contain exactly: ${fields.join(", ")}`);
  }
  for (const field of fields) {
    const descriptor = Object.getOwnPropertyDescriptor(value, field);
    if (!descriptor || !("value" in descriptor) || descriptor.get || descriptor.set) {
      throw new Error(`${label}.${field} must be an own data property`);
    }
  }
  return value;
}

function assertDenseDataArray(value, label, maximum) {
  if (!Array.isArray(value) || isProxy(value) || value.length > maximum) {
    throw new Error(`${label} must be a bounded non-Proxy array`);
  }
  const keys = Reflect.ownKeys(value);
  const expected = Array.from({ length: value.length }, (_, index) => String(index));
  expected.push("length");
  if (keys.some((key) => typeof key !== "string")
    || canonicalJson([...keys].sort()) !== canonicalJson(expected.sort())) {
    throw new Error(`${label} must be a dense data-only array`);
  }
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (!descriptor || !("value" in descriptor) || descriptor.get || descriptor.set) {
      throw new Error(`${label}[${index}] must be an own data property`);
    }
  }
  return value;
}

function assertCallable(value, label) {
  if (typeof value !== "function" || isProxy(value) || utilTypes.isAsyncFunction(value)) {
    throw new Error(`${label} must be a synchronous non-Proxy function`);
  }
  return value;
}

function ownDataBuffer(value, field) {
  if (value == null || !["object", "function"].includes(typeof value) || isProxy(value)) return null;
  let descriptor;
  try {
    descriptor = Object.getOwnPropertyDescriptor(value, field);
  } catch {
    return null;
  }
  if (!descriptor || !("value" in descriptor) || descriptor.get || descriptor.set
    || isProxy(descriptor.value) || !Buffer.isBuffer(descriptor.value)) return null;
  return descriptor.value;
}

function wipeRejectedOpenResponse(value) {
  const plaintext = ownDataBuffer(value, "plaintext_archive");
  if (plaintext) plaintext.fill(0);
}

function invokeCallback(callback, args, label, { cleanup_rejected_output: cleanup = null } = {}) {
  let output;
  try {
    output = Reflect.apply(callback, undefined, args);
  } catch {
    return Object.freeze({ failed: true, output: null });
  }
  const rejectNonSynchronousOutput = () => {
    if (cleanup) {
      try { cleanup(output); } catch {}
    }
    throw new Error(`${label} must return synchronously without a Proxy, Promise, or thenable`);
  };
  if (isProxy(output) || output instanceof Promise) {
    rejectNonSynchronousOutput();
  }
  if (output != null && ["object", "function"].includes(typeof output)) {
    // Inspect the entire prototype chain without invoking a hostile getter.
    // Checking only an own descriptor lets Object.prototype/Array.prototype
    // pollution turn an otherwise closed response into an inherited thenable.
    let candidate = output;
    let unsafePrototypeChain = false;
    try {
      while (candidate != null) {
        if (isProxy(candidate)) {
          unsafePrototypeChain = true;
          break;
        }
        const descriptor = Object.getOwnPropertyDescriptor(candidate, "then");
        if (descriptor
          && (typeof descriptor.value === "function" || descriptor.get || descriptor.set)) {
          unsafePrototypeChain = true;
          break;
        }
        candidate = Object.getPrototypeOf(candidate);
      }
    } catch {
      unsafePrototypeChain = true;
    }
    if (unsafePrototypeChain) rejectNonSynchronousOutput();
  }
  return Object.freeze({ failed: false, output });
}

function assertDigest(value, label) {
  if (typeof value !== "string" || !SHA256_RE.test(value)) {
    throw new Error(`${label} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function assertVaultBindings(input, label) {
  if (typeof input.vault_id !== "string" || !VAULT_ID_RE.test(input.vault_id)) {
    throw new Error(`${label}.vault_id is invalid`);
  }
  if (typeof input.vault_slot !== "string" || !VAULT_SLOT_RE.test(input.vault_slot)) {
    throw new Error(`${label}.vault_slot is invalid`);
  }
  assertDigest(input.session_nucleus_hash, `${label}.session_nucleus_hash`);
}

function normalizeCurrentState(input, expected, label) {
  assertClosedDataObject(input, label, [
    "version",
    "custody_id",
    "custody_epoch",
    "status",
    "vault_id",
    "vault_slot",
    "session_nucleus_hash",
    "production_ready",
    "hil_verified",
    "revocation_policy",
    "backup_media_erasure_attested",
  ]);
  if (input.version !== ARTIFACT_VAULT_SCHEMA_VERSION
    || typeof input.custody_id !== "string" || !CUSTODY_ID_RE.test(input.custody_id)
    || !Number.isSafeInteger(input.custody_epoch) || input.custody_epoch < 1
    || !["active", "revoked"].includes(input.status)) {
    throw new Error(`${label} has an invalid custody identity, epoch, or status`);
  }
  assertVaultBindings(input, label);
  if (input.production_ready !== false || input.hil_verified !== false
    || input.revocation_policy !== REVOCATION_POLICY
    || input.backup_media_erasure_attested !== false) {
    throw new Error(`${label} must remain explicitly non-production and cannot attest media erasure`);
  }
  if (expected) {
    for (const field of [
      "custody_id",
      "custody_epoch",
      "vault_id",
      "vault_slot",
      "session_nucleus_hash",
    ]) {
      if (input[field] !== expected[field]) {
        throw new Error(`${label}.${field} drifted from the enrolled custody binding`);
      }
    }
  }
  return Object.freeze({
    version: ARTIFACT_VAULT_SCHEMA_VERSION,
    custody_id: input.custody_id,
    custody_epoch: input.custody_epoch,
    status: input.status,
    vault_id: input.vault_id,
    vault_slot: input.vault_slot,
    session_nucleus_hash: input.session_nucleus_hash,
    production_ready: false,
    hil_verified: false,
    revocation_policy: REVOCATION_POLICY,
    backup_media_erasure_attested: false,
  });
}

function currentQuery(binding) {
  return Object.freeze({
    version: ARTIFACT_VAULT_SCHEMA_VERSION,
    custody_id: binding.custody_id,
    custody_epoch: binding.custody_epoch,
    vault_id: binding.vault_id,
    vault_slot: binding.vault_slot,
    session_nucleus_hash: binding.session_nucleus_hash,
  });
}

function resolveCurrent(state, label) {
  const invocation = invokeCallback(
    state.callbacks.resolve_current_custody,
    [currentQuery(state.binding)],
    `${label} current custody resolver`,
  );
  if (invocation.failed) throw new Error(`${label} current custody resolver is unavailable`);
  const current = normalizeCurrentState(
    invocation.output,
    state.binding,
    `${label} current custody state`,
  );
  if (current.status !== "active") throw new Error(`${label} custody enrollment is revoked`);
  return current;
}

function assertOperatorBackupKeyCustodyPort(port, expected = null) {
  if (port == null || typeof port !== "object" || isProxy(port)
    || !CUSTODY_PORTS.has(port) || !CUSTODY_PORT_STATE.has(port)) {
    throw new Error("backupKeyCustody must be a private branded operator-only custody port");
  }
  const state = CUSTODY_PORT_STATE.get(port);
  const fields = [
    "version",
    "custody_id",
    "custody_epoch",
    "custody_binding_digest",
    "vault_id",
    "vault_slot",
    "session_nucleus_hash",
    "production_ready",
    "hil_verified",
    "revocation_policy",
    "backup_media_erasure_attested",
  ];
  assertClosedDataObject(port, "backupKeyCustody", fields);
  if (!Object.isFrozen(port)
    || port.version !== ARTIFACT_VAULT_SCHEMA_VERSION
    || port.custody_id !== state.binding.custody_id
    || port.custody_epoch !== state.binding.custody_epoch
    || port.custody_binding_digest !== state.binding_digest
    || port.vault_id !== state.binding.vault_id
    || port.vault_slot !== state.binding.vault_slot
    || port.session_nucleus_hash !== state.binding.session_nucleus_hash
    || port.production_ready !== false || port.hil_verified !== false
    || port.revocation_policy !== REVOCATION_POLICY
    || port.backup_media_erasure_attested !== false) {
    throw new Error("backupKeyCustody private capability drifted from its enrollment");
  }
  if (expected) {
    for (const field of ["vault_id", "vault_slot", "session_nucleus_hash"]) {
      if (port[field] !== expected[field]) {
        throw new Error(`backupKeyCustody.${field} belongs to another vault`);
      }
    }
  }
  resolveCurrent(state, "backupKeyCustody");
  return state;
}

function createOperatorBackupKeyCustodyPort(input) {
  const fields = [
    "version",
    "custody_id",
    "custody_epoch",
    "vault_id",
    "vault_slot",
    "session_nucleus_hash",
    "resolve_current_custody",
    "seal_archive",
    "read_archive_state",
    "open_archive",
    "acquire_restore_fence",
    "read_restore_fence",
    "release_restore_fence",
    "retire_artifact",
    "read_artifact_retirement",
  ];
  assertClosedDataObject(input, "operator_backup_key_custody", fields);
  if (input.version !== ARTIFACT_VAULT_SCHEMA_VERSION
    || typeof input.custody_id !== "string" || !CUSTODY_ID_RE.test(input.custody_id)
    || !Number.isSafeInteger(input.custody_epoch) || input.custody_epoch < 1) {
    throw new Error("operator_backup_key_custody identity or epoch is invalid");
  }
  assertVaultBindings(input, "operator_backup_key_custody");
  const callbacks = Object.freeze({
    resolve_current_custody: assertCallable(
      input.resolve_current_custody,
      "operator_backup_key_custody.resolve_current_custody",
    ),
    seal_archive: assertCallable(input.seal_archive, "operator_backup_key_custody.seal_archive"),
    read_archive_state: assertCallable(
      input.read_archive_state,
      "operator_backup_key_custody.read_archive_state",
    ),
    open_archive: assertCallable(input.open_archive, "operator_backup_key_custody.open_archive"),
    acquire_restore_fence: assertCallable(
      input.acquire_restore_fence,
      "operator_backup_key_custody.acquire_restore_fence",
    ),
    read_restore_fence: assertCallable(
      input.read_restore_fence,
      "operator_backup_key_custody.read_restore_fence",
    ),
    release_restore_fence: assertCallable(
      input.release_restore_fence,
      "operator_backup_key_custody.release_restore_fence",
    ),
    retire_artifact: assertCallable(
      input.retire_artifact,
      "operator_backup_key_custody.retire_artifact",
    ),
    read_artifact_retirement: assertCallable(
      input.read_artifact_retirement,
      "operator_backup_key_custody.read_artifact_retirement",
    ),
  });
  const binding = Object.freeze({
    custody_id: input.custody_id,
    custody_epoch: input.custody_epoch,
    vault_id: input.vault_id,
    vault_slot: input.vault_slot,
    session_nucleus_hash: input.session_nucleus_hash,
  });
  const currentInvocation = invokeCallback(
    callbacks.resolve_current_custody,
    [currentQuery(binding)],
    "operator_backup_key_custody current custody resolver",
  );
  if (currentInvocation.failed) {
    throw new Error("operator_backup_key_custody current custody resolver is unavailable");
  }
  const current = normalizeCurrentState(
    currentInvocation.output,
    binding,
    "operator_backup_key_custody current custody state",
  );
  if (current.status !== "active") throw new Error("operator backup-key custody is revoked");
  const bindingDigest = sha256(canonicalJson({
    domain: "hacker-bob/operator-backup-key-custody/v1",
    ...binding,
    production_ready: false,
    hil_verified: false,
    revocation_policy: REVOCATION_POLICY,
    backup_media_erasure_attested: false,
  }));
  const port = Object.freeze({
    version: ARTIFACT_VAULT_SCHEMA_VERSION,
    custody_id: binding.custody_id,
    custody_epoch: binding.custody_epoch,
    custody_binding_digest: bindingDigest,
    vault_id: binding.vault_id,
    vault_slot: binding.vault_slot,
    session_nucleus_hash: binding.session_nucleus_hash,
    production_ready: false,
    hil_verified: false,
    revocation_policy: REVOCATION_POLICY,
    backup_media_erasure_attested: false,
  });
  const state = Object.freeze({ binding, binding_digest: bindingDigest, callbacks });
  CUSTODY_PORTS.add(port);
  CUSTODY_PORT_STATE.set(port, state);
  return port;
}

function normalizeArtifactInventory(input, label = "artifact_inventory") {
  assertDenseDataArray(input, label, MAX_ARTIFACTS);
  const output = input.map((entry, index) => {
    assertClosedDataObject(entry, `${label}[${index}]`, ["artifact_handle", "record_digest"]);
    if (typeof entry.artifact_handle !== "string"
      || !PUBLIC_ARTIFACT_HANDLE_RE.test(entry.artifact_handle)) {
      throw new Error(`${label}[${index}].artifact_handle is invalid`);
    }
    assertDigest(entry.record_digest, `${label}[${index}].record_digest`);
    return Object.freeze({
      artifact_handle: entry.artifact_handle,
      record_digest: entry.record_digest,
    });
  }).sort((left, right) => left.artifact_handle.localeCompare(right.artifact_handle));
  if (new Set(output.map((entry) => entry.artifact_handle)).size !== output.length) {
    throw new Error(`${label} contains duplicate artifact handles`);
  }
  return Object.freeze(output);
}

function normalizeArchiveState(input, expected, label = "external archive custody state") {
  assertClosedDataObject(input, label, [
    "version",
    "status",
    "custody_id",
    "custody_epoch",
    "vault_id",
    "vault_slot",
    "session_nucleus_hash",
    "backup_ref",
    "backup_digest",
    "artifact_inventory_digest",
    "seal_effect_ref",
    "seal_ref",
    "custody_format",
    "sealed_archive",
    "sealed_archive_digest",
    "revocation_effect_ref",
    "revoked_at",
  ]);
  if (input.version !== ARTIFACT_VAULT_SCHEMA_VERSION
    || !["active", "revoked"].includes(input.status)
    || typeof input.custody_id !== "string" || !CUSTODY_ID_RE.test(input.custody_id)
    || !Number.isSafeInteger(input.custody_epoch) || input.custody_epoch < 1
    || typeof input.backup_ref !== "string" || !BACKUP_REF_RE.test(input.backup_ref)
    || typeof input.seal_effect_ref !== "string" || !EFFECT_REF_RE.test(input.seal_effect_ref)
    || typeof input.seal_ref !== "string" || !BACKUP_SEAL_REF_RE.test(input.seal_ref)
    || typeof input.custody_format !== "string" || !FORMAT_RE.test(input.custody_format)) {
    throw new Error(`${label} has an invalid identity, status, or format`);
  }
  assertVaultBindings(input, label);
  assertDigest(input.backup_digest, `${label}.backup_digest`);
  assertDigest(input.artifact_inventory_digest, `${label}.artifact_inventory_digest`);
  assertDigest(input.sealed_archive_digest, `${label}.sealed_archive_digest`);
  if (typeof input.sealed_archive !== "string"
    || input.sealed_archive.length < 1
    || input.sealed_archive.length > MAX_SEALED_BASE64_LENGTH) {
    throw new Error(`${label}.sealed_archive exceeds its canonical bound`);
  }
  const sealed = Buffer.from(input.sealed_archive, "base64");
  try {
    if (sealed.length < 1 || sealed.toString("base64") !== input.sealed_archive
      || sha256(sealed) !== input.sealed_archive_digest) {
      throw new Error(`${label}.sealed_archive is not canonical or does not match its digest`);
    }
  } finally {
    sealed.fill(0);
  }
  if (input.status === "active") {
    if (input.revocation_effect_ref !== null || input.revoked_at !== null) {
      throw new Error(`${label} active archive has revocation fields`);
    }
  } else if (typeof input.revocation_effect_ref !== "string"
    || !EFFECT_REF_RE.test(input.revocation_effect_ref)) {
    throw new Error(`${label}.revocation_effect_ref is invalid`);
  } else {
    assertCanonicalTimestamp(input.revoked_at, `${label}.revoked_at`);
  }
  if (expected) {
    for (const field of [
      "custody_id",
      "custody_epoch",
      "vault_id",
      "vault_slot",
      "session_nucleus_hash",
      "backup_ref",
      "backup_digest",
      "artifact_inventory_digest",
      "seal_effect_ref",
    ]) {
      if (Object.prototype.hasOwnProperty.call(expected, field)
        && input[field] !== expected[field]) {
        throw new Error(`${label}.${field} binding mismatch`);
      }
    }
  }
  return Object.freeze({
    version: ARTIFACT_VAULT_SCHEMA_VERSION,
    status: input.status,
    custody_id: input.custody_id,
    custody_epoch: input.custody_epoch,
    vault_id: input.vault_id,
    vault_slot: input.vault_slot,
    session_nucleus_hash: input.session_nucleus_hash,
    backup_ref: input.backup_ref,
    backup_digest: input.backup_digest,
    artifact_inventory_digest: input.artifact_inventory_digest,
    seal_effect_ref: input.seal_effect_ref,
    seal_ref: input.seal_ref,
    custody_format: input.custody_format,
    sealed_archive: input.sealed_archive,
    sealed_archive_digest: input.sealed_archive_digest,
    revocation_effect_ref: input.revocation_effect_ref,
    revoked_at: input.revoked_at,
  });
}

function archiveReadRequest(binding, expected) {
  return Object.freeze({
    version: ARTIFACT_VAULT_SCHEMA_VERSION,
    custody_id: binding.custody_id,
    custody_epoch: binding.custody_epoch,
    vault_id: binding.vault_id,
    vault_slot: binding.vault_slot,
    session_nucleus_hash: binding.session_nucleus_hash,
    backup_ref: expected.backup_ref,
    backup_digest: expected.backup_digest,
    artifact_inventory_digest: expected.artifact_inventory_digest,
    seal_effect_ref: expected.seal_effect_ref,
  });
}

function readArchiveState(state, expected, label) {
  const invocation = invokeCallback(
    state.callbacks.read_archive_state,
    [archiveReadRequest(state.binding, expected)],
    `${label} read_archive_state`,
  );
  if (invocation.failed) throw new Error(`${label} archive-state readback is unavailable`);
  if (invocation.output === null) return null;
  return normalizeArchiveState(invocation.output, { ...state.binding, ...expected }, `${label} readback`);
}

function readBackupArchiveState(port, expected) {
  const state = assertOperatorBackupKeyCustodyPort(port);
  resolveCurrent(state, "backup archive state inspection");
  assertClosedDataObject(expected, "backup archive state inspection request", [
    "backup_ref",
    "backup_digest",
    "artifact_inventory_digest",
    "seal_effect_ref",
  ]);
  return readArchiveState(
    state,
    expected,
    "backup archive state inspection",
  );
}

function immutableArchiveStateMatches(left, right) {
  return [
    "custody_id",
    "custody_epoch",
    "vault_id",
    "vault_slot",
    "session_nucleus_hash",
    "backup_ref",
    "backup_digest",
    "artifact_inventory_digest",
    "seal_effect_ref",
    "seal_ref",
    "custody_format",
    "sealed_archive",
    "sealed_archive_digest",
  ].every((field) => left[field] === right[field]);
}

function artifactRetirementReadRequest(binding, artifactHandle) {
  return Object.freeze({
    version: ARTIFACT_VAULT_SCHEMA_VERSION,
    custody_id: binding.custody_id,
    custody_epoch: binding.custody_epoch,
    vault_id: binding.vault_id,
    vault_slot: binding.vault_slot,
    session_nucleus_hash: binding.session_nucleus_hash,
    artifact_handle: artifactHandle,
  });
}

function normalizeRevokedArchiveSummary(input, expected, label) {
  assertClosedDataObject(input, label, [
    "backup_ref",
    "backup_digest",
    "artifact_inventory_digest",
    "seal_effect_ref",
    "seal_ref",
    "sealed_archive_digest",
    "revocation_effect_ref",
    "revoked_at",
    "revocation_receipt",
  ]);
  if (typeof input.backup_ref !== "string" || !BACKUP_REF_RE.test(input.backup_ref)
    || typeof input.seal_effect_ref !== "string" || !EFFECT_REF_RE.test(input.seal_effect_ref)
    || typeof input.seal_ref !== "string" || !BACKUP_SEAL_REF_RE.test(input.seal_ref)
    || typeof input.revocation_effect_ref !== "string" || !EFFECT_REF_RE.test(input.revocation_effect_ref)) {
    throw new Error(`${label} identity is invalid`);
  }
  for (const field of [
    "backup_digest",
    "artifact_inventory_digest",
    "sealed_archive_digest",
    "revocation_receipt",
  ]) assertDigest(input[field], `${label}.${field}`);
  assertCanonicalTimestamp(input.revoked_at, `${label}.revoked_at`);
  return Object.freeze({
    backup_ref: input.backup_ref,
    backup_digest: input.backup_digest,
    artifact_inventory_digest: input.artifact_inventory_digest,
    seal_effect_ref: input.seal_effect_ref,
    seal_ref: input.seal_ref,
    sealed_archive_digest: input.sealed_archive_digest,
    revocation_effect_ref: input.revocation_effect_ref,
    revoked_at: input.revoked_at,
    revocation_receipt: input.revocation_receipt,
  });
}

function normalizeMemberArchiveRegistry(input, label = "member_archive_registry") {
  assertDenseDataArray(input, label, MAX_MEMBER_ARCHIVES_PER_ARTIFACT);
  const output = input.map((entry, index) => {
    const entryLabel = `${label}[${index}]`;
    assertClosedDataObject(entry, entryLabel, [
      "backup_ref",
      "backup_digest",
      "artifact_inventory_digest",
      "seal_effect_ref",
      "seal_ref",
      "sealed_archive_digest",
    ]);
    if (typeof entry.backup_ref !== "string" || !BACKUP_REF_RE.test(entry.backup_ref)
      || typeof entry.seal_effect_ref !== "string" || !EFFECT_REF_RE.test(entry.seal_effect_ref)
      || typeof entry.seal_ref !== "string" || !BACKUP_SEAL_REF_RE.test(entry.seal_ref)) {
      throw new Error(`${entryLabel} identity is invalid`);
    }
    for (const field of ["backup_digest", "artifact_inventory_digest", "sealed_archive_digest"]) {
      assertDigest(entry[field], `${entryLabel}.${field}`);
    }
    return Object.freeze({
      backup_ref: entry.backup_ref,
      backup_digest: entry.backup_digest,
      artifact_inventory_digest: entry.artifact_inventory_digest,
      seal_effect_ref: entry.seal_effect_ref,
      seal_ref: entry.seal_ref,
      sealed_archive_digest: entry.sealed_archive_digest,
    });
  }).sort((left, right) => left.backup_ref.localeCompare(right.backup_ref));
  if (new Set(output.map((entry) => entry.backup_ref)).size !== output.length) {
    throw new Error(`${label} contains duplicate backup references`);
  }
  return Object.freeze(output);
}

function normalizeRetirementState(input, expected, label = "external artifact retirement state") {
  assertClosedDataObject(input, label, [
    "version",
    "status",
    "custody_id",
    "custody_epoch",
    "vault_id",
    "vault_slot",
    "session_nucleus_hash",
    "artifact_handle",
    "reason_ref",
    "retirement_effect_ref",
    "retired_at",
    "revocation_policy",
    "member_archive_registry_digest",
    "revoked_archives",
    "revoked_archives_digest",
    "active_archive_count",
    "retirement_receipt",
    "production_ready",
    "hil_verified",
    "backup_media_erasure_attested",
  ]);
  if (input.version !== ARTIFACT_VAULT_SCHEMA_VERSION || input.status !== "retired"
    || typeof input.custody_id !== "string" || !CUSTODY_ID_RE.test(input.custody_id)
    || !Number.isSafeInteger(input.custody_epoch) || input.custody_epoch < 1
    || typeof input.artifact_handle !== "string"
    || !PUBLIC_ARTIFACT_HANDLE_RE.test(input.artifact_handle)
    || typeof input.retirement_effect_ref !== "string"
    || !EFFECT_REF_RE.test(input.retirement_effect_ref)
    || input.revocation_policy !== REVOCATION_POLICY
    || input.active_archive_count !== 0
    || input.production_ready !== false || input.hil_verified !== false
    || input.backup_media_erasure_attested !== false) {
    throw new Error(`${label} has an invalid identity, status, policy, or assurance claim`);
  }
  assertVaultBindings(input, label);
  assertOpaqueRef(input.reason_ref, `${label}.reason_ref`);
  assertCanonicalTimestamp(input.retired_at, `${label}.retired_at`);
  assertDigest(input.revoked_archives_digest, `${label}.revoked_archives_digest`);
  assertDigest(
    input.member_archive_registry_digest,
    `${label}.member_archive_registry_digest`,
  );
  assertDigest(input.retirement_receipt, `${label}.retirement_receipt`);
  assertDenseDataArray(input.revoked_archives, `${label}.revoked_archives`, MAX_ARTIFACTS);
  const revokedArchives = input.revoked_archives.map((entry, index) => normalizeRevokedArchiveSummary(
    entry,
    input,
    `${label}.revoked_archives[${index}]`,
  )).sort((left, right) => left.backup_ref.localeCompare(right.backup_ref));
  if (new Set(revokedArchives.map((entry) => entry.backup_ref)).size !== revokedArchives.length) {
    throw new Error(`${label}.revoked_archives contains duplicate backup references`);
  }
  if (sha256(canonicalJson(revokedArchives)) !== input.revoked_archives_digest) {
    throw new Error(`${label}.revoked_archives_digest does not bind the exact archive inventory`);
  }
  if (expected) {
    for (const field of [
      "custody_id",
      "custody_epoch",
      "vault_id",
      "vault_slot",
      "session_nucleus_hash",
      "artifact_handle",
    ]) {
      if (input[field] !== expected[field]) throw new Error(`${label}.${field} binding mismatch`);
    }
    if (expected.retirement_effect_ref
      && input.retirement_effect_ref !== expected.retirement_effect_ref) {
      throw new Error(`${label}.retirement_effect_ref binding mismatch`);
    }
    if (expected.reason_ref && input.reason_ref !== expected.reason_ref) {
      throw new Error(`${label}.reason_ref binding mismatch`);
    }
    if (expected.retired_at && input.retired_at !== expected.retired_at) {
      throw new Error(`${label}.retired_at binding mismatch`);
    }
    if (expected.member_archive_registry) {
      const memberRegistry = normalizeMemberArchiveRegistry(
        expected.member_archive_registry,
        `${label} expected member archive registry`,
      );
      const memberRegistryDigest = sha256(canonicalJson(memberRegistry));
      if (input.member_archive_registry_digest !== memberRegistryDigest) {
        throw new Error(`${label}.member_archive_registry_digest binding mismatch`);
      }
      if (revokedArchives.length !== memberRegistry.length) {
        throw new Error(`${label} does not cover the exact member archive registry`);
      }
      for (let index = 0; index < memberRegistry.length; index += 1) {
        const expectedArchive = memberRegistry[index];
        const revokedArchive = revokedArchives[index];
        for (const field of [
          "backup_ref",
          "backup_digest",
          "artifact_inventory_digest",
          "seal_effect_ref",
          "seal_ref",
          "sealed_archive_digest",
        ]) {
          if (revokedArchive[field] !== expectedArchive[field]) {
            throw new Error(`${label}.revoked_archives[${index}].${field} binding mismatch`);
          }
        }
      }
    }
  }
  return Object.freeze({
    version: ARTIFACT_VAULT_SCHEMA_VERSION,
    status: "retired",
    custody_id: input.custody_id,
    custody_epoch: input.custody_epoch,
    vault_id: input.vault_id,
    vault_slot: input.vault_slot,
    session_nucleus_hash: input.session_nucleus_hash,
    artifact_handle: input.artifact_handle,
    reason_ref: input.reason_ref,
    retirement_effect_ref: input.retirement_effect_ref,
    retired_at: input.retired_at,
    revocation_policy: REVOCATION_POLICY,
    member_archive_registry_digest: input.member_archive_registry_digest,
    revoked_archives: Object.freeze(revokedArchives),
    revoked_archives_digest: input.revoked_archives_digest,
    active_archive_count: 0,
    retirement_receipt: input.retirement_receipt,
    production_ready: false,
    hil_verified: false,
    backup_media_erasure_attested: false,
  });
}

function readArtifactRetirement(state, artifactHandle, label) {
  const invocation = invokeCallback(
    state.callbacks.read_artifact_retirement,
    [artifactRetirementReadRequest(state.binding, artifactHandle)],
    `${label} read_artifact_retirement`,
  );
  if (invocation.failed) throw new Error(`${label} retirement readback is unavailable`);
  if (invocation.output === null) return null;
  return normalizeRetirementState(
    invocation.output,
    { ...state.binding, artifact_handle: artifactHandle },
    `${label} retirement readback`,
  );
}

function sealBackupArchive(port, {
  backup_ref: backupRef,
  seal_effect_ref: suppliedSealEffectRef = null,
  plaintext_archive: plaintextArchive,
  artifact_inventory: artifactInventory,
} = {}) {
  const state = assertOperatorBackupKeyCustodyPort(port);
  resolveCurrent(state, "backup archive seal");
  if (typeof backupRef !== "string" || !BACKUP_REF_RE.test(backupRef)) {
    throw new Error("backup_ref must be a random opaque backup reference");
  }
  if (isProxy(plaintextArchive) || !Buffer.isBuffer(plaintextArchive)
    || plaintextArchive.length < 1 || plaintextArchive.length > MAX_ARCHIVE_BYTES) {
    throw new Error("plaintext_archive must be a bounded non-Proxy Buffer");
  }
  const inventory = normalizeArtifactInventory(artifactInventory);
  const artifactInventoryDigest = sha256(canonicalJson(inventory));
  for (const artifact of inventory) {
    if (readArtifactRetirement(state, artifact.artifact_handle, "backup archive seal")) {
      throw new Error("backup archive contains an externally retired artifact");
    }
  }
  const backupDigest = sha256(plaintextArchive);
  const sealEffectRef = suppliedSealEffectRef == null
    ? randomRef("backup-effect:v1:")
    : suppliedSealEffectRef;
  if (typeof sealEffectRef !== "string" || !EFFECT_REF_RE.test(sealEffectRef)) {
    throw new Error("seal_effect_ref must be a random opaque backup effect reference");
  }
  const request = Object.freeze({
    version: ARTIFACT_VAULT_SCHEMA_VERSION,
    action: "seal_backup_archive",
    ...state.binding,
    backup_ref: backupRef,
    backup_digest: backupDigest,
    artifact_inventory: inventory,
    artifact_inventory_digest: artifactInventoryDigest,
    seal_effect_ref: sealEffectRef,
  });
  const expected = { ...state.binding, backup_ref: backupRef, backup_digest: backupDigest,
    artifact_inventory_digest: artifactInventoryDigest, seal_effect_ref: sealEffectRef };
  const before = readArchiveState(state, expected, "backup archive seal");
  // A caller that durably journals these identities may safely reconcile a
  // committed-but-unacknowledged seal without submitting a second effect.
  if (before) {
    if (before.status !== "active") {
      throw new Error("backup archive seal intent was already revoked");
    }
    return before;
  }
  const plaintextCopy = Buffer.from(plaintextArchive);
  let invocation;
  try {
    invocation = invokeCallback(
      state.callbacks.seal_archive,
      [request, plaintextCopy],
      "backup archive seal_archive",
    );
  } finally {
    plaintextCopy.fill(0);
  }
  let returned = null;
  let responseError = null;
  if (!invocation.failed) {
    try {
      returned = normalizeArchiveState(invocation.output, expected, "backup archive seal response");
      if (returned.status !== "active") throw new Error("new backup archive was not sealed active");
    } catch (error) {
      responseError = error;
    }
  }
  const observed = readArchiveState(state, expected, "backup archive seal");
  if (!observed || observed.status !== "active") {
    if (responseError) throw responseError;
    throw new Error("backup archive seal did not produce exact durable active readback");
  }
  if (returned && canonicalJson(returned) !== canonicalJson(observed)) {
    throw new Error("backup archive seal response conflicts with its exact readback");
  }
  for (const artifact of inventory) {
    if (readArtifactRetirement(state, artifact.artifact_handle, "backup archive seal")) {
      throw new Error("backup archive was revoked by concurrent artifact retirement");
    }
  }
  return observed;
}

function normalizeStoredBackupCustodyEnvelope(input, expected) {
  const envelope = normalizeArchiveState(input, expected, "stored external custody envelope");
  if (envelope.status !== "active"
    || envelope.revocation_effect_ref !== null || envelope.revoked_at !== null) {
    throw new Error("stored external custody envelope was not an active seal projection");
  }
  return envelope;
}

function restoreFenceReadRequest(binding, expected) {
  return Object.freeze({
    version: ARTIFACT_VAULT_SCHEMA_VERSION,
    ...binding,
    backup_ref: expected.backup_ref,
    backup_digest: expected.backup_digest,
    artifact_inventory_digest: expected.artifact_inventory_digest,
    seal_effect_ref: expected.seal_effect_ref,
    seal_ref: expected.seal_ref,
    restore_ref: expected.restore_ref,
    acquire_effect_ref: expected.acquire_effect_ref,
  });
}

function normalizeRestoreFenceState(input, expected, label) {
  assertClosedDataObject(input, label, [
    "version",
    "status",
    "custody_id",
    "custody_epoch",
    "vault_id",
    "vault_slot",
    "session_nucleus_hash",
    "backup_ref",
    "backup_digest",
    "artifact_inventory_digest",
    "seal_effect_ref",
    "seal_ref",
    "restore_ref",
    "acquire_effect_ref",
    "release_effect_ref",
    "production_ready",
    "hil_verified",
  ]);
  if (input.version !== ARTIFACT_VAULT_SCHEMA_VERSION
    || !["active", "released"].includes(input.status)
    || typeof input.backup_ref !== "string" || !BACKUP_REF_RE.test(input.backup_ref)
    || typeof input.seal_effect_ref !== "string" || !EFFECT_REF_RE.test(input.seal_effect_ref)
    || typeof input.seal_ref !== "string" || !BACKUP_SEAL_REF_RE.test(input.seal_ref)
    || typeof input.restore_ref !== "string" || !RESTORE_REF_RE.test(input.restore_ref)
    || typeof input.acquire_effect_ref !== "string" || !EFFECT_REF_RE.test(input.acquire_effect_ref)
    || input.production_ready !== false || input.hil_verified !== false) {
    throw new Error(`${label} identity, state, or assurance claim is invalid`);
  }
  assertVaultBindings(input, label);
  assertDigest(input.backup_digest, `${label}.backup_digest`);
  assertDigest(input.artifact_inventory_digest, `${label}.artifact_inventory_digest`);
  if (input.status === "active") {
    if (input.release_effect_ref !== null) throw new Error(`${label} active fence has release state`);
  } else if (typeof input.release_effect_ref !== "string"
    || !EFFECT_REF_RE.test(input.release_effect_ref)) {
    throw new Error(`${label}.release_effect_ref is invalid`);
  }
  for (const field of [
    "custody_id", "custody_epoch", "vault_id", "vault_slot", "session_nucleus_hash",
    "backup_ref", "backup_digest", "artifact_inventory_digest", "seal_effect_ref",
    "seal_ref", "restore_ref", "acquire_effect_ref",
  ]) {
    if (input[field] !== expected[field]) throw new Error(`${label}.${field} binding mismatch`);
  }
  if (expected.release_effect_ref !== undefined
    && input.release_effect_ref !== expected.release_effect_ref) {
    throw new Error(`${label}.release_effect_ref binding mismatch`);
  }
  return Object.freeze({
    version: ARTIFACT_VAULT_SCHEMA_VERSION,
    status: input.status,
    custody_id: input.custody_id,
    custody_epoch: input.custody_epoch,
    vault_id: input.vault_id,
    vault_slot: input.vault_slot,
    session_nucleus_hash: input.session_nucleus_hash,
    backup_ref: input.backup_ref,
    backup_digest: input.backup_digest,
    artifact_inventory_digest: input.artifact_inventory_digest,
    seal_effect_ref: input.seal_effect_ref,
    seal_ref: input.seal_ref,
    restore_ref: input.restore_ref,
    acquire_effect_ref: input.acquire_effect_ref,
    release_effect_ref: input.release_effect_ref,
    production_ready: false,
    hil_verified: false,
  });
}

function readRestoreFence(state, expected, label) {
  const invocation = invokeCallback(
    state.callbacks.read_restore_fence,
    [restoreFenceReadRequest(state.binding, expected)],
    `${label} read_restore_fence`,
  );
  if (invocation.failed) throw new Error(`${label} restore-fence readback is unavailable`);
  if (invocation.output === null) return null;
  return normalizeRestoreFenceState(
    invocation.output,
    { ...state.binding, ...expected },
    `${label} readback`,
  );
}

function readBackupRestoreFence(port, envelopeInput, {
  restore_ref: restoreRef,
  acquire_effect_ref: acquireEffectRef,
} = {}) {
  const state = assertOperatorBackupKeyCustodyPort(port);
  resolveCurrent(state, "backup restore fence read");
  const envelope = normalizeStoredBackupCustodyEnvelope(envelopeInput, state.binding);
  if (typeof restoreRef !== "string" || !RESTORE_REF_RE.test(restoreRef)) {
    throw new Error("restore_ref must be a random opaque backup restore reference");
  }
  if (typeof acquireEffectRef !== "string" || !EFFECT_REF_RE.test(acquireEffectRef)) {
    throw new Error("acquire_effect_ref must be a random opaque backup effect reference");
  }
  const observed = readRestoreFence(state, {
    ...state.binding,
    backup_ref: envelope.backup_ref,
    backup_digest: envelope.backup_digest,
    artifact_inventory_digest: envelope.artifact_inventory_digest,
    seal_effect_ref: envelope.seal_effect_ref,
    seal_ref: envelope.seal_ref,
    restore_ref: restoreRef,
    acquire_effect_ref: acquireEffectRef,
  }, "backup restore fence read");
  if (observed) RESTORE_FENCE_EVIDENCE.add(observed);
  return observed;
}

function acquireBackupRestoreFence(port, envelopeInput, {
  restore_ref: restoreRef,
  acquire_effect_ref: suppliedAcquireEffectRef = null,
} = {}) {
  const state = assertOperatorBackupKeyCustodyPort(port);
  resolveCurrent(state, "backup restore fence acquisition");
  const envelope = normalizeStoredBackupCustodyEnvelope(envelopeInput, state.binding);
  const archive = readArchiveState(state, envelope, "backup restore fence acquisition");
  if (!archive || !immutableArchiveStateMatches(archive, envelope)) {
    throw new Error("stored backup custody envelope is absent, replayed, or tampered");
  }
  if (archive.status !== "active") {
    throw new Error("external backup key is revoked; a restore fence cannot be acquired");
  }
  if (typeof restoreRef !== "string" || !RESTORE_REF_RE.test(restoreRef)) {
    throw new Error("restore_ref must be a random opaque backup restore reference");
  }
  const acquireEffectRef = suppliedAcquireEffectRef == null
    ? randomRef("backup-effect:v1:")
    : suppliedAcquireEffectRef;
  if (typeof acquireEffectRef !== "string" || !EFFECT_REF_RE.test(acquireEffectRef)) {
    throw new Error("acquire_effect_ref must be a random opaque backup effect reference");
  }
  const expected = {
    ...state.binding,
    backup_ref: envelope.backup_ref,
    backup_digest: envelope.backup_digest,
    artifact_inventory_digest: envelope.artifact_inventory_digest,
    seal_effect_ref: envelope.seal_effect_ref,
    seal_ref: envelope.seal_ref,
    restore_ref: restoreRef,
    acquire_effect_ref: acquireEffectRef,
  };
  const before = readRestoreFence(state, expected, "backup restore fence acquisition");
  if (before) {
    if (before.status !== "active") throw new Error("backup restore fence was already released");
    RESTORE_FENCE_EVIDENCE.add(before);
    return before;
  }
  const request = Object.freeze({
    version: ARTIFACT_VAULT_SCHEMA_VERSION,
    action: "acquire_backup_restore_fence",
    ...expected,
  });
  const invocation = invokeCallback(
    state.callbacks.acquire_restore_fence,
    [request],
    "backup restore fence acquire_restore_fence",
  );
  let returned = null;
  let responseError = null;
  if (!invocation.failed) {
    try {
      returned = normalizeRestoreFenceState(
        invocation.output,
        expected,
        "backup restore fence acquisition response",
      );
      if (returned.status !== "active") throw new Error("new backup restore fence was not active");
    } catch (error) {
      responseError = error;
    }
  }
  const observed = readRestoreFence(state, expected, "backup restore fence acquisition");
  if (!observed || observed.status !== "active") {
    if (responseError) throw responseError;
    throw new Error("backup restore fence acquisition did not produce exact durable readback");
  }
  if (returned && canonicalJson(returned) !== canonicalJson(observed)) {
    throw new Error("backup restore fence response conflicts with exact readback");
  }
  RESTORE_FENCE_EVIDENCE.add(observed);
  return observed;
}

function assertBackupRestoreFence(port, fence, envelopeInput) {
  const state = assertOperatorBackupKeyCustodyPort(port);
  if (!fence || typeof fence !== "object" || isProxy(fence)
    || !RESTORE_FENCE_EVIDENCE.has(fence)) {
    throw new Error("backup restore fence must be a private branded active result");
  }
  const envelope = normalizeStoredBackupCustodyEnvelope(envelopeInput, state.binding);
  const expected = {
    ...fence,
    ...state.binding,
    backup_ref: envelope.backup_ref,
    backup_digest: envelope.backup_digest,
    artifact_inventory_digest: envelope.artifact_inventory_digest,
    seal_effect_ref: envelope.seal_effect_ref,
    seal_ref: envelope.seal_ref,
  };
  const observed = readRestoreFence(state, expected, "backup restore fence assertion");
  if (!observed || observed.status !== "active") {
    throw new Error("backup restore fence is absent or no longer active");
  }
  return observed;
}

function releaseBackupRestoreFence(port, fence, {
  release_effect_ref: suppliedReleaseEffectRef = null,
} = {}) {
  const state = assertOperatorBackupKeyCustodyPort(port);
  if (!fence || typeof fence !== "object" || isProxy(fence)
    || !RESTORE_FENCE_EVIDENCE.has(fence)) {
    throw new Error("backup restore fence must be a private branded active result");
  }
  const releaseEffectRef = suppliedReleaseEffectRef == null
    ? randomRef("backup-effect:v1:")
    : suppliedReleaseEffectRef;
  if (typeof releaseEffectRef !== "string" || !EFFECT_REF_RE.test(releaseEffectRef)) {
    throw new Error("release_effect_ref must be a random opaque backup effect reference");
  }
  const expected = { ...fence, ...state.binding, release_effect_ref: releaseEffectRef };
  const request = Object.freeze({
    version: ARTIFACT_VAULT_SCHEMA_VERSION,
    action: "release_backup_restore_fence",
    ...restoreFenceReadRequest(state.binding, fence),
    release_effect_ref: releaseEffectRef,
  });
  const invocation = invokeCallback(
    state.callbacks.release_restore_fence,
    [request],
    "backup restore fence release_restore_fence",
  );
  let returned = null;
  let responseError = null;
  if (!invocation.failed) {
    try {
      returned = normalizeRestoreFenceState(
        invocation.output,
        expected,
        "backup restore fence release response",
      );
      if (returned.status !== "released") throw new Error("backup restore fence was not released");
    } catch (error) {
      responseError = error;
    }
  }
  const observed = readRestoreFence(state, expected, "backup restore fence release");
  if (!observed || observed.status !== "released") {
    if (responseError) throw responseError;
    throw new Error("backup restore fence release did not produce exact durable readback");
  }
  if (returned && canonicalJson(returned) !== canonicalJson(observed)) {
    throw new Error("backup restore fence release response conflicts with exact readback");
  }
  return observed;
}

function openBackupArchive(port, input, { restore_fence: restoreFence = null } = {}) {
  const state = assertOperatorBackupKeyCustodyPort(port);
  resolveCurrent(state, "backup archive open");
  const envelope = normalizeStoredBackupCustodyEnvelope(input, state.binding);
  const activeRestoreFence = restoreFence == null
    ? null
    : assertBackupRestoreFence(port, restoreFence, envelope);
  const observed = readArchiveState(state, envelope, "backup archive open");
  if (!observed || !immutableArchiveStateMatches(observed, envelope)) {
    throw new Error("stored backup custody envelope is absent, replayed, or tampered");
  }
  if (observed.status !== "active") {
    throw new Error("external backup key is revoked; the archive cannot be opened");
  }
  const openRef = randomRef("backup-open:v1:");
  const request = Object.freeze({
    version: ARTIFACT_VAULT_SCHEMA_VERSION,
    action: "open_backup_archive",
    ...state.binding,
    backup_ref: envelope.backup_ref,
    backup_digest: envelope.backup_digest,
    artifact_inventory_digest: envelope.artifact_inventory_digest,
    seal_effect_ref: envelope.seal_effect_ref,
    seal_ref: envelope.seal_ref,
    custody_format: envelope.custody_format,
    sealed_archive: envelope.sealed_archive,
    sealed_archive_digest: envelope.sealed_archive_digest,
    open_ref: openRef,
    restore_ref: activeRestoreFence ? activeRestoreFence.restore_ref : null,
  });
  const invocation = invokeCallback(
    state.callbacks.open_archive,
    [request],
    "backup archive open_archive",
    { cleanup_rejected_output: wipeRejectedOpenResponse },
  );
  if (invocation.failed) throw new Error("external backup archive open failed");
  let responsePlaintext = null;
  let plaintext;
  try {
    // Capture an own, data-only Buffer before validating any other response
    // field so even a malformed wrapper cannot strand plaintext until GC.
    responsePlaintext = ownDataBuffer(invocation.output, "plaintext_archive");
    assertClosedDataObject(invocation.output, "backup archive open response", [
      "version",
      "custody_id",
      "custody_epoch",
      "vault_id",
      "vault_slot",
      "session_nucleus_hash",
      "backup_ref",
      "backup_digest",
      "artifact_inventory_digest",
      "seal_ref",
      "open_ref",
      "restore_ref",
      "plaintext_archive",
    ]);
    if (invocation.output.version !== ARTIFACT_VAULT_SCHEMA_VERSION
      || isProxy(invocation.output.plaintext_archive)
      || !Buffer.isBuffer(invocation.output.plaintext_archive)
      || invocation.output.plaintext_archive.length < 1
      || invocation.output.plaintext_archive.length > MAX_ARCHIVE_BYTES) {
      throw new Error("backup archive open response plaintext is invalid");
    }
    responsePlaintext = invocation.output.plaintext_archive;
    for (const field of [
      "custody_id", "custody_epoch", "vault_id", "vault_slot", "session_nucleus_hash",
      "backup_ref", "backup_digest", "artifact_inventory_digest", "seal_ref", "open_ref",
      "restore_ref",
    ]) {
      const expected = field === "open_ref"
        ? openRef
        : field === "restore_ref"
          ? (activeRestoreFence ? activeRestoreFence.restore_ref : null)
          : envelope[field];
      if (invocation.output[field] !== expected) {
        throw new Error(`backup archive open response.${field} binding mismatch`);
      }
    }
    plaintext = Buffer.from(responsePlaintext);
  } finally {
    if (responsePlaintext) responsePlaintext.fill(0);
  }
  if (sha256(plaintext) !== envelope.backup_digest) {
    plaintext.fill(0);
    throw new Error("backup archive open response does not match the sealed backup digest");
  }
  let after;
  try {
    after = readArchiveState(state, envelope, "backup archive open");
  } catch (error) {
    plaintext.fill(0);
    throw error;
  }
  if (!after || after.status !== "active" || !immutableArchiveStateMatches(after, envelope)) {
    plaintext.fill(0);
    throw new Error("external backup key changed or was revoked during archive open");
  }
  return plaintext;
}

function verifyRetirementReadback(state, retirement, label) {
  const observed = readArtifactRetirement(state, retirement.artifact_handle, label);
  if (!observed || canonicalJson(observed) !== canonicalJson(retirement)) {
    throw new Error(`${label} retirement state failed exact durable readback`);
  }
  for (const summary of observed.revoked_archives) {
    const archive = readArchiveState(state, {
      ...state.binding,
      backup_ref: summary.backup_ref,
      backup_digest: summary.backup_digest,
      artifact_inventory_digest: summary.artifact_inventory_digest,
      seal_effect_ref: summary.seal_effect_ref,
    }, `${label} revoked archive`);
    // Read every whole-archive revocation independently instead of trusting the
    // aggregate retirement claim on its own.
    if (!archive || archive.status !== "revoked"
      || archive.backup_ref !== summary.backup_ref
      || archive.backup_digest !== summary.backup_digest
      || archive.artifact_inventory_digest !== summary.artifact_inventory_digest
      || archive.seal_ref !== summary.seal_ref
      || archive.sealed_archive_digest !== summary.sealed_archive_digest
      || archive.revocation_effect_ref !== summary.revocation_effect_ref
      || archive.revoked_at !== summary.revoked_at) {
      throw new Error(`${label} archive-key revocation failed exact readback`);
    }
  }
  return observed;
}

function retireArtifactBackupKeys(port, {
  artifact_handle: artifactHandle,
  reason_ref: reasonRef,
  requested_at: requestedAt,
  retirement_effect_ref: suppliedRetirementEffectRef = null,
  member_archive_registry: memberArchiveRegistry = [],
} = {}) {
  const state = assertOperatorBackupKeyCustodyPort(port);
  resolveCurrent(state, "artifact backup-key retirement");
  if (typeof artifactHandle !== "string" || !PUBLIC_ARTIFACT_HANDLE_RE.test(artifactHandle)) {
    throw new Error("artifact_handle is invalid for backup-key retirement");
  }
  const normalizedReason = assertOpaqueRef(reasonRef, "backup-key retirement reason_ref");
  const normalizedRequestedAt = assertCanonicalTimestamp(
    requestedAt,
    "backup-key retirement requested_at",
  );
  const normalizedMemberRegistry = normalizeMemberArchiveRegistry(memberArchiveRegistry);
  const memberArchiveRegistryDigest = sha256(canonicalJson(normalizedMemberRegistry));
  const retirementEffectRef = suppliedRetirementEffectRef == null
    ? randomRef("backup-effect:v1:")
    : suppliedRetirementEffectRef;
  if (typeof retirementEffectRef !== "string" || !EFFECT_REF_RE.test(retirementEffectRef)) {
    throw new Error("retirement_effect_ref must be a random opaque backup effect reference");
  }
  const exactExpected = {
    ...state.binding,
    artifact_handle: artifactHandle,
    reason_ref: normalizedReason,
    retired_at: normalizedRequestedAt,
    retirement_effect_ref: retirementEffectRef,
    member_archive_registry: normalizedMemberRegistry,
  };
  const existing = readArtifactRetirement(state, artifactHandle, "artifact backup-key retirement");
  if (existing) {
    normalizeRetirementState(
      existing,
      exactExpected,
      "artifact backup-key retirement existing state",
    );
    const reconciled = verifyRetirementReadback(
      state,
      existing,
      "artifact backup-key retirement reconciliation",
    );
    RETIREMENT_EVIDENCE.add(reconciled);
    return reconciled;
  }
  const request = Object.freeze({
    version: ARTIFACT_VAULT_SCHEMA_VERSION,
    action: "retire_artifact_and_revoke_member_archive_keys",
    ...state.binding,
    artifact_handle: artifactHandle,
    reason_ref: normalizedReason,
    requested_at: normalizedRequestedAt,
    retirement_effect_ref: retirementEffectRef,
    revocation_policy: REVOCATION_POLICY,
    member_archive_registry: normalizedMemberRegistry,
    member_archive_registry_digest: memberArchiveRegistryDigest,
  });
  const invocation = invokeCallback(
    state.callbacks.retire_artifact,
    [request],
    "artifact backup-key retire_artifact",
  );
  let returned = null;
  let responseError = null;
  if (!invocation.failed) {
    try {
      returned = normalizeRetirementState(
        invocation.output,
        exactExpected,
        "artifact backup-key retirement response",
      );
    } catch (error) {
      responseError = error;
    }
  }
  const observed = readArtifactRetirement(state, artifactHandle, "artifact backup-key retirement");
  if (!observed || observed.retirement_effect_ref !== retirementEffectRef) {
    if (responseError) throw responseError;
    throw new Error("artifact backup-key retirement outcome is absent or ambiguous; the effect was not retried");
  }
  normalizeRetirementState(observed, exactExpected, "artifact backup-key retirement readback");
  if (returned && canonicalJson(returned) !== canonicalJson(observed)) {
    throw new Error("artifact backup-key retirement response conflicts with exact readback");
  }
  const verified = verifyRetirementReadback(state, observed, "artifact backup-key retirement");
  RETIREMENT_EVIDENCE.add(verified);
  return verified;
}

function assertBackupKeyRetirementEvidence(port, input, artifactHandle) {
  const state = assertOperatorBackupKeyCustodyPort(port);
  if (input == null || typeof input !== "object" || isProxy(input)
    || !RETIREMENT_EVIDENCE.has(input)) {
    throw new Error("external backup-key retirement evidence must be a private branded result");
  }
  const normalized = normalizeRetirementState(
    input,
    { ...state.binding, artifact_handle: artifactHandle },
    "external backup-key retirement evidence",
  );
  return verifyRetirementReadback(state, normalized, "external backup-key retirement evidence");
}

function normalizeSerializedBackupKeyRetirementEvidence(port, input, artifactHandle) {
  const state = assertOperatorBackupKeyCustodyPort(port);
  return normalizeRetirementState(
    input,
    { ...state.binding, artifact_handle: artifactHandle },
    "serialized external backup-key retirement evidence",
  );
}

function verifySerializedBackupKeyRetirementEvidence(port, input, artifactHandle) {
  const state = assertOperatorBackupKeyCustodyPort(port);
  const normalized = normalizeRetirementState(
    input,
    { ...state.binding, artifact_handle: artifactHandle },
    "serialized external backup-key retirement evidence",
  );
  return verifyRetirementReadback(
    state,
    normalized,
    "serialized external backup-key retirement evidence",
  );
}

module.exports = {
  MAX_MEMBER_ARCHIVES_PER_ARTIFACT,
  REVOCATION_POLICY,
  acquireBackupRestoreFence,
  assertBackupKeyRetirementEvidence,
  assertBackupRestoreFence,
  assertOperatorBackupKeyCustodyPort,
  createOperatorBackupKeyCustodyPort,
  normalizeArtifactInventory,
  normalizeSerializedBackupKeyRetirementEvidence,
  normalizeStoredBackupCustodyEnvelope,
  openBackupArchive,
  readBackupArchiveState,
  readBackupRestoreFence,
  releaseBackupRestoreFence,
  retireArtifactBackupKeys,
  sealBackupArchive,
  verifySerializedBackupKeyRetirementEvidence,
};
