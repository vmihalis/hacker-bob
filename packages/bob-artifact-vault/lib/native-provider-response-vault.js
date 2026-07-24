"use strict";

// Vault-owned consumer for the fixed native Chameleon response record.  The
// native custodian receives only a write-only append descriptor.  This module
// retains a separate owner descriptor, validates the complete record against
// the already branded provider-response sink, and hands only the raw response
// slice to the existing authenticated vault commit.  No filesystem path is
// accepted or projected by this API.

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { types: utilTypes } = require("node:util");

const { getProviderResponseVaultOwner } = require("./vault.js");
const {
  PROVIDER_RESPONSE_VAULT_VERSION,
  assertProviderResponseSink,
  assertProviderResponseRawCustodyReceipt,
  commitProviderResponseRawCustody,
  confirmProviderResponseRawCustodyPlaintextCleanup,
} = require("./provider-response-vault.js");

const arrayIsArray = Array.isArray;
const bufferAlloc = Buffer.alloc;
const bufferConcat = Buffer.concat;
const bufferFrom = Buffer.from;
const bufferIsBuffer = Buffer.isBuffer;
const objectFreeze = Object.freeze;
const objectGetOwnPropertyDescriptors = Object.getOwnPropertyDescriptors;
const objectGetPrototypeOf = Object.getPrototypeOf;
const objectHasOwn = Object.hasOwn;
const objectPrototype = Object.prototype;
const reflectOwnKeys = Reflect.ownKeys;
const utilIsPromise = utilTypes.isPromise;
const utilIsProxy = utilTypes.isProxy;

const NATIVE_PROVIDER_RESPONSE_VAULT_VERSION = 1;
const NATIVE_PROVIDER_RESPONSE_RECORD_HEADER_BYTES = 280;
const NATIVE_PROVIDER_RESPONSE_RECORD_MAGIC = bufferFrom("HBPHVSR1", "ascii");
const NATIVE_PROVIDER_RESPONSE_SINK_IDENTITY_MAGIC = bufferFrom("HBPHDVS1", "ascii");
const ARTIFACT_HANDLE_DIGEST_DOMAIN = bufferFrom(
  "hacker-bob/native-response-vault-artifact-handle/v1\0",
  "utf8",
);
const ZERO_DIGEST = "0".repeat(64);
const SHA256_RE = /^[a-f0-9]{64}$/u;
const UINT64_RE = /^(?:0|[1-9][0-9]{0,19})$/u;
const MAX_UINT64 = (1n << 64n) - 1n;

const PREPARE_FIELDS = objectFreeze(["version", "sink"]);
const CONSUME_FIELDS = objectFreeze([
  "version",
  "kind",
  "lineage",
  "native_terminal_result",
  "execution_claim_receipt_digest",
  "deadline_fence_receipt_digest",
]);
const NATIVE_TERMINAL_RESULT_FIELDS = objectFreeze([
  "version",
  "status",
  "wrote_any_command_bytes",
  "dispatch_signature_verified",
  "descriptor_identity_verified",
  "deadline_rechecked_before_first_write",
  "response_sink_committed",
  "response_byte_length",
  "ticket_sequence",
  "settled_continuous_ns",
  "dispatch_envelope_digest",
  "delegated_descriptor_identity_digest",
  "response_digest",
  "vault_sink_descriptor_identity_digest",
  "vault_sink_record_digest",
  "production_ready",
  "hardware_access_authorized",
  "authoritative",
]);

const PORTS = new WeakSet();
const PORT_PRIVATE = new WeakMap();

const NATIVE_PROVIDER_RESPONSE_VAULT_ASSURANCE = objectFreeze({
  version: NATIVE_PROVIDER_RESPONSE_VAULT_VERSION,
  assurance: "vault_owned_fixed_native_response_record_consumer_v1",
  production_ready: false,
  hardware_access_authorized: false,
  execution_authority: false,
  caller_selected_paths_accepted: false,
  vault_owned_pre_reserved_descriptor: true,
  independent_owner_read_capability_retained: true,
  exact_native_record_header_validated: true,
  exact_lineage_and_reservation_binding_validated: true,
  artifact_handle_derived_from_vault_reservation: true,
  response_digest_and_byte_ceiling_validated: true,
  ambiguous_native_settlement_committable_as_expected_result: false,
  ambiguous_native_settlement_committed_as_raw_custody: true,
  rejected_sink_reservation_revoked: true,
  native_record_buffers_zeroized_after_consumption: true,
  semantic_result_claims_emitted: false,
  device_state_claims_emitted: false,
  distinct_private_raw_custody_receipt: true,
  raw_custody_and_semantic_journal_modes_mutually_exclusive: true,
  reservation_scoped_durable_journal_mode_and_lineage_fence: true,
  raw_custody_restart_readback: true,
  operation_specific_semantic_validation_performed: false,
  write_descriptor_one_use_issuance: true,
  duplicate_preparation_preserves_existing_owned_inode: true,
  preparation_filesystem_errors_redacted: true,
  failed_partial_preparation_path_reclaimed_automatically: false,
  explicit_write_descriptor_revocation_and_sink_cancellation: true,
  vault_destroy_registered_sink_drain: true,
  managed_staging_inode_zero_truncate_and_path_unlink_fsync_verified_before_success: true,
  plaintext_staging_unlink_verified_before_success: true,
  externally_duplicated_writer_capabilities_revoked: false,
  native_writer_process_quiescence_attested: false,
  durable_plaintext_cleanup_under_external_writer_duplication_proven: false,
  apfs_copy_on_write_physical_erasure_proven: false,
  physical_media_secure_erasure_proven: false,
  existing_provider_response_semantic_receipt_reused: false,
  native_terminal_private_origin_attested: false,
  separately_isolated_vault_principal: false,
  external_monotonic_receipt_anchor: false,
  hardware_in_loop_proven: false,
  production_blockers: objectFreeze([
    "separately_isolated_vault_principal_missing",
    "external_monotonic_receipt_anchor_missing",
    "native_worker_to_vault_hil_missing",
    "native_terminal_private_origin_attestation_missing",
    "privately_branded_native_terminal_receipt_missing",
    "privately_branded_lineage_claim_and_deadline_receipts_missing",
    "externally_duplicated_writer_process_lifecycle_custody_missing",
    "plaintext_sink_crash_recovery_missing",
    "failed_partial_sink_preparation_orphan_reconciliation_missing",
    "physical_media_secure_erasure_unavailable",
  ]),
});

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function constantTimeDigestEqual(left, right) {
  if (typeof left !== "string" || typeof right !== "string"
      || !SHA256_RE.test(left) || !SHA256_RE.test(right)) return false;
  const leftBytes = bufferFrom(left, "hex");
  const rightBytes = bufferFrom(right, "hex");
  try {
    return crypto.timingSafeEqual(leftBytes, rightBytes);
  } finally {
    leftBytes.fill(0);
    rightBytes.fill(0);
  }
}

function assertExactDataObject(input, fields, label) {
  if (input == null || typeof input !== "object" || arrayIsArray(input)
      || bufferIsBuffer(input) || utilIsProxy(input) || utilIsPromise(input)) {
    throw new Error(`${label} must be a non-proxy data object`);
  }
  const prototype = objectGetPrototypeOf(input);
  if (prototype !== objectPrototype && prototype !== null) {
    throw new Error(`${label} must have an ordinary or null prototype`);
  }
  const descriptors = objectGetOwnPropertyDescriptors(input);
  const keys = reflectOwnKeys(descriptors);
  if (keys.some((key) => typeof key !== "string")) {
    throw new Error(`${label} must not contain symbol fields`);
  }
  const allowed = new Set(fields);
  const unknown = keys.filter((key) => !allowed.has(key)).sort();
  const missing = fields.filter((key) => !objectHasOwn(descriptors, key));
  if (unknown.length > 0 || missing.length > 0) {
    throw new Error(`${label} has unknown or missing fields`);
  }
  for (const key of fields) {
    const descriptor = descriptors[key];
    if (!objectHasOwn(descriptor, "value") || descriptor.enumerable !== true) {
      throw new Error(`${label}.${key} must be an enumerable data property`);
    }
  }
  return descriptors;
}

function descriptorValue(descriptors, field) {
  return descriptors[field].value;
}

function exactOwnDataValue(input, field, label) {
  if (input == null || typeof input !== "object" || utilIsProxy(input)) {
    throw new Error(`${label} must be a non-proxy data object`);
  }
  const descriptors = objectGetOwnPropertyDescriptors(input);
  const descriptor = descriptors[field];
  if (!descriptor || !objectHasOwn(descriptor, "value") || descriptor.enumerable !== true) {
    throw new Error(`${label}.${field} must be an own enumerable data property`);
  }
  return descriptor.value;
}

function assertVersion(value, label) {
  if (value !== NATIVE_PROVIDER_RESPONSE_VAULT_VERSION) {
    throw new Error(`${label}.version is invalid`);
  }
}

function assertDigest(value, label) {
  if (typeof value !== "string" || !SHA256_RE.test(value)) {
    throw new Error(`${label} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function assertPositiveUint64(value, label) {
  if (typeof value !== "string" || !UINT64_RE.test(value)) {
    throw new Error(`${label} must be a canonical positive uint64 decimal string`);
  }
  const parsed = BigInt(value);
  if (parsed < 1n || parsed > MAX_UINT64) {
    throw new Error(`${label} must be a canonical positive uint64 decimal string`);
  }
  return value;
}

function assertNonnegativeInteger(value, label, ceiling) {
  if (!Number.isSafeInteger(value) || value < 0 || value > ceiling) {
    throw new Error(`${label} must be an integer between 0 and ${ceiling}`);
  }
  return value;
}

function assertExactBoolean(value, expected, label) {
  if (value !== expected) throw new Error(`${label} must be ${expected}`);
  return value;
}

function ensurePrivateDirectory(directory, label) {
  let created = false;
  try {
    fs.mkdirSync(directory, { mode: 0o700 });
    created = true;
  } catch (error) {
    if (!error || error.code !== "EEXIST") throw error;
  }
  const stats = fs.lstatSync(directory);
  if (!stats.isDirectory() || stats.isSymbolicLink()
      || (stats.mode & 0o777) !== 0o700
      || (typeof process.getuid === "function" && stats.uid !== process.getuid())) {
    throw new Error(`${label} must be a real mode-0700 directory owned by this process`);
  }
  if (created) fs.chmodSync(directory, 0o700);
  return stats;
}

function fsyncDirectory(directory) {
  const descriptor = fs.openSync(
    directory,
    fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0)
      | (fs.constants.O_CLOEXEC || 0),
  );
  try {
    const stats = fs.fstatSync(descriptor);
    if (!stats.isDirectory() || (stats.mode & 0o077) !== 0
        || (typeof process.getuid === "function" && stats.uid !== process.getuid())) {
      throw new Error("native response sink directory descriptor is unsafe");
    }
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
}

function sameIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino
    && left.mode === right.mode && left.rdev === right.rdev
    && left.nlink === right.nlink && left.uid === right.uid && left.gid === right.gid;
}

function sameInode(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
}

function assertSafeSinkStats(stats, label, { empty = false } = {}) {
  if (!stats.isFile() || stats.nlink !== 1n || (stats.mode & 0o077n) !== 0n
      || (stats.mode & 0o200n) === 0n
      || (typeof process.getuid === "function" && stats.uid !== BigInt(process.getuid()))) {
    throw new Error(`${label} must be a single-link owner-writable private regular file`);
  }
  if (empty && stats.size !== 0n) throw new Error(`${label} must be empty`);
  return stats;
}

function encodeU32(value) {
  const output = bufferAlloc(4);
  output.writeUInt32BE(value, 0);
  return output;
}

function encodeI64(value) {
  const output = bufferAlloc(8);
  output.writeBigInt64BE(value, 0);
  return output;
}

function encodeU64(value) {
  const output = bufferAlloc(8);
  output.writeBigUInt64BE(value, 0);
  return output;
}

function encodeTlv(tag, value) {
  const framing = bufferAlloc(6);
  framing.writeUInt16BE(tag, 0);
  framing.writeUInt32BE(value.length, 2);
  return [framing, value];
}

function deriveNativeResponseSinkDescriptorIdentityDigest(stats) {
  const header = bufferAlloc(12);
  NATIVE_PROVIDER_RESPONSE_SINK_IDENTITY_MAGIC.copy(header, 0);
  header.writeUInt16BE(1, 8);
  header.writeUInt16BE(16, 10);
  const definitions = [
    [1, encodeU32(1)],
    [2, bufferFrom("vault_reserved_provider_response_sink", "utf8")],
    [3, encodeU32(7)],
    [4, bufferFrom("physical_native_response_vault_ingest", "utf8")],
    [5, encodeI64(stats.dev)],
    [6, encodeU64(stats.ino)],
    [7, encodeI64(stats.rdev)],
    [8, encodeU32(Number(stats.mode))],
    [9, encodeU64(stats.nlink)],
    [10, encodeU32(Number(stats.uid))],
    [11, encodeU32(Number(stats.gid))],
    [12, bufferFrom([1])],
    [13, encodeU32(1)],
    // Darwin O_WRONLY | O_APPEND. This package can parse fixture bytes on
    // other hosts, but preparing the actual native descriptor is Darwin-only.
    [14, encodeU32(9)],
    [15, encodeU32(0)],
    [16, encodeU64(0n)],
  ];
  const chunks = [header];
  try {
    for (const [tag, value] of definitions) chunks.push(...encodeTlv(tag, value));
    const encoded = bufferConcat(chunks);
    try {
      return sha256(encoded);
    } finally {
      encoded.fill(0);
    }
  } finally {
    for (const chunk of chunks) chunk.fill(0);
  }
}

function artifactHandleDigest(artifactHandle) {
  const handleBytes = bufferFrom(artifactHandle, "utf8");
  try {
    return crypto.createHash("sha256")
      .update(ARTIFACT_HANDLE_DIGEST_DOMAIN)
      .update(handleBytes)
      .digest("hex");
  } finally {
    handleBytes.fill(0);
  }
}

function closeTrackedDescriptor(state, field) {
  const descriptor = state[field];
  if (!Number.isSafeInteger(descriptor) || descriptor < 0) return;
  state[field] = -1;
  try {
    const stats = fs.fstatSync(descriptor, { bigint: true });
    if (!sameInode(stats, state.identity)) {
      throw new Error(`native response ${field} identity drifted before close`);
    }
    fs.closeSync(descriptor);
  } catch (error) {
    throw error;
  }
}

function cleanupReconciliationError(errors) {
  return new Error(
    "native provider response sink cleanup reconciliation failed",
    { cause: new AggregateError(errors, "native response plaintext staging cleanup failed") },
  );
}

function sinkPreparationError() {
  const error = new Error("native provider response sink preparation failed");
  error.code = "native_provider_response_sink_preparation_failed";
  return error;
}

function closeWriteDescriptorForCleanup(state, errors) {
  const descriptor = state.write_fd;
  state.write_fd = -1;
  state.write_descriptor_revoked = true;
  if (!Number.isSafeInteger(descriptor) || descriptor < 0) return;
  try {
    const stats = fs.fstatSync(descriptor, { bigint: true });
    if (!sameInode(stats, state.identity)) {
      errors.push(new Error("native response write descriptor identity drifted before revocation"));
      return;
    }
    fs.closeSync(descriptor);
  } catch (error) {
    // A launcher is permitted to close the inherited parent descriptor after
    // duplicating it into the native child. A stale number must never cause us
    // to close an unrelated descriptor if the process subsequently reused it.
    if (!error || error.code !== "EBADF") errors.push(error);
  }
}

function overwriteAndVerifyZero(descriptor, byteLength) {
  if (byteLength === 0) return;
  const chunk = bufferAlloc(Math.min(64 * 1024, byteLength));
  const verification = bufferAlloc(chunk.length);
  try {
    let offset = 0;
    while (offset < byteLength) {
      const length = Math.min(chunk.length, byteLength - offset);
      let written = 0;
      while (written < length) {
        written += fs.writeSync(
          descriptor,
          chunk,
          written,
          length - written,
          offset + written,
        );
      }
      offset += length;
    }
    fs.fsyncSync(descriptor);
    offset = 0;
    while (offset < byteLength) {
      const length = Math.min(verification.length, byteLength - offset);
      verification.fill(0xff, 0, length);
      let read = 0;
      while (read < length) {
        const count = fs.readSync(
          descriptor,
          verification,
          read,
          length - read,
          offset + read,
        );
        if (count === 0) throw new Error("native response staging bytes changed during zero verification");
        read += count;
      }
      for (let index = 0; index < length; index += 1) {
        if (verification[index] !== 0) {
          throw new Error("native response staging bytes were not logically overwritten");
        }
      }
      offset += length;
    }
  } finally {
    chunk.fill(0);
    verification.fill(0);
  }
}

function reconcileOwnedRecordCleanup(state) {
  if (state.cleanup_complete) return;
  const errors = [];
  closeWriteDescriptorForCleanup(state, errors);
  const descriptor = state.owner_fd;
  let descriptorLogicallyEmpty = false;
  let managedPathAbsent = false;
  let directorySynced = false;
  if (!Number.isSafeInteger(descriptor) || descriptor < 0) {
    errors.push(new Error("native response owner descriptor is unavailable for cleanup"));
  } else {
    try {
      const before = fs.fstatSync(descriptor, { bigint: true });
      if (!sameInode(before, state.identity) || !before.isFile()
          || before.isSymbolicLink()
          || before.uid !== state.identity.uid || before.rdev !== state.identity.rdev
          || (before.mode & 0o077n) !== 0n) {
        throw new Error("native response owner descriptor identity drifted before cleanup");
      }
      if (before.nlink > 1n) {
        errors.push(new Error("native response staging inode acquired an unexpected hardlink"));
      }
      const maximumExpected = BigInt(
        NATIVE_PROVIDER_RESPONSE_RECORD_HEADER_BYTES + state.byte_ceiling,
      );
      if (before.size > maximumExpected) {
        errors.push(new Error("native response staging inode exceeded its cleanup byte ceiling"));
      } else {
        try {
          overwriteAndVerifyZero(descriptor, Number(before.size));
        } catch (error) {
          errors.push(error);
        }
      }
      try {
        fs.ftruncateSync(descriptor, 0);
        fs.fsyncSync(descriptor);
        const after = fs.fstatSync(descriptor, { bigint: true });
        if (!sameInode(after, state.identity) || after.size !== 0n) {
          throw new Error("native response staging inode did not remain logically truncated");
        }
        descriptorLogicallyEmpty = true;
      } catch (error) {
        errors.push(error);
      }
    } catch (error) {
      errors.push(error);
    }
  }

  try {
    const pathStats = fs.lstatSync(state.file_path, { bigint: true });
    if (!sameInode(pathStats, state.identity) || !pathStats.isFile()
        || pathStats.isSymbolicLink()) {
      throw new Error("native response staging path no longer names its owned inode");
    }
    fs.unlinkSync(state.file_path);
  } catch (error) {
    if (!error || error.code !== "ENOENT") errors.push(error);
  }
  try {
    fsyncDirectory(state.directory);
    directorySynced = true;
  } catch (error) {
    errors.push(error);
  }
  try {
    fs.lstatSync(state.file_path);
    errors.push(new Error("native response staging path remained linked after cleanup"));
  } catch (error) {
    if (error && error.code === "ENOENT") managedPathAbsent = true;
    else errors.push(error);
  }
  if (descriptorLogicallyEmpty && Number.isSafeInteger(descriptor) && descriptor >= 0) {
    try {
      const finalDescriptorState = fs.fstatSync(descriptor, { bigint: true });
      if (!sameInode(finalDescriptorState, state.identity)
          || finalDescriptorState.size !== 0n) {
        throw new Error("native response staging inode was rewritten during path cleanup");
      }
    } catch (error) {
      errors.push(error);
      descriptorLogicallyEmpty = false;
    }
  }

  if (errors.length === 0 && descriptorLogicallyEmpty
      && managedPathAbsent && directorySynced) {
    try {
      closeTrackedDescriptor(state, "owner_fd");
      if (state.drain_registered) {
        state.owner.unregister_native_response_sink_drain(state.drain);
        state.drain_registered = false;
      }
      state.cleanup_complete = true;
      state.lifecycle = "closed";
      return;
    } catch (error) {
      state.lifecycle = "cleanup_failed";
      throw cleanupReconciliationError([error]);
    }
  }
  state.lifecycle = "cleanup_failed";
  throw cleanupReconciliationError(errors.length > 0
    ? errors : [new Error("native response cleanup did not establish every required invariant")]);
}

function prepareNativeProviderResponseSink(vault, input) {
  const descriptors = assertExactDataObject(
    input,
    PREPARE_FIELDS,
    "prepare_native_provider_response_sink_request",
  );
  assertVersion(
    descriptorValue(descriptors, "version"),
    "prepare_native_provider_response_sink_request",
  );
  const sink = assertProviderResponseSink(descriptorValue(descriptors, "sink"));
  const owner = getProviderResponseVaultOwner(vault);
  owner.assert_live();
  const current = owner.with_lock(() => owner.read_reservation(sink.vault_reservation_handle));
  if (!current || current.state !== "active") {
    throw new Error("native provider response sink requires an active vault reservation");
  }
  if (current.byte_ceiling !== sink.byte_ceiling) {
    throw new Error("native provider response sink byte ceiling drifted from its reservation");
  }

  const directory = owner.native_response_sink_root;
  const filePath = path.join(directory, `${sink.vault_ingest_capability_digest}.bin`);
  let ownerFd = -1;
  let writeFd = -1;
  try {
    ensurePrivateDirectory(owner.receipt_root, "provider response receipt root");
    ensurePrivateDirectory(directory, "native provider response sink directory");
    ownerFd = fs.openSync(
      filePath,
      fs.constants.O_RDWR | fs.constants.O_CREAT | fs.constants.O_EXCL
        | (fs.constants.O_NOFOLLOW || 0) | (fs.constants.O_CLOEXEC || 0),
      0o600,
    );
    fs.fchmodSync(ownerFd, 0o600);
    writeFd = fs.openSync(
      filePath,
      fs.constants.O_WRONLY | fs.constants.O_APPEND
        | (fs.constants.O_NOFOLLOW || 0) | (fs.constants.O_CLOEXEC || 0),
    );
    const ownerStats = assertSafeSinkStats(
      fs.fstatSync(ownerFd, { bigint: true }),
      "native provider response owner descriptor",
      { empty: true },
    );
    const writeStats = assertSafeSinkStats(
      fs.fstatSync(writeFd, { bigint: true }),
      "native provider response write descriptor",
      { empty: true },
    );
    const pathStats = assertSafeSinkStats(
      fs.lstatSync(filePath, { bigint: true }),
      "native provider response sink path",
      { empty: true },
    );
    if (!sameIdentity(ownerStats, writeStats) || !sameIdentity(ownerStats, pathStats)) {
      throw new Error("native provider response sink descriptors do not share one exact inode");
    }
    fsyncDirectory(directory);
    const sinkDescriptorDigest = deriveNativeResponseSinkDescriptorIdentityDigest(writeStats);
    const handleDigest = artifactHandleDigest(current.artifact_handle);
    const kind = "vault_owned_native_provider_response_sink";
    const port = objectFreeze({
      version: NATIVE_PROVIDER_RESPONSE_VAULT_VERSION,
      kind,
      vault_reservation_digest: sink.vault_reservation_digest,
      vault_ingest_capability_digest: sink.vault_ingest_capability_digest,
      artifact_handle_digest: handleDigest,
      vault_sink_descriptor_identity_digest: sinkDescriptorDigest,
      byte_ceiling: sink.byte_ceiling,
      production_ready: false,
      hardware_access_authorized: false,
      execution_authority: false,
      toJSON() {
        return {
          version: NATIVE_PROVIDER_RESPONSE_VAULT_VERSION,
          kind,
          vault_reservation_digest: sink.vault_reservation_digest,
          vault_ingest_capability_digest: sink.vault_ingest_capability_digest,
          artifact_handle_digest: handleDigest,
          vault_sink_descriptor_identity_digest: sinkDescriptorDigest,
          byte_ceiling: sink.byte_ceiling,
          production_ready: false,
          hardware_access_authorized: false,
          execution_authority: false,
        };
      },
    });
    const state = {
      vault,
      owner,
      sink,
      directory,
      file_path: filePath,
      owner_fd: ownerFd,
      write_fd: writeFd,
      identity: ownerStats,
      byte_ceiling: sink.byte_ceiling,
      artifact_handle: current.artifact_handle,
      artifact_handle_digest: handleDigest,
      sink_descriptor_digest: sinkDescriptorDigest,
      lifecycle: "active",
      write_descriptor_issued: false,
      write_descriptor_revoked: false,
      cleanup_complete: false,
      drain_registered: false,
      drain: null,
    };
    state.drain = () => {
      if (state.cleanup_complete) return;
      if (state.lifecycle === "active") state.lifecycle = "vault_destroy_drain";
      reconcileOwnedRecordCleanup(state);
    };
    PORTS.add(port);
    PORT_PRIVATE.set(port, state);
    owner.register_native_response_sink_drain(state.drain);
    state.drain_registered = true;
    ownerFd = -1;
    writeFd = -1;
    return port;
  } catch {
    if (writeFd >= 0) try { fs.closeSync(writeFd); } catch {}
    // O_EXCL failure means this invocation never owned the existing path. A
    // later failure may have created the path, but JavaScript has no atomic
    // unlink-by-open-file-description primitive: lstat-then-unlink permits a
    // same-principal replacement race. Never unlink from this error path. An
    // empty partial preparation therefore remains an inert fail-closed orphan
    // and blocks reuse until a separately designed, identity-safe recovery
    // custodian exists.
    if (ownerFd >= 0) try { fs.closeSync(ownerFd); } catch {}
    // Filesystem errors can contain the absolute vault root and the
    // capability-derived staging filename. Neither belongs on the public API.
    throw sinkPreparationError();
  }
}

function assertNativeProviderResponseSink(value) {
  if (!PORTS.has(value)) {
    throw new Error("native provider response sink is not vault-private branded");
  }
  return value;
}

function nativeProviderResponseSinkWriteDescriptor(port) {
  assertNativeProviderResponseSink(port);
  const state = PORT_PRIVATE.get(port);
  state.owner.assert_live();
  if (state.lifecycle !== "active" || state.write_fd < 0
      || state.write_descriptor_issued || state.write_descriptor_revoked) {
    throw new Error("native provider response sink write descriptor is no longer live");
  }
  const stats = assertSafeSinkStats(
    fs.fstatSync(state.write_fd, { bigint: true }),
    "native provider response write descriptor",
    { empty: true },
  );
  if (!sameIdentity(stats, state.identity)) {
    throw new Error("native provider response write descriptor identity drifted");
  }
  state.write_descriptor_issued = true;
  return state.write_fd;
}

function revokeNativeProviderResponseSinkWriteDescriptor(port) {
  assertNativeProviderResponseSink(port);
  const state = PORT_PRIVATE.get(port);
  state.owner.assert_live();
  if (state.lifecycle !== "active" || state.write_descriptor_revoked
      || state.write_fd < 0) {
    throw new Error("native provider response sink write descriptor is no longer live");
  }
  const errors = [];
  closeWriteDescriptorForCleanup(state, errors);
  if (errors.length > 0) throw cleanupReconciliationError(errors);
  return true;
}

function normalizeConsumeRequest(input) {
  const label = "consume_native_provider_response_record_request";
  const descriptors = assertExactDataObject(input, CONSUME_FIELDS, label);
  assertVersion(descriptorValue(descriptors, "version"), label);
  if (descriptorValue(descriptors, "kind") !== label) {
    throw new Error(`${label}.kind is invalid`);
  }
  const terminalLabel = `${label}.native_terminal_result`;
  const terminalDescriptors = assertExactDataObject(
    descriptorValue(descriptors, "native_terminal_result"),
    NATIVE_TERMINAL_RESULT_FIELDS,
    terminalLabel,
  );
  assertVersion(descriptorValue(terminalDescriptors, "version"), terminalLabel);
  const terminalStatus = descriptorValue(terminalDescriptors, "status");
  if (terminalStatus !== "ambiguous_quarantined"
      && terminalStatus !== "fixture_complete_non_authorizing") {
    throw new Error(`${terminalLabel}.status is not a committed response status`);
  }
  const terminalResponseLength = assertNonnegativeInteger(
    descriptorValue(terminalDescriptors, "response_byte_length"),
    `${terminalLabel}.response_byte_length`,
    1024 * 1024,
  );
  const terminalResponseDigest = assertDigest(
    descriptorValue(terminalDescriptors, "response_digest"),
    `${terminalLabel}.response_digest`,
  );
  if ((terminalResponseLength === 0 && terminalResponseDigest !== ZERO_DIGEST)
      || (terminalResponseLength > 0 && terminalResponseDigest === ZERO_DIGEST)
      || (terminalStatus === "fixture_complete_non_authorizing"
        && terminalResponseLength < 10)) {
    throw new Error(`${terminalLabel} has an incoherent response observation`);
  }
  const terminal = objectFreeze({
    version: NATIVE_PROVIDER_RESPONSE_VAULT_VERSION,
    status: terminalStatus,
    wrote_any_command_bytes: assertExactBoolean(
      descriptorValue(terminalDescriptors, "wrote_any_command_bytes"),
      true,
      `${terminalLabel}.wrote_any_command_bytes`,
    ),
    dispatch_signature_verified: assertExactBoolean(
      descriptorValue(terminalDescriptors, "dispatch_signature_verified"),
      true,
      `${terminalLabel}.dispatch_signature_verified`,
    ),
    descriptor_identity_verified: assertExactBoolean(
      descriptorValue(terminalDescriptors, "descriptor_identity_verified"),
      true,
      `${terminalLabel}.descriptor_identity_verified`,
    ),
    deadline_rechecked_before_first_write: assertExactBoolean(
      descriptorValue(terminalDescriptors, "deadline_rechecked_before_first_write"),
      true,
      `${terminalLabel}.deadline_rechecked_before_first_write`,
    ),
    response_sink_committed: assertExactBoolean(
      descriptorValue(terminalDescriptors, "response_sink_committed"),
      true,
      `${terminalLabel}.response_sink_committed`,
    ),
    response_byte_length: terminalResponseLength,
    ticket_sequence: assertPositiveUint64(
      descriptorValue(terminalDescriptors, "ticket_sequence"),
      `${terminalLabel}.ticket_sequence`,
    ),
    settled_continuous_ns: assertPositiveUint64(
      descriptorValue(terminalDescriptors, "settled_continuous_ns"),
      `${terminalLabel}.settled_continuous_ns`,
    ),
    dispatch_envelope_digest: assertDigest(
      descriptorValue(terminalDescriptors, "dispatch_envelope_digest"),
      `${terminalLabel}.dispatch_envelope_digest`,
    ),
    delegated_descriptor_identity_digest: assertDigest(
      descriptorValue(terminalDescriptors, "delegated_descriptor_identity_digest"),
      `${terminalLabel}.delegated_descriptor_identity_digest`,
    ),
    response_digest: terminalResponseDigest,
    vault_sink_descriptor_identity_digest: assertDigest(
      descriptorValue(terminalDescriptors, "vault_sink_descriptor_identity_digest"),
      `${terminalLabel}.vault_sink_descriptor_identity_digest`,
    ),
    vault_sink_record_digest: assertDigest(
      descriptorValue(terminalDescriptors, "vault_sink_record_digest"),
      `${terminalLabel}.vault_sink_record_digest`,
    ),
    production_ready: assertExactBoolean(
      descriptorValue(terminalDescriptors, "production_ready"),
      false,
      `${terminalLabel}.production_ready`,
    ),
    hardware_access_authorized: assertExactBoolean(
      descriptorValue(terminalDescriptors, "hardware_access_authorized"),
      false,
      `${terminalLabel}.hardware_access_authorized`,
    ),
    authoritative: assertExactBoolean(
      descriptorValue(terminalDescriptors, "authoritative"),
      false,
      `${terminalLabel}.authoritative`,
    ),
  });
  if (terminal.dispatch_envelope_digest === ZERO_DIGEST
      || terminal.delegated_descriptor_identity_digest === ZERO_DIGEST
      || terminal.vault_sink_descriptor_identity_digest === ZERO_DIGEST
      || terminal.vault_sink_record_digest === ZERO_DIGEST) {
    throw new Error(`${terminalLabel} contains a zero committed binding digest`);
  }
  return objectFreeze({
    lineage: descriptorValue(descriptors, "lineage"),
    native_terminal_result: terminal,
    execution_claim_receipt_digest: assertDigest(
      descriptorValue(descriptors, "execution_claim_receipt_digest"),
      `${label}.execution_claim_receipt_digest`,
    ),
    deadline_fence_receipt_digest: assertDigest(
      descriptorValue(descriptors, "deadline_fence_receipt_digest"),
      `${label}.deadline_fence_receipt_digest`,
    ),
  });
}

function parseAndValidateRecord(state, request, record) {
  if (record.length < NATIVE_PROVIDER_RESPONSE_RECORD_HEADER_BYTES
      || record.length > NATIVE_PROVIDER_RESPONSE_RECORD_HEADER_BYTES + state.byte_ceiling
      || !record.subarray(0, 8).equals(NATIVE_PROVIDER_RESPONSE_RECORD_MAGIC)
      || record.readUInt16BE(8) !== NATIVE_PROVIDER_RESPONSE_VAULT_VERSION) {
    throw new Error("native provider response record framing is invalid");
  }
  const status = record.readUInt16BE(10);
  const terminal = request.native_terminal_result;
  const expectedStatus = terminal.status === "ambiguous_quarantined" ? 2 : 3;
  if (status !== expectedStatus) {
    throw new Error("native provider response record terminal status drifted");
  }
  const responseLength = record.readUInt32BE(12);
  if (record.length !== NATIVE_PROVIDER_RESPONSE_RECORD_HEADER_BYTES + responseLength) {
    throw new Error("native provider response record length is invalid");
  }
  if (status === 3 && responseLength < 10) {
    throw new Error("complete native provider response must contain a complete frame");
  }
  const ticketSequence = record.readBigUInt64BE(16).toString(10);
  const fieldDigest = (offset) => record.subarray(offset, offset + 32).toString("hex");
  const executionLineageDigest = fieldDigest(24);
  const dispatchEnvelopeDigest = fieldDigest(56);
  const sourceDescriptorIdentityDigest = fieldDigest(88);
  const sinkDescriptorDigest = fieldDigest(120);
  const reservationDigest = fieldDigest(152);
  const capabilityDigest = fieldDigest(184);
  const handleDigest = fieldDigest(216);
  const recordedResponseDigest = fieldDigest(248);
  const headerDigest = sha256(record.subarray(0, NATIVE_PROVIDER_RESPONSE_RECORD_HEADER_BYTES));
  const response = record.subarray(NATIVE_PROVIDER_RESPONSE_RECORD_HEADER_BYTES);
  const actualResponseDigest = response.length === 0 ? ZERO_DIGEST : sha256(response);

  const lineageExecutionDigest = assertDigest(exactOwnDataValue(
    request.lineage,
    "execution_lineage_digest",
    "native provider response lineage",
  ), "native provider response lineage.execution_lineage_digest");
  const lineageReservationHandle = exactOwnDataValue(
    request.lineage,
    "vault_reservation_handle",
    "native provider response lineage",
  );
  const lineageReservationDigest = assertDigest(exactOwnDataValue(
    request.lineage,
    "vault_reservation_digest",
    "native provider response lineage",
  ), "native provider response lineage.vault_reservation_digest");
  const lineageCapabilityDigest = assertDigest(exactOwnDataValue(
    request.lineage,
    "vault_ingest_capability_digest",
    "native provider response lineage",
  ), "native provider response lineage.vault_ingest_capability_digest");
  const lineageMaximum = exactOwnDataValue(
    request.lineage,
    "maximum_response_bytes",
    "native provider response lineage",
  );
  const lineageVaultCeiling = exactOwnDataValue(
    request.lineage,
    "vault_byte_ceiling",
    "native provider response lineage",
  );
  if (!Number.isSafeInteger(lineageMaximum) || lineageMaximum < 1
      || !Number.isSafeInteger(lineageVaultCeiling) || lineageVaultCeiling < 1) {
    throw new Error("native provider response lineage byte ceilings are invalid");
  }
  if (lineageReservationHandle !== state.sink.vault_reservation_handle
      || !constantTimeDigestEqual(executionLineageDigest, lineageExecutionDigest)
      || !constantTimeDigestEqual(dispatchEnvelopeDigest, terminal.dispatch_envelope_digest)
      || !constantTimeDigestEqual(sourceDescriptorIdentityDigest,
        terminal.delegated_descriptor_identity_digest)
      || !constantTimeDigestEqual(sinkDescriptorDigest, state.sink_descriptor_digest)
      || !constantTimeDigestEqual(sinkDescriptorDigest,
        terminal.vault_sink_descriptor_identity_digest)
      || !constantTimeDigestEqual(reservationDigest, state.sink.vault_reservation_digest)
      || !constantTimeDigestEqual(reservationDigest, lineageReservationDigest)
      || !constantTimeDigestEqual(capabilityDigest,
        state.sink.vault_ingest_capability_digest)
      || !constantTimeDigestEqual(capabilityDigest, lineageCapabilityDigest)
      || !constantTimeDigestEqual(handleDigest, state.artifact_handle_digest)
      || !constantTimeDigestEqual(recordedResponseDigest, actualResponseDigest)
      || !constantTimeDigestEqual(recordedResponseDigest, terminal.response_digest)
      || !constantTimeDigestEqual(headerDigest, terminal.vault_sink_record_digest)
      || ticketSequence !== terminal.ticket_sequence
      || responseLength !== terminal.response_byte_length
      || responseLength > state.byte_ceiling
      || responseLength > lineageMaximum
      || responseLength > lineageVaultCeiling) {
    throw new Error("native provider response record drifted from its exact dispatch or vault binding");
  }
  return objectFreeze({
    response,
    header_digest: headerDigest,
    source_descriptor_identity_digest: sourceDescriptorIdentityDigest,
  });
}

function commitValidatedRecord(state, request, record) {
  const validated = parseAndValidateRecord(state, request, record);
  const terminal = request.native_terminal_result;
  const receipt = commitProviderResponseRawCustody(state.sink, {
    version: PROVIDER_RESPONSE_VAULT_VERSION,
    kind: "commit_provider_response_raw_custody_request",
    lineage: request.lineage,
    execution_claim_receipt_digest: request.execution_claim_receipt_digest,
    deadline_fence_receipt_digest: request.deadline_fence_receipt_digest,
    custody_ref: `raw-custody:native-response-vault:${validated.header_digest}`,
    transport_observation: {
      transport_settlement_kind: `native-settlement:${terminal.status}`,
      dispatch_envelope_digest: terminal.dispatch_envelope_digest,
      source_descriptor_identity_digest: validated.source_descriptor_identity_digest,
      sink_descriptor_identity_digest: terminal.vault_sink_descriptor_identity_digest,
      sink_record_digest: terminal.vault_sink_record_digest,
      ticket_sequence: terminal.ticket_sequence,
      settled_monotonic_ns: terminal.settled_continuous_ns,
    },
    response_bytes: validated.response,
  });
  return assertProviderResponseRawCustodyReceipt(receipt);
}

function readOwnedRecord(state) {
  const revokeErrors = [];
  closeWriteDescriptorForCleanup(state, revokeErrors);
  if (revokeErrors.length > 0) throw cleanupReconciliationError(revokeErrors);
  const before = assertSafeSinkStats(
    fs.fstatSync(state.owner_fd, { bigint: true }),
    "native provider response owner descriptor",
  );
  const pathStats = assertSafeSinkStats(
    fs.lstatSync(state.file_path, { bigint: true }),
    "native provider response sink path",
  );
  if (!sameIdentity(before, state.identity) || !sameIdentity(pathStats, state.identity)
      || before.size < BigInt(NATIVE_PROVIDER_RESPONSE_RECORD_HEADER_BYTES)
      || before.size > BigInt(NATIVE_PROVIDER_RESPONSE_RECORD_HEADER_BYTES + state.byte_ceiling)) {
    throw new Error("native provider response sink file identity or size is invalid");
  }
  const output = bufferAlloc(Number(before.size));
  try {
    let offset = 0;
    while (offset < output.length) {
      const count = fs.readSync(state.owner_fd, output, offset, output.length - offset, offset);
      if (count === 0) throw new Error("native provider response sink changed while reading");
      offset += count;
    }
    const after = fs.fstatSync(state.owner_fd, { bigint: true });
    const afterPath = fs.lstatSync(state.file_path, { bigint: true });
    if (!sameIdentity(after, before) || after.size !== before.size
        || !sameIdentity(afterPath, before)) {
      throw new Error("native provider response sink changed while reading");
    }
    return output;
  } catch (error) {
    output.fill(0);
    throw error;
  }
}

function beginOneUseSinkAction(state, lifecycle) {
  state.owner.assert_live();
  if (state.lifecycle !== "active") {
    throw new Error("native provider response sink is one-use and no longer active");
  }
  state.lifecycle = lifecycle;
}

function finishOneUseSinkAction(state, actionError) {
  let cleanupError = null;
  try {
    reconcileOwnedRecordCleanup(state);
  } catch (error) {
    cleanupError = error;
  }
  if (actionError && cleanupError) {
    throw new AggregateError(
      [actionError, cleanupError],
      "native provider response action failed and plaintext cleanup could not be reconciled",
    );
  }
  if (cleanupError) throw cleanupError;
  if (actionError) throw actionError;
}

function revokeReservationAfterFailedSinkAction(state, actionError) {
  try {
    state.owner.release_reservation(
      state.sink.vault_reservation_handle,
      "reason:native-provider-response-settlement-rejected",
    );
    return actionError;
  } catch (releaseError) {
    return new AggregateError(
      [actionError, releaseError],
      "native provider response action failed and its vault reservation could not be revoked",
    );
  }
}

function consumeNativeProviderResponseRecord(port, input) {
  assertNativeProviderResponseSink(port);
  const state = PORT_PRIVATE.get(port);
  beginOneUseSinkAction(state, "consuming_native_record");
  let result;
  let actionError = null;
  let record = null;
  try {
    const request = normalizeConsumeRequest(input);
    record = readOwnedRecord(state);
    result = commitValidatedRecord(state, request, record);
  } catch (error) {
    actionError = revokeReservationAfterFailedSinkAction(state, error);
  } finally {
    if (record) record.fill(0);
  }
  finishOneUseSinkAction(state, actionError);
  confirmProviderResponseRawCustodyPlaintextCleanup(state.vault, result);
  return result;
}

function cancelNativeProviderResponseSink(port) {
  assertNativeProviderResponseSink(port);
  const state = PORT_PRIVATE.get(port);
  beginOneUseSinkAction(state, "cancelling");
  let release = null;
  let actionError = null;
  try {
    release = state.owner.release_reservation(
      state.sink.vault_reservation_handle,
      "reason:native-provider-response-sink-cancelled",
    );
  } catch (error) {
    actionError = error;
  }
  finishOneUseSinkAction(state, actionError);
  return objectFreeze({
    version: NATIVE_PROVIDER_RESPONSE_VAULT_VERSION,
    kind: "native_provider_response_sink_cancelled",
    vault_reservation_digest: state.sink.vault_reservation_digest,
    vault_ingest_capability_digest: state.sink.vault_ingest_capability_digest,
    reservation_release_receipt_digest: release.release_receipt,
    production_ready: false,
    hardware_access_authorized: false,
    authoritative: false,
  });
}

module.exports = objectFreeze({
  NATIVE_PROVIDER_RESPONSE_RECORD_HEADER_BYTES,
  NATIVE_PROVIDER_RESPONSE_VAULT_ASSURANCE,
  NATIVE_PROVIDER_RESPONSE_VAULT_VERSION,
  assertNativeProviderResponseSink,
  cancelNativeProviderResponseSink,
  consumeNativeProviderResponseRecord,
  nativeProviderResponseSinkWriteDescriptor,
  prepareNativeProviderResponseSink,
  revokeNativeProviderResponseSinkWriteDescriptor,
});
