"use strict";

// Whole-engine singleton election for one user-owned session root.
//
// A live owner is never timed out or displaced. A crash-left lock may be
// reclaimed only when it is a bounded, private, single-link regular file,
// names this exact host, and the kernel reports that its PID does not exist.
// Malformed, foreign-host, inaccessible, symlinked, hard-linked, or otherwise
// ambiguous locks fail closed. This preserves the second-engine bypass
// defense without turning SIGKILL or power loss into a permanent installation
// latch.

const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const {
  engineLockPath,
} = require("./paths.js");
const {
  writeFileExclusiveAtomic,
} = require("./storage.js");

const ENGINE_LOCK_RECORD_VERSION = 1;
const MAX_ENGINE_LOCK_BYTES = 4096;
const MAX_ENGINE_LOCK_TOKEN_BYTES = 512;

let heldLock = null;

function sameFileIdentity(left, right) {
  return left != null && right != null
    && left.dev === right.dev
    && left.ino === right.ino;
}

function assertSessionRoot(lockPathValue) {
  const rootPath = path.dirname(lockPathValue);
  fs.mkdirSync(rootPath, { recursive: true, mode: 0o700 });
  const stats = fs.lstatSync(rootPath);
  if (!stats.isDirectory() || stats.isSymbolicLink()) {
    throw new Error("engine singleton lock root must be a real directory");
  }
  if (typeof process.getuid === "function" && stats.uid !== process.getuid()) {
    throw new Error("engine singleton lock root must be owned by this user");
  }
  if ((stats.mode & 0o022) !== 0) {
    throw new Error("engine singleton lock root must not be writable by group or other users");
  }
  return Object.freeze({ path: rootPath, dev: stats.dev, ino: stats.ino });
}

function assertSessionRootIdentity(identity) {
  const stats = fs.lstatSync(identity.path);
  if (!stats.isDirectory() || stats.isSymbolicLink()
      || stats.dev !== identity.dev || stats.ino !== identity.ino) {
    throw new Error("engine singleton lock root identity changed");
  }
  if (typeof process.getuid === "function" && stats.uid !== process.getuid()) {
    throw new Error("engine singleton lock root ownership changed");
  }
  if ((stats.mode & 0o022) !== 0) {
    throw new Error("engine singleton lock root permissions changed");
  }
}

function fsyncDirectory(directoryPath) {
  let descriptor;
  try {
    descriptor = fs.openSync(
      directoryPath,
      fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0),
    );
    fs.fsyncSync(descriptor);
  } finally {
    if (descriptor != null) fs.closeSync(descriptor);
  }
}

function assertCanonicalTimestamp(value) {
  if (typeof value !== "string" || Number.isNaN(Date.parse(value))
      || new Date(value).toISOString() !== value) {
    throw new Error("engine singleton lock timestamp is invalid");
  }
  return value;
}

function normalizeLockPayload(input) {
  if (input == null || typeof input !== "object" || Array.isArray(input)) {
    throw new Error("engine singleton lock payload must be an object");
  }
  const legacy = !Object.prototype.hasOwnProperty.call(input, "version");
  const expected = legacy
    ? ["hostname", "pid", "timestamp", "token"]
    : ["hostname", "pid", "timestamp", "token", "version"];
  const keys = Object.keys(input).sort();
  if (keys.length !== expected.length
      || keys.some((field, index) => field !== expected[index])) {
    throw new Error("engine singleton lock payload has an invalid shape");
  }
  if (!legacy && input.version !== ENGINE_LOCK_RECORD_VERSION) {
    throw new Error("engine singleton lock payload version is unsupported");
  }
  if (!Number.isSafeInteger(input.pid) || input.pid < 1) {
    throw new Error("engine singleton lock PID is invalid");
  }
  if (typeof input.hostname !== "string" || input.hostname.length < 1
      || Buffer.byteLength(input.hostname, "utf8") > 255
      || /[\u0000-\u001f\u007f]/u.test(input.hostname)) {
    throw new Error("engine singleton lock hostname is invalid");
  }
  if (typeof input.token !== "string" || input.token.length < 16
      || Buffer.byteLength(input.token, "utf8") > MAX_ENGINE_LOCK_TOKEN_BYTES
      || !/^[A-Za-z0-9._:@-]+$/u.test(input.token)) {
    throw new Error("engine singleton lock token is invalid");
  }
  return Object.freeze({
    version: legacy ? 0 : ENGINE_LOCK_RECORD_VERSION,
    pid: input.pid,
    hostname: input.hostname,
    timestamp: assertCanonicalTimestamp(input.timestamp),
    token: input.token,
  });
}

function readLockSnapshot(lockPathValue, rootIdentity) {
  assertSessionRootIdentity(rootIdentity);
  let descriptor;
  try {
    try {
      descriptor = fs.openSync(
        lockPathValue,
        fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0),
      );
    } catch (error) {
      if (error && error.code === "ENOENT") return null;
      throw error;
    }
    const before = fs.fstatSync(descriptor);
    if (!before.isFile() || before.nlink !== 1
        || before.size < 1 || before.size > MAX_ENGINE_LOCK_BYTES) {
      throw new Error("engine singleton lock must be a bounded single-link regular file");
    }
    if (typeof process.getuid === "function" && before.uid !== process.getuid()) {
      throw new Error("engine singleton lock must be owned by this user");
    }
    if ((before.mode & 0o077) !== 0) {
      throw new Error("engine singleton lock must deny group and other access");
    }
    const bytes = Buffer.alloc(before.size);
    let offset = 0;
    while (offset < bytes.length) {
      const count = fs.readSync(descriptor, bytes, offset, bytes.length - offset, offset);
      if (count === 0) throw new Error("engine singleton lock was truncated while reading");
      offset += count;
    }
    const after = fs.fstatSync(descriptor);
    if (!sameFileIdentity(before, after) || after.size !== before.size || after.nlink !== 1) {
      throw new Error("engine singleton lock changed while reading");
    }
    const content = bytes.toString("utf8");
    bytes.fill(0);
    const payload = normalizeLockPayload(JSON.parse(content));
    assertSessionRootIdentity(rootIdentity);
    return Object.freeze({
      identity: Object.freeze({ dev: before.dev, ino: before.ino }),
      size: before.size,
      content_digest: crypto.createHash("sha256").update(content, "utf8").digest("hex"),
      payload,
    });
  } finally {
    if (descriptor != null) fs.closeSync(descriptor);
  }
}

function ownerLiveness(pid) {
  try {
    process.kill(pid, 0);
    return "alive";
  } catch (error) {
    return error && error.code === "ESRCH" ? "dead" : "unknown";
  }
}

function sameSnapshot(left, right) {
  return left != null && right != null
    && sameFileIdentity(left.identity, right.identity)
    && left.size === right.size
    && left.content_digest === right.content_digest;
}

function reclaimDeadOwnerLock(lockPathValue, rootIdentity, snapshot) {
  if (snapshot.payload.hostname !== os.hostname()
      || ownerLiveness(snapshot.payload.pid) !== "dead") {
    return false;
  }
  let current;
  try {
    current = readLockSnapshot(lockPathValue, rootIdentity);
  } catch {
    return false;
  }
  if (!sameSnapshot(snapshot, current)
      || current.payload.hostname !== os.hostname()
      || ownerLiveness(current.payload.pid) !== "dead") {
    return false;
  }
  assertSessionRootIdentity(rootIdentity);
  const atPath = fs.lstatSync(lockPathValue);
  if (!atPath.isFile() || atPath.isSymbolicLink()
      || !sameFileIdentity(atPath, current.identity) || atPath.nlink !== 1) {
    return false;
  }
  fs.unlinkSync(lockPathValue);
  fsyncDirectory(rootIdentity.path);
  assertSessionRootIdentity(rootIdentity);
  return true;
}

function createOwnedLock(lockPathValue, rootIdentity, token) {
  const payload = `${JSON.stringify({
    version: ENGINE_LOCK_RECORD_VERSION,
    pid: process.pid,
    hostname: os.hostname(),
    timestamp: new Date().toISOString(),
    token,
  }, null, 2)}\n`;
  assertSessionRootIdentity(rootIdentity);
  const created = writeFileExclusiveAtomic(lockPathValue, payload, { mode: 0o600 });
  assertSessionRootIdentity(rootIdentity);
  if (!created) return null;
  fsyncDirectory(rootIdentity.path);
  const snapshot = readLockSnapshot(lockPathValue, rootIdentity);
  if (!snapshot || snapshot.payload.version !== ENGINE_LOCK_RECORD_VERSION
      || snapshot.payload.pid !== process.pid || snapshot.payload.hostname !== os.hostname()
      || snapshot.payload.token !== token) {
    throw new Error("engine singleton lock publication could not be authenticated");
  }
  return snapshot;
}

function acquireEngineSingletonLock() {
  if (heldLock) throw new Error("engine singleton lock already held by this process");
  const lockPathValue = engineLockPath();
  const rootIdentity = assertSessionRoot(lockPathValue);
  const token = `${process.pid}-${Date.now()}-${crypto.randomBytes(18).toString("base64url")}`;

  let snapshot = createOwnedLock(lockPathValue, rootIdentity, token);
  if (snapshot == null) {
    let existing;
    try {
      existing = readLockSnapshot(lockPathValue, rootIdentity);
    } catch {
      return false;
    }
    if (!existing || !reclaimDeadOwnerLock(lockPathValue, rootIdentity, existing)) return false;
    snapshot = createOwnedLock(lockPathValue, rootIdentity, token);
    if (snapshot == null) return false;
  }

  heldLock = Object.freeze({
    lockPath: lockPathValue,
    rootIdentity,
    token,
    identity: snapshot.identity,
  });
  return true;
}

function releaseEngineSingletonLock() {
  if (!heldLock) return;
  const owned = heldLock;
  heldLock = null;
  try {
    const snapshot = readLockSnapshot(owned.lockPath, owned.rootIdentity);
    if (!snapshot || !sameFileIdentity(snapshot.identity, owned.identity)
        || snapshot.payload.pid !== process.pid
        || snapshot.payload.hostname !== os.hostname()
        || snapshot.payload.token !== owned.token) {
      return;
    }
    assertSessionRootIdentity(owned.rootIdentity);
    const atPath = fs.lstatSync(owned.lockPath);
    if (!atPath.isFile() || atPath.isSymbolicLink()
        || !sameFileIdentity(atPath, owned.identity) || atPath.nlink !== 1) {
      return;
    }
    fs.unlinkSync(owned.lockPath);
    fsyncDirectory(owned.rootIdentity.path);
  } catch {}
}

function _isEngineSingletonLockHeldForTest() {
  return heldLock != null;
}

module.exports = {
  acquireEngineSingletonLock,
  releaseEngineSingletonLock,
  _isEngineSingletonLockHeldForTest,
};
