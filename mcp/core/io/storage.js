"use strict";

const fs = require("fs");
const crypto = require("crypto");
const os = require("os");
const path = require("path");
const {
  SESSION_LOCK_NAME,
  SESSION_LOCK_STALE_MS,
} = require("../session/session-state-vocabulary.js");
const {
  sessionDir,
  sessionLockPath,
} = require("./paths.js");
const {
  ERROR_CODES,
  ToolError,
} = require("./envelope.js");

const DEFAULT_ARTIFACT_READ_MAX_BYTES = 16 * 1024 * 1024;
const activeSessionLocks = new Map();
const activeSessionLockDirectoryIdentities = new Map();
const sessionLockReleaseHooks = [];

function ensureParentDir(filePath) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
}

function readJsonlStrict(filePath, label, normalizeRecord) {
  if (!fs.existsSync(filePath)) return [];
  const raw = readFileUtf8(filePath, { label });
  const lines = raw.split(/\r?\n/).filter((line) => line.trim().length > 0);
  const records = [];
  for (let i = 0; i < lines.length; i++) {
    let parsed;
    try {
      parsed = JSON.parse(lines[i]);
    } catch (error) {
      throw new Error(`Malformed ${label} at line ${i + 1}: ${error.message || String(error)}`);
    }
    records.push(normalizeRecord ? normalizeRecord(parsed, i) : parsed);
  }
  return records;
}

function writeJsonDocument(filePath, document) {
  writeFileAtomic(filePath, `${JSON.stringify(document, null, 2)}\n`);
}

function registerSessionLockReleaseHook(callback) {
  if (typeof callback !== "function") {
    throw new Error("session-lock release hook must be a function");
  }
  if (!sessionLockReleaseHooks.includes(callback)) {
    sessionLockReleaseHooks.push(callback);
  }
  return () => {
    const index = sessionLockReleaseHooks.indexOf(callback);
    if (index >= 0) sessionLockReleaseHooks.splice(index, 1);
  };
}

function runSessionLockReleaseHooks(domain) {
  // Best-effort fan-out: a misbehaving hook must not regress the producer or
  // leave another hook unfired. Hooks run after the lock is released and
  // re-acquire it themselves if they need it.
  for (const hook of sessionLockReleaseHooks.slice()) {
    try {
      hook(domain);
    } catch {}
  }
}

function readFileUtf8(filePath, {
  label = path.basename(filePath),
  maxBytes = DEFAULT_ARTIFACT_READ_MAX_BYTES,
} = {}) {
  if (maxBytes != null && (!Number.isInteger(maxBytes) || maxBytes < 1)) {
    throw new Error("maxBytes must be a positive integer");
  }
  const stats = fs.statSync(filePath);
  if (maxBytes != null && stats.size > maxBytes) {
    throw new Error(`${label} exceeds read cap of ${maxBytes} bytes: ${filePath}`);
  }
  return fs.readFileSync(filePath, "utf8");
}

function readJsonFile(filePath, options = {}) {
  return JSON.parse(readFileUtf8(filePath, options));
}

function writeFileAtomic(filePath, content) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  const tempPath = siblingTempPath(filePath);
  try {
    fs.writeFileSync(tempPath, content);
    fs.renameSync(tempPath, filePath);
  } finally {
    try { fs.unlinkSync(tempPath); } catch {}
  }
}

function siblingTempPath(filePath) {
  return path.join(
    path.dirname(filePath),
    `.${path.basename(filePath)}.${process.pid}.${Date.now()}.${Math.random().toString(16).slice(2)}.tmp`,
  );
}

function writeFileExclusiveAtomic(filePath, content, { mode } = {}) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  const tempPath = siblingTempPath(filePath);
  const writeOptions = { flag: "wx" };
  if (mode != null) writeOptions.mode = mode;
  try {
    fs.writeFileSync(tempPath, content, writeOptions);
    try {
      fs.linkSync(tempPath, filePath);
      return true;
    } catch (error) {
      if (error && error.code === "EEXIST") return false;
      throw error;
    }
  } finally {
    try { fs.unlinkSync(tempPath); } catch {}
  }
}

function normalizeMaxJsonlRecords(maxRecords) {
  if (maxRecords == null) return null;
  if (!Number.isInteger(maxRecords) || maxRecords < 1) {
    throw new Error("maxRecords must be a positive integer");
  }
  return maxRecords;
}

function trimJsonlFile(filePath, maxRecords) {
  const normalizedMaxRecords = normalizeMaxJsonlRecords(maxRecords);
  if (normalizedMaxRecords == null || !fs.existsSync(filePath)) {
    return { trimmed: false, total: 0, retained: 0 };
  }

  // Retention is the recovery path for oversized JSONL artifacts, so it must
  // be able to read and trim files that already exceed the normal read cap.
  const content = readFileUtf8(filePath, { label: path.basename(filePath), maxBytes: null });
  const lines = content.split("\n").filter((line) => line.trim());
  if (lines.length <= normalizedMaxRecords) {
    return { trimmed: false, total: lines.length, retained: lines.length };
  }

  const retainedLines = lines.slice(-normalizedMaxRecords);
  writeFileAtomic(filePath, `${retainedLines.join("\n")}\n`);
  return { trimmed: true, total: lines.length, retained: retainedLines.length };
}

function appendJsonlLines(filePath, documents, { maxRecords = null } = {}) {
  const normalizedMaxRecords = normalizeMaxJsonlRecords(maxRecords);
  if (!Array.isArray(documents)) {
    throw new Error("documents must be an array");
  }
  if (documents.length === 0) {
    return;
  }

  // Contract: session-owned callers must hold withSessionLock. This helper is
  // intentionally low-level so tests and non-session artifacts can use it too.
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.appendFileSync(
    filePath,
    `${documents.map((document) => JSON.stringify(document)).join("\n")}\n`,
    "utf8",
  );
  if (normalizedMaxRecords != null) {
    trimJsonlFile(filePath, normalizedMaxRecords);
  }
}

function appendJsonlLine(filePath, document, { maxRecords = null } = {}) {
  appendJsonlLines(filePath, [document], { maxRecords });
}

function writeMarkdownMirror(markdownPath, content, response) {
  try {
    writeFileAtomic(markdownPath, content);
    response.written_md = markdownPath;
  } catch (error) {
    response.markdown_sync_error = error.message || String(error);
  }
}

function appendMarkdownMirror(markdownPath, content, response) {
  try {
    fs.mkdirSync(path.dirname(markdownPath), { recursive: true });
    fs.appendFileSync(markdownPath, content, "utf8");
    response.written_md = markdownPath;
  } catch (error) {
    response.markdown_sync_error = error.message || String(error);
  }
}

function loadJsonDocumentStrict(filePath, label) {
  if (!fs.existsSync(filePath)) {
    throw new Error(`Missing ${label}: ${filePath}`);
  }

  const raw = readFileUtf8(filePath, { label });
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (error) {
    throw new Error(`Malformed ${label}: ${filePath} (${error.message || String(error)})`);
  }

  if (parsed == null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error(`Malformed ${label}: ${filePath} (expected object)`);
  }

  return parsed;
}

function isSessionDirEffectivelyEmpty(dirPath) {
  if (!fs.existsSync(dirPath)) {
    return true;
  }

  const entries = fs.readdirSync(dirPath).filter((entry) => entry !== SESSION_LOCK_NAME);
  return entries.length === 0;
}

function lstatIfPresent(filePath) {
  try {
    return fs.lstatSync(filePath);
  } catch (error) {
    if (error && error.code === "ENOENT") return null;
    throw error;
  }
}

function realDirectoryIdentity(directoryPath, label, { create = false, recursive = false } = {}) {
  let stats = lstatIfPresent(directoryPath);
  if (stats == null && create) {
    try {
      fs.mkdirSync(directoryPath, { recursive, mode: 0o700 });
    } catch (error) {
      // Another process may have won the create race. The lstat below decides
      // whether the winner created the exact real directory we require.
      if (!error || error.code !== "EEXIST") throw error;
    }
    stats = lstatIfPresent(directoryPath);
  }
  if (!stats || !stats.isDirectory() || stats.isSymbolicLink()) {
    throw new Error(`${label} must be a real directory, not a symbolic link`);
  }
  return Object.freeze({
    path: directoryPath,
    dev: stats.dev,
    ino: stats.ino,
  });
}

function assertRealDirectoryIdentity(identity, label) {
  const stats = lstatIfPresent(identity.path);
  if (
    !stats
    || !stats.isDirectory()
    || stats.isSymbolicLink()
    || stats.dev !== identity.dev
    || stats.ino !== identity.ino
  ) throw new Error(`${label} changed during session lock operation`);
}

// Capture both path components that anchor .session.lock. Node's synchronous
// filesystem API does not expose openat(2), so callers also recheck these
// identities immediately around pathname-based lock and persistence syscalls.
// This rejects pre-existing symlinks and narrows rename/swap races to the
// unavoidable interval between the final identity check and one syscall.
function ensureSafeSessionDirectory(domain) {
  const dirPath = sessionDir(domain);
  const rootPath = path.dirname(dirPath);
  const root = realDirectoryIdentity(rootPath, "Hacker Bob sessions root", {
    create: true,
    recursive: true,
  });
  const directory = realDirectoryIdentity(dirPath, "Hacker Bob session directory", {
    create: true,
    recursive: false,
  });
  assertRealDirectoryIdentity(root, "Hacker Bob sessions root");
  return Object.freeze({ root, directory });
}

function assertSafeSessionDirectoryIdentity(identity) {
  if (!identity || !identity.root || !identity.directory) {
    throw new Error("session directory identity is required");
  }
  assertRealDirectoryIdentity(identity.root, "Hacker Bob sessions root");
  assertRealDirectoryIdentity(identity.directory, "Hacker Bob session directory");
  if (path.dirname(identity.directory.path) !== identity.root.path) {
    throw new Error("Hacker Bob session directory is not anchored under the sessions root");
  }
  return identity;
}

function safeSessionLockStats(lockPathValue) {
  const stats = lstatIfPresent(lockPathValue);
  if (stats == null) return null;
  if (stats.isSymbolicLink()) {
    throw new Error("Session lock path must not be a symbolic link");
  }
  if (!stats.isFile() && !stats.isDirectory()) {
    throw new Error("Session lock path must be a regular file or legacy lock directory");
  }
  if (stats.isFile() && stats.nlink !== 1) {
    throw new Error("Session lock path must be a single-link regular file");
  }
  return stats;
}

function readSessionLockFile(lockPathValue, expectedStats) {
  let descriptor;
  try {
    descriptor = fs.openSync(
      lockPathValue,
      fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0),
    );
    const stats = fs.fstatSync(descriptor);
    if (
      !stats.isFile()
      || stats.nlink !== 1
      || (expectedStats && (stats.dev !== expectedStats.dev || stats.ino !== expectedStats.ino))
    ) throw new Error("Session lock file identity changed during verified read");
    if (stats.size > 64 * 1024) throw new Error("Session lock file exceeds the verified read cap");
    return fs.readFileSync(descriptor, "utf8");
  } catch (error) {
    if (error && ["ELOOP", "EMLINK"].includes(error.code)) {
      throw new Error("Session lock path must not be a symbolic link");
    }
    throw error;
  } finally {
    if (descriptor != null) fs.closeSync(descriptor);
  }
}

function writeSessionLockExclusiveAtomic(lockPathValue, payload, directoryIdentity) {
  let descriptor;
  let createdIdentity = null;
  let completed = false;
  try {
    assertSafeSessionDirectoryIdentity(directoryIdentity);
    try {
      // Create the final lock inode directly. Publishing a completed sibling
      // through link(2) leaves a legitimate nlink=2 interval until the sibling
      // is removed; a concurrent contender must reject multi-link lock files,
      // so that interval is indistinguishable from a hard-link attack. O_EXCL
      // is already the atomic election primitive and O_NOFOLLOW closes the
      // final-component symlink path without introducing that ambiguity.
      descriptor = fs.openSync(
        lockPathValue,
        fs.constants.O_CREAT
          | fs.constants.O_EXCL
          | fs.constants.O_WRONLY
          | (fs.constants.O_NOFOLLOW || 0),
        0o600,
      );
    } catch (error) {
      if (error && error.code === "EEXIST") return false;
      throw error;
    }
    const openedStats = fs.fstatSync(descriptor);
    if (!openedStats.isFile() || openedStats.nlink !== 1) {
      throw new Error("Session lock creation did not produce a single-link regular file");
    }
    createdIdentity = { dev: openedStats.dev, ino: openedStats.ino };
    fs.writeFileSync(descriptor, payload, "utf8");
    fs.fsyncSync(descriptor);
    fs.closeSync(descriptor);
    descriptor = null;
    assertSafeSessionDirectoryIdentity(directoryIdentity);
    const finalStats = safeSessionLockStats(lockPathValue);
    if (!finalStats
        || finalStats.dev !== createdIdentity.dev
        || finalStats.ino !== createdIdentity.ino) {
      throw new Error("Session lock file identity changed during creation");
    }
    completed = true;
    return true;
  } finally {
    if (descriptor != null) fs.closeSync(descriptor);
    if (!completed && createdIdentity) {
      try {
        // Remove only the exact inode this call created. If the verified parent
        // or final component changed, leave it for operator recovery rather
        // than unlinking an attacker-selected path.
        assertSafeSessionDirectoryIdentity(directoryIdentity);
        const stats = safeSessionLockStats(lockPathValue);
        if (stats
            && stats.isFile()
            && stats.dev === createdIdentity.dev
            && stats.ino === createdIdentity.ino) {
          fs.unlinkSync(lockPathValue);
        }
      } catch {}
    }
  }
}

function tryAcquireSessionLock(lockPathValue, directoryIdentity) {
  if (
    !directoryIdentity
    || path.dirname(lockPathValue) !== directoryIdentity.directory.path
    || path.basename(lockPathValue) !== SESSION_LOCK_NAME
  ) throw new Error("Session lock path is not anchored in the verified session directory");
  assertSafeSessionDirectoryIdentity(directoryIdentity);
  // Refuse a hostile final component before creating even the sibling temp.
  safeSessionLockStats(lockPathValue);
  const token = `${process.pid}-${Date.now()}-${Math.random().toString(16).slice(2)}`;
  const payload = `${JSON.stringify({
    pid: process.pid,
    hostname: os.hostname(),
    timestamp: new Date().toISOString(),
    token,
  }, null, 2)}\n`;
  const created = writeSessionLockExclusiveAtomic(lockPathValue, payload, directoryIdentity);
  assertSafeSessionDirectoryIdentity(directoryIdentity);
  return created ? token : null;
}

function readLockIdentity(lockPathValue) {
  try {
    const stats = safeSessionLockStats(lockPathValue);
    if (!stats) return null;
    return {
      dev: stats.dev,
      ino: stats.ino,
      isDirectory: stats.isDirectory(),
    };
  } catch {
    return null;
  }
}

function sameLockIdentity(stats, identity) {
  if (!stats || !identity) return false;
  return (
    stats.dev === identity.dev &&
    stats.ino === identity.ino &&
    stats.isDirectory() === identity.isDirectory
  );
}

function releaseSessionLock(lockPathValue, token, identity) {
  let stats;
  try {
    stats = safeSessionLockStats(lockPathValue);
  } catch {
    return;
  }
  if (!stats) return;

  const sameOwnedFile = sameLockIdentity(stats, identity);
  if (identity && !sameOwnedFile) {
    return;
  }

  let tokenMatches = false;
  try {
    if (!stats.isFile()) return;
    const current = JSON.parse(readSessionLockFile(lockPathValue, stats));
    tokenMatches = current && typeof current === "object" && current.token === token;
  } catch {}

  if (tokenMatches || sameOwnedFile) {
    try {
      const current = safeSessionLockStats(lockPathValue);
      if (current && sameLockIdentity(current, identity) && current.isFile()) {
        fs.unlinkSync(lockPathValue);
      }
    } catch {}
  }
}

function readSessionLockSnapshot(lockPathValue) {
  let stats;
  try {
    stats = safeSessionLockStats(lockPathValue);
  } catch (error) {
    throw error;
  }
  if (!stats) {
    return null;
  }

  let timestampMs = Number.NaN;
  let contentHash = null;
  if (stats.isFile()) {
    try {
      const content = readSessionLockFile(lockPathValue, stats);
      contentHash = crypto.createHash("sha256").update(content).digest("hex");
      const parsed = JSON.parse(content);
      timestampMs = Date.parse(parsed.timestamp);
    } catch {}
  }

  const staleReferenceMs = Number.isFinite(timestampMs)
    ? Math.min(timestampMs, stats.mtimeMs)
    : stats.mtimeMs;
  return {
    dev: stats.dev,
    ino: stats.ino,
    size: stats.size,
    mtimeMs: stats.mtimeMs,
    isDirectory: stats.isDirectory(),
    contentHash,
    isStale: Date.now() - staleReferenceMs > SESSION_LOCK_STALE_MS,
  };
}

function removeStaleSessionLock(lockPathValue, snapshot) {
  if (!snapshot || !snapshot.isStale) {
    return false;
  }

  let currentStats;
  try {
    currentStats = safeSessionLockStats(lockPathValue);
  } catch {
    return false;
  }
  if (!currentStats) return false;
  if (currentStats.dev !== snapshot.dev || currentStats.ino !== snapshot.ino) {
    return false;
  }
  if (currentStats.isDirectory() !== snapshot.isDirectory) {
    return false;
  }
  if (currentStats.size !== snapshot.size || currentStats.mtimeMs !== snapshot.mtimeMs) {
    return false;
  }
  if (!snapshot.isDirectory) {
    let currentContentHash = null;
    try {
      currentContentHash = crypto
        .createHash("sha256")
        .update(readSessionLockFile(lockPathValue, currentStats))
        .digest("hex");
    } catch {
      return false;
    }
    if (currentContentHash !== snapshot.contentHash) {
      return false;
    }
  }

  if (snapshot.isDirectory) fs.rmdirSync(lockPathValue);
  else fs.unlinkSync(lockPathValue);
  return true;
}

function acquireSessionLock(domain) {
  const dir = sessionDir(domain);
  const directoryIdentity = ensureSafeSessionDirectory(domain);

  const lockPathValue = sessionLockPath(domain);
  for (let attempt = 0; attempt < 2; attempt += 1) {
    assertSafeSessionDirectoryIdentity(directoryIdentity);
    const token = tryAcquireSessionLock(lockPathValue, directoryIdentity);
    if (token) {
      const identity = readLockIdentity(lockPathValue);
      if (!identity || identity.isDirectory) {
        throw new Error("Session lock acquisition did not produce a regular lock file");
      }
      assertSafeSessionDirectoryIdentity(directoryIdentity);
      const release = () => releaseSessionLock(lockPathValue, token, identity);
      Object.defineProperty(release, "sessionDirectoryIdentity", {
        value: directoryIdentity,
        enumerable: false,
        writable: false,
        configurable: false,
      });
      return release;
    }

    const staleSnapshot = readSessionLockSnapshot(lockPathValue);
    if (attempt === 0 && staleSnapshot && staleSnapshot.isStale) {
      try {
        assertSafeSessionDirectoryIdentity(directoryIdentity);
        removeStaleSessionLock(lockPathValue, staleSnapshot);
        assertSafeSessionDirectoryIdentity(directoryIdentity);
      } catch {}
      continue;
    }

    throw new ToolError(ERROR_CODES.STATE_CONFLICT, `Session lock busy: ${dir}`);
  }

  throw new ToolError(ERROR_CODES.STATE_CONFLICT, `Session lock busy: ${dir}`);
}

function withSessionLock(domain, callback) {
  const lockKey = sessionLockPath(domain);
  const heldCount = activeSessionLocks.get(lockKey) || 0;
  if (heldCount > 0) {
    const directoryIdentity = activeSessionLockDirectoryIdentities.get(lockKey);
    assertSafeSessionDirectoryIdentity(directoryIdentity);
    activeSessionLocks.set(lockKey, heldCount + 1);
    try {
      const result = callback(directoryIdentity);
      if (result && typeof result.then === "function") {
        throw new Error("withSessionLock callback must be synchronous");
      }
      return result;
    } finally {
      const nextCount = (activeSessionLocks.get(lockKey) || 1) - 1;
      if (nextCount > 0) activeSessionLocks.set(lockKey, nextCount);
      else {
        activeSessionLocks.delete(lockKey);
        activeSessionLockDirectoryIdentities.delete(lockKey);
      }
    }
  }

  const release = acquireSessionLock(domain);
  const directoryIdentity = release.sessionDirectoryIdentity;
  assertSafeSessionDirectoryIdentity(directoryIdentity);
  activeSessionLocks.set(lockKey, 1);
  activeSessionLockDirectoryIdentities.set(lockKey, directoryIdentity);
  let result;
  let callbackFailed = false;
  try {
    result = callback(directoryIdentity);
    if (result && typeof result.then === "function") {
      throw new Error("withSessionLock callback must be synchronous");
    }
  } catch (error) {
    callbackFailed = true;
    activeSessionLocks.delete(lockKey);
    activeSessionLockDirectoryIdentities.delete(lockKey);
    release();
    throw error;
  }
  activeSessionLocks.delete(lockKey);
  activeSessionLockDirectoryIdentities.delete(lockKey);
  release();
  if (!callbackFailed) {
    // Outermost release: fire deferred hooks (e.g., frontier materialization
    // debounce). Hooks run after the lock is released so they cannot deadlock;
    // hooks that need the lock must re-acquire it themselves.
    runSessionLockReleaseHooks(domain);
  }
  return result;
}

module.exports = {
  DEFAULT_ARTIFACT_READ_MAX_BYTES,
  acquireSessionLock,
  appendJsonlLine,
  appendJsonlLines,
  appendMarkdownMirror,
  ensureParentDir,
  isSessionDirEffectivelyEmpty,
  ensureSafeSessionDirectory,
  assertSafeSessionDirectoryIdentity,
  loadJsonDocumentStrict,
  readFileUtf8,
  readJsonFile,
  readJsonlStrict,
  registerSessionLockReleaseHook,
  trimJsonlFile,
  readSessionLockSnapshot,
  removeStaleSessionLock,
  tryAcquireSessionLock,
  withSessionLock,
  writeFileAtomic,
  writeFileExclusiveAtomic,
  writeJsonDocument,
  writeMarkdownMirror,
};
