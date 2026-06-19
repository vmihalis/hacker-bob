"use strict";

const fs = require("fs");
const crypto = require("crypto");
const os = require("os");
const path = require("path");
const {
  SESSION_LOCK_NAME,
  SESSION_LOCK_STALE_MS,
} = require("./constants.js");
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
const sessionLockReleaseHooks = [];

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

function tryAcquireSessionLock(lockPathValue) {
  const token = `${process.pid}-${Date.now()}-${Math.random().toString(16).slice(2)}`;
  const payload = `${JSON.stringify({
    pid: process.pid,
    hostname: os.hostname(),
    timestamp: new Date().toISOString(),
    token,
  }, null, 2)}\n`;
  return writeFileExclusiveAtomic(lockPathValue, payload, { mode: 0o600 })
    ? token
    : null;
}

function readLockIdentity(lockPathValue) {
  try {
    const stats = fs.statSync(lockPathValue);
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
    stats = fs.statSync(lockPathValue);
  } catch {
    return;
  }

  const sameOwnedFile = sameLockIdentity(stats, identity);
  if (identity && !sameOwnedFile) {
    return;
  }

  let tokenMatches = false;
  try {
    const current = JSON.parse(fs.readFileSync(lockPathValue, "utf8"));
    tokenMatches = current && typeof current === "object" && current.token === token;
  } catch {}

  if (tokenMatches || sameOwnedFile) {
    try { fs.rmSync(lockPathValue, { force: true }); } catch {}
  }
}

function readSessionLockSnapshot(lockPathValue) {
  let stats;
  try {
    stats = fs.statSync(lockPathValue);
  } catch {
    return null;
  }

  let timestampMs = Number.NaN;
  let contentHash = null;
  if (stats.isFile()) {
    try {
      const content = fs.readFileSync(lockPathValue, "utf8");
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
    currentStats = fs.statSync(lockPathValue);
  } catch {
    return false;
  }
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
        .update(fs.readFileSync(lockPathValue, "utf8"))
        .digest("hex");
    } catch {
      return false;
    }
    if (currentContentHash !== snapshot.contentHash) {
      return false;
    }
  }

  fs.rmSync(lockPathValue, { recursive: snapshot.isDirectory, force: true });
  return true;
}

function acquireSessionLock(domain) {
  const dir = sessionDir(domain);
  fs.mkdirSync(dir, { recursive: true });

  const lockPathValue = sessionLockPath(domain);
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const token = tryAcquireSessionLock(lockPathValue);
    if (token) {
      const identity = readLockIdentity(lockPathValue);
      return () => releaseSessionLock(lockPathValue, token, identity);
    }

    const staleSnapshot = readSessionLockSnapshot(lockPathValue);
    if (attempt === 0 && staleSnapshot && staleSnapshot.isStale) {
      try {
        removeStaleSessionLock(lockPathValue, staleSnapshot);
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
    activeSessionLocks.set(lockKey, heldCount + 1);
    try {
      const result = callback();
      if (result && typeof result.then === "function") {
        throw new Error("withSessionLock callback must be synchronous");
      }
      return result;
    } finally {
      const nextCount = (activeSessionLocks.get(lockKey) || 1) - 1;
      if (nextCount > 0) activeSessionLocks.set(lockKey, nextCount);
      else activeSessionLocks.delete(lockKey);
    }
  }

  const release = acquireSessionLock(domain);
  activeSessionLocks.set(lockKey, 1);
  let result;
  let callbackFailed = false;
  try {
    result = callback();
    if (result && typeof result.then === "function") {
      throw new Error("withSessionLock callback must be synchronous");
    }
  } catch (error) {
    callbackFailed = true;
    activeSessionLocks.delete(lockKey);
    release();
    throw error;
  }
  activeSessionLocks.delete(lockKey);
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
  isSessionDirEffectivelyEmpty,
  loadJsonDocumentStrict,
  readFileUtf8,
  readJsonFile,
  registerSessionLockReleaseHook,
  trimJsonlFile,
  readSessionLockSnapshot,
  removeStaleSessionLock,
  tryAcquireSessionLock,
  withSessionLock,
  writeFileAtomic,
  writeFileExclusiveAtomic,
  writeMarkdownMirror,
};
