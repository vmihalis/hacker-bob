"use strict";

const fs = require("fs");
const crypto = require("crypto");
const path = require("path");
const {
  appendJsonlLine,
  readFileUtf8,
  writeFileExclusiveAtomic,
} = require("../io/storage.js");
const {
  agentRunStopSeenDir,
} = require("../io/paths.js");

const PHANTOM_MARKER_RE = /^[0-9a-f]{16}$/;
const PHANTOM_MARKER_MAX_RECORDS = 5000;
const PHANTOM_SUPPRESSION_MAX_RECORDS = 5000;
const PHANTOM_SUPPRESSION_FILE_NAME = "suppressed.jsonl";
const PHANTOM_LOCK_WAIT_MS = 2000;
const PHANTOM_LOCK_STALE_MS = 30000;
const PHANTOM_LOCK_POLL_MS = 10;
const waitCell = new Int32Array(new SharedArrayBuffer(4));

function phantomTranscriptKey(input) {
  const transcriptPath = input && typeof input.transcript_path === "string"
    ? input.transcript_path.trim()
    : "";
  if (!transcriptPath) return null;
  return crypto.createHash("sha256").update(transcriptPath).digest("hex").slice(0, 16);
}

function markerFile(key, env) {
  return path.join(agentRunStopSeenDir(env), key);
}

function lockFile(key, env) {
  return path.join(agentRunStopSeenDir(env), `${key}.lock`);
}

function suppressionFile(env) {
  return path.join(agentRunStopSeenDir(env), PHANTOM_SUPPRESSION_FILE_NAME);
}

function sameFileIdentity(left, right) {
  return left && right
    && left.dev === right.dev
    && left.ino === right.ino
    && left.size === right.size
    && left.mtimeMs === right.mtimeMs;
}

function removeStaleLock(file) {
  try {
    const before = fs.lstatSync(file);
    if (!before.isFile() || before.isSymbolicLink()) return false;
    if (Date.now() - before.mtimeMs <= PHANTOM_LOCK_STALE_MS) return false;
    const after = fs.lstatSync(file);
    if (!sameFileIdentity(before, after)) return false;
    fs.unlinkSync(file);
    return true;
  } catch {
    return false;
  }
}

function acquireLock(key, env) {
  const file = lockFile(key, env);
  const token = `${process.pid}:${Date.now()}:${crypto.randomBytes(12).toString("hex")}`;
  const deadline = Date.now() + PHANTOM_LOCK_WAIT_MS;
  while (true) {
    try {
      if (writeFileExclusiveAtomic(file, token)) return { file, token };
    } catch {
      return null;
    }
    removeStaleLock(file);
    if (Date.now() >= deadline) return null;
    Atomics.wait(waitCell, 0, 0, PHANTOM_LOCK_POLL_MS);
  }
}

function releaseLock(lock) {
  if (!lock) return;
  try {
    const before = fs.lstatSync(lock.file);
    if (!before.isFile() || before.isSymbolicLink()) return;
    if (readFileUtf8(lock.file, { maxBytes: 512 }) !== lock.token) return;
    const after = fs.lstatSync(lock.file);
    if (!sameFileIdentity(before, after)) return;
    fs.unlinkSync(lock.file);
  } catch {
    // Best-effort telemetry locking must not affect the stop-hook decision.
  }
}

function recordSuppression(key, env) {
  try {
    appendJsonlLine(suppressionFile(env), {
      version: 1,
      ts: new Date().toISOString(),
      transcript_key: key,
    }, { maxRecords: PHANTOM_SUPPRESSION_MAX_RECORDS });
  } catch {
    // Best-effort telemetry must not affect the stop-hook decision.
  }
}

function pruneMarkers(env, retainCount) {
  const dir = agentRunStopSeenDir(env);
  try {
    const markers = fs.readdirSync(dir)
      .filter((name) => PHANTOM_MARKER_RE.test(name))
      .map((name) => {
        try {
          const file = path.join(dir, name);
          const stats = fs.lstatSync(file);
          return stats.isFile() && !stats.isSymbolicLink()
            ? { file, mtimeMs: stats.mtimeMs }
            : null;
        } catch {
          return null;
        }
      })
      .filter(Boolean);
    const excess = markers.length - retainCount;
    if (excess <= 0) return;
    markers
      .sort((left, right) => left.mtimeMs - right.mtimeMs || left.file.localeCompare(right.file))
      .slice(0, excess)
      .forEach((entry) => {
        try { fs.unlinkSync(entry.file); } catch {}
      });
  } catch {
    // Retention is best effort; the next successful first-seen write retries it.
  }
}

function writeBoundedMarker(file, env) {
  const retentionLock = acquireLock("retention", env);
  if (!retentionLock) return false;
  try {
    pruneMarkers(env, PHANTOM_MARKER_MAX_RECORDS - 1);
    return writeFileExclusiveAtomic(file, JSON.stringify({
      version: 2,
      created_at: new Date().toISOString(),
    }));
  } finally {
    releaseLock(retentionLock);
  }
}

function recordPhantomBlockRowOnce(input, recordRow, env = process.env) {
  const key = phantomTranscriptKey(input);
  if (!key) return recordRow();
  const lock = acquireLock(key, env);
  if (!lock) return recordRow();
  try {
    const file = markerFile(key, env);
    if (fs.existsSync(file)) {
      recordSuppression(key, env);
      return undefined;
    }
    if (recordRow() !== true) return undefined;
    try {
      writeBoundedMarker(file, env);
    } catch {
      // The row was recorded, but a broken marker store must not block the hook.
    }
    return undefined;
  } finally {
    releaseLock(lock);
  }
}

function readSuppressedPhantomBlockRows(env = process.env) {
  let content;
  try {
    content = readFileUtf8(suppressionFile(env), { maxBytes: 2 * 1024 * 1024 });
  } catch {
    return {
      scope: "retained_workspace_window",
      total: 0,
      max_records: PHANTOM_SUPPRESSION_MAX_RECORDS,
    };
  }
  let total = 0;
  for (const line of content.split(/\r?\n/)) {
    if (!line.trim()) continue;
    try {
      const entry = JSON.parse(line);
      if (entry && entry.version === 1 && PHANTOM_MARKER_RE.test(entry.transcript_key)) total += 1;
    } catch {
      // Ignore malformed best-effort telemetry records.
    }
  }
  return {
    scope: "retained_workspace_window",
    total,
    max_records: PHANTOM_SUPPRESSION_MAX_RECORDS,
  };
}

module.exports = {
  PHANTOM_MARKER_MAX_RECORDS,
  PHANTOM_SUPPRESSION_MAX_RECORDS,
  readSuppressedPhantomBlockRows,
  recordPhantomBlockRowOnce,
};
