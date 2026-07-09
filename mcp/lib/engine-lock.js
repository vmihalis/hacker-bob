"use strict";

// engine-lock.js — fx-gate-bypass defense 1: a process-lifetime, EXCLUSIVE
// singleton lock on the whole engine, keyed on the HOME/EFS session root.
//
// WHY: `claude --dangerously-skip-permissions` lets a prompt-injected model
// spawn its OWN second `node mcp/server.js` engine instance (e.g. `env -u
// BOB_AGENTCORE node .../mcp/server.js`) against the SAME deterministic
// session dir, with the BOB_AGENTCORE-keyed approval gates inert on that
// rogue instance (it controls its own subprocess env). This lock closes that
// specific vector: only ONE `node mcp/server.js` process may ever be serving
// requests against a given HOME's session root at a time.
//
// ROOT-LEVEL, NOT PER-DOMAIN: acquireEngineSingletonLock() is called at
// process boot (mcp/server.js startServer(), before startStdioServer), long
// before any tools/call request names a target_domain. It cannot key on
// mcp/lib/paths.js's sessionLockPath(domain) the way the per-session lock
// does; it keys on engineLockPath() (sessionsRoot()/.engine.lock) instead.
//
// REUSE, NOT REIMPLEMENT: the acquire mechanism is storage.js's
// writeFileExclusiveAtomic — the exact same O_EXCL/'wx' atomic-link primitive
// mcp/lib/storage.js's own acquireSessionLock uses. This module does NOT
// reuse acquireSessionLock/withSessionLock wholesale: their
// staleness-reclaim-after-one-retry policy is correct for short transactional
// per-domain writes (a crashed writer's lock should eventually be
// reclaimable), but it is WRONG here — it would let a rogue second engine
// instance simply wait out (or force past) this lock, defeating the entire
// point of a singleton. This lock is held for the life of the process and is
// released ONLY by an explicit, self-owned call (normally on clean shutdown
// via mcp/server.js's process.on('exit'|'SIGTERM'|'SIGINT') hooks).

const fs = require("fs");
const os = require("os");
const {
  engineLockPath,
} = require("./paths.js");
const {
  writeFileExclusiveAtomic,
} = require("./storage.js");

// In-process state: which lock (if any) THIS process currently holds. Not a
// Map keyed by path (unlike storage.js's activeSessionLocks) because there is
// exactly one engine lock per process, ever — acquireEngineSingletonLock is
// called once, at boot, not nested/re-entrant like withSessionLock.
let heldLock = null; // { lockPath, token, identity } | null

function readLockIdentity(lockPathValue) {
  try {
    const stats = fs.statSync(lockPathValue);
    return { dev: stats.dev, ino: stats.ino };
  } catch {
    return null;
  }
}

function sameLockIdentity(stats, identity) {
  if (!stats || !identity) return false;
  return stats.dev === identity.dev && stats.ino === identity.ino;
}

// Attempts to acquire the whole-engine singleton lock. Returns `true` on
// success (this process now holds it), `false` if another process already
// holds it (the lock file exists and could not be created via the exclusive
// 'wx' write). NEVER retries and NEVER reclaims a "stale" lock — a second
// engine instance must refuse outright, not wait out or steal the first
// instance's lock. Throws if called twice by the same process without an
// intervening release (a programming error, not a runtime contention case).
function acquireEngineSingletonLock() {
  if (heldLock) {
    throw new Error("engine singleton lock already held by this process");
  }
  const lockPathValue = engineLockPath();
  const token = `${process.pid}-${Date.now()}-${Math.random().toString(16).slice(2)}`;
  const payload = `${JSON.stringify({
    pid: process.pid,
    hostname: os.hostname(),
    timestamp: new Date().toISOString(),
    token,
  }, null, 2)}\n`;
  const acquired = writeFileExclusiveAtomic(lockPathValue, payload, { mode: 0o600 });
  if (!acquired) {
    return false;
  }
  heldLock = {
    lockPath: lockPathValue,
    token,
    identity: readLockIdentity(lockPathValue),
  };
  return true;
}

// Safe self-owned release, mirroring storage.js's
// readLockIdentity/releaseSessionLock pattern: only removes the lock file
// when it is STILL the exact same file this process created (dev+ino
// identity match) AND its content still carries this process's own token —
// guards against removing a lock file that a different process replaced
// (e.g. after PID/inode reuse) between acquire and release. No-op if this
// process does not currently hold the lock.
function releaseEngineSingletonLock() {
  if (!heldLock) return;
  const { lockPath, token, identity } = heldLock;
  heldLock = null;
  let stats;
  try {
    stats = fs.statSync(lockPath);
  } catch {
    return;
  }
  if (!sameLockIdentity(stats, identity)) return;
  let tokenMatches = false;
  try {
    const current = JSON.parse(fs.readFileSync(lockPath, "utf8"));
    tokenMatches = current != null && typeof current === "object" && current.token === token;
  } catch {}
  if (tokenMatches) {
    try { fs.rmSync(lockPath, { force: true }); } catch {}
  }
}

// Test-only introspection: whether THIS process currently holds the lock.
function _isEngineSingletonLockHeldForTest() {
  return heldLock != null;
}

module.exports = {
  acquireEngineSingletonLock,
  releaseEngineSingletonLock,
  _isEngineSingletonLockHeldForTest,
};
