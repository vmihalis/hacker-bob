"use strict";

// Browser-session registry. Wraps mcp/browser-driver.js subprocesses with a
// session_id keyed map, per-domain concurrency cap, idle timeout enforcement,
// and patchright availability detection.
//
// Each entry: { childProcess, sessionId, targetDomain, targetUrl, pending,
//               lastActivity, idleTimer, hardTimer, readyPromise, closed,
//               stdoutBuffer, stderrChunks }
//
// Wire shape on stdin to the subprocess:
//   {"command_id":"<uuid>","command":"<name>","args":{...}}\n
// Wire shape on stdout from the subprocess:
//   {"ready":true,"session_id":"..."}\n  (first line only)
//   {"command_id":"<uuid>","result":...} | {"command_id":"<uuid>","error":"..."}

const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawn } = require("child_process");

const MAX_SESSIONS_PER_DOMAIN = 3;
// Timeouts are mutable so tests can run the reaping path without waiting for
// the real 5-min/30-min budget. Production callers should treat them as
// constants; the reset() helper exists for the test harness only.
const DEFAULT_IDLE_TIMEOUT_MS = 5 * 60 * 1000;
const DEFAULT_HARD_TIMEOUT_MS = 30 * 60 * 1000;
const COMMAND_TIMEOUT_MS = 90_000;
const START_TIMEOUT_MS = 60_000;
const DRIVER_SCRIPT_PATH = path.join(__dirname, "..", "browser-driver.js");

let currentIdleTimeoutMs = DEFAULT_IDLE_TIMEOUT_MS;
let currentHardTimeoutMs = DEFAULT_HARD_TIMEOUT_MS;

function setTimeoutsForTesting({ idleTimeoutMs, hardTimeoutMs } = {}) {
  if (Number.isFinite(idleTimeoutMs)) currentIdleTimeoutMs = idleTimeoutMs;
  if (Number.isFinite(hardTimeoutMs)) currentHardTimeoutMs = hardTimeoutMs;
}

function resetTimeoutsForTesting() {
  currentIdleTimeoutMs = DEFAULT_IDLE_TIMEOUT_MS;
  currentHardTimeoutMs = DEFAULT_HARD_TIMEOUT_MS;
}

const sessions = new Map();
const sessionIdsByDomain = new Map();

function isPatchrightAvailable() {
  try {
    require.resolve("patchright");
    return true;
  } catch {
    return false;
  }
}

function patchrightUnavailableError() {
  const err = new Error(
    "patchright_unavailable: optional dependency patchright is not installed. Run `npm install` and `npx patchright install chromium` to enable the browser-driver MCP tools.",
  );
  err.code = "patchright_unavailable";
  return err;
}

function generateSessionId(targetDomain) {
  const seed = `${targetDomain}|${process.pid}|${Date.now()}|${crypto.randomBytes(8).toString("hex")}`;
  return `bs-${crypto.createHash("sha256").update(seed).digest("hex").slice(0, 24)}`;
}

function activeSessionCountForDomain(targetDomain) {
  const ids = sessionIdsByDomain.get(targetDomain);
  if (!ids) return 0;
  let count = 0;
  for (const id of ids) {
    const entry = sessions.get(id);
    if (entry && !entry.closed) count += 1;
  }
  return count;
}

function trackSession(entry) {
  sessions.set(entry.sessionId, entry);
  let set = sessionIdsByDomain.get(entry.targetDomain);
  if (!set) {
    set = new Set();
    sessionIdsByDomain.set(entry.targetDomain, set);
  }
  set.add(entry.sessionId);
}

function untrackSession(entry) {
  sessions.delete(entry.sessionId);
  const set = sessionIdsByDomain.get(entry.targetDomain);
  if (set) {
    set.delete(entry.sessionId);
    if (!set.size) sessionIdsByDomain.delete(entry.targetDomain);
  }
}

function clearTimers(entry) {
  if (entry.idleTimer) {
    clearTimeout(entry.idleTimer);
    entry.idleTimer = null;
  }
  if (entry.hardTimer) {
    clearTimeout(entry.hardTimer);
    entry.hardTimer = null;
  }
}

function rejectPending(entry, reason) {
  for (const [, deferred] of entry.pending.entries()) {
    deferred.reject(new Error(reason));
  }
  entry.pending.clear();
}

function finalizeEntry(entry, reason = "closed") {
  if (entry.closed) return;
  entry.closed = true;
  clearTimers(entry);
  rejectPending(entry, `session_closed:${reason}`);
  untrackSession(entry);
}

function scheduleIdleTimer(entry) {
  if (entry.idleTimer) clearTimeout(entry.idleTimer);
  entry.idleTimer = setTimeout(() => {
    if (entry.closed) return;
    closeSessionByEntry(entry, "idle_timeout");
  }, currentIdleTimeoutMs);
  if (entry.idleTimer && typeof entry.idleTimer.unref === "function") {
    entry.idleTimer.unref();
  }
}

function scheduleHardTimer(entry) {
  if (entry.hardTimer) clearTimeout(entry.hardTimer);
  entry.hardTimer = setTimeout(() => {
    if (entry.closed) return;
    closeSessionByEntry(entry, "hard_timeout");
  }, currentHardTimeoutMs);
  if (entry.hardTimer && typeof entry.hardTimer.unref === "function") {
    entry.hardTimer.unref();
  }
}

function touchActivity(entry) {
  entry.lastActivity = Date.now();
  scheduleIdleTimer(entry);
}

function handleStdoutLine(entry, line) {
  if (!line) return;
  let payload;
  try {
    payload = JSON.parse(line);
  } catch (err) {
    entry.stderrChunks.push(`unparseable_stdout: ${line.slice(0, 200)}`);
    return;
  }
  if (payload && payload.ready === true && entry.readyResolver) {
    entry.readyResolver(payload);
    entry.readyResolver = null;
    entry.readyRejector = null;
    return;
  }
  if (payload && payload.ready === false && entry.readyRejector) {
    const err = new Error(payload.error || "driver_failed_to_start");
    err.code = payload.code || "driver_start_error";
    entry.readyRejector(err);
    entry.readyResolver = null;
    entry.readyRejector = null;
    return;
  }
  const commandId = payload && payload.command_id;
  if (!commandId) return;
  const deferred = entry.pending.get(commandId);
  if (!deferred) return;
  entry.pending.delete(commandId);
  if (payload.error) {
    const err = new Error(payload.error);
    if (payload.code) err.code = payload.code;
    deferred.reject(err);
    return;
  }
  deferred.resolve(payload.result);
}

function attachChildHandlers(entry, child) {
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk) => {
    entry.stdoutBuffer += chunk;
    let newlineIndex = entry.stdoutBuffer.indexOf("\n");
    while (newlineIndex !== -1) {
      const line = entry.stdoutBuffer.slice(0, newlineIndex).trim();
      entry.stdoutBuffer = entry.stdoutBuffer.slice(newlineIndex + 1);
      handleStdoutLine(entry, line);
      newlineIndex = entry.stdoutBuffer.indexOf("\n");
    }
  });
  child.stderr.on("data", (chunk) => {
    entry.stderrChunks.push(chunk);
    // Keep the buffer bounded so a chatty subprocess does not balloon memory.
    if (entry.stderrChunks.length > 200) {
      entry.stderrChunks.splice(0, entry.stderrChunks.length - 100);
    }
  });
  child.on("error", (err) => {
    if (entry.readyRejector) {
      entry.readyRejector(err);
      entry.readyResolver = null;
      entry.readyRejector = null;
    }
    finalizeEntry(entry, `child_error:${err && err.message ? err.message : err}`);
  });
  child.on("exit", (code, signal) => {
    if (entry.readyRejector) {
      entry.readyRejector(new Error(`browser-driver exited before ready (code=${code} signal=${signal})`));
      entry.readyResolver = null;
      entry.readyRejector = null;
    }
    finalizeEntry(entry, `exit_${code == null ? "null" : code}`);
  });
}

async function startSession({
  targetDomain,
  targetUrl,
  headless = false,
  recordMode = false,
  sessionsRoot,
  patchrightCheck = isPatchrightAvailable,
  proxy = null,
  spawnFn = spawn,
} = {}) {
  if (!patchrightCheck()) {
    throw patchrightUnavailableError();
  }
  if (typeof targetDomain !== "string" || !targetDomain.trim()) {
    throw new Error("target_domain is required");
  }
  if (typeof targetUrl !== "string" || !targetUrl.trim()) {
    throw new Error("target_url is required");
  }
  if (!fs.existsSync(DRIVER_SCRIPT_PATH)) {
    throw new Error(`browser_driver_missing: ${DRIVER_SCRIPT_PATH}`);
  }
  const trimmedDomain = targetDomain.trim();
  if (activeSessionCountForDomain(trimmedDomain) >= MAX_SESSIONS_PER_DOMAIN) {
    const err = new Error(
      `browser_session_limit: max ${MAX_SESSIONS_PER_DOMAIN} concurrent browser sessions per target_domain ${trimmedDomain}; close an existing session via bob_browser_session_close before starting another.`,
    );
    err.code = "browser_session_limit";
    throw err;
  }

  const sessionId = generateSessionId(trimmedDomain);
  const resolvedSessionsRoot = sessionsRoot || path.join(os.homedir(), "hacker-bob-sessions");
  const initPayload = {
    session_id: sessionId,
    target_domain: trimmedDomain,
    target_url: targetUrl.trim(),
    headless: headless === true,
    record_mode: recordMode === true,
    sessions_root: resolvedSessionsRoot,
    // proxy: { server, username?, password? } — passed straight to Patchright's
    // chromium.launch({ proxy }) in the subprocess. The egress profile is
    // already resolved + env-expanded + scheme-validated by the tool wrapper
    // (see mcp/lib/browser-tools-shared.js#resolveBrowserEgressProfile). null
    // means direct egress (no proxy), which is the default.
    proxy: proxy && typeof proxy === "object" ? proxy : null,
  };

  const child = spawnFn(process.execPath, [DRIVER_SCRIPT_PATH], {
    stdio: ["pipe", "pipe", "pipe"],
    env: {
      ...process.env,
      BOB_BROWSER_DRIVER_INIT: JSON.stringify(initPayload),
    },
  });

  const entry = {
    sessionId,
    targetDomain: trimmedDomain,
    targetUrl: targetUrl.trim(),
    child,
    pending: new Map(),
    stdoutBuffer: "",
    stderrChunks: [],
    closed: false,
    readyResolver: null,
    readyRejector: null,
    readyPromise: null,
    idleTimer: null,
    hardTimer: null,
    lastActivity: Date.now(),
    headless: headless === true,
    recordMode: recordMode === true,
  };

  entry.readyPromise = new Promise((resolve, reject) => {
    entry.readyResolver = resolve;
    entry.readyRejector = reject;
  });
  attachChildHandlers(entry, child);

  trackSession(entry);
  // Hard timeout is armed immediately because Chromium startup itself is
  // bounded by START_TIMEOUT_MS. The idle timer waits for ready so a slow
  // launch doesn't trip the reaper before the agent has a chance to send the
  // first command.
  scheduleHardTimer(entry);

  let readyResult;
  try {
    readyResult = await raceWithTimeout(entry.readyPromise, START_TIMEOUT_MS, "browser_driver_ready_timeout");
  } catch (err) {
    closeSessionByEntry(entry, "ready_failed");
    throw err;
  }
  scheduleIdleTimer(entry);

  return {
    session_id: sessionId,
    target_domain: trimmedDomain,
    target_url: targetUrl.trim(),
    driver_session_id: readyResult && readyResult.session_id ? readyResult.session_id : sessionId,
    headless: headless === true,
    record_mode: recordMode === true,
  };
}

function raceWithTimeout(promise, timeoutMs, message) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      reject(new Error(message));
    }, timeoutMs);
    if (timer && typeof timer.unref === "function") timer.unref();
    promise
      .then((value) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolve(value);
      })
      .catch((err) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        reject(err);
      });
  });
}

function getSession(sessionId) {
  return sessions.get(sessionId) || null;
}

async function sendCommand(sessionId, command, args = {}, { timeoutMs = COMMAND_TIMEOUT_MS } = {}) {
  const entry = sessions.get(sessionId);
  if (!entry || entry.closed) {
    const err = new Error(`browser_session_not_found: ${sessionId}`);
    err.code = "browser_session_not_found";
    throw err;
  }
  const commandId = `c-${crypto.randomBytes(6).toString("hex")}`;
  const payload = JSON.stringify({ command_id: commandId, command, args }) + "\n";
  const deferred = {};
  const promise = new Promise((resolve, reject) => {
    deferred.resolve = resolve;
    deferred.reject = reject;
  });
  entry.pending.set(commandId, deferred);
  touchActivity(entry);
  try {
    entry.child.stdin.write(payload);
  } catch (err) {
    entry.pending.delete(commandId);
    throw err;
  }
  return raceWithTimeout(promise, timeoutMs, `browser_command_timeout:${command}`);
}

function closeSessionByEntry(entry, reason) {
  if (!entry || entry.closed) return;
  try {
    if (entry.child && entry.child.stdin && !entry.child.stdin.destroyed) {
      // Best-effort polite close so the subprocess can shutdown Chromium.
      try {
        entry.child.stdin.write(
          JSON.stringify({ command_id: `close-${reason}`, command: "close", args: {} }) + "\n",
        );
      } catch {
        // ignore
      }
      try {
        entry.child.stdin.end();
      } catch {
        // ignore
      }
    }
  } finally {
    finalizeEntry(entry, reason);
    if (entry.child && !entry.child.killed) {
      try {
        entry.child.kill("SIGTERM");
      } catch {
        // ignore
      }
    }
  }
}

async function closeSession(sessionId, reason = "explicit_close") {
  const entry = sessions.get(sessionId);
  if (!entry) {
    return { closed: false, reason: "browser_session_not_found" };
  }
  if (entry.closed) {
    return { closed: true, reason: "already_closed" };
  }
  // T.7: if record_mode is on, drain any residual capture buffer before we
  // sever the subprocess. The flush command is best-effort — a failed flush
  // (subprocess already dying, timeout) still allows the close to proceed.
  let residualRecorded = [];
  if (entry.recordMode) {
    try {
      const result = await sendCommand(sessionId, "flush_recorded_requests", {}, { timeoutMs: 5_000 });
      if (result && Array.isArray(result.recorded)) {
        residualRecorded = result.recorded;
      }
    } catch {
      // Best-effort drain on close. The caller already received earlier
      // batches via explicit flush_recorded_requests; nothing else to do.
    }
  }
  // Send close command; ignore result since driver exits shortly after.
  const payload = JSON.stringify({ command_id: `close-${reason}`, command: "close", args: {} }) + "\n";
  try {
    entry.child.stdin.write(payload);
  } catch {
    // ignore — fall through to finalize.
  }
  finalizeEntry(entry, reason);
  try {
    entry.child.stdin.end();
  } catch {
    // ignore
  }
  if (entry.child && !entry.child.killed) {
    try {
      entry.child.kill("SIGTERM");
    } catch {
      // ignore
    }
  }
  return { closed: true, reason, recorded: residualRecorded };
}

function closeAllSessions(reason = "shutdown") {
  for (const entry of [...sessions.values()]) {
    closeSessionByEntry(entry, reason);
  }
}

function listActiveSessions() {
  const summary = [];
  for (const entry of sessions.values()) {
    if (entry.closed) continue;
    summary.push({
      session_id: entry.sessionId,
      target_domain: entry.targetDomain,
      target_url: entry.targetUrl,
      headless: entry.headless,
      record_mode: entry.recordMode === true,
      last_activity_ms_ago: Date.now() - entry.lastActivity,
    });
  }
  return summary;
}

// T.7: pull the in-driver buffer of recorded HTTP requests. The driver returns
// the recorded array and clears its internal buffer atomically; callers that
// need the records to land in http-records.jsonl must hand the result to the
// import-http-traffic.js path (which already holds the per-domain session
// lock — that's the T-R5 guarantee).
async function flushRecordedRequests(sessionId, { timeoutMs } = {}) {
  const entry = sessions.get(sessionId);
  if (!entry || entry.closed) {
    const err = new Error(`browser_session_not_found: ${sessionId}`);
    err.code = "browser_session_not_found";
    throw err;
  }
  if (!entry.recordMode) {
    return { record_mode: false, recorded: [] };
  }
  const result = await sendCommand(sessionId, "flush_recorded_requests", {}, timeoutMs ? { timeoutMs } : {});
  return result || { record_mode: true, recorded: [] };
}

module.exports = {
  DEFAULT_IDLE_TIMEOUT_MS,
  DEFAULT_HARD_TIMEOUT_MS,
  IDLE_TIMEOUT_MS: DEFAULT_IDLE_TIMEOUT_MS,
  HARD_TIMEOUT_MS: DEFAULT_HARD_TIMEOUT_MS,
  MAX_SESSIONS_PER_DOMAIN,
  COMMAND_TIMEOUT_MS,
  activeSessionCountForDomain,
  closeAllSessions,
  closeSession,
  flushRecordedRequests,
  getSession,
  isPatchrightAvailable,
  listActiveSessions,
  patchrightUnavailableError,
  resetTimeoutsForTesting,
  sendCommand,
  setTimeoutsForTesting,
  startSession,
};
