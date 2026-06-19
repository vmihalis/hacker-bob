"use strict";

// Plane T Cycle T.2 — CLI tool install-presence cache.
//
// Each target domain has a sidecar cache at
//   ~/hacker-bob-sessions/<target_domain>/cli-tool-presence.json
// shape:
//   {
//     checked_at: ISO-8601,
//     results: {
//       <tool_id>: { installed: bool, version?: string, checked_at: ISO-8601 }
//     }
//   }
//
// Plane T pact:
//   T-P3 "install-graceful" — a missing tool yields `{ installed: false }`,
//        never a thrown error.
//   T-R2 "stale install-checks" — cache TTL defaults to 1 hour, configurable
//        via env BOB_CLI_TOOL_CACHE_TTL_MS for test determinism.
//   T-R8 "pure-enough" — wall-clock is the only impurity; tests inject `now`
//        and an `execFile` shim so behaviour is deterministic under unit test.
//
// The cache write is protected by withSessionLock so concurrent presence
// probes do not race on the JSON file.

const fs = require("fs");
const path = require("path");
const { execFile } = require("child_process");
const { promisify } = require("util");

const { sessionDir } = require("./paths.js");
const {
  readJsonFile,
  withSessionLock,
  writeFileAtomic,
} = require("./storage.js");

const execFilePromise = promisify(execFile);

const CACHE_FILE_NAME = "cli-tool-presence.json";
const DEFAULT_CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour
const PROBE_TIMEOUT_MS = 5000;
const VERSION_LINE_LIMIT = 240;

function cacheTtlMs(env = process.env) {
  const raw = env.BOB_CLI_TOOL_CACHE_TTL_MS;
  if (typeof raw !== "string" || !raw.trim()) return DEFAULT_CACHE_TTL_MS;
  const parsed = Number(raw);
  if (!Number.isFinite(parsed) || parsed < 0) return DEFAULT_CACHE_TTL_MS;
  return parsed;
}

function presenceCachePath(targetDomain) {
  return path.join(sessionDir(targetDomain), CACHE_FILE_NAME);
}

function readCache(targetDomain) {
  const filePath = presenceCachePath(targetDomain);
  if (!fs.existsSync(filePath)) return null;
  try {
    return readJsonFile(filePath);
  } catch {
    return null;
  }
}

function writeCache(targetDomain, cache) {
  const filePath = presenceCachePath(targetDomain);
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  writeFileAtomic(filePath, `${JSON.stringify(cache, null, 2)}\n`);
}

function normalizeCacheShape(cache) {
  if (!cache || typeof cache !== "object" || Array.isArray(cache)) {
    return { checked_at: new Date(0).toISOString(), results: {} };
  }
  const results = cache.results && typeof cache.results === "object" && !Array.isArray(cache.results)
    ? cache.results
    : {};
  const checkedAt = typeof cache.checked_at === "string" && cache.checked_at
    ? cache.checked_at
    : new Date(0).toISOString();
  return { checked_at: checkedAt, results };
}

function entryIsFresh(entry, ttlMs, now) {
  if (!entry || typeof entry !== "object") return false;
  if (typeof entry.checked_at !== "string") return false;
  const stamp = Date.parse(entry.checked_at);
  if (!Number.isFinite(stamp)) return false;
  return (now - stamp) < ttlMs;
}

function parseVersionFromOutput(stdout, stderr) {
  const combined = `${stdout || ""}\n${stderr || ""}`;
  if (!combined.trim()) return null;
  const firstLine = combined.split(/\r?\n/).find((line) => line.trim());
  if (!firstLine) return null;
  return firstLine.trim().slice(0, VERSION_LINE_LIMIT);
}

function splitCommand(installCheckCmd) {
  // Conservative tokenizer: shell-style argv split on whitespace, respecting
  // single/double-quoted spans. install_check entries in cli-tool-packs.js
  // are simple "tool -V" / "which tool" forms so this is sufficient and
  // avoids shell expansion (which would defeat the timeout guard).
  const tokens = [];
  let current = "";
  let quote = null;
  for (let i = 0; i < installCheckCmd.length; i += 1) {
    const ch = installCheckCmd[i];
    if (quote) {
      if (ch === quote) {
        quote = null;
      } else {
        current += ch;
      }
      continue;
    }
    if (ch === "'" || ch === "\"") {
      quote = ch;
      continue;
    }
    if (/\s/.test(ch)) {
      if (current) {
        tokens.push(current);
        current = "";
      }
      continue;
    }
    current += ch;
  }
  if (current) tokens.push(current);
  return tokens;
}

async function runInstallCheck(installCheckCmd, runtime) {
  const tokens = splitCommand(installCheckCmd);
  if (tokens.length === 0) return { installed: false };
  const [command, ...args] = tokens;
  const runner = runtime && typeof runtime.execFile === "function"
    ? runtime.execFile
    : execFilePromise;
  try {
    const result = await runner(command, args, { timeout: PROBE_TIMEOUT_MS });
    const version = parseVersionFromOutput(result.stdout, result.stderr);
    return version ? { installed: true, version } : { installed: true };
  } catch {
    return { installed: false };
  }
}

async function checkCliToolInstallation(toolId, installCheckCmd, targetDomain, options = {}) {
  if (typeof toolId !== "string" || !toolId.trim()) {
    throw new Error("checkCliToolInstallation: tool_id must be a non-empty string");
  }
  if (typeof installCheckCmd !== "string" || !installCheckCmd.trim()) {
    throw new Error("checkCliToolInstallation: install_check_cmd must be a non-empty string");
  }
  if (typeof targetDomain !== "string" || !targetDomain.trim()) {
    throw new Error("checkCliToolInstallation: target_domain must be a non-empty string");
  }
  const now = typeof options.now === "function" ? options.now() : Date.now();
  const ttlMs = typeof options.cacheTtlMs === "number" ? options.cacheTtlMs : cacheTtlMs(options.env || process.env);
  const cache = normalizeCacheShape(readCache(targetDomain));
  const cached = cache.results[toolId];
  if (entryIsFresh(cached, ttlMs, now)) {
    return {
      installed: Boolean(cached.installed),
      ...(cached.version ? { version: cached.version } : {}),
      cached: true,
    };
  }

  const probe = await runInstallCheck(installCheckCmd, options.runtime || null);
  const entry = {
    installed: Boolean(probe.installed),
    checked_at: new Date(now).toISOString(),
    ...(probe.version ? { version: probe.version } : {}),
  };
  withSessionLock(targetDomain, () => {
    const fresh = normalizeCacheShape(readCache(targetDomain));
    fresh.results[toolId] = entry;
    fresh.checked_at = entry.checked_at;
    writeCache(targetDomain, fresh);
  });
  return {
    installed: entry.installed,
    ...(entry.version ? { version: entry.version } : {}),
    cached: false,
  };
}

module.exports = {
  CACHE_FILE_NAME,
  DEFAULT_CACHE_TTL_MS,
  PROBE_TIMEOUT_MS,
  cacheTtlMs,
  checkCliToolInstallation,
  presenceCachePath,
  splitCommand,
};
