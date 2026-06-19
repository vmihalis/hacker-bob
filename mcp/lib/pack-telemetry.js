"use strict";

// Plane T Cycle T.8 — pack-telemetry reader + adaptive curation gate.
//
// Replaces T.3's `telemetryPromotionForPack: () => 0` stub with a real reader
// over `tool-invocations.jsonl`. Computes, per known CLI tool pack id:
//   - invocation_count : Bash invocations whose `command` field starts with
//     the pack id token (e.g. `"sqlmap "`, `"ffuf "`).
//   - claim_correlation: number of `bob_record_candidate_claim` invocations
//     that landed within a correlation window AFTER each pack invocation,
//     divided by invocation_count. Range [0, 1].
//   - telemetry_promotion : claim_correlation - baseline_rate.
//
// Plane T pact:
//   T-P5 "telemetry as feedback" — pack curation reads from the renamed
//        tool-invocations.jsonl stream (C.1).
//   T-D5 "adaptive curation is opt-in" — when `adaptive_curation` is absent
//        or not strictly `true`, every promotion is 0 and the scoring formula
//        collapses to its T.3 form. Default-off matches T-P5's "explicit
//        operator opt-in".
//   T-R8 "deterministic for fixed inputs" — telemetry consumes the on-disk
//        ledger and config file only; no Date.now, no random, no env reads
//        for selection. The rolling window is anchored on `now()` so tests
//        inject a fixed `now` to keep determinism observable.
//
// File layout:
//   ~/hacker-bob-sessions/<target_domain>/pack-telemetry-config.json
//   {
//     adaptive_curation: bool,        // T-D5 opt-in switch
//     window_ms?: number,             // default DEFAULT_WINDOW_MS (7 days)
//     correlation_window_ms?: number, // default DEFAULT_CORRELATION_WINDOW_MS (5m)
//     baseline_rate?: number,         // default DEFAULT_BASELINE_RATE (0.10)
//     demotion_floor?: number,        // default DEFAULT_DEMOTION_FLOOR (0.05)
//     min_invocation_count?: number,  // default DEFAULT_MIN_INVOCATION_COUNT (5)
//   }

const fs = require("fs");
const path = require("path");

const { CLI_TOOL_PACKS } = require("./cli-tool-packs.js");
const { sessionDir } = require("./paths.js");
const {
  readJsonFile,
  withSessionLock,
  writeFileAtomic,
} = require("./storage.js");
const { toolInvocationTelemetryPath } = require("./tool-telemetry.js");

const CONFIG_FILE_NAME = "pack-telemetry-config.json";
const DEFAULT_WINDOW_MS = 7 * 24 * 60 * 60 * 1000; // 7 days
const DEFAULT_CORRELATION_WINDOW_MS = 5 * 60 * 1000; // 5 minutes
const DEFAULT_BASELINE_RATE = 0.1;
const DEFAULT_DEMOTION_FLOOR = 0.05;
const DEFAULT_MIN_INVOCATION_COUNT = 5;
const DEMOTION_SCORE_PENALTY = -1.0;
const CLAIM_TOOL_NAME = "bob_record_candidate_claim";
const RECORD_BYTE_CAP = 64 * 1024 * 1024; // 64 MiB telemetry read cap

function packTelemetryConfigPath(targetDomain) {
  return path.join(sessionDir(targetDomain), CONFIG_FILE_NAME);
}

function envWindowOverride(envName, fallback, env) {
  if (!env || typeof env !== "object") return fallback;
  const raw = env[envName];
  if (typeof raw !== "string" || !raw.trim()) return fallback;
  const parsed = Number(raw);
  if (!Number.isFinite(parsed) || parsed < 0) return fallback;
  return parsed;
}

function readConfigFromDisk(targetDomain) {
  if (typeof targetDomain !== "string" || !targetDomain.trim()) return null;
  let filePath;
  try {
    filePath = packTelemetryConfigPath(targetDomain);
  } catch {
    return null;
  }
  if (!fs.existsSync(filePath)) return null;
  try {
    const raw = readJsonFile(filePath);
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) return null;
    return raw;
  } catch {
    return null;
  }
}

// Normalize a (possibly absent) on-disk config into a settled shape. The
// `adaptive_curation` field is the only one with a hard default — `false` —
// so a missing config file behaves identically to a config with
// `adaptive_curation: false`. Numeric overrides fall back to env then to
// module-level defaults.
function normalizePackTelemetryConfig(raw, { env = process.env } = {}) {
  const adaptive = raw && raw.adaptive_curation === true;
  const windowMs = pickPositiveNumber(
    raw && raw.window_ms,
    envWindowOverride("BOB_PACK_TELEMETRY_WINDOW_MS", DEFAULT_WINDOW_MS, env),
  );
  const correlationWindowMs = pickPositiveNumber(
    raw && raw.correlation_window_ms,
    envWindowOverride(
      "BOB_PACK_TELEMETRY_CORRELATION_WINDOW_MS",
      DEFAULT_CORRELATION_WINDOW_MS,
      env,
    ),
  );
  const baselineRate = pickFiniteNumber(raw && raw.baseline_rate, DEFAULT_BASELINE_RATE);
  const demotionFloor = pickFiniteNumber(raw && raw.demotion_floor, DEFAULT_DEMOTION_FLOOR);
  const minInvocationCount = pickPositiveInteger(
    raw && raw.min_invocation_count,
    DEFAULT_MIN_INVOCATION_COUNT,
  );
  return Object.freeze({
    adaptive_curation: adaptive,
    window_ms: windowMs,
    correlation_window_ms: correlationWindowMs,
    baseline_rate: baselineRate,
    demotion_floor: demotionFloor,
    min_invocation_count: minInvocationCount,
  });
}

function pickPositiveNumber(value, fallback) {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) return fallback;
  return value;
}

function pickFiniteNumber(value, fallback) {
  if (typeof value !== "number" || !Number.isFinite(value)) return fallback;
  return value;
}

function pickPositiveInteger(value, fallback) {
  if (!Number.isFinite(value)) return fallback;
  const truncated = Math.trunc(value);
  if (truncated < 0) return fallback;
  return truncated;
}

function readPackTelemetryConfig(targetDomain, { env = process.env } = {}) {
  return normalizePackTelemetryConfig(readConfigFromDisk(targetDomain), { env });
}

// Operator-facing writer. Validation is intentionally narrow: only
// `adaptive_curation` is required, numeric overrides are accepted when they
// are finite numbers in a sensible range, and the rest of the file is left
// to the normalizer (so reads see consistent defaults). Per Pact T-D5 the
// switch is operator-gated; the tool is registered with
// `orchestrator`-only role bundle.
function writePackTelemetryConfig(targetDomain, configInput, { env = process.env } = {}) {
  if (typeof targetDomain !== "string" || !targetDomain.trim()) {
    throw new Error("writePackTelemetryConfig: target_domain must be a non-empty string");
  }
  if (!configInput || typeof configInput !== "object" || Array.isArray(configInput)) {
    throw new Error("writePackTelemetryConfig: config must be a plain object");
  }
  if (typeof configInput.adaptive_curation !== "boolean") {
    throw new Error("writePackTelemetryConfig: config.adaptive_curation must be a boolean");
  }

  const sanitized = { adaptive_curation: configInput.adaptive_curation };
  if (configInput.window_ms != null) {
    if (!Number.isFinite(configInput.window_ms) || configInput.window_ms < 0) {
      throw new Error("writePackTelemetryConfig: window_ms must be a non-negative number");
    }
    sanitized.window_ms = Number(configInput.window_ms);
  }
  if (configInput.correlation_window_ms != null) {
    if (!Number.isFinite(configInput.correlation_window_ms) || configInput.correlation_window_ms < 0) {
      throw new Error("writePackTelemetryConfig: correlation_window_ms must be a non-negative number");
    }
    sanitized.correlation_window_ms = Number(configInput.correlation_window_ms);
  }
  if (configInput.baseline_rate != null) {
    if (!Number.isFinite(configInput.baseline_rate)) {
      throw new Error("writePackTelemetryConfig: baseline_rate must be a finite number");
    }
    sanitized.baseline_rate = Number(configInput.baseline_rate);
  }
  if (configInput.demotion_floor != null) {
    if (!Number.isFinite(configInput.demotion_floor)) {
      throw new Error("writePackTelemetryConfig: demotion_floor must be a finite number");
    }
    sanitized.demotion_floor = Number(configInput.demotion_floor);
  }
  if (configInput.min_invocation_count != null) {
    if (!Number.isFinite(configInput.min_invocation_count) || configInput.min_invocation_count < 0) {
      throw new Error("writePackTelemetryConfig: min_invocation_count must be a non-negative integer");
    }
    sanitized.min_invocation_count = Math.trunc(Number(configInput.min_invocation_count));
  }

  withSessionLock(targetDomain, () => {
    const filePath = packTelemetryConfigPath(targetDomain);
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    writeFileAtomic(filePath, `${JSON.stringify(sanitized, null, 2)}\n`);
  });

  return normalizePackTelemetryConfig(sanitized, { env });
}

function knownPackIds() {
  return CLI_TOOL_PACKS.map((pack) => pack.id);
}

// Returns the alphanumeric prefix of a command string. Pack ids in T.2/T.6
// are kebab-case but some seed packs (e.g. `jwt-tool`) map to a different
// executable name (`jwt_tool`). We match the literal pack id token AND a
// best-effort underscore variant when the id contains a hyphen, since CLI
// binaries commonly underscore-canonicalize. The match is anchored at the
// start of the string and requires a whitespace (or end-of-line) terminator
// so `sqlmap-helper foo` does NOT count toward `sqlmap`.
function commandStartsWithPackId(command, packId) {
  if (typeof command !== "string" || !command) return false;
  if (typeof packId !== "string" || !packId) return false;
  const trimmed = command.trimStart();
  return tokenMatches(trimmed, packId) || (
    packId.includes("-") && tokenMatches(trimmed, packId.replace(/-/g, "_"))
  );
}

function tokenMatches(commandText, token) {
  if (!commandText.startsWith(token)) return false;
  if (commandText.length === token.length) return true;
  const next = commandText.charCodeAt(token.length);
  // accept whitespace, NUL, or end-of-input as terminator
  return next === 0x20 || next === 0x09 || next === 0x0a || next === 0x0d;
}

function recordTimestampMs(record) {
  if (!record || typeof record !== "object") return null;
  const ts = record.ts;
  if (typeof ts !== "string" || !ts) return null;
  const parsed = Date.parse(ts);
  return Number.isFinite(parsed) ? parsed : null;
}

function recordCommandString(record) {
  if (!record || typeof record !== "object") return null;
  // Direct command field (the spec's documented case).
  if (typeof record.command === "string" && record.command) return record.command;
  // Nested under `tool_input` / `payload.command` when the telemetry source
  // is a wrapped Bash event. We accept these defensively so the reader is
  // graceful when the on-disk ledger evolves; absent fields make the entry
  // unmatchable (count toward neither invocation nor claim correlation).
  if (record.tool_input && typeof record.tool_input.command === "string") {
    return record.tool_input.command;
  }
  if (record.payload && typeof record.payload.command === "string") {
    return record.payload.command;
  }
  return null;
}

function recordIsCandidateClaim(record) {
  if (!record || typeof record !== "object") return false;
  return record.tool === CLAIM_TOOL_NAME || record.tool_name === CLAIM_TOOL_NAME;
}

function readTelemetryRecords({ env = process.env } = {}) {
  const filePath = toolInvocationTelemetryPath(env);
  if (!filePath || !fs.existsSync(filePath)) return [];
  let raw;
  try {
    const stats = fs.statSync(filePath);
    if (stats.size > RECORD_BYTE_CAP) return [];
    raw = fs.readFileSync(filePath, "utf8");
  } catch {
    return [];
  }
  const out = [];
  for (const line of raw.split(/\r?\n/)) {
    if (!line.trim()) continue;
    try {
      const parsed = JSON.parse(line);
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
        out.push(parsed);
      }
    } catch {
      // Skip malformed lines; the wider telemetry reader logs malformed
      // counts. Pack telemetry is a derived projection — we don't
      // re-implement that bookkeeping.
    }
  }
  return out;
}

// Core projection: for each known pack id, scan the rolling-window slice of
// records and compute the three metrics. Always returns a Map keyed by every
// known pack id (even when adaptive_curation is off, so callers can rely on
// the shape).
function loadPackTelemetry(target_domain, {
  env = process.env,
  now = () => Date.now(),
  records: providedRecords = null,
  config: providedConfig = null,
} = {}) {
  const config = providedConfig || readPackTelemetryConfig(target_domain, { env });
  const nowMs = typeof now === "function" ? now() : Date.now();

  const result = new Map();
  for (const id of knownPackIds()) {
    result.set(id, {
      invocation_count: 0,
      claim_correlation: 0,
      telemetry_promotion: 0,
      demoted: false,
    });
  }

  if (!config.adaptive_curation) {
    return result;
  }

  const cutoff = nowMs - config.window_ms;
  const records = providedRecords != null ? providedRecords : readTelemetryRecords({ env });
  const inWindow = [];
  for (const record of records) {
    const ts = recordTimestampMs(record);
    if (ts == null) continue;
    if (ts < cutoff || ts > nowMs) continue;
    inWindow.push({ ts, record });
  }
  // Stable chronological ordering. Date.parse is monotonic over ISO-8601
  // strings to ms resolution; ties are broken by original position to keep
  // the correlation walk deterministic.
  inWindow.sort((a, b) => a.ts - b.ts);

  const claimTimestamps = inWindow
    .filter((entry) => recordIsCandidateClaim(entry.record))
    .map((entry) => entry.ts);

  for (const id of knownPackIds()) {
    const packInvocations = [];
    for (const entry of inWindow) {
      const command = recordCommandString(entry.record);
      if (command && commandStartsWithPackId(command, id)) {
        packInvocations.push(entry.ts);
      }
    }
    const invocationCount = packInvocations.length;
    let correlatedClaims = 0;
    if (invocationCount > 0 && claimTimestamps.length > 0) {
      for (const invocationTs of packInvocations) {
        if (claimWithinWindow(invocationTs, claimTimestamps, config.correlation_window_ms)) {
          correlatedClaims += 1;
        }
      }
    }
    const claimCorrelation = invocationCount === 0
      ? 0
      : correlatedClaims / invocationCount;
    const telemetryPromotion = invocationCount === 0
      ? 0
      : claimCorrelation - config.baseline_rate;
    const invocationRate = config.window_ms > 0
      ? invocationCount / (config.window_ms / DEFAULT_WINDOW_MS)
      : 0;
    const demoted = shouldDemote({
      invocationCount,
      invocationRate,
      claimCorrelation,
      config,
    });
    result.set(id, {
      invocation_count: invocationCount,
      claim_correlation: claimCorrelation,
      telemetry_promotion: telemetryPromotion,
      invocation_rate: invocationRate,
      demoted,
    });
  }

  return result;
}

// `invocation_rate × claim_correlation` is the operator-readable composite
// score from the spec: a pack that fires often but never correlates with a
// claim filing gets demoted; so does a pack that correlates well but barely
// ever fires (since the sample-size floor catches it). The sample-size
// guard (`invocation_count >= min_invocation_count`) is what stops a single
// lucky invocation from yanking a pack out of the surfaced list.
function shouldDemote({ invocationCount, invocationRate, claimCorrelation, config }) {
  if (invocationCount < config.min_invocation_count) return false;
  return (invocationRate * claimCorrelation) < config.demotion_floor;
}

function isDemoted(packId, telemetryMap) {
  if (!telemetryMap || typeof telemetryMap.get !== "function") return false;
  const entry = telemetryMap.get(packId);
  return !!(entry && entry.demoted === true);
}

module.exports = {
  CLAIM_TOOL_NAME,
  CONFIG_FILE_NAME,
  DEFAULT_BASELINE_RATE,
  DEFAULT_CORRELATION_WINDOW_MS,
  DEFAULT_DEMOTION_FLOOR,
  DEFAULT_MIN_INVOCATION_COUNT,
  DEFAULT_WINDOW_MS,
  DEMOTION_SCORE_PENALTY,
  commandStartsWithPackId,
  isDemoted,
  loadPackTelemetry,
  normalizePackTelemetryConfig,
  packTelemetryConfigPath,
  readPackTelemetryConfig,
  writePackTelemetryConfig,
};

function claimWithinWindow(invocationTs, claimTimestamps, windowMs) {
  // Bisect would be ideal here; the on-disk ledger is small enough in
  // practice (capped at 5_000 lines by tool-telemetry.js) that a linear
  // forward scan is faster than maintaining a sorted index. The walk is
  // pure-functional over its inputs, so the determinism invariant holds.
  for (const claimTs of claimTimestamps) {
    if (claimTs <= invocationTs) continue;
    if (claimTs - invocationTs <= windowMs) return true;
    // Claims are sorted ascending — once we pass the window we are done.
    if (claimTs - invocationTs > windowMs) return false;
  }
  return false;
}
