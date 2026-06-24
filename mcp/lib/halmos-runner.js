"use strict";

const { spawn } = require("child_process");
const fs = require("fs");
const path = require("path");
const os = require("os");
const {
  directSmartContractSubprocessEnv,
  redactRpcEndpointText,
} = require("./sc-egress-policy.js");

const DEFAULT_TIMEOUT_MS = 120_000;
const MAX_TIMEOUT_MS = 600_000;
const MAX_OUTPUT_BYTES = 512 * 1024;
const RAW_EXCERPT_BYTES = 8 * 1024;

// Allowlisted halmos flags. Halmos has many tuning knobs; this list keeps the
// agent surface narrow. NOT allowed: any --ffi-style escape, --root override,
// --solver-command (arbitrary solver command plumbing = arbitrary host
// process execution), --debug (emits JSON-shaped diagnostics that the parser
// could mistake for test results), --smt-output (path argument with no
// validator), --json-output (forced by the runner; users do not need to pass it).
const HALMOS_EXTRA_ARG_ALLOWLIST = new Set([
  "--verbose",
  "--solver-timeout-assertion",
  "--solver-timeout-branching",
  "--depth",
  "--show-tx-data",
  "--statistics",
  "--no-cache",
]);

function isUnderHome(absPath) {
  let home = os.homedir();
  try { home = fs.realpathSync(home); } catch {}
  return absPath.startsWith(home + path.sep) || absPath === home;
}

function assertHarnessPath(harnessPath) {
  if (typeof harnessPath !== "string" || !harnessPath.trim()) {
    throw new Error("harness_path is required");
  }
  const resolved = path.resolve(harnessPath);
  if (!isUnderHome(resolved)) {
    throw new Error(`harness_path must live under the user home directory; received: ${resolved}`);
  }
  if (!fs.existsSync(resolved)) {
    throw new Error(`harness_path does not exist: ${resolved}`);
  }
  // Symlink resolution mirrors foundry-runner so a $HOME/link → /etc style
  // bypass cannot deliver a harness from outside the user home.
  const realResolved = fs.realpathSync(resolved);
  if (!isUnderHome(realResolved)) {
    throw new Error(`harness_path must live under the user home directory after symlink resolution; resolved to: ${realResolved}`);
  }
  if (!fs.statSync(realResolved).isDirectory()) {
    throw new Error(`harness_path must be a directory: ${realResolved}`);
  }
  return realResolved;
}

function spawnHalmos(args, { workdir, timeoutMs }) {
  return new Promise((resolve) => {
    let killed = false;
    const stdoutChunks = [];
    const stderrChunks = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;

    let child;
    try {
      // detached: true lets us kill the process group on timeout — halmos
      // spawns solver subprocesses that would otherwise survive a parent kill.
      child = spawn("halmos", args, {
        cwd: workdir,
        env: directSmartContractSubprocessEnv({}),
        stdio: ["ignore", "pipe", "pipe"],
        detached: true,
      });
    } catch (error) {
      resolve({ ok: false, reason: "halmos_spawn_failed", error: error.message || String(error) });
      return;
    }

    const killGroup = (signal) => {
      try {
        // Negative PID targets the process group created by detached: true.
        if (child.pid) process.kill(-child.pid, signal);
      } catch {
        try { child.kill(signal); } catch {}
      }
    };

    const timer = setTimeout(() => {
      killed = true;
      killGroup("SIGTERM");
      setTimeout(() => killGroup("SIGKILL"), 5000);
    }, timeoutMs);

    child.stdout.on("data", (chunk) => {
      const remaining = MAX_OUTPUT_BYTES - stdoutBytes;
      if (remaining > 0) stdoutChunks.push(chunk.length > remaining ? chunk.subarray(0, remaining) : chunk);
      stdoutBytes += chunk.length;
    });
    child.stderr.on("data", (chunk) => {
      const remaining = MAX_OUTPUT_BYTES - stderrBytes;
      if (remaining > 0) stderrChunks.push(chunk.length > remaining ? chunk.subarray(0, remaining) : chunk);
      stderrBytes += chunk.length;
    });
    child.on("error", (error) => {
      clearTimeout(timer);
      resolve({
        ok: false,
        reason: error.code === "ENOENT" ? "halmos_not_in_path" : "halmos_spawn_failed",
        error: error.message || String(error),
      });
    });
    child.on("close", (code, signal) => {
      clearTimeout(timer);
      const stdout = Buffer.concat(stdoutChunks).toString("utf8");
      const stderr = Buffer.concat(stderrChunks).toString("utf8");
      resolve({
        ok: !killed && code === 0,
        timed_out: killed,
        exit_code: code,
        signal,
        stdout,
        stderr,
        stdout_bytes: stdoutBytes,
        stderr_bytes: stderrBytes,
        truncated: stdoutBytes > MAX_OUTPUT_BYTES || stderrBytes > MAX_OUTPUT_BYTES,
      });
    });
  });
}

function truncateString(value, maxChars) {
  if (typeof value !== "string") return null;
  if (value.length <= maxChars) return value;
  return value.slice(0, maxChars) + `…[truncated, total ${value.length} chars]`;
}

function parseHalmosOutput(stdout) {
  // Prefer the LAST balanced JSON document on stdout — halmos emits the
  // result envelope at the tail. The first-success scan would happily accept
  // mid-stream debug objects as the result. Halmos result documents must
  // include either a `results`/`tests` array at the root or a top-level
  // `version` marker; documents without those are rejected so duck-typed
  // mid-stream JSON cannot pass through.
  const trimmed = stdout.trim();
  if (!trimmed) return { ok: false, reason: "empty_stdout" };

  let lastValidDocument = null;
  for (let start = trimmed.length - 1; start >= 0; start--) {
    if (trimmed[start] !== "{" && trimmed[start] !== "[") continue;
    try {
      const parsed = JSON.parse(trimmed.slice(start));
      if (looksLikeHalmosResult(parsed)) {
        lastValidDocument = parsed;
        break;
      }
    } catch {
      // not a valid JSON tail starting here; keep scanning
    }
  }

  if (lastValidDocument) {
    return { ok: true, document: lastValidDocument };
  }

  // Text fallback — used when --json-output is unsupported by the installed
  // halmos version. Force ok=false if any [FAIL] line is observed but the
  // regex misses it (rather than silently dropping failures).
  const tests = [];
  let observedUnmatchedFail = false;
  for (const line of trimmed.split("\n")) {
    const passMatch = line.match(/\[PASS\]\s+(\S+)/);
    if (passMatch) {
      tests.push({ test: passMatch[1], status: "Pass", counterexample: null });
      continue;
    }
    if (/\[FAIL\]/.test(line)) {
      // Capture the test name with optional trailing context. If we can't even
      // capture a name, treat the entire run as a failure rather than dropping.
      const failMatch = line.match(/\[FAIL\]\s+(\S+)/);
      if (failMatch) {
        tests.push({ test: failMatch[1], status: "Fail", counterexample: redactRpcEndpointText(line) });
      } else {
        observedUnmatchedFail = true;
      }
    }
  }
  if (observedUnmatchedFail) {
    return { ok: false, reason: "unmatched_fail_line" };
  }
  if (tests.length > 0) return { ok: true, document: { _text_parsed: true, tests } };
  return { ok: false, reason: "unparseable_output" };
}

function looksLikeHalmosResult(document) {
  if (!document || typeof document !== "object") return false;
  if (Array.isArray(document)) return false;
  if (Array.isArray(document.results)) return true;
  if (Array.isArray(document.tests)) return true;
  if (typeof document.version === "string") return true;
  return false;
}

function summarizeHalmosOutput(document) {
  if (!document || typeof document !== "object") return { tests: [], total: 0, passed: 0, failed: 0 };
  // Strict shape only: results[] (preferred) OR tests[] OR _text_parsed marker.
  // No recursive duck-typed visiting — that path accepts mid-stream debug JSON
  // as test results. Anything else is treated as zero-test (and thus the
  // ok-gate's summary.total > 0 check will reject it).
  const tests = [];
  let passed = 0;
  let failed = 0;

  const recordTest = (entry) => {
    const name = typeof entry.test === "string" ? entry.test
      : (typeof entry.name === "string" ? entry.name : null);
    if (!name) return;
    const explicitStatus = typeof entry.status === "string" ? entry.status : null;
    const explicitPassed = entry.passed === true ? "Pass" : (entry.passed === false ? "Fail" : null);
    const status = explicitStatus || explicitPassed || (entry._text_parsed ? "Unknown" : "Unknown");
    const ok = status === "Pass";
    if (ok) passed += 1; else failed += 1;
    tests.push({
      test: name,
      status: ok ? "Pass" : "Fail",
      counterexample: entry.counterexample
        ? truncateString(redactRpcEndpointText(typeof entry.counterexample === "string" ? entry.counterexample : JSON.stringify(entry.counterexample)), 1024)
        : null,
      time_ms: typeof entry.time_ms === "number" ? entry.time_ms : null,
    });
  };

  if (Array.isArray(document.results)) {
    for (const entry of document.results) {
      if (entry && typeof entry === "object") recordTest(entry);
    }
  } else if (Array.isArray(document.tests)) {
    for (const entry of document.tests) {
      if (entry && typeof entry === "object") recordTest(entry);
    }
  }

  return { tests, total: tests.length, passed, failed };
}

async function runHalmos({
  workdir,
  matchTest,
  matchContract,
  extraArgs = [],
  timeoutMs = DEFAULT_TIMEOUT_MS,
} = {}) {
  const resolvedWorkdir = assertHarnessPath(workdir);
  if (!matchTest && !matchContract) {
    throw new Error("at least one of match_test or match_contract is required (halmos must be filtered)");
  }
  const cappedTimeout = Math.min(Math.max(Number(timeoutMs) || DEFAULT_TIMEOUT_MS, 5_000), MAX_TIMEOUT_MS);

  if (matchTest && typeof matchTest !== "string") throw new Error("match_test must be a string");
  if (matchContract && typeof matchContract !== "string") throw new Error("match_contract must be a string");

  // Always force --json-output so the structured parser is the primary path,
  // not the text fallback (which is brittle across halmos versions).
  const baseArgs = ["--json-output"];
  if (matchTest) baseArgs.push("--function", matchTest);
  if (matchContract) baseArgs.push("--contract", matchContract);
  let expectingValueFor = null;
  for (const arg of extraArgs) {
    if (typeof arg !== "string" || arg.length === 0 || arg.length > 200) continue;
    if (expectingValueFor) {
      baseArgs.push(arg);
      expectingValueFor = null;
      continue;
    }
    if (!HALMOS_EXTRA_ARG_ALLOWLIST.has(arg)) {
      throw new Error(`extra_args[${arg}] is not in the halmos allowlist; accepted: ${[...HALMOS_EXTRA_ARG_ALLOWLIST].join(", ")}`);
    }
    baseArgs.push(arg);
    if (arg === "--solver-timeout-assertion" || arg === "--solver-timeout-branching" || arg === "--depth") {
      expectingValueFor = arg;
    }
  }

  const result = await spawnHalmos(baseArgs, { workdir: resolvedWorkdir, timeoutMs: cappedTimeout });

  if (!result.ok && (result.reason === "halmos_not_in_path" || result.reason === "halmos_spawn_failed")) {
    return {
      ok: false,
      reason: result.reason,
      error: result.error || null,
      command: ["halmos", ...baseArgs],
    };
  }

  const parseResult = parseHalmosOutput(result.stdout || "");
  const summary = parseResult.ok ? summarizeHalmosOutput(parseResult.document) : { tests: [], total: 0, passed: 0, failed: 0 };

  // MINT ≠ CONFIRM. `ok` (summary.failed===0 && summary.total>0) is a SINGLE-RUN
  // PRIMITIVE — "no counterexample on THIS tree" — NOT a verified verdict. A
  // verified FV finding requires the executed two-arm flip adjudicated by
  // invariant-runner.js::verifyInvariantDifferential (classifyHalmosViolation maps
  // this run to held/violated/degraded; `ok` mints only "held"). runHalmos mints no
  // verdict and writes no audit-graded ledger.
  return {
    ok: result.ok && parseResult.ok && summary.failed === 0 && summary.total > 0,
    timed_out: result.timed_out === true,
    exit_code: result.exit_code,
    signal: result.signal || null,
    command: ["halmos", ...baseArgs],
    summary: { total: summary.total, passed: summary.passed, failed: summary.failed },
    tests: summary.tests,
    raw_excerpt: {
      stdout: truncateString(redactRpcEndpointText(result.stdout || ""), RAW_EXCERPT_BYTES),
      stderr: truncateString(redactRpcEndpointText(result.stderr || ""), RAW_EXCERPT_BYTES),
      truncated: result.truncated === true,
    },
    parse_warning: parseResult.ok ? null : parseResult.reason,
  };
}

module.exports = {
  DEFAULT_TIMEOUT_MS,
  MAX_TIMEOUT_MS,
  parseHalmosOutput,
  runHalmos,
  summarizeHalmosOutput,
};
