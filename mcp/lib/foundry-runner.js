"use strict";

const { spawn } = require("child_process");
const fs = require("fs");
const path = require("path");
const os = require("os");
const { resolveEvmRpcEndpoints } = require("./evm-rpc-pool.js");
const {
  directSmartContractSubprocessEnv,
  filterResolvedPublicRpcEndpoints,
  redactRpcEndpoint,
  redactRpcEndpointArgs,
  redactRpcEndpointText,
  summarizeRpcPolicyRejections,
} = require("./sc-egress-policy.js");

const DEFAULT_TIMEOUT_MS = 60_000;
const MAX_TIMEOUT_MS = 300_000;
const MAX_OUTPUT_BYTES = 512 * 1024;
const RAW_EXCERPT_BYTES = 8 * 1024;
const FORGE_TESTS_CAP = 100;

// Allowlisted forge flags evaluators may pass via `extra_args`. Anything not on
// this list is rejected to keep the subprocess surface narrow. NOT allowed:
// --ffi (FFI = arbitrary host command execution), --rpc-url (would override
// the public ladder), --evm-version (not relevant for Bob's read-only assertions),
// --match-path (lets agents target out-of-harness files), and any --tx-* flag.
const FORGE_EXTRA_ARG_ALLOWLIST = new Set([
  "--no-cache",
  "--force",
  "--silent",
  "--gas-report",
  "-vvv",
  "-vvvv",
  "-vvvvv",
  "--show-progress",
  "--isolate",
  "--fail-fast",
  "--threads",
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
  // Symlink resolution: a evaluator could plant $HOME/poc → /var/some/forge-tree.
  // Lexical containment via path.resolve passes; statSync follows the link;
  // forge would then run in an off-home tree with vm.readFile cheatcodes
  // available against arbitrary files. Re-check containment on the realpath.
  const realResolved = fs.realpathSync(resolved);
  if (!isUnderHome(realResolved)) {
    throw new Error(`harness_path must live under the user home directory after symlink resolution; resolved to: ${realResolved}`);
  }
  const stat = fs.statSync(realResolved);
  if (!stat.isDirectory()) {
    throw new Error(`harness_path must be a directory: ${realResolved}`);
  }
  return realResolved;
}

function spawnForge(args, { workdir, env, timeoutMs }) {
  return new Promise((resolve) => {
    let killed = false;
    let stdoutChunks = [];
    let stderrChunks = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;

    let child;
    try {
      // detached: true lets us kill the process group on timeout. Forge spawns
      // solc and (when forking) anvil subprocesses; a parent-only kill leaves
      // them running.
      child = spawn("forge", args, {
        cwd: workdir,
        env: directSmartContractSubprocessEnv(env),
        stdio: ["ignore", "pipe", "pipe"],
        detached: true,
      });
    } catch (error) {
      resolve({
        ok: false,
        reason: "forge_spawn_failed",
        error: error.message || String(error),
      });
      return;
    }

    const killGroup = (signal) => {
      try {
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
      if (remaining > 0) {
        stdoutChunks.push(chunk.length > remaining ? chunk.subarray(0, remaining) : chunk);
      }
      stdoutBytes += chunk.length;
    });
    child.stderr.on("data", (chunk) => {
      const remaining = MAX_OUTPUT_BYTES - stderrBytes;
      if (remaining > 0) {
        stderrChunks.push(chunk.length > remaining ? chunk.subarray(0, remaining) : chunk);
      }
      stderrBytes += chunk.length;
    });
    child.on("error", (error) => {
      clearTimeout(timer);
      resolve({
        ok: false,
        reason: error.code === "ENOENT" ? "forge_not_in_path" : "forge_spawn_failed",
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

function parseForgeJson(stdout) {
  // forge test --json emits one or more JSON objects. Try to parse the trailing
  // JSON document; tolerate human-readable preface.
  const trimmed = stdout.trim();
  if (!trimmed) return { ok: false, reason: "empty_stdout" };
  // Find the last '{' that begins a balanced JSON object.
  for (let start = 0; start < trimmed.length; start++) {
    if (trimmed[start] !== "{") continue;
    try {
      const parsed = JSON.parse(trimmed.slice(start));
      return { ok: true, document: parsed };
    } catch {
      // try the next opening brace
    }
  }
  return { ok: false, reason: "unparseable_json" };
}

function summarizeForgeJson(document) {
  const tests = [];
  let total = 0;
  let passed = 0;
  let failed = 0;
  let truncated = false;
  if (!document || typeof document !== "object") return { tests, total, passed, failed, truncated };
  // Forge JSON uses "Success"/"Failure"/"Skipped" status strings. Verifier
  // prompts speak "Pass"/"Fail" for the test-pass=bug-reproduced convention.
  // Translate at the runner so prompts and runner share one vocabulary; if the
  // runner shape ever drifts, this single mapping is the only place to update.
  const STATUS_MAP = { Success: "Pass", Failure: "Fail", Skipped: "Skipped" };
  for (const [suiteName, suite] of Object.entries(document)) {
    if (!suite || typeof suite !== "object") continue;
    const results = suite.test_results && typeof suite.test_results === "object" ? suite.test_results : {};
    for (const [testName, result] of Object.entries(results)) {
      total += 1;
      const rawStatus = result && typeof result.status === "string" ? result.status : "Unknown";
      const normalizedStatus = STATUS_MAP[rawStatus] || rawStatus;
      const passedTest = normalizedStatus === "Pass";
      if (passedTest) passed += 1; else failed += 1;
      // Cap tests[] at FORGE_TESTS_CAP entries to bound verifier context spend
      // when a hostile or buggy harness produces thousands of test rows.
      if (tests.length < FORGE_TESTS_CAP) {
        tests.push({
          suite: suiteName,
          test: testName,
          status: normalizedStatus,
          status_raw: rawStatus,
          reason: typeof result?.reason === "string" ? redactRpcEndpointText(result.reason) : null,
          gas_used: typeof result?.kind?.Standard?.gasUsed === "number"
            ? result.kind.Standard.gasUsed
            : (typeof result?.gas === "number" ? result.gas : null),
          counterexample: result && result.counterexample ? truncateString(redactRpcEndpointText(JSON.stringify(result.counterexample)), 1024) : null,
        });
      } else {
        truncated = true;
      }
    }
  }
  return { tests, total, passed, failed, truncated };
}

function truncateString(value, maxChars) {
  if (typeof value !== "string") return null;
  if (value.length <= maxChars) return value;
  return value.slice(0, maxChars) + `…[truncated, total ${value.length} chars]`;
}

async function runFoundryTest({
  workdir,
  matchTest,
  matchContract,
  chainId,
  forkBlock,
  forkUrls,
  extraArgs = [],
  timeoutMs = DEFAULT_TIMEOUT_MS,
} = {}) {
  const resolvedWorkdir = assertHarnessPath(workdir);
  if (!matchTest && !matchContract) {
    throw new Error("at least one of match_test or match_contract is required (forge test must be filtered)");
  }
  const cappedTimeout = Math.min(Math.max(Number(timeoutMs) || DEFAULT_TIMEOUT_MS, 5_000), MAX_TIMEOUT_MS);

  const explicitForkUrls = Array.isArray(forkUrls) && forkUrls.length > 0
    ? forkUrls
    : null;
  const rawCandidateForkUrls = explicitForkUrls && explicitForkUrls.length > 0
    ? explicitForkUrls
    : (chainId ? resolveEvmRpcEndpoints(chainId) : []);
  const {
    endpoints: candidateForkUrls,
    rejected: rpcPolicyRejections,
  } = await filterResolvedPublicRpcEndpoints(rawCandidateForkUrls);

  // Validate match expressions are simple regex-safe strings to keep the
  // command line well-formed; forge accepts regex but we keep it conservative.
  if (matchTest && typeof matchTest !== "string") throw new Error("match_test must be a string");
  if (matchContract && typeof matchContract !== "string") throw new Error("match_contract must be a string");

  const baseArgs = ["test", "--json"];
  if (matchTest) baseArgs.push("--match-test", matchTest);
  if (matchContract) baseArgs.push("--match-contract", matchContract);
  if (forkBlock != null) baseArgs.push("--fork-block-number", String(forkBlock));
  // Allowlist extra_args. Reject anything not in the allowlist (no --ffi, no
  // --rpc-url, no --match-path, no -- pass-through). A flag value (e.g. "8" for
  // --threads) is allowed only when it follows an allowlisted flag.
  let expectingValueFor = null;
  for (const arg of extraArgs) {
    if (typeof arg !== "string" || arg.length === 0 || arg.length > 200) continue;
    if (expectingValueFor) {
      baseArgs.push(arg);
      expectingValueFor = null;
      continue;
    }
    if (!FORGE_EXTRA_ARG_ALLOWLIST.has(arg)) {
      throw new Error(`extra_args[${arg}] is not in the forge allowlist; accepted: ${[...FORGE_EXTRA_ARG_ALLOWLIST].join(", ")}`);
    }
    baseArgs.push(arg);
    if (arg === "--threads") expectingValueFor = arg;
  }

  const forkAttempts = [];
  if (candidateForkUrls.length === 0) {
    if (chainId != null || explicitForkUrls) {
      // Fail closed: the user asked for a forked run on a specific chain but
      // we have no endpoints. Silently running a local-only test would let a
      // evaluator record "tested" without ever touching the target chain.
      return {
        ok: false,
        reason: "no_fork_endpoints_for_chain",
        chain_id: chainId == null ? null : Number(chainId),
        error: chainId == null
          ? "no public HTTPS RPC endpoints remain after applying the smart-contract egress policy"
          : `no public HTTPS RPC endpoints available for chain_id ${chainId}; supply fork_urls explicitly or set BOB_EVM_RPCS_${chainId}=url1,url2 in the MCP server env`,
        command: ["forge", ...redactRpcEndpointArgs(baseArgs)],
        rpc_policy_rejections: summarizeRpcPolicyRejections(rpcPolicyRejections),
        fork_attempts: [],
      };
    }
    // No chain_id supplied — run a local-only test (covers chain-independent
    // fixtures and pure-fuzz harnesses).
    const result = await spawnForge(baseArgs, { workdir: resolvedWorkdir, timeoutMs: cappedTimeout, env: {} });
    return finalizeRun({ result, args: baseArgs, forkAttempts: [], forkBlock, fork_used: null, rpcPolicyRejections });
  }

  let lastResult = null;
  for (const url of candidateForkUrls) {
    const args = [...baseArgs, "--fork-url", url];
    const result = await spawnForge(args, { workdir: resolvedWorkdir, timeoutMs: cappedTimeout, env: {} });
    lastResult = result;
    forkAttempts.push({
      endpoint: redactRpcEndpoint(url),
      ok: result.ok,
      exit_code: result.exit_code,
      timed_out: result.timed_out === true,
      reason: result.reason || null,
      stderr_excerpt: truncateString(redactRpcEndpointText(result.stderr || ""), 600),
    });
    if (result.ok) {
      return finalizeRun({ result, args, forkAttempts, forkBlock, fork_used: redactRpcEndpoint(url), rpcPolicyRejections });
    }
    // If forge is missing entirely, no point trying other RPCs.
    if (result.reason === "forge_not_in_path") {
      return finalizeRun({ result, args, forkAttempts, forkBlock, fork_used: null, rpcPolicyRejections });
    }
    // Differentiate test failure from RPC failure: if stderr shows our forge
    // produced JSON, the RPC was fine — the test simply failed/asserted.
    const looksLikeJsonOnStdout = typeof result.stdout === "string" && /^\s*\{/.test(result.stdout);
    if (looksLikeJsonOnStdout) {
      return finalizeRun({ result, args, forkAttempts, forkBlock, fork_used: redactRpcEndpoint(url), rpcPolicyRejections });
    }
    // Otherwise treat as RPC failure and try the next endpoint.
  }
  return finalizeRun({ result: lastResult, args: baseArgs, forkAttempts, forkBlock, fork_used: null, rpcPolicyRejections });
}

function finalizeRun({ result, args, forkAttempts, forkBlock, fork_used, rpcPolicyRejections = [] }) {
  if (!result || result.reason === "forge_not_in_path" || result.reason === "forge_spawn_failed") {
    return {
      ok: false,
      reason: result && result.reason ? result.reason : "spawn_failed",
      error: result && result.error ? result.error : null,
      command: ["forge", ...redactRpcEndpointArgs(args)],
      rpc_policy_rejections: summarizeRpcPolicyRejections(rpcPolicyRejections),
      fork_attempts: forkAttempts,
    };
  }

  const parseResult = parseForgeJson(result.stdout || "");
  const summary = parseResult.ok
    ? summarizeForgeJson(parseResult.document)
    : { tests: [], total: 0, passed: 0, failed: 0, truncated: false };

  // Distinguish "no fork endpoint worked" from "test asserted (failed)". When
  // forkAttempts is non-empty AND none reported ok AND we never produced
  // structured forge JSON, the failure is RPC-shaped, not test-shaped. Verifier
  // prompts depend on this top-level reason for fail-closed behavior.
  const allForkAttemptsFailed = forkAttempts.length > 0
    && forkAttempts.every((attempt) => attempt.ok !== true);
  const everyAttemptHasNoJson = forkAttempts.every((attempt) => {
    const stderr = String(attempt.stderr_excerpt || "");
    return !/^\s*\{/.test(stderr);
  });
  const looksRpcUnreachable = allForkAttemptsFailed
    && everyAttemptHasNoJson
    && !parseResult.ok
    && !fork_used;

  // fork_block_used: the block actually anchoring the run. If the caller
  // pinned forkBlock, that's the block. Otherwise, when the fork succeeded
  // and parsing surfaced a block in the forge JSON, prefer that. As a final
  // fallback, expose null so the verifier prompt treats absence as "do not
  // claim a verified-at-block reference."
  let forkBlockUsed = null;
  if (forkBlock != null) {
    forkBlockUsed = Number(forkBlock);
  } else if (parseResult.ok && parseResult.document && typeof parseResult.document === "object") {
    // Forge sometimes embeds block info inside test telemetry; try common
    // shapes without throwing on miss. Returning null is the safe default.
    for (const suite of Object.values(parseResult.document)) {
      const candidate = suite && suite.kind && suite.kind.Standard && suite.kind.Standard.fork_block_number;
      if (typeof candidate === "number" && Number.isFinite(candidate)) {
        forkBlockUsed = candidate;
        break;
      }
    }
  }

  const envelope = {
    // ok requires: forge exited cleanly, parsed JSON, no failed tests, AND at
    // least one test ran. A run with summary.total === 0 is "no tests matched"
    // — silently rubber-stamping it would let evaluators record "tested" without
    // any execution.
    ok: result.ok && parseResult.ok && summary.failed === 0 && summary.total > 0,
    timed_out: result.timed_out === true,
    exit_code: result.exit_code,
    signal: result.signal || null,
    fork_used,
    fork_block: forkBlock || null,
    fork_block_used: forkBlockUsed,
    fork_attempts: forkAttempts,
    command: ["forge", ...redactRpcEndpointArgs(args)],
    rpc_policy_rejections: summarizeRpcPolicyRejections(rpcPolicyRejections),
    summary: {
      total: summary.total,
      passed: summary.passed,
      failed: summary.failed,
    },
    tests: summary.tests,
    tests_truncated: summary.truncated === true,
    raw_excerpt: {
      stdout: truncateString(redactRpcEndpointText(result.stdout || ""), RAW_EXCERPT_BYTES),
      stderr: truncateString(redactRpcEndpointText(result.stderr || ""), RAW_EXCERPT_BYTES),
      truncated: result.truncated === true,
    },
    parse_warning: parseResult.ok ? null : parseResult.reason,
  };
  if (looksRpcUnreachable) {
    envelope.reason = "rpc_unreachable";
  }
  return envelope;
}

module.exports = {
  DEFAULT_TIMEOUT_MS,
  MAX_TIMEOUT_MS,
  parseForgeJson,
  runFoundryTest,
  summarizeForgeJson,
};
