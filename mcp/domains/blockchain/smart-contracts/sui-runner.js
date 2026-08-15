"use strict";

const { scSubprocessContainerExec } = require("./sc-container-exec.js");
const fs = require("fs");
const path = require("path");
const os = require("os");
const { resolveSuiRpcEndpoints } = require("./sui-rpc-pool.js");
const { parseMoveTestStdout } = require("./move-test-output.js");
const {
  directSmartContractSubprocessEnv,
  filterResolvedPublicRpcEndpoints,
  redactRpcEndpoint,
  redactRpcEndpointArgs,
  redactRpcEndpointText,
  summarizeRpcPolicyRejections,
} = require("./sc-egress-policy.js");

const DEFAULT_TIMEOUT_MS = 90_000;
const MAX_TIMEOUT_MS = 600_000;
const MAX_OUTPUT_BYTES = 512 * 1024;
const RAW_EXCERPT_BYTES = 8 * 1024;

// Allowlisted `sui move test` flags. Forbidden: --client.config (could read
// off-home config), --rpc-url (network override that bypasses our RPC pool),
// --gas-coin (irrelevant for local tests).
const SUI_EXTRA_ARG_ALLOWLIST = new Set([
  "--skip-fetch-latest-git-deps",
  "--coverage",
  "--gas-limit",
  "--lint",
  "--no-lint",
  "--silence-warnings",
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

function spawnSui(args, { workdir, env, timeoutMs, targetDomain = null }) {
  return new Promise((resolve) => {
    let killed = false;
    const stdoutChunks = [];
    const stderrChunks = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;

    let child;
    try {
      // The container route mounts ONLY this workdir (never the session tree /
      // signing key) and runs as a non-signer container user; the degrade route
      // is a byte-identical direct spawn.
      child = scSubprocessContainerExec("sui", args, {
        cwd: workdir,
        env: directSmartContractSubprocessEnv(env),
        stdio: ["ignore", "pipe", "pipe"],
        detached: true,
        targetDomain,
      });
    } catch (error) {
      resolve({
        ok: false,
        reason: "sui_spawn_failed",
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
      // The killGroup above only kills the docker CLIENT; a daemon-managed container
      // detaches and keeps running. teardownContainer() issues `docker kill <name>`
      // so the daemon reaps the container. Optional-chained: the degrade/refuse-route
      // child has no method, so this is a no-op there (normal path untouched).
      try { child.teardownContainer && child.teardownContainer(); } catch {}
      setTimeout(() => {
        killGroup("SIGKILL");
        try { child.teardownContainer && child.teardownContainer(); } catch {}
      }, 5000);
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
        reason: error.code === "ENOENT" ? "sui_not_in_path" : "sui_spawn_failed",
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
        // Whether the SC seam ran this sui in a filesystem-namespace container (true)
        // or degraded to a host spawn AS THE SIGNER (false). absence/non-true defaults
        // to false. Sui Move backs findings via candidate-claims/verification-rounds, not
        // a keyed invariant-runs-style ledger, so the gate does not inspect this row
        // today; lifted for symmetry across all seven families.
        container_isolated: child.container_isolated === true,
      });
    });
  });
}

function truncateString(value, maxChars) {
  if (typeof value !== "string") return null;
  if (value.length <= maxChars) return value;
  return value.slice(0, maxChars) + `…[truncated, total ${value.length} chars]`;
}

const DEPENDENCY_MISSING_PATTERNS = [
  /(cargo|rustc):.*command not found/i,
  /(cargo|rustc):.*No such file or directory/i,
  /\bmove\b.*command not found/i,
  /\bmove-cli\b.*(command not found|No such file or directory)/i,
];
const COMPILE_FAIL_PATTERNS = [
  /Compilation error/i,
  /error\[E\d+\]/,
  /unable to find package/i,
  /failed to fetch git dependencies/i,
];
// Sui CLI versions vary in flag accepted; older versions take a positional
// regex argument instead of --filter and reject --path. A flag-rejection
// emits a clap usage error which we classify as a tooling blocker rather
// than letting it pass as a generic non-zero exit.
const CLI_USAGE_ERROR_PATTERNS = [
  /unrecognized argument/i,
  /found argument .* which wasn't expected/i,
  /unexpected argument/i,
  /the following required arguments were not provided/i,
  /^error: .*--filter|--path/im,
];

function classifySuiFailure(result, parseResultOk) {
  if (!result || result.ok || parseResultOk) return null;
  const stderr = String(result.stderr || "");
  const stdout = String(result.stdout || "");
  const combined = stderr + "\n" + stdout;
  for (const pattern of DEPENDENCY_MISSING_PATTERNS) {
    if (pattern.test(combined)) return "sui_dependency_missing";
  }
  for (const pattern of CLI_USAGE_ERROR_PATTERNS) {
    if (pattern.test(combined)) return "sui_dependency_missing";
  }
  if (!parseResultOk) {
    for (const pattern of COMPILE_FAIL_PATTERNS) {
      if (pattern.test(combined)) return "move_compile_failed";
    }
  }
  return null;
}

async function runSuiTest({
  workdir,
  matchTest,
  network,
  forkCheckpoint,
  forkUrls,
  extraArgs = [],
  timeoutMs = DEFAULT_TIMEOUT_MS,
  targetDomain = null,
} = {}) {
  const resolvedWorkdir = assertHarnessPath(workdir);
  if (!matchTest) {
    throw new Error("match_test is required (sui move test --filter)");
  }
  if (typeof matchTest !== "string") throw new Error("match_test must be a string");
  if (matchTest.length < 1 || matchTest.length > 200) {
    throw new Error("match_test must be 1..200 chars");
  }
  const cappedTimeout = Math.min(Math.max(Number(timeoutMs) || DEFAULT_TIMEOUT_MS, 5_000), MAX_TIMEOUT_MS);

  const explicitForkUrls = Array.isArray(forkUrls) && forkUrls.length > 0
    ? forkUrls
    : null;
  const rawCandidateForkUrls = explicitForkUrls && explicitForkUrls.length > 0
    ? explicitForkUrls
    : (network ? resolveSuiRpcEndpoints(network) : []);
  const {
    endpoints: candidateForkUrls,
    rejected: rpcPolicyRejections,
  } = await filterResolvedPublicRpcEndpoints(rawCandidateForkUrls);

  // sui move test takes a positional filter (no --filter flag is required;
  // instead a regex argument matches test names). To stay deterministic and
  // cross-version we use --filter explicitly; CLI versions that don't
  // recognize the flag will surface a CLI usage error which we'll classify
  // as a runtime issue rather than a test failure.
  const baseArgs = ["move", "test", "--filter", matchTest, "--path", resolvedWorkdir];
  for (const arg of extraArgs) {
    if (typeof arg !== "string" || arg.length === 0 || arg.length > 200) continue;
    if (!SUI_EXTRA_ARG_ALLOWLIST.has(arg)) {
      throw new Error(`extra_args[${arg}] is not in the sui allowlist; accepted: ${[...SUI_EXTRA_ARG_ALLOWLIST].join(", ")}`);
    }
    baseArgs.push(arg);
  }

  const forkAttempts = [];
  if (candidateForkUrls.length === 0) {
    if (explicitForkUrls || (network != null && network !== "localnet")) {
      // localnet has no public default — accept zero candidate URLs and let
      // the test run locally without a network. For other networks, fail
      // closed.
      return {
        ok: false,
        reason: "no_fork_endpoints_for_network",
        network,
        error: network == null || network === "localnet"
          ? "no public HTTPS RPC endpoints remain after applying the smart-contract egress policy"
          : `no public HTTPS RPC endpoints available for network ${network}; supply fork_urls explicitly or set BOB_SUI_RPCS_${String(network).toUpperCase().replace(/-/g, "_")}=url1,url2 in the MCP server env`,
        command: ["sui", ...redactRpcEndpointArgs(baseArgs)],
        rpc_policy_rejections: summarizeRpcPolicyRejections(rpcPolicyRejections),
        fork_attempts: [],
      };
    }
    const result = await spawnSui(baseArgs, { workdir: resolvedWorkdir, timeoutMs: cappedTimeout, env: {}, targetDomain });
    return finalizeRun({ result, args: baseArgs, forkAttempts: [], forkCheckpoint, fork_used: null, rpcPolicyRejections });
  }

  let lastResult = null;
  for (const url of candidateForkUrls) {
    const env = { BOB_SUI_FORK_URL: url, BOB_SUI_NETWORK: network || "" };
    const result = await spawnSui(baseArgs, { workdir: resolvedWorkdir, timeoutMs: cappedTimeout, env, targetDomain });
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
      return finalizeRun({ result, args: baseArgs, forkAttempts, forkCheckpoint, fork_used: redactRpcEndpoint(url), rpcPolicyRejections });
    }
    if (result.reason === "sui_not_in_path") {
      return finalizeRun({ result, args: baseArgs, forkAttempts, forkCheckpoint, fork_used: null, rpcPolicyRejections });
    }
    const looksLikeTestRan = typeof result.stdout === "string" && /\[\s*(PASS|FAIL|TIMEOUT|SKIP)\s*\]/.test(result.stdout);
    if (looksLikeTestRan) {
      return finalizeRun({ result, args: baseArgs, forkAttempts, forkCheckpoint, fork_used: redactRpcEndpoint(url), rpcPolicyRejections });
    }
  }
  return finalizeRun({ result: lastResult, args: baseArgs, forkAttempts, forkCheckpoint, fork_used: null, rpcPolicyRejections });
}

function finalizeRun({ result, args, forkAttempts, forkCheckpoint, fork_used, rpcPolicyRejections = [] }) {
  if (!result || result.reason === "sui_not_in_path" || result.reason === "sui_spawn_failed") {
    return {
      ok: false,
      reason: result && result.reason ? result.reason : "spawn_failed",
      error: result && result.error ? result.error : null,
      // A not-in-path / spawn-failed / refused run never executed the SC tool, so it is
      // by definition not containerized. Surface false explicitly (fail-closed un-isolated)
      // so the lift is present on EVERY return shape, not just success.
      container_isolated: false,
      command: ["sui", ...redactRpcEndpointArgs(args)],
      rpc_policy_rejections: summarizeRpcPolicyRejections(rpcPolicyRejections),
      fork_attempts: forkAttempts,
    };
  }

  const parseResult = parseMoveTestStdout(result.stdout || "");
  const summary = parseResult.ok
    ? { tests: parseResult.tests, total: parseResult.total, passed: parseResult.passed, failed: parseResult.failed, timed_out: parseResult.timed_out, truncated: parseResult.truncated }
    : { tests: [], total: 0, passed: 0, failed: 0, timed_out: 0, truncated: false };

  const explicitFailureReason = classifySuiFailure(result, parseResult.ok);

  const allForkAttemptsFailed = forkAttempts.length > 0
    && forkAttempts.every((attempt) => attempt.ok !== true);
  const everyAttemptHasNoTestLines = forkAttempts.every((attempt) => {
    const stderr = String(attempt.stderr_excerpt || "");
    return !/\[\s*(PASS|FAIL|TIMEOUT|SKIP)\s*\]/.test(stderr);
  });
  const looksRpcUnreachable = allForkAttemptsFailed
    && everyAttemptHasNoTestLines
    && !parseResult.ok
    && !fork_used
    && !explicitFailureReason;

  let forkCheckpointUsed = null;
  if (forkCheckpoint != null) {
    forkCheckpointUsed = Number(forkCheckpoint);
  }

  const envelope = {
    ok: result.ok && parseResult.ok && summary.failed === 0 && summary.total > 0,
    timed_out: result.timed_out === true,
    exit_code: result.exit_code,
    signal: result.signal || null,
    // TOP-LEVEL containerization signal lifted from the spawnSui result. Symmetry
    // with the keyed-ledger families; a host-as-signer (degrade) run resolves false.
    container_isolated: result.container_isolated === true,
    fork_used,
    fork_checkpoint: forkCheckpoint || null,
    fork_checkpoint_used: forkCheckpointUsed,
    fork_attempts: forkAttempts,
    command: ["sui", ...redactRpcEndpointArgs(args)],
    rpc_policy_rejections: summarizeRpcPolicyRejections(rpcPolicyRejections),
    summary: {
      total: summary.total,
      passed: summary.passed,
      failed: summary.failed,
      timed_out: summary.timed_out,
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
  if (explicitFailureReason) {
    envelope.reason = explicitFailureReason;
  } else if (looksRpcUnreachable) {
    envelope.reason = "rpc_unreachable";
  }
  return envelope;
}

module.exports = {
  SUI_EXTRA_ARG_ALLOWLIST,
  DEFAULT_TIMEOUT_MS,
  MAX_TIMEOUT_MS,
  classifySuiFailure,
  runSuiTest,
};
