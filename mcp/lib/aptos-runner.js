"use strict";

const { spawn } = require("child_process");
const fs = require("fs");
const path = require("path");
const os = require("os");
const { resolveAptosRpcEndpoints } = require("./aptos-rpc-pool.js");
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

// Allowlisted aptos move test flags. We forbid any flag value that selects
// a network or a wallet path (a evaluator-supplied --profile could escape
// $HOME containment via path traversal in Aptos profile config).
const APTOS_EXTRA_ARG_ALLOWLIST = new Set([
  "--skip-fetch-latest-git-deps",
  "--coverage",
  "--instruction-execution-cost",
  "--ignore-compile-warnings",
  "--check-test-code",
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

function spawnAptos(args, { workdir, env, timeoutMs }) {
  return new Promise((resolve) => {
    let killed = false;
    const stdoutChunks = [];
    const stderrChunks = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;

    let child;
    try {
      child = spawn("aptos", args, {
        cwd: workdir,
        env: directSmartContractSubprocessEnv(env),
        stdio: ["ignore", "pipe", "pipe"],
        detached: true,
      });
    } catch (error) {
      resolve({
        ok: false,
        reason: "aptos_spawn_failed",
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
        reason: error.code === "ENOENT" ? "aptos_not_in_path" : "aptos_spawn_failed",
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

// `aptos move test` exit code is 0 when ALL tests pass, non-zero when any
// fails. Combined with stderr scanning we classify the more specific failures.
const DEPENDENCY_MISSING_PATTERNS = [
  /(cargo|rustc):.*command not found/i,
  /(cargo|rustc):.*No such file or directory/i,
  /\bmove\b.*command not found/i,
  /\bmove-cli\b.*(command not found|No such file or directory)/i,
];
// "Cannot find module" patterns are JS-specific (jest/mocha) — Move tests
// don't use them. Instead we look for compiler/build failures that mean the
// runner setup is wrong (e.g., Move.toml malformed, dependency unresolvable).
const COMPILE_FAIL_PATTERNS = [
  /Compilation error/i,
  /error\[E\d+\]/, // Move compiler error code, e.g. error[E04001]
  /unable to find package/i,
  /failed to fetch git dependencies/i,
];
// Old aptos CLIs (pre-1.0) used positional <PACKAGE_PATH> instead of
// --package-dir. A version that doesn't recognize the flag emits a clap-style
// usage error rather than running the test, so we surface it as a tooling
// blocker (kind: aptos_dependency_missing) rather than letting it slip through
// as a generic non-zero exit with no reason set — verifier prompts treat
// "no recognized reason" as a confirmed denial.
const CLI_USAGE_ERROR_PATTERNS = [
  /unrecognized argument/i,
  /found argument .* which wasn't expected/i,
  /unexpected argument/i,
  /the following required arguments were not provided/i,
  /^error: .*--package-dir/im,
];

function classifyAptosFailure(result, parseResultOk) {
  if (!result || result.ok || parseResultOk) return null;
  const stderr = String(result.stderr || "");
  const stdout = String(result.stdout || "");
  const combined = stderr + "\n" + stdout;
  for (const pattern of DEPENDENCY_MISSING_PATTERNS) {
    if (pattern.test(combined)) return "aptos_dependency_missing";
  }
  // CLI usage errors take precedence over compile-fail because they indicate
  // a tooling-version mismatch, not a Move-source bug. Without this, an old
  // aptos CLI plus a present Move package would surface as compile_failed
  // and confuse triagers.
  for (const pattern of CLI_USAGE_ERROR_PATTERNS) {
    if (pattern.test(combined)) return "aptos_dependency_missing";
  }
  if (!parseResultOk) {
    for (const pattern of COMPILE_FAIL_PATTERNS) {
      if (pattern.test(combined)) return "move_compile_failed";
    }
  }
  return null;
}

async function runAptosTest({
  workdir,
  matchTest,
  network,
  forkVersion,
  forkUrls,
  extraArgs = [],
  timeoutMs = DEFAULT_TIMEOUT_MS,
} = {}) {
  const resolvedWorkdir = assertHarnessPath(workdir);
  if (!matchTest) {
    throw new Error("match_test is required (aptos move test --filter)");
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
    : (network ? resolveAptosRpcEndpoints(network) : []);
  const {
    endpoints: candidateForkUrls,
    rejected: rpcPolicyRejections,
  } = await filterResolvedPublicRpcEndpoints(rawCandidateForkUrls);

  const baseArgs = ["move", "test", "--filter", matchTest, "--package-dir", resolvedWorkdir];
  for (const arg of extraArgs) {
    if (typeof arg !== "string" || arg.length === 0 || arg.length > 200) continue;
    if (!APTOS_EXTRA_ARG_ALLOWLIST.has(arg)) {
      throw new Error(`extra_args[${arg}] is not in the aptos allowlist; accepted: ${[...APTOS_EXTRA_ARG_ALLOWLIST].join(", ")}`);
    }
    baseArgs.push(arg);
  }

  const forkAttempts = [];
  if (candidateForkUrls.length === 0) {
    if (explicitForkUrls || (network != null && network !== "localnet")) {
      return {
        ok: false,
        reason: "no_fork_endpoints_for_network",
        network,
        error: network == null
          ? "no public HTTPS REST endpoints remain after applying the smart-contract egress policy"
          : `no public HTTPS REST endpoints available for network ${network}; supply fork_urls explicitly or set BOB_APTOS_RPCS_${String(network).toUpperCase().replace(/-/g, "_")}=url1,url2 in the MCP server env`,
        command: ["aptos", ...redactRpcEndpointArgs(baseArgs)],
        rpc_policy_rejections: summarizeRpcPolicyRejections(rpcPolicyRejections),
        fork_attempts: [],
      };
    }
    // Local-only run (no network or localnet). Move tests are pure-VM and
    // don't require external state, so this is the default for sandboxed test
    // harnesses.
    const result = await spawnAptos(baseArgs, { workdir: resolvedWorkdir, timeoutMs: cappedTimeout, env: {} });
    return finalizeRun({ result, args: baseArgs, forkAttempts: [], forkVersion, fork_used: null, rpcPolicyRejections });
  }

  let lastResult = null;
  for (const url of candidateForkUrls) {
    // Move unit tests run in a sandboxed VM so the network URL is exposed via
    // env for harnesses that opt into mainnet-clone test fixtures (rare). Most
    // harnesses ignore it.
    const env = { BOB_APTOS_FORK_URL: url, BOB_APTOS_NETWORK: network || "" };
    const result = await spawnAptos(baseArgs, { workdir: resolvedWorkdir, timeoutMs: cappedTimeout, env });
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
      return finalizeRun({ result, args: baseArgs, forkAttempts, forkVersion, fork_used: redactRpcEndpoint(url), rpcPolicyRejections });
    }
    if (result.reason === "aptos_not_in_path") {
      return finalizeRun({ result, args: baseArgs, forkAttempts, forkVersion, fork_used: null, rpcPolicyRejections });
    }
    // If parser produced any test lines, the compiler/runner ran fine — the
    // tests just asserted. Don't keep failing over.
    const looksLikeTestRan = typeof result.stdout === "string" && /\[\s*(PASS|FAIL|TIMEOUT|SKIP)\s*\]/.test(result.stdout);
    if (looksLikeTestRan) {
      return finalizeRun({ result, args: baseArgs, forkAttempts, forkVersion, fork_used: redactRpcEndpoint(url), rpcPolicyRejections });
    }
  }
  return finalizeRun({ result: lastResult, args: baseArgs, forkAttempts, forkVersion, fork_used: null, rpcPolicyRejections });
}

function finalizeRun({ result, args, forkAttempts, forkVersion, fork_used, rpcPolicyRejections = [] }) {
  if (!result || result.reason === "aptos_not_in_path" || result.reason === "aptos_spawn_failed") {
    return {
      ok: false,
      reason: result && result.reason ? result.reason : "spawn_failed",
      error: result && result.error ? result.error : null,
      command: ["aptos", ...redactRpcEndpointArgs(args)],
      rpc_policy_rejections: summarizeRpcPolicyRejections(rpcPolicyRejections),
      fork_attempts: forkAttempts,
    };
  }

  const parseResult = parseMoveTestStdout(result.stdout || "");
  const summary = parseResult.ok
    ? { tests: parseResult.tests, total: parseResult.total, passed: parseResult.passed, failed: parseResult.failed, timed_out: parseResult.timed_out, truncated: parseResult.truncated }
    : { tests: [], total: 0, passed: 0, failed: 0, timed_out: 0, truncated: false };

  const explicitFailureReason = classifyAptosFailure(result, parseResult.ok);

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

  let forkVersionUsed = null;
  if (forkVersion != null) {
    forkVersionUsed = Number(forkVersion);
  }

  const envelope = {
    ok: result.ok && parseResult.ok && summary.failed === 0 && summary.total > 0,
    timed_out: result.timed_out === true,
    exit_code: result.exit_code,
    signal: result.signal || null,
    fork_used,
    fork_version: forkVersion || null,
    fork_version_used: forkVersionUsed,
    fork_attempts: forkAttempts,
    command: ["aptos", ...redactRpcEndpointArgs(args)],
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
  APTOS_EXTRA_ARG_ALLOWLIST,
  DEFAULT_TIMEOUT_MS,
  MAX_TIMEOUT_MS,
  classifyAptosFailure,
  runAptosTest,
};
