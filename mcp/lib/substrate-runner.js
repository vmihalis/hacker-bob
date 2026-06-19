"use strict";

const { spawn } = require("child_process");
const fs = require("fs");
const path = require("path");
const os = require("os");
const { resolveSubstrateRpcEndpoints } = require("./substrate-rpc-pool.js");
const { parseCargoTestStdout } = require("./cargo-test-output.js");
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

// Allowlisted `cargo test` flags. We pin the test invocation to a known shape
// (cargo test --manifest-path X --features Y -- --nocapture --test-threads=1
// --exact <match_test>) so harness Cargo.toml can't smuggle in unsafe flags
// via extra_args. The most common ink! / cargo-contract flags are accepted;
// anything else is rejected at spawn time. Forbidden by omission: --target
// (could compile to attacker-controlled wasm artifacts), --offline (could
// hide network operations), --release (changes test semantics in subtle ways),
// --workspace (would expand the test set to every workspace member,
// compounding build.rs blast radius beyond the evaluator's named harness).
const SUBSTRATE_EXTRA_ARG_ALLOWLIST = new Set([
  "--features",       // followed by feature names (we accept the whole token)
  "--all-features",
  "--no-default-features",
  "--locked",
  "--quiet",
]);
// Some allowlisted flags take a value (e.g., --features e2e-tests). The runner
// accepts the next argv slot as the value when the flag matches one of these.
const SUBSTRATE_EXTRA_ARG_WITH_VALUE = new Set([
  "--features",
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
  // ink! / substrate-contracts harnesses always have a Cargo.toml at the
  // workspace root or per-crate root. Reject silently-empty or non-Rust
  // directories so misrouted finding records fail-loud here rather than
  // emitting a confusing "no test lines" output.
  const cargoTomlPath = path.join(realResolved, "Cargo.toml");
  if (!fs.existsSync(cargoTomlPath)) {
    throw new Error(`harness_path must contain Cargo.toml at the root: ${realResolved}`);
  }
  return realResolved;
}

function spawnCargo(args, { workdir, env, timeoutMs }) {
  return new Promise((resolve) => {
    let killed = false;
    const stdoutChunks = [];
    const stderrChunks = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;

    let child;
    try {
      child = spawn("cargo", args, {
        cwd: workdir,
        env: directSmartContractSubprocessEnv(env),
        stdio: ["ignore", "pipe", "pipe"],
        detached: true,
      });
    } catch (error) {
      resolve({
        ok: false,
        reason: "cargo_spawn_failed",
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
        reason: error.code === "ENOENT" ? "cargo_not_in_path" : "cargo_spawn_failed",
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

const DEPENDENCY_MISSING_PATTERNS = [
  /(rustc|cargo):.*command not found/i,
  /(rustc|cargo):.*No such file or directory/i,
  /linker `cc` not found/i,
  /could not find native static library/i,
  // ink! E2E tests require substrate-contracts-node or an equivalent. If
  // the harness invokes it via env-config and it's missing, classify as
  // dependency missing rather than a generic compile fail.
  /substrate-contracts-node:.*command not found/i,
  /substrate-contracts-node:.*No such file or directory/i,
];
const COMPILE_FAIL_PATTERNS = [
  /^error\[E\d+\]/m,                              // rustc compile error
  /could not compile/i,
  /unresolved import/i,
  /failed to load source for dependency/i,
  /error: failed to load manifest for/i,
];
// Older cargo versions don't accept some flags we use. Surface a clap-style
// usage error as a tooling blocker rather than letting it slip through.
const CLI_USAGE_ERROR_PATTERNS = [
  /Found argument .* which wasn't expected/i,
  /unexpected argument/i,
  /the following required arguments were not provided/i,
  /^error: unrecognized argument/im,
];

function classifySubstrateFailure(result, parseResultOk) {
  if (!result || result.ok || parseResultOk) return null;
  const stderr = String(result.stderr || "");
  const stdout = String(result.stdout || "");
  const combined = stderr + "\n" + stdout;
  for (const pattern of DEPENDENCY_MISSING_PATTERNS) {
    if (pattern.test(combined)) return "substrate_dependency_missing";
  }
  for (const pattern of CLI_USAGE_ERROR_PATTERNS) {
    if (pattern.test(combined)) return "substrate_dependency_missing";
  }
  if (!parseResultOk) {
    for (const pattern of COMPILE_FAIL_PATTERNS) {
      if (pattern.test(combined)) return "cargo_compile_failed";
    }
  }
  return null;
}

function buildExtraArgs(extraArgs) {
  // Walk the input array. Each token is either a flag (must be in allowlist)
  // or the value for the previous --flag (only when the prior flag is in the
  // with-value allowlist). Anything else throws.
  const out = [];
  let expectingValueFor = null;
  for (const arg of extraArgs) {
    if (typeof arg !== "string" || arg.length === 0 || arg.length > 200) continue;
    if (expectingValueFor) {
      // Accept this token as the value for the prior flag without further
      // checking; Cargo will validate the value itself.
      out.push(arg);
      expectingValueFor = null;
      continue;
    }
    if (!SUBSTRATE_EXTRA_ARG_ALLOWLIST.has(arg)) {
      throw new Error(`extra_args[${arg}] is not in the substrate cargo allowlist; accepted: ${[...SUBSTRATE_EXTRA_ARG_ALLOWLIST].join(", ")}`);
    }
    out.push(arg);
    if (SUBSTRATE_EXTRA_ARG_WITH_VALUE.has(arg)) {
      expectingValueFor = arg;
    }
  }
  if (expectingValueFor) {
    throw new Error(`extra_args ended with --${expectingValueFor.replace(/^-+/, "")} but no value followed`);
  }
  return out;
}

async function runSubstrateTest({
  workdir,
  matchTest,
  network,
  forkBlock,
  forkUrls,
  extraArgs = [],
  timeoutMs = DEFAULT_TIMEOUT_MS,
} = {}) {
  const resolvedWorkdir = assertHarnessPath(workdir);
  if (!matchTest) {
    throw new Error("match_test is required (cargo test test name filter)");
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
    : (network ? resolveSubstrateRpcEndpoints(network) : []);
  const {
    endpoints: candidateForkUrls,
    rejected: rpcPolicyRejections,
  } = await filterResolvedPublicRpcEndpoints(rawCandidateForkUrls);

  const extraArgvOut = buildExtraArgs(extraArgs);
  // cargo test --manifest-path X [extra cargo flags] -- --nocapture --test-threads=1 --exact <match_test>
  // Test-threads=1 makes ordering deterministic; --nocapture lets the failure
  // panic message reach stdout for the parser; --exact prevents a partial
  // match collision that would re-run unrelated tests.
  const baseArgs = [
    "test",
    "--manifest-path",
    path.join(resolvedWorkdir, "Cargo.toml"),
    ...extraArgvOut,
    "--",
    "--nocapture",
    "--test-threads=1",
    "--exact",
    matchTest,
  ];

  const forkAttempts = [];
  if (candidateForkUrls.length === 0) {
    if (explicitForkUrls || (network != null && network !== "localnet")) {
      return {
        ok: false,
        reason: "no_fork_endpoints_for_network",
        network,
        error: network == null || network === "localnet"
          ? "no public HTTPS RPC endpoints remain after applying the smart-contract egress policy"
          : `no public HTTPS RPC endpoints available for network ${network}; supply fork_urls explicitly or set BOB_SUBSTRATE_RPCS_${String(network).toUpperCase().replace(/-/g, "_")}=url1,url2 in the MCP server env`,
        command: ["cargo", ...redactRpcEndpointArgs(baseArgs)],
        rpc_policy_rejections: summarizeRpcPolicyRejections(rpcPolicyRejections),
        fork_attempts: [],
      };
    }
    // Local-only run (no network or localnet): ink! unit tests are pure-VM
    // and don't require external state. E2E tests require an external node
    // but the harness wires that itself; we just spawn cargo and let it
    // surface the error.
    const result = await spawnCargo(baseArgs, { workdir: resolvedWorkdir, timeoutMs: cappedTimeout, env: {} });
    return finalizeRun({ result, args: baseArgs, forkAttempts: [], forkBlock, fork_used: null, rpcPolicyRejections });
  }

  let lastResult = null;
  for (const url of candidateForkUrls) {
    // BOB_SUBSTRATE_FORK_URL: harnesses that opt into chain-state replay can
    // read this env to point ink_e2e at a forked node. Most harnesses ignore
    // it and use their own substrate-contracts-node binary.
    const env = { BOB_SUBSTRATE_FORK_URL: url, BOB_SUBSTRATE_NETWORK: network || "" };
    const result = await spawnCargo(baseArgs, { workdir: resolvedWorkdir, timeoutMs: cappedTimeout, env });
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
      return finalizeRun({ result, args: baseArgs, forkAttempts, forkBlock, fork_used: redactRpcEndpoint(url), rpcPolicyRejections });
    }
    if (result.reason === "cargo_not_in_path") {
      return finalizeRun({ result, args: baseArgs, forkAttempts, forkBlock, fork_used: null, rpcPolicyRejections });
    }
    // If parser sees test status lines, the binary ran fine — tests just
    // asserted. Don't keep failing over.
    const looksLikeTestRan = typeof result.stdout === "string" && /^test\s+\S+\s+\.\.\.\s+(ok|FAILED|ignored)\b/m.test(result.stdout);
    if (looksLikeTestRan) {
      return finalizeRun({ result, args: baseArgs, forkAttempts, forkBlock, fork_used: redactRpcEndpoint(url), rpcPolicyRejections });
    }
  }
  return finalizeRun({ result: lastResult, args: baseArgs, forkAttempts, forkBlock, fork_used: null, rpcPolicyRejections });
}

function finalizeRun({ result, args, forkAttempts, forkBlock, fork_used, rpcPolicyRejections = [] }) {
  if (!result || result.reason === "cargo_not_in_path" || result.reason === "cargo_spawn_failed") {
    return {
      ok: false,
      // Map cargo_not_in_path to substrate_not_in_path so verifier prompts
      // can match a single per-family fail-mode label.
      reason: result && result.reason === "cargo_not_in_path" ? "substrate_not_in_path"
        : (result && result.reason ? result.reason : "spawn_failed"),
      error: result && result.error ? result.error : null,
      command: ["cargo", ...redactRpcEndpointArgs(args)],
      rpc_policy_rejections: summarizeRpcPolicyRejections(rpcPolicyRejections),
      fork_attempts: forkAttempts,
    };
  }

  const parseResult = parseCargoTestStdout(result.stdout || "");
  const summary = parseResult.ok
    ? {
        tests: parseResult.tests,
        total: parseResult.total,
        passed: parseResult.passed,
        failed: parseResult.failed,
        ignored: parseResult.ignored,
        truncated: parseResult.truncated,
      }
    : { tests: [], total: 0, passed: 0, failed: 0, ignored: 0, truncated: false };

  const explicitFailureReason = classifySubstrateFailure(result, parseResult.ok);

  const allForkAttemptsFailed = forkAttempts.length > 0
    && forkAttempts.every((attempt) => attempt.ok !== true);
  const everyAttemptHasNoTestLines = forkAttempts.every((attempt) => {
    const stderr = String(attempt.stderr_excerpt || "");
    return !/^test\s+\S+\s+\.\.\.\s+(ok|FAILED|ignored)\b/m.test(stderr);
  });
  const looksRpcUnreachable = allForkAttemptsFailed
    && everyAttemptHasNoTestLines
    && !parseResult.ok
    && !fork_used
    && !explicitFailureReason;

  // fork_block_used reports the block the runner ACTUALLY pinned the test
  // against. cargo test for ink! has no native fork-pinning — the harness
  // can opt into chain-state replay via BOB_SUBSTRATE_FORK_URL but that's
  // harness-driven, not runner-driven. We therefore leave fork_block_used
  // null whenever the runner did not pin (the evaluator's `forkBlock` argument
  // is the PoC pin and is preserved in the `fork_block` response field).
  // Verifier prompts cascade to follow-up `block_used` from the read tools
  // when fork_block_used is null.
  const forkBlockUsed = null;

  const envelope = {
    ok: result.ok && parseResult.ok && summary.failed === 0 && summary.total > 0,
    timed_out: result.timed_out === true,
    exit_code: result.exit_code,
    signal: result.signal || null,
    fork_used,
    fork_block: forkBlock || null,
    fork_block_used: forkBlockUsed,
    fork_attempts: forkAttempts,
    command: ["cargo", ...redactRpcEndpointArgs(args)],
    rpc_policy_rejections: summarizeRpcPolicyRejections(rpcPolicyRejections),
    summary: {
      total: summary.total,
      passed: summary.passed,
      failed: summary.failed,
      ignored: summary.ignored,
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
  SUBSTRATE_EXTRA_ARG_ALLOWLIST,
  SUBSTRATE_EXTRA_ARG_WITH_VALUE,
  DEFAULT_TIMEOUT_MS,
  MAX_TIMEOUT_MS,
  classifySubstrateFailure,
  runSubstrateTest,
};
