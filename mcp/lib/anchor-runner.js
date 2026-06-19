"use strict";

const { spawn } = require("child_process");
const fs = require("fs");
const path = require("path");
const os = require("os");
const { resolveSvmRpcEndpoints } = require("./svm-rpc-pool.js");
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
const ANCHOR_TESTS_CAP = 100;

// Allowlisted anchor flags evaluators may pass via `extra_args`. Anything not on
// this list is rejected to keep the subprocess surface narrow. NOT allowed:
// --provider.cluster (cluster comes from sc_evidence; allowing override would
// let a evaluator point a verifier at a private localnet that produces fake
// PASS), --provider.wallet (key file path could escape $HOME via path
// traversal), and --skip-build with a evaluator-supplied path.
const ANCHOR_EXTRA_ARG_ALLOWLIST = new Set([
  "--skip-build",
  "--skip-deploy",
  "--skip-lint",
  "--detach",
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
  // Symlink resolution: a evaluator could plant $HOME/poc → /var/some/anchor-tree.
  // Lexical containment via path.resolve passes; statSync follows the link;
  // anchor would then run in an off-home tree. Re-check on realpath.
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

function spawnAnchor(args, { workdir, env, timeoutMs }) {
  return new Promise((resolve) => {
    let killed = false;
    let stdoutChunks = [];
    let stderrChunks = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;

    let child;
    try {
      // detached: true so we can kill the process group on timeout. Anchor
      // spawns solana-test-validator + cargo + npm/yarn subprocesses; a
      // parent-only kill leaves them running.
      child = spawn("anchor", args, {
        cwd: workdir,
        env: directSmartContractSubprocessEnv(env),
        stdio: ["ignore", "pipe", "pipe"],
        detached: true,
      });
    } catch (error) {
      resolve({
        ok: false,
        reason: "anchor_spawn_failed",
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
        reason: error.code === "ENOENT" ? "anchor_not_in_path" : "anchor_spawn_failed",
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

// anchor test runs mocha under the hood. Mocha JSON reporter writes a single
// JSON document with stats + per-test results to stdout. We detect the trailing
// JSON document and parse it; everything before is anchor's own log preface
// (build output, validator boot lines, deploy txid, etc.).
function parseAnchorMochaJson(stdout) {
  const trimmed = stdout.trim();
  if (!trimmed) return { ok: false, reason: "empty_stdout" };
  for (let start = 0; start < trimmed.length; start++) {
    if (trimmed[start] !== "{") continue;
    try {
      const parsed = JSON.parse(trimmed.slice(start));
      // Validate shape: mocha JSON has stats + tests/passes/failures arrays.
      if (parsed && typeof parsed === "object" && parsed.stats && Array.isArray(parsed.tests)) {
        return { ok: true, document: parsed };
      }
    } catch {
      // try the next opening brace
    }
  }
  return { ok: false, reason: "unparseable_json" };
}

function summarizeAnchorMochaJson(document) {
  const tests = [];
  let total = 0;
  let passed = 0;
  let failed = 0;
  let truncated = false;
  if (!document || typeof document !== "object" || !Array.isArray(document.tests)) {
    return { tests, total, passed, failed, truncated };
  }
  // Mocha test entries: { title, fullTitle, duration, currentRetry, err: {} }
  // A test with empty err object passed; non-empty err means failed; pending
  // is signaled in stats (not per-entry). We treat both `pending` and the
  // skipped flag as "Skipped" to mirror foundry's STATUS_MAP.
  for (const entry of document.tests) {
    if (!entry || typeof entry !== "object") continue;
    total += 1;
    const hasErr = entry.err && typeof entry.err === "object" && Object.keys(entry.err).length > 0;
    const isPending = entry.pending === true;
    let status;
    if (isPending) {
      status = "Skipped";
    } else if (hasErr) {
      status = "Fail";
      failed += 1;
    } else {
      status = "Pass";
      passed += 1;
    }
    if (tests.length < ANCHOR_TESTS_CAP) {
      tests.push({
        suite: typeof entry.fullTitle === "string" && typeof entry.title === "string"
          ? entry.fullTitle.slice(0, Math.max(0, entry.fullTitle.length - entry.title.length)).trim()
          : null,
        test: typeof entry.title === "string" ? entry.title : null,
        full_title: typeof entry.fullTitle === "string" ? entry.fullTitle : null,
        status,
        status_raw: isPending ? "pending" : (hasErr ? "failure" : "success"),
        reason: hasErr && typeof entry.err.message === "string" ? redactRpcEndpointText(entry.err.message).slice(0, 1024) : null,
        duration_ms: typeof entry.duration === "number" ? entry.duration : null,
      });
    } else {
      truncated = true;
    }
  }
  return { tests, total, passed, failed, truncated };
}

function truncateString(value, maxChars) {
  if (typeof value !== "string") return null;
  if (value.length <= maxChars) return value;
  return value.slice(0, maxChars) + `…[truncated, total ${value.length} chars]`;
}

async function runAnchorTest({
  workdir,
  matchTest,
  cluster,
  forkSlot,
  forkUrls,
  extraArgs = [],
  timeoutMs = DEFAULT_TIMEOUT_MS,
} = {}) {
  const resolvedWorkdir = assertHarnessPath(workdir);
  if (!matchTest) {
    throw new Error("match_test is required (mocha grep filter)");
  }
  const cappedTimeout = Math.min(Math.max(Number(timeoutMs) || DEFAULT_TIMEOUT_MS, 5_000), MAX_TIMEOUT_MS);

  const explicitForkUrls = Array.isArray(forkUrls) && forkUrls.length > 0
    ? forkUrls
    : null;
  const rawCandidateForkUrls = explicitForkUrls && explicitForkUrls.length > 0
    ? explicitForkUrls
    : (cluster ? resolveSvmRpcEndpoints(cluster) : []);
  const {
    endpoints: candidateForkUrls,
    rejected: rpcPolicyRejections,
  } = await filterResolvedPublicRpcEndpoints(rawCandidateForkUrls);

  if (typeof matchTest !== "string") throw new Error("match_test must be a string");
  if (matchTest.length < 1 || matchTest.length > 200) {
    throw new Error("match_test must be 1..200 chars");
  }

  // Build args: anchor test transitively runs mocha; --skip-build keeps runs
  // fast when the evaluator has already compiled. The `--` separator passes
  // remaining args to the underlying test runner (mocha for TS suites).
  const baseArgs = ["test"];
  // Allowlist extra_args. Reject anything not in the allowlist. No
  // --provider.cluster (we control cluster via env), no flag values to
  // split-validate.
  for (const arg of extraArgs) {
    if (typeof arg !== "string" || arg.length === 0 || arg.length > 200) continue;
    if (!ANCHOR_EXTRA_ARG_ALLOWLIST.has(arg)) {
      throw new Error(`extra_args[${arg}] is not in the anchor allowlist; accepted: ${[...ANCHOR_EXTRA_ARG_ALLOWLIST].join(", ")}`);
    }
    baseArgs.push(arg);
  }
  // Mocha is invoked by anchor's [scripts] test config (typically `ts-mocha`).
  // Passing args after `--` forwards them to mocha. JSON reporter is the only
  // reliable machine-parseable shape across mocha versions; --grep filters by
  // test description so the evaluator's match_test maps cleanly.
  baseArgs.push("--", "--reporter", "json", "--grep", matchTest);

  const forkAttempts = [];
  // Anchor can run against the embedded validator (no fork) OR a evaluator-set-up
  // mainnet-clone localnet. We don't shell out a separate solana-test-validator
  // — that's the evaluator's harness responsibility. We pass the cluster URL via
  // env so the test can read it via process.env if needed; if Anchor.toml in
  // the workdir already pins cluster, that wins.
  if (candidateForkUrls.length === 0) {
    if (cluster != null || explicitForkUrls) {
      // Fail closed: the evaluator declared a cluster but we have no endpoints.
      // Silently running against localnet would let a evaluator record "tested"
      // without the real cluster ever being touched.
      return {
        ok: false,
        reason: "no_fork_endpoints_for_cluster",
        cluster,
        error: cluster == null
          ? "no public HTTPS RPC endpoints remain after applying the smart-contract egress policy"
          : `no public HTTPS RPC endpoints available for cluster ${cluster}; supply fork_urls explicitly or set BOB_SVM_RPCS_${String(cluster).toUpperCase().replace(/-/g, "_")}=url1,url2 in the MCP server env`,
        command: ["anchor", ...redactRpcEndpointArgs(baseArgs)],
        rpc_policy_rejections: summarizeRpcPolicyRejections(rpcPolicyRejections),
        fork_attempts: [],
      };
    }
    // No cluster supplied — run with whatever Anchor.toml configures. Covers
    // pure-localnet harnesses that don't depend on cloning.
    const result = await spawnAnchor(baseArgs, { workdir: resolvedWorkdir, timeoutMs: cappedTimeout, env: {} });
    return finalizeRun({ result, args: baseArgs, forkAttempts: [], forkSlot, fork_used: null, rpcPolicyRejections });
  }

  let lastResult = null;
  for (const url of candidateForkUrls) {
    // BOB_SVM_FORK_URL is read by the evaluator's anchor harness if they choose
    // to fork at runtime (validator clone via solana-test-validator --url).
    // We don't pass a CLI flag to anchor itself — anchor doesn't accept one.
    const env = { BOB_SVM_FORK_URL: url, BOB_SVM_CLUSTER: cluster || "" };
    const result = await spawnAnchor(baseArgs, { workdir: resolvedWorkdir, timeoutMs: cappedTimeout, env });
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
      return finalizeRun({ result, args: baseArgs, forkAttempts, forkSlot, fork_used: redactRpcEndpoint(url), rpcPolicyRejections });
    }
    // If anchor is missing entirely, no point trying other RPCs.
    if (result.reason === "anchor_not_in_path") {
      return finalizeRun({ result, args: baseArgs, forkAttempts, forkSlot, fork_used: null, rpcPolicyRejections });
    }
    // Differentiate test failure from RPC failure: if stdout shows mocha JSON,
    // the RPC was fine — the test simply asserted/failed.
    const looksLikeJsonOnStdout = typeof result.stdout === "string" && /\{\s*"stats"\s*:/.test(result.stdout);
    if (looksLikeJsonOnStdout) {
      return finalizeRun({ result, args: baseArgs, forkAttempts, forkSlot, fork_used: redactRpcEndpoint(url), rpcPolicyRejections });
    }
    // Otherwise treat as RPC failure and try the next endpoint.
  }
  return finalizeRun({ result: lastResult, args: baseArgs, forkAttempts, forkSlot, fork_used: null, rpcPolicyRejections });
}

// Classify a non-zero anchor exit by inspecting stderr. ENOENT on the anchor
// binary itself fires anchor_not_in_path early in spawnAnchor; this function
// covers the "anchor present, but its dependencies / test runner mis-configured"
// failure modes. The order matters — dependency-missing is more specific than
// runner-unknown, so we scan that first.
//
// Patterns are intentionally narrow. A bare "command not found" without one of
// the named tools nearby is too vague to attribute; we leave it as a generic
// run failure rather than risk a false dependency-missing classification.
const DEPENDENCY_MISSING_PATTERNS = [
  /(cargo|rustc):.*command not found/i,
  /(cargo|rustc):.*No such file or directory/i,
  /\bsolana\b.*command not found/i,
  /\bsolana-test-validator\b.*(command not found|No such file or directory)/i,
  /\b(yarn|npm|pnpm):.*command not found/i,
];
const TEST_RUNNER_UNKNOWN_PATTERNS = [
  /\bjest\b/i,
  /\bts-node\b/i,
  /\bts-mocha\b/i,
  /\bvitest\b/i,
  /Cannot find module .*reporter/i,
];

function classifyAnchorFailure(result, parseResultOk) {
  if (!result || result.ok || parseResultOk) return null;
  const stderr = String(result.stderr || "");
  const stdout = String(result.stdout || "");
  const combined = stderr + "\n" + stdout;
  for (const pattern of DEPENDENCY_MISSING_PATTERNS) {
    if (pattern.test(combined)) return "anchor_dependency_missing";
  }
  // Runner-unknown only triggers when no mocha JSON was produced — otherwise
  // the runner shape is fine and the test simply asserted (failed).
  if (!parseResultOk) {
    for (const pattern of TEST_RUNNER_UNKNOWN_PATTERNS) {
      if (pattern.test(combined)) return "anchor_test_runner_unknown";
    }
  }
  return null;
}

function finalizeRun({ result, args, forkAttempts, forkSlot, fork_used, rpcPolicyRejections = [] }) {
  if (!result || result.reason === "anchor_not_in_path" || result.reason === "anchor_spawn_failed") {
    return {
      ok: false,
      reason: result && result.reason ? result.reason : "spawn_failed",
      error: result && result.error ? result.error : null,
      command: ["anchor", ...redactRpcEndpointArgs(args)],
      rpc_policy_rejections: summarizeRpcPolicyRejections(rpcPolicyRejections),
      fork_attempts: forkAttempts,
    };
  }

  const parseResult = parseAnchorMochaJson(result.stdout || "");
  const summary = parseResult.ok
    ? summarizeAnchorMochaJson(parseResult.document)
    : { tests: [], total: 0, passed: 0, failed: 0, truncated: false };

  // Classify dependency-missing or runner-unknown failure modes BEFORE the
  // looksRpcUnreachable heuristic. Both run with non-zero exit + no mocha
  // JSON — without this branch they would all collapse into rpc_unreachable
  // and verifier prompts could not distinguish "tooling absent" from
  // "RPC down."
  const explicitFailureReason = classifyAnchorFailure(result, parseResult.ok);

  // Distinguish "no fork endpoint worked" from "test asserted (failed)". When
  // forkAttempts is non-empty AND none reported ok AND we never produced
  // structured mocha JSON, the failure is RPC-shaped, not test-shaped. Verifier
  // prompts depend on this top-level reason for fail-closed behavior.
  const allForkAttemptsFailed = forkAttempts.length > 0
    && forkAttempts.every((attempt) => attempt.ok !== true);
  const everyAttemptHasNoJson = forkAttempts.every((attempt) => {
    const stderr = String(attempt.stderr_excerpt || "");
    return !/\{\s*"stats"\s*:/.test(stderr);
  });
  const looksRpcUnreachable = allForkAttemptsFailed
    && everyAttemptHasNoJson
    && !parseResult.ok
    && !fork_used
    && !explicitFailureReason;

  // fork_slot_used: SVM analog of foundry's fork_block_used. If the caller
  // pinned forkSlot, that's the slot. Otherwise the verifier prompt treats
  // null as "do not claim a verified-at-slot reference."
  let forkSlotUsed = null;
  if (forkSlot != null) {
    forkSlotUsed = Number(forkSlot);
  }

  const envelope = {
    // ok requires: anchor exited cleanly, parsed JSON, no failed tests, AND
    // at least one test ran. summary.total === 0 ("no tests matched") would
    // otherwise let a evaluator record "tested" without execution.
    ok: result.ok && parseResult.ok && summary.failed === 0 && summary.total > 0,
    timed_out: result.timed_out === true,
    exit_code: result.exit_code,
    signal: result.signal || null,
    fork_used,
    fork_slot: forkSlot || null,
    fork_slot_used: forkSlotUsed,
    fork_attempts: forkAttempts,
    command: ["anchor", ...redactRpcEndpointArgs(args)],
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
  if (explicitFailureReason) {
    envelope.reason = explicitFailureReason;
  } else if (looksRpcUnreachable) {
    envelope.reason = "rpc_unreachable";
  }
  return envelope;
}

module.exports = {
  ANCHOR_EXTRA_ARG_ALLOWLIST,
  DEFAULT_TIMEOUT_MS,
  MAX_TIMEOUT_MS,
  classifyAnchorFailure,
  parseAnchorMochaJson,
  runAnchorTest,
  summarizeAnchorMochaJson,
};
