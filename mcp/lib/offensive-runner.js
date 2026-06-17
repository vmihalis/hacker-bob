"use strict";

// offensive-runner.js — runs ONE offensive tool inside the hardened wide-open
// container (offensive-sandbox.js), captures+caps+redacts its output, and signs an
// offensive-runs row ONLY on a classified positive. PR5a foundation: NO MCP tool
// surface, NO arsenal tool, NO oracle — `classify` defaults to null (never signs in
// production); the sign path is exercised only by tests with an injected stub.
//
// HOST-SIDE GUARDS (folded in from the PR5a adversarial review — PR5b wires a live
// tool directly on top and inherits this posture):
//   F1  container lifecycle: --name/--cidfile + `docker kill`/`rm -f` on timeout
//       (killing the docker CLI client alone orphans a --rm wide-open container) +
//       a startup sweep of stale bob-off-* containers/networks.
//   F2  the runner spawns `docker` with a SCRUBBED env (PATH/HOME + clean
//       DOCKER_CONFIG only), dropping DOCKER_HOST/DOCKER_CONTEXT/DOCKER_TLS_*/
//       *_PROXY so a poisoned host env can't redirect the client to a hostile daemon.
//   F3  per-session run budget checked BEFORE spawn + each run recorded to
//       http-audit so the circuit-breaker counts container traffic it can't see.
//   F7  live stdout/stderr stream to a scratch dir (repo-runs), read back with the
//       O_NOFOLLOW discipline, then handed to buildAndSignOffensiveRow which
//       exclusively (O_EXCL) owns offensive-runs/ — no capture-path collision.
//   F8  a throwaway per-run user-defined network (created/removed per run) so the
//       container can't reach docker0 neighbours (still wide-open OUTBOUND).
//   F9  fail-closed flag ALLOWLIST over the tool argv + runner-injected FORCED flags.
//   F11 surfaceId/canonicalTarget for the signed row are server-derived by the
//       CALLER from the routed, scope-validated target — never agent free-input
//       (the record gate does not prove the row attacked that surface).
//
// ACCEPTED RESIDUAL (operator-locked, documented — not fixed here): wide-open
// OUTBOUND egress, cloud-metadata/LAN reachability, DNS exfil, kernel-0-day
// breakout. Mitigations are redaction-before-agent (here), the count/boolean oracle
// default (PR5b), and OOB-only SSRF proof (PR6).

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { spawn, spawnSync } = require("child_process");

const { ERROR_CODES, ToolError } = require("./envelope.js");
const { repoRunsDir } = require("./paths.js");
const { withSessionLock } = require("./storage.js");
const { validateNoSensitiveMaterial } = require("./sensitive-material.js");
const { assertSafeRequestUrl } = require("./safe-fetch.js");
const { SCOPE_VALIDATION_OPTS, auditConfirmRequest } = require("./offensive-http-common.js");
const { readHttpAuditRecordsFromJsonl } = require("./http-records.js");
const { buildAndSignOffensiveRow } = require("./offensive-capture-writer.js");
const { buildOffensiveDockerRunArgv, BOB_OFF_NAME_RE } = require("./offensive-sandbox.js");

const DEFAULT_TIMEOUT_MS = 120_000;
const MAX_TIMEOUT_MS = 600_000;
const MIN_TIMEOUT_MS = 5_000;
// Per-session cap on offensive container runs (fail-closed). A wide-open container
// can fire unbounded requests, so the number of runs a session may launch is
// bounded; each run is recorded to http-audit so the breaker also sees the traffic.
const MAX_OFFENSIVE_RUNS = 200;
// http-audit normalization STRIPS the `tool` field, so offensive container runs are
// marked + counted by a distinctive `method` token that survives normalization.
// This makes the budget GLOBAL across offensive tools (the per-session intent).
const OFFENSIVE_RUN_AUDIT_METHOD = "CONTAINER_RUN";
// Only the first slice of each capture is read back for the redaction scan + the
// (PR5b) oracle. The on-disk stream is independently capped by the spawn writer.
const CAPTURE_READ_CAP_BYTES = 2 * 1024 * 1024;
const STREAM_CAP_BYTES = 16 * 1024 * 1024;

function rejectInvalid(message, details = null) {
  throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, message, details);
}

function mintRunId() {
  // bob-off-<24 hex> — matches BOB_OFF_NAME_RE; the container name, network name,
  // and capture/cid leaves all derive from it.
  return `bob-off-${crypto.randomBytes(12).toString("hex")}`;
}

// F2: the env handed to the `docker` CLIENT. A curated allowlist only — never the
// inherited process env — so DOCKER_HOST / DOCKER_CONTEXT / DOCKER_TLS_VERIFY /
// DOCKER_CERT_PATH / *_PROXY cannot redirect the client to a hostile daemon, and a
// poisoned ~/.docker/config.json default context is bypassed via a clean
// DOCKER_CONFIG dir.
function scrubbedDockerEnv(dockerConfigDir) {
  return {
    PATH: process.env.PATH || "/usr/local/bin:/usr/bin:/bin",
    HOME: dockerConfigDir,
    DOCKER_CONFIG: dockerConfigDir,
  };
}

// F7/F10: read a capture leaf with the O_NOFOLLOW / regular-file / single-link
// discipline (a same-uid container/agent must not redirect the read via a symlink),
// bounded to CAPTURE_READ_CAP_BYTES.
function secureReadCaptureBytes(filePath) {
  const noFollow = fs.constants.O_NOFOLLOW || 0;
  let fd;
  try {
    fd = fs.openSync(filePath, fs.constants.O_RDONLY | noFollow);
  } catch {
    return Buffer.alloc(0);
  }
  try {
    const st = fs.fstatSync(fd);
    if (!st.isFile() || st.nlink !== 1) return Buffer.alloc(0);
    const len = Math.min(st.size, CAPTURE_READ_CAP_BYTES);
    if (len <= 0) return Buffer.alloc(0);
    const buf = Buffer.alloc(len);
    fs.readSync(fd, buf, 0, len, 0);
    return buf;
  } finally {
    fs.closeSync(fd);
  }
}

// F9: every flag token (a token starting with "-") must be in the allowlist; a
// value token is accepted only when it follows an allowlisted flag. Reject the "--"
// pass-through separator. forcedFlags the runner injects are exempt (it owns them).
function assertToolArgvAllowed(toolArgv, flagAllowlist) {
  if (!Array.isArray(toolArgv) || toolArgv.length === 0 || !toolArgv.every((t) => typeof t === "string" && t.length > 0)) {
    rejectInvalid("toolArgv must be a non-empty array of non-empty strings");
  }
  const allow = flagAllowlist instanceof Set ? flagAllowlist : new Set(flagAllowlist || []);
  let prevWasAllowedFlag = false;
  // toolArgv[0] is the tool binary name (no leading dash) — skip it.
  for (let i = 1; i < toolArgv.length; i += 1) {
    const tok = toolArgv[i];
    if (tok === "--") rejectInvalid("toolArgv must not contain the '--' pass-through separator");
    if (tok.startsWith("-")) {
      const flagName = tok.split("=")[0];
      if (!allow.has(flagName)) {
        rejectInvalid(`flag ${flagName} is not in the tool flag allowlist`, { code: "offensive_flag_not_allowlisted" });
      }
      prevWasAllowedFlag = !tok.includes("=");
    } else if (!prevWasAllowedFlag) {
      rejectInvalid(`bare argument ${JSON.stringify(tok)} is not permitted (must follow an allowlisted flag)`, { code: "offensive_bare_arg" });
    } else {
      prevWasAllowedFlag = false;
    }
  }
}

// F3: count prior offensive container runs for this (session, tool) from http-audit
// and fail closed at the cap. (PR5b can generalise to a global offensive count.)
function offensiveRunCount(domain) {
  let records;
  try {
    records = readHttpAuditRecordsFromJsonl(domain);
  } catch {
    return 0;
  }
  if (!Array.isArray(records)) return 0;
  return records.filter((r) => r && r.method === OFFENSIVE_RUN_AUDIT_METHOD && r.scope_decision === "allowed").length;
}

// The default docker exec interface. Injectable so tests drive the runner with NO
// real docker. Network/kill/sweep use spawnSync (short, best-effort); run streams.
const defaultOffensiveDocker = Object.freeze({
  sweep(env) {
    // Best-effort cleanup of stragglers from a crashed prior run.
    try {
      const ps = spawnSync("docker", ["ps", "-aq", "--filter", "name=bob-off-"], { env, timeout: 10_000, encoding: "utf8" });
      const ids = (ps.stdout || "").split("\n").map((s) => s.trim()).filter(Boolean);
      if (ids.length) spawnSync("docker", ["rm", "-f", ...ids], { env, timeout: 30_000 });
      const nets = spawnSync("docker", ["network", "ls", "-q", "--filter", "name=bob-off-"], { env, timeout: 10_000, encoding: "utf8" });
      const netIds = (nets.stdout || "").split("\n").map((s) => s.trim()).filter(Boolean);
      for (const n of netIds) spawnSync("docker", ["network", "rm", n], { env, timeout: 10_000 });
    } catch {}
  },
  networkCreate(name, env) {
    const r = spawnSync("docker", ["network", "create", "--internal=false", name], { env, timeout: 20_000, encoding: "utf8" });
    if (r.status !== 0) throw new ToolError(ERROR_CODES.STATE_CONFLICT, `docker network create failed: ${(r.stderr || "").trim() || r.status}`);
  },
  networkRm(name, env) {
    try { spawnSync("docker", ["network", "rm", name], { env, timeout: 10_000 }); } catch {}
  },
  kill(name, env) {
    try { spawnSync("docker", ["kill", name], { env, timeout: 10_000 }); } catch {}
    try { spawnSync("docker", ["rm", "-f", name], { env, timeout: 10_000 }); } catch {}
  },
  run({ args, env, timeoutMs, stdoutPath, stderrPath, containerName }) {
    return new Promise((resolve) => {
      const noFollow = fs.constants.O_NOFOLLOW || 0;
      const flags = fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | noFollow;
      let outFd;
      let errFd;
      try {
        outFd = fs.openSync(stdoutPath, flags, 0o600);
        errFd = fs.openSync(stderrPath, flags, 0o600);
      } catch (e) {
        if (outFd != null) try { fs.closeSync(outFd); } catch {}
        resolve({ exit_code: null, timed_out: false, spawn_error: `capture open failed: ${e.message || String(e)}` });
        return;
      }
      let outBytes = 0;
      let errBytes = 0;
      let killed = false;
      let child;
      try {
        child = spawn("docker", args, { env, detached: true, stdio: ["ignore", "pipe", "pipe"] });
      } catch (e) {
        fs.closeSync(outFd); fs.closeSync(errFd);
        resolve({ exit_code: null, timed_out: false, spawn_error: e.message || String(e) });
        return;
      }
      const cappedWrite = (fd, chunk, countRef) => {
        if (countRef.n >= STREAM_CAP_BYTES) return;
        const room = STREAM_CAP_BYTES - countRef.n;
        const slice = chunk.length > room ? chunk.subarray(0, room) : chunk;
        try { fs.writeSync(fd, slice); } catch {}
        countRef.n += slice.length;
      };
      const outRef = { n: 0 };
      const errRef = { n: 0 };
      child.stdout.on("data", (c) => cappedWrite(outFd, c, outRef));
      child.stderr.on("data", (c) => cappedWrite(errFd, c, errRef));
      const timer = setTimeout(() => {
        killed = true;
        // F1: kill the docker CLIENT process group AND the CONTAINER (the --rm
        // container outlives a client-only kill; the daemon owns its lifecycle).
        try { if (child.pid) process.kill(-child.pid, "SIGTERM"); } catch {}
        defaultOffensiveDocker.kill(containerName, env);
        setTimeout(() => { try { if (child.pid) process.kill(-child.pid, "SIGKILL"); } catch {} }, 5_000);
      }, timeoutMs);
      child.on("error", (e) => {
        clearTimeout(timer);
        try { fs.closeSync(outFd); fs.closeSync(errFd); } catch {}
        resolve({ exit_code: null, timed_out: killed, spawn_error: e.code === "ENOENT" ? "docker_not_in_path" : (e.message || String(e)) });
      });
      child.on("close", (code) => {
        clearTimeout(timer);
        try { fs.closeSync(outFd); fs.closeSync(errFd); } catch {}
        resolve({ exit_code: killed ? null : code, timed_out: killed, out_bytes: outRef.n, err_bytes: errRef.n });
      });
    });
  },
});

// Run one offensive tool. Returns a MASKED result (booleans/counts/run_id only,
// never raw response bytes). `classify`/`sign` are injectable; in production
// classify is null (PR5a never signs).
async function runOffensiveTool({
  domain,
  toolId,
  imageDigest,
  toolArgv,
  flagAllowlist = [],
  forcedFlags = [],
  scopeUrlArgs = [],
  egressProxyUrl = null,
  workTmpfsBytes,
  timeoutMs = DEFAULT_TIMEOUT_MS,
  docker = defaultOffensiveDocker,
  classify = null,
  sign = buildAndSignOffensiveRow,
}) {
  if (typeof domain !== "string" || !domain.trim()) rejectInvalid("domain is required");
  if (typeof toolId !== "string" || !toolId.trim()) rejectInvalid("toolId is required");
  const cappedTimeout = Math.min(Math.max(Number(timeoutMs) || DEFAULT_TIMEOUT_MS, MIN_TIMEOUT_MS), MAX_TIMEOUT_MS);

  // 1) Aim-check: scope-gate EVERY externally-reachable URL arg BEFORE any spawn.
  for (const url of scopeUrlArgs) {
    assertSafeRequestUrl(String(url), domain, SCOPE_VALIDATION_OPTS); // throws SCOPE_BLOCKED out of scope
  }
  // 2) Flag allowlist (fail-closed) over the agent/caller-supplied tool argv.
  assertToolArgvAllowed(toolArgv, flagAllowlist);
  // 3) Run budget (fail-closed) BEFORE spawn.
  if (offensiveRunCount(domain) >= MAX_OFFENSIVE_RUNS) {
    return { confirmed: false, target_domain: domain, tool_id: toolId, offensive_outcome: "blocked_by_infra", reason: "offensive_run_budget_exhausted", row_written: false };
  }

  const runId = mintRunId();
  const scratchDir = repoRunsDir(domain);
  fs.mkdirSync(scratchDir, { recursive: true });
  const stdoutPath = path.join(scratchDir, `${runId}.stdout`);
  const stderrPath = path.join(scratchDir, `${runId}.stderr`);
  const cidfilePath = path.join(scratchDir, `${runId}.cid`);
  const dockerConfigDir = path.join(scratchDir, `${runId}.dockercfg`);
  fs.mkdirSync(dockerConfigDir, { recursive: true });
  const env = scrubbedDockerEnv(dockerConfigDir);
  const startedAt = Date.now();

  // The full container command: tool + runner-FORCED flags (F9, e.g. --max-redirs 0,
  // -disable-update-check) + the caller's allowlisted argv tail.
  const command = [toolArgv[0], ...forcedFlags, ...toolArgv.slice(1)];
  const { args } = buildOffensiveDockerRunArgv({
    imageDigest, command, containerName: runId, networkName: runId, cidfilePath, workTmpfsBytes, egressProxyUrl,
  });

  // F3 write: record the run to http-audit (redacted target) so the breaker counts
  // it. Use the primary scope-gated target as the audit url (or the session apex).
  const auditUrl = scopeUrlArgs.length ? String(scopeUrlArgs[0]) : `https://${domain}/`;
  auditConfirmRequest({ domain, surfaceId: null, method: OFFENSIVE_RUN_AUDIT_METHOD, url: auditUrl, egressProfile: egressProxyUrl ? "proxy" : null, status: null, scopeDecision: "allowed", error: null, startedAt, toolId });

  // F1/F8: best-effort sweep, then a throwaway per-run network; run; always tear down.
  docker.sweep(env);
  let runResult;
  try {
    docker.networkCreate(runId, env);
  } catch (e) {
    return { confirmed: false, target_domain: domain, tool_id: toolId, offensive_outcome: "blocked_by_infra", reason: "offensive_network_create_failed", failure_reason: e.message || String(e), row_written: false };
  }
  try {
    runResult = await docker.run({ args, env, timeoutMs: cappedTimeout, stdoutPath, stderrPath, containerName: runId });
  } finally {
    docker.kill(runId, env); // F1: ensure the container is gone even on a clean exit path
    docker.networkRm(runId, env);
  }

  if (runResult.spawn_error) {
    return { confirmed: false, target_domain: domain, tool_id: toolId, offensive_outcome: "blocked_by_infra", reason: "offensive_spawn_failed", failure_reason: runResult.spawn_error, row_written: false };
  }
  if (runResult.timed_out) {
    return { confirmed: false, target_domain: domain, tool_id: toolId, offensive_outcome: "blocked_by_infra", reason: "offensive_run_timed_out", row_written: false };
  }

  // F7/F10: read the captured bytes back with the O_NOFOLLOW discipline.
  const stdoutBytes = secureReadCaptureBytes(stdoutPath);
  const stderrBytes = secureReadCaptureBytes(stderrPath);
  const stdoutText = stdoutBytes.toString("utf8");
  const stderrText = stderrBytes.toString("utf8");

  // F4 redaction backstop: the captured output must never carry secrets/credentials
  // into the agent-facing return or a signed row. Fail closed (no row) if it does.
  try {
    validateNoSensitiveMaterial(stdoutText, "offensive_stdout");
    validateNoSensitiveMaterial(stderrText, "offensive_stderr");
  } catch {
    return { confirmed: false, target_domain: domain, tool_id: toolId, offensive_outcome: "blocked_operator_pii", reason: "offensive_output_contains_sensitive_value", row_written: false };
  }

  // PR5a: no oracle → never sign. PR5b supplies a registry-bound classify.
  if (typeof classify !== "function") {
    return {
      confirmed: false, target_domain: domain, tool_id: toolId,
      offensive_outcome: runResult.exit_code === 0 ? "blocked_by_design" : "blocked_by_defense",
      reason: "no_oracle_classifier", row_written: false,
      masked_summary: { exit_code: runResult.exit_code, stdout_bytes: runResult.out_bytes || 0, stderr_bytes: runResult.err_bytes || 0 },
    };
  }

  const verdict = classify({ exitCode: runResult.exit_code, stdoutText, stderrText });
  if (!verdict || verdict.positive !== true) {
    return { confirmed: false, target_domain: domain, tool_id: toolId, offensive_outcome: "blocked_by_defense", reason: (verdict && verdict.reason) || "oracle_negative", row_written: false };
  }

  // F11: surfaceId/canonicalTarget MUST be server-derived by the caller (verdict),
  // never agent free-input. Sign under the session lock; the signer re-hashes from
  // its own O_EXCL-owned offensive-runs/ leaves (NOT these scratch files).
  const row = withSessionLock(domain, () => sign(domain, {
    runIdPrefix: "reflect", // placeholder; PR5b passes a per-tool prefix
    toolId,
    method: "GET",
    canonicalTarget: verdict.canonicalTarget,
    surfaceId: verdict.surfaceId,
    identityTag: "unauth-offensive",
    stdoutContent: verdict.stdoutContent != null ? verdict.stdoutContent : stdoutText,
    stderrContent: verdict.stderrContent != null ? verdict.stderrContent : stderrText,
    relationBooleans: verdict.relationBooleans || {},
  }));

  return {
    confirmed: true, target_domain: domain, tool_id: row.tool_id,
    offensive_outcome: "exploited_safely", row_written: true,
    run_id: row.run_id, target: row.target, demonstrated_severity: row.demonstrated_severity,
    command_hash: row.command_hash, stdout_hash: row.stdout_hash, stderr_hash: row.stderr_hash, exit_code: row.exit_code,
    masked_summary: { relation: verdict.relationBooleans || {}, fragment_hash: row.stdout_hash },
  };
}

module.exports = {
  runOffensiveTool,
  // exported for unit tests / PR5b
  assertToolArgvAllowed,
  scrubbedDockerEnv,
  secureReadCaptureBytes,
  offensiveRunCount,
  mintRunId,
  defaultOffensiveDocker,
  MAX_OFFENSIVE_RUNS,
  MAX_TIMEOUT_MS,
};
