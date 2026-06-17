"use strict";

// offensive-runner.js — runs ONE offensive tool inside the hardened wide-open
// container (offensive-sandbox.js), captures+scans+redacts its output, and signs an
// offensive-runs row ONLY on a classified positive. PR5a foundation: NO MCP tool
// surface, NO arsenal tool, NO oracle — `classify` defaults to null (NEVER signs in
// production); the sign path is exercised only by tests with an injected stub.
//
// HOST-SIDE GUARDS (folded in from two adversarial-review rounds — PR5b wires a live
// tool directly on top and inherits this posture):
//   F1  container lifecycle: --name/--cidfile + `docker kill`/`rm -f` on timeout AND
//       on every exit path (killing the docker CLI client alone orphans a --rm
//       wide-open container).
//   F2  the runner spawns `docker` with a SCRUBBED env — a FIXED minimal PATH (not
//       the inherited one, so a poisoned PATH can't redirect the docker binary),
//       HOME + a clean DOCKER_CONFIG only, dropping DOCKER_HOST/CONTEXT/TLS/*_PROXY.
//   F3  per-session run budget RESERVED under the session lock BEFORE spawn (so
//       concurrent agents can't all pass a stale count), fail-closed on a read error,
//       fail-closed if the audit write fails (a run invisible to the breaker is not
//       allowed); each run is recorded to http-audit (method CONTAINER_RUN, which
//       survives the normalization that strips `tool`) so the breaker counts it.
//   F7/F10 stdout/stderr stream to a realpath-verified scratch dir with
//       O_EXCL|O_NOFOLLOW, are read back with the O_NOFOLLOW/regular-file/nlink
//       discipline, the FULL capture is secret-scanned, and the scratch is DELETED
//       on every exit path so raw output (and any secret in it) never lingers.
//   F9  fail-closed flag ALLOWLIST that distinguishes BOOLEAN flags (consume no
//       value) from VALUE flags (consume exactly one) — a boolean flag does not
//       authorize the next token; bare args and `--` are rejected; runner-injected
//       FORCED flags are trusted.
//   AIM the scope gate operates on the URLs ACTUALLY IN THE COMMAND — the values of
//       the spec's URL flags parsed out of toolArgv — never a separate parallel list
//       the caller could mis-map.
//   F11 surfaceId/canonicalTarget for the signed row are server-derived by the
//       caller (verdict), never agent free-input.
//
// DEFERRED to PR5b (the sign path is DEAD here, classify=null): binding the signed
// row's command_hash to the ACTUAL container command (the stub `sign` call below
// uses placeholder method/prefix); PR5b's registry-bound oracle supplies the real
// command-bound signing. `classify` in PR5b MUST be keyed on tool_id server-side,
// never a parameter crossing the MCP boundary.
//
// ACCEPTED RESIDUAL (operator-locked): wide-open OUTBOUND egress, cloud-metadata/LAN
// reachability, DNS exfil, kernel-0-day breakout. Mitigations: redaction-before-agent
// (here), the count/boolean oracle default (PR5b), OOB-only SSRF proof (PR6).

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { spawn, spawnSync } = require("child_process");

const { ERROR_CODES, ToolError } = require("./envelope.js");
const { repoRunsDir, sessionDir } = require("./paths.js");
const { withSessionLock } = require("./storage.js");
const { validateNoSensitiveMaterial } = require("./sensitive-material.js");
const { assertSafeRequestUrl } = require("./safe-fetch.js");
const { SCOPE_VALIDATION_OPTS, auditConfirmRequest } = require("./offensive-http-common.js");
const { readHttpAuditRecordsFromJsonl } = require("./http-records.js");
const { buildAndSignOffensiveRow } = require("./offensive-capture-writer.js");
const { buildOffensiveDockerRunArgv } = require("./offensive-sandbox.js");

const DEFAULT_TIMEOUT_MS = 120_000;
const MAX_TIMEOUT_MS = 600_000;
const MIN_TIMEOUT_MS = 5_000;
// Per-session cap on offensive container runs (fail-closed, global across tools).
const MAX_OFFENSIVE_RUNS = 200;
// http-audit normalization STRIPS `tool`, so offensive runs are marked + counted by
// a distinctive `method` token that survives normalization.
const OFFENSIVE_RUN_AUDIT_METHOD = "CONTAINER_RUN";
// On-disk stream cap per stream; the FULL captured slice up to this is secret-scanned
// (no unscanned-but-persisted tail), so the read cap == the stream cap.
const STREAM_CAP_BYTES = 16 * 1024 * 1024;
const CAPTURE_READ_CAP_BYTES = STREAM_CAP_BYTES;
// A FIXED minimal PATH for the docker client — never the inherited PATH (F2).
const FIXED_DOCKER_PATH = "/usr/local/bin:/usr/bin:/bin";

function rejectInvalid(message, details = null) {
  throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, message, details);
}

function mintRunId() {
  return `bob-off-${crypto.randomBytes(12).toString("hex")}`;
}

// F2: the env handed to the `docker` CLIENT — a fixed allowlist only.
function scrubbedDockerEnv(dockerConfigDir) {
  return { PATH: FIXED_DOCKER_PATH, HOME: dockerConfigDir, DOCKER_CONFIG: dockerConfigDir };
}

// F7/F10: read a capture leaf with the O_NOFOLLOW / regular-file / single-link
// discipline, bounded to CAPTURE_READ_CAP_BYTES.
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

// F9: parse + allowlist the tool argv. `spec` distinguishes boolean flags (no value)
// from value flags (exactly one value). Bare args + the `--` separator are rejected.
// Returns a Map of value-flag → value (so URL-flag values can be scope-checked).
function parseAllowlistedArgv(toolArgv, spec) {
  if (!Array.isArray(toolArgv) || toolArgv.length === 0 || !toolArgv.every((t) => typeof t === "string" && t.length > 0)) {
    rejectInvalid("toolArgv must be a non-empty array of non-empty strings");
  }
  const booleanFlags = spec && spec.boolean ? new Set(spec.boolean) : new Set();
  const valueFlags = spec && spec.value ? new Set(spec.value) : new Set();
  const values = new Map();
  let i = 1; // toolArgv[0] is the binary name
  while (i < toolArgv.length) {
    const tok = toolArgv[i];
    if (tok === "--") rejectInvalid("toolArgv must not contain the '--' pass-through separator");
    if (!tok.startsWith("-")) {
      rejectInvalid(`bare argument ${JSON.stringify(tok)} is not permitted (every value must follow an allowlisted value flag)`, { code: "offensive_bare_arg" });
    }
    const eq = tok.indexOf("=");
    const flagName = eq >= 0 ? tok.slice(0, eq) : tok;
    const inlineValue = eq >= 0 ? tok.slice(eq + 1) : null;
    if (booleanFlags.has(flagName)) {
      if (inlineValue !== null) rejectInvalid(`boolean flag ${flagName} must not take a value`, { code: "offensive_bool_flag_value" });
      i += 1;
      continue;
    }
    if (valueFlags.has(flagName)) {
      if (inlineValue !== null) {
        values.set(flagName, inlineValue);
        i += 1;
      } else {
        const next = toolArgv[i + 1];
        if (next === undefined || (typeof next === "string" && next.startsWith("-"))) {
          rejectInvalid(`value flag ${flagName} requires a value`, { code: "offensive_value_flag_missing" });
        }
        values.set(flagName, next);
        i += 2;
      }
      continue;
    }
    rejectInvalid(`flag ${flagName} is not in the tool flag allowlist`, { code: "offensive_flag_not_allowlisted" });
  }
  return values;
}

// F3 (fail-closed): count prior offensive container runs from http-audit. On a read
// error return Infinity so the budget check blocks (never fail open).
function offensiveRunCount(domain) {
  let records;
  try {
    records = readHttpAuditRecordsFromJsonl(domain);
  } catch {
    return Number.POSITIVE_INFINITY;
  }
  if (!Array.isArray(records)) return Number.POSITIVE_INFINITY;
  return records.filter((r) => r && r.method === OFFENSIVE_RUN_AUDIT_METHOD && r.scope_decision === "allowed").length;
}

// Realpath-verify a session-internal dir is actually under the session dir (defends
// a symlinked scratch dir, beyond the per-leaf O_NOFOLLOW).
function assertDirUnderSession(domain, dir) {
  const sessionReal = fs.realpathSync(sessionDir(domain));
  const dirReal = fs.realpathSync(dir);
  if (dirReal !== sessionReal && !dirReal.startsWith(sessionReal + path.sep)) {
    throw new ToolError(ERROR_CODES.STATE_CONFLICT, "offensive scratch dir escaped the session directory");
  }
}

// The default docker exec interface. Injectable so tests drive the runner with NO
// real docker. NOTE: the per-run startup sweep is intentionally NOT called from
// runOffensiveTool — a per-run `docker rm -f` of every bob-off-* would kill
// concurrent sessions' containers; `sweep` is exported for a session-INIT caller.
const defaultOffensiveDocker = Object.freeze({
  sweep(env) {
    try {
      const ps = spawnSync("docker", ["ps", "-aq", "--filter", "name=^bob-off-"], { env, timeout: 10_000, encoding: "utf8" });
      const ids = (ps.stdout || "").split("\n").map((s) => s.trim()).filter(Boolean);
      if (ids.length) spawnSync("docker", ["rm", "-f", ...ids], { env, timeout: 30_000 });
    } catch {}
  },
  networkCreate(name, env) {
    const r = spawnSync("docker", ["network", "create", "--internal=false", name], { env, timeout: 20_000, encoding: "utf8" });
    if (r.status !== 0) throw new ToolError(ERROR_CODES.STATE_CONFLICT, `docker network create failed: ${(r.stderr || "").trim() || r.status}`);
  },
  networkRm(name, env) { try { spawnSync("docker", ["network", "rm", name], { env, timeout: 10_000 }); } catch {} },
  kill(name, env) {
    try { spawnSync("docker", ["kill", name], { env, timeout: 10_000 }); } catch {}
    try { spawnSync("docker", ["rm", "-f", name], { env, timeout: 10_000 }); } catch {}
  },
  run({ args, env, timeoutMs, stdoutPath, stderrPath, containerName }) {
    return new Promise((resolve) => {
      const noFollow = fs.constants.O_NOFOLLOW || 0;
      const flags = fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | noFollow;
      let outFd; let errFd;
      try {
        outFd = fs.openSync(stdoutPath, flags, 0o600);
        errFd = fs.openSync(stderrPath, flags, 0o600);
      } catch (e) {
        if (outFd != null) try { fs.closeSync(outFd); } catch {}
        resolve({ exit_code: null, timed_out: false, spawn_error: `capture open failed: ${e.message || String(e)}` });
        return;
      }
      let killed = false; let child;
      try {
        child = spawn("docker", args, { env, detached: true, stdio: ["ignore", "pipe", "pipe"] });
      } catch (e) {
        fs.closeSync(outFd); fs.closeSync(errFd);
        resolve({ exit_code: null, timed_out: false, spawn_error: e.message || String(e) });
        return;
      }
      const cappedWrite = (fd, chunk, ref) => {
        if (ref.n >= STREAM_CAP_BYTES) return;
        const slice = chunk.length > STREAM_CAP_BYTES - ref.n ? chunk.subarray(0, STREAM_CAP_BYTES - ref.n) : chunk;
        try { fs.writeSync(fd, slice); } catch {}
        ref.n += slice.length;
      };
      const outRef = { n: 0 }; const errRef = { n: 0 };
      child.stdout.on("data", (c) => cappedWrite(outFd, c, outRef));
      child.stderr.on("data", (c) => cappedWrite(errFd, c, errRef));
      // Single-settle guard: `error` and `close` can both fire on one child — close
      // the fds and resolve exactly once (no double-close EBADF, no double-resolve).
      let settled = false;
      const finish = (result) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        try { fs.closeSync(outFd); } catch {}
        try { fs.closeSync(errFd); } catch {}
        resolve(result);
      };
      const timer = setTimeout(() => {
        killed = true;
        try { if (child.pid) process.kill(-child.pid, "SIGTERM"); } catch {}
        defaultOffensiveDocker.kill(containerName, env); // F1: kill the CONTAINER, not just the client
        setTimeout(() => { try { if (child.pid) process.kill(-child.pid, "SIGKILL"); } catch {} }, 5_000);
      }, timeoutMs);
      child.on("error", (e) => finish({ exit_code: null, timed_out: killed, spawn_error: e.code === "ENOENT" ? "docker_not_in_path" : (e.message || String(e)) }));
      child.on("close", (code) => finish({ exit_code: killed ? null : code, timed_out: killed, out_bytes: outRef.n, err_bytes: errRef.n }));
    });
  },
});

function blocked(domain, toolId, outcome, reason, extra = {}) {
  return { confirmed: false, target_domain: domain, tool_id: toolId, offensive_outcome: outcome, reason, row_written: false, ...extra };
}

// Run one offensive tool. Returns a MASKED result (booleans/counts/run_id only).
async function runOffensiveTool({
  domain,
  toolId,
  imageDigest,
  toolArgv,
  flagSpec = {},
  forcedFlags = [],
  egressProxyUrl = null,
  workTmpfsBytes,
  timeoutMs = DEFAULT_TIMEOUT_MS,
  docker = defaultOffensiveDocker,
  classify = null,
  sign = buildAndSignOffensiveRow,
}) {
  if (typeof domain !== "string" || !domain.trim()) rejectInvalid("domain is required");
  if (typeof toolId !== "string" || !toolId.trim()) rejectInvalid("toolId is required");
  // forcedFlags are TRUSTED, server/spec-defined tokens the runner injects (e.g.
  // --max-redirs 0, -disable-update-check) — NEVER agent-supplied. They bypass the
  // tool-argv allowlist by design, so assert each is a flag token: a bare arg or a
  // command cannot be smuggled through the exemption.
  if (!Array.isArray(forcedFlags) || !forcedFlags.every((f) => typeof f === "string" && f.startsWith("-"))) {
    rejectInvalid("forcedFlags must be server-defined flag tokens (each starting with '-')");
  }
  const cappedTimeout = Math.min(Math.max(Number(timeoutMs) || DEFAULT_TIMEOUT_MS, MIN_TIMEOUT_MS), MAX_TIMEOUT_MS);

  // 1) Flag allowlist (fail-closed) → parsed value-flag map.
  const valueFlags = parseAllowlistedArgv(toolArgv, flagSpec);
  // 2) AIM-CHECK: scope-gate the URLs ACTUALLY in the command (the values of the
  // spec's URL flags), BEFORE any spawn. Decoupled-list drift is impossible.
  const urlFlagNames = flagSpec && flagSpec.url ? new Set(flagSpec.url) : new Set();
  for (const [flag, value] of valueFlags) {
    if (urlFlagNames.has(flag)) {
      assertSafeRequestUrl(String(value), domain, SCOPE_VALIDATION_OPTS); // throws SCOPE_BLOCKED out of scope
    }
  }

  // 3) Reserve a run budget slot ATOMICALLY under the session lock (count +
  // audit-record write together), fail-closed on over-budget / audit failure.
  const startedAt = Date.now();
  const primaryUrl = [...valueFlags].find(([f]) => urlFlagNames.has(f));
  const auditUrl = primaryUrl ? String(primaryUrl[1]) : `https://${domain}/`;
  const reservation = withSessionLock(domain, () => {
    if (offensiveRunCount(domain) >= MAX_OFFENSIVE_RUNS) return { ok: false, reason: "offensive_run_budget_exhausted" };
    const auditOk = auditConfirmRequest({ domain, surfaceId: null, method: OFFENSIVE_RUN_AUDIT_METHOD, url: auditUrl, egressProfile: egressProxyUrl ? "proxy" : null, status: null, scopeDecision: "allowed", error: null, startedAt, toolId });
    if (auditOk === false) return { ok: false, reason: "offensive_run_audit_failed" };
    return { ok: true };
  });
  if (!reservation.ok) {
    return blocked(domain, toolId, "blocked_by_infra", reservation.reason);
  }

  const runId = mintRunId();
  const scratchDir = repoRunsDir(domain);
  fs.mkdirSync(scratchDir, { recursive: true });
  assertDirUnderSession(domain, scratchDir);
  const stdoutPath = path.join(scratchDir, `${runId}.stdout`);
  const stderrPath = path.join(scratchDir, `${runId}.stderr`);
  const cidfilePath = path.join(scratchDir, `${runId}.cid`);
  const dockerConfigDir = path.join(scratchDir, `${runId}.dockercfg`);
  fs.mkdirSync(dockerConfigDir, { recursive: true });
  const env = scrubbedDockerEnv(dockerConfigDir);

  // Container command: tool + runner-FORCED flags (trusted) + the allowlisted tail.
  const command = [toolArgv[0], ...forcedFlags, ...toolArgv.slice(1)];
  const { args } = buildOffensiveDockerRunArgv({ imageDigest, command, containerName: runId, networkName: runId, cidfilePath, workTmpfsBytes, egressProxyUrl });

  const cleanupScratch = () => {
    for (const p of [stdoutPath, stderrPath, cidfilePath]) { try { fs.rmSync(p, { force: true }); } catch {} }
    try { fs.rmSync(dockerConfigDir, { recursive: true, force: true }); } catch {}
  };

  let runResult;
  try {
    docker.networkCreate(runId, env);
  } catch (e) {
    cleanupScratch();
    return blocked(domain, toolId, "blocked_by_infra", "offensive_network_create_failed", { failure_reason: e.message || String(e) });
  }
  let stdoutBytes = Buffer.alloc(0);
  let stderrBytes = Buffer.alloc(0);
  try {
    runResult = await docker.run({ args, env, timeoutMs: cappedTimeout, stdoutPath, stderrPath, containerName: runId });
    // Read the captures back (O_NOFOLLOW) BEFORE teardown deletes them.
    stdoutBytes = secureReadCaptureBytes(stdoutPath);
    stderrBytes = secureReadCaptureBytes(stderrPath);
  } finally {
    docker.kill(runId, env);        // F1: ensure the container is gone on every path
    docker.networkRm(runId, env);
    cleanupScratch();               // F7-cleanup: raw output never lingers on disk
  }

  if (runResult.spawn_error) return blocked(domain, toolId, "blocked_by_infra", "offensive_spawn_failed", { failure_reason: runResult.spawn_error });
  if (runResult.timed_out) return blocked(domain, toolId, "blocked_by_infra", "offensive_run_timed_out");

  const stdoutText = stdoutBytes.toString("utf8");
  const stderrText = stderrBytes.toString("utf8");
  // F4 redaction backstop: scan the FULL capture (large cap so a real tool's output
  // is scanned, not rejected for length). Fail closed (no row, masked block) if it
  // carries secrets/credentials.
  try {
    validateNoSensitiveMaterial(stdoutText, "offensive_stdout", { maxTextChars: STREAM_CAP_BYTES });
    validateNoSensitiveMaterial(stderrText, "offensive_stderr", { maxTextChars: STREAM_CAP_BYTES });
  } catch {
    return blocked(domain, toolId, "blocked_operator_pii", "offensive_output_contains_sensitive_value");
  }

  // PR5a: no oracle → never sign. PR5b supplies a registry-bound classify.
  if (typeof classify !== "function") {
    return {
      ...blocked(domain, toolId, runResult.exit_code === 0 ? "blocked_by_design" : "blocked_by_defense", "no_oracle_classifier"),
      masked_summary: { exit_code: runResult.exit_code, stdout_bytes: runResult.out_bytes || 0, stderr_bytes: runResult.err_bytes || 0 },
    };
  }
  const verdict = classify({ exitCode: runResult.exit_code, stdoutText, stderrText });
  if (!verdict || verdict.positive !== true) {
    return blocked(domain, toolId, "blocked_by_defense", (verdict && verdict.reason) || "oracle_negative");
  }
  // Defense-in-depth: re-validate the oracle's target is in-scope before it is signed
  // into a durable row — even a server-side classify cannot sign an off-scope target.
  try {
    assertSafeRequestUrl(String(verdict.canonicalTarget), domain, SCOPE_VALIDATION_OPTS);
  } catch {
    return blocked(domain, toolId, "blocked_by_design", "oracle_target_out_of_scope");
  }

  // F11: surfaceId/canonicalTarget are server-derived by the caller (verdict). The
  // signer re-hashes from its OWN O_EXCL-owned offensive-runs/ leaves.
  // DEFERRED (PR5b): bind the row's command_hash to the actual container command —
  // the placeholder method/prefix here are inert because classify is null in prod.
  const row = withSessionLock(domain, () => sign(domain, {
    runIdPrefix: "reflect",
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
    confirmed: true, target_domain: domain, tool_id: row.tool_id, offensive_outcome: "exploited_safely", row_written: true,
    run_id: row.run_id, target: row.target, demonstrated_severity: row.demonstrated_severity,
    command_hash: row.command_hash, stdout_hash: row.stdout_hash, stderr_hash: row.stderr_hash, exit_code: row.exit_code,
    masked_summary: { relation: verdict.relationBooleans || {}, fragment_hash: row.stdout_hash },
  };
}

module.exports = {
  runOffensiveTool,
  parseAllowlistedArgv,
  scrubbedDockerEnv,
  secureReadCaptureBytes,
  offensiveRunCount,
  mintRunId,
  defaultOffensiveDocker,
  MAX_OFFENSIVE_RUNS,
  MAX_TIMEOUT_MS,
  OFFENSIVE_RUN_AUDIT_METHOD,
};
