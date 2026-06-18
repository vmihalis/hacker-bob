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
const { buildAndSignOffensiveRow } = require("./offensive-capture-writer.js");
const { buildOffensiveDockerRunArgv } = require("./offensive-sandbox.js");

const DEFAULT_TIMEOUT_MS = 120_000;
const MAX_TIMEOUT_MS = 600_000;
const MIN_TIMEOUT_MS = 5_000;
// Per-session cap on offensive container runs (fail-closed, global across tools).
const MAX_OFFENSIVE_RUNS = 200;
// #124-3: cap on infra failures (network-create / spawn errors — the container never
// ran). These are REFUNDED from the run budget (an infra failure must not burn a
// genuine-run slot), so they need their own bound, or a daemon/target that fails every
// spawn could spin unbounded docker attempts. Fail-closed like the run budget.
const MAX_OFFENSIVE_INFRA_FAILURES = 50;
// http-audit normalization STRIPS `tool`, so offensive runs are marked + counted by
// a distinctive `method` token that survives normalization.
const OFFENSIVE_RUN_AUDIT_METHOD = "CONTAINER_RUN";
// On-disk stream cap per stream; the FULL captured slice up to this is secret-scanned
// (no unscanned-but-persisted tail), so the read cap == the stream cap. Kept modest
// (4 MiB) so the synchronous secret scan can't block the event loop on a huge capture
// — far more than a count/boolean oracle needs; output past it is truncated.
const STREAM_CAP_BYTES = 4 * 1024 * 1024;
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
  // If the platform lacks O_NOFOLLOW, lstat-gate the path so a symlink swapped in
  // after the O_EXCL write is not followed (don't silently drop the protection).
  if (!noFollow) {
    try { if (fs.lstatSync(filePath).isSymbolicLink()) return Buffer.alloc(0); } catch { return Buffer.alloc(0); }
  }
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
    // read() may return fewer bytes than requested — loop until full, and return
    // only the bytes actually read so a partial read can't leave a zero-padded tail
    // that corrupts the secret scan or the row hash.
    let off = 0;
    while (off < len) {
      const n = fs.readSync(fd, buf, off, len - off, off);
      if (n <= 0) break;
      off += n;
    }
    return off === len ? buf : buf.subarray(0, off);
  } finally {
    fs.closeSync(fd);
  }
}

// A value is treated as a network target (and scope-checked) if it carries a URL
// scheme OR is protocol-relative (`//host`). Bare schemeless hosts (e.g. `evil.com`)
// need PR5b's typed scope_url_fields to disambiguate from non-target values
// (filenames, numbers); until then a bare host on an UNDECLARED flag is part of the
// accepted aim-check residual (declared flagSpec.url flags are checked regardless).
function looksLikeUrl(value) {
  return /^([a-z][a-z0-9+.-]*:)?\/\//i.test(String(value));
}

// F9: parse + allowlist the tool argv. `spec` distinguishes boolean flags (no value)
// from value flags (exactly one value). Bare args + the `--` separator are rejected.
// Returns a list of {flag,value} pairs (repeats preserved) for scope-checking.
function parseAllowlistedArgv(toolArgv, spec) {
  if (!Array.isArray(toolArgv) || toolArgv.length === 0 || !toolArgv.every((t) => typeof t === "string" && t.length > 0)) {
    rejectInvalid("toolArgv must be a non-empty array of non-empty strings");
  }
  // toolArgv[0] is the container binary the runner executes — constrain it to a bare
  // binary-name token (no path separators / metacharacters) so an arbitrary in-image
  // binary or path can't be run.
  if (!/^[a-zA-Z0-9._-]+$/.test(toolArgv[0])) {
    rejectInvalid("toolArgv[0] (the container binary name) must be a bare [a-zA-Z0-9._-] token", { code: "offensive_bad_binary" });
  }
  // #124-1: bind toolArgv[0] to the tool spec's DECLARED binary. PR5b's registry sets
  // spec.binary per tool_id from server-side config (never agent input), so a live
  // caller forwarding agent-influenced argv cannot run a DIFFERENT in-image binary
  // (sh, curl) under the claimed tool_id. When no binary is declared (the PR5a inert
  // path) only the bare-token shape check above constrains it.
  if (spec && spec.binary != null) {
    if (typeof spec.binary !== "string" || !/^[a-zA-Z0-9._-]+$/.test(spec.binary)) {
      rejectInvalid("flagSpec.binary must be a bare [a-zA-Z0-9._-] binary name", { code: "offensive_bad_spec_binary" });
    }
    if (toolArgv[0] !== spec.binary) {
      rejectInvalid(`toolArgv[0] ${JSON.stringify(toolArgv[0])} does not match the tool's declared binary ${JSON.stringify(spec.binary)}`, { code: "offensive_binary_mismatch" });
    }
  }
  const booleanFlags = spec && spec.boolean ? new Set(spec.boolean) : new Set();
  const valueFlags = spec && spec.value ? new Set(spec.value) : new Set();
  // A LIST (not a Map) so EVERY occurrence of a repeated value flag is preserved —
  // the container runs all of them, so the scope gate must see all of them (a Map
  // would keep only the last value while `-u in-scope -u evil` still attacks evil).
  const pairs = [];
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
        pairs.push({ flag: flagName, value: inlineValue });
        i += 1;
      } else {
        const next = toolArgv[i + 1];
        if (next === undefined || (typeof next === "string" && next.startsWith("-"))) {
          rejectInvalid(`value flag ${flagName} requires a value`, { code: "offensive_value_flag_missing" });
        }
        pairs.push({ flag: flagName, value: next });
        i += 2;
      }
      continue;
    }
    rejectInvalid(`flag ${flagName} is not in the tool flag allowlist`, { code: "offensive_flag_not_allowlisted" });
  }
  return pairs;
}

function offensiveRunBudgetPath(domain) {
  return path.join(sessionDir(domain), "offensive-run-budget");
}

// #124-3: infra failures (container never ran) are counted in their OWN session file so
// they can be capped + refunded independently of the genuine-run budget.
function offensiveInfraFailurePath(domain) {
  return path.join(sessionDir(domain), "offensive-infra-failures");
}

// Read a fail-closed MONOTONIC counter file with O_NOFOLLOW + regular-file discipline:
// missing = 0 (fresh session); a SYMLINKED / hardlinked / irregular / unreadable /
// malformed leaf fails CLOSED (Infinity → blocks). The O_NOFOLLOW open refuses to read
// THROUGH a symlink a same-UID stale artifact could pre-create to point the counter at an
// attacker-chosen file (e.g. one containing "0" to silently reset the budget). Strict
// digits-only — parseInt would accept "7x" / "0x10" / "7\ntrailing" and under-count.
function readCounterFile(filePath) {
  const noFollow = fs.constants.O_NOFOLLOW || 0;
  let fd;
  try {
    fd = fs.openSync(filePath, fs.constants.O_RDONLY | noFollow);
  } catch (e) {
    if (e && e.code === "ENOENT") return 0;
    return Number.POSITIVE_INFINITY; // ELOOP (symlinked leaf) / any open error → fail closed
  }
  try {
    const st = fs.fstatSync(fd);
    if (!st.isFile() || st.nlink !== 1) return Number.POSITIVE_INFINITY;
    const buf = Buffer.alloc(32); // a counter is a few digits; bound the read
    const n = fs.readSync(fd, buf, 0, buf.length, 0);
    const trimmed = buf.subarray(0, n).toString("utf8").trim();
    if (!/^\d+$/.test(trimmed)) return Number.POSITIVE_INFINITY;
    const v = Number.parseInt(trimmed, 10);
    return Number.isInteger(v) && v >= 0 ? v : Number.POSITIVE_INFINITY;
  } finally {
    fs.closeSync(fd);
  }
}

// Write a counter with O_NOFOLLOW + regular-file/nlink discipline so the write can never
// be redirected THROUGH a symlinked or hardlinked leaf to a path outside Bob's session
// files (a same-UID stale artifact pre-creating the counter as a symlink must not turn a
// counter write into a write-where primitive). nlink is checked BEFORE truncating so a
// hardlinked target is never clobbered. Returns false on any failure (caller treats a
// failed reserve as fail-closed).
function writeCounterFile(domain, filePath, value) {
  const noFollow = fs.constants.O_NOFOLLOW || 0;
  let fd;
  try {
    fs.mkdirSync(sessionDir(domain), { recursive: true });
    fd = fs.openSync(filePath, fs.constants.O_WRONLY | fs.constants.O_CREAT | noFollow, 0o600);
  } catch {
    return false; // ELOOP (symlinked leaf) / any open error → refuse the write
  }
  try {
    const st = fs.fstatSync(fd);
    if (!st.isFile() || st.nlink !== 1) return false;
    fs.ftruncateSync(fd, 0);
    fs.writeSync(fd, String(value), 0);
    return true;
  } catch {
    return false;
  } finally {
    fs.closeSync(fd);
  }
}

// F3 (fail-closed): the per-session offensive-run count is a MONOTONIC counter in a
// dedicated session file — NOT derived from http-audit.jsonl, which is trimmed to the
// last HTTP_AUDIT_LOG_MAX_RECORDS (5000) and would let early CONTAINER_RUN rows evict
// so the budget silently resets and permits unlimited wide-open runs. (The run is STILL
// recorded to http-audit for circuit-breaker visibility; that write is just no longer
// the budget source.) O(1) read, so the count under the lock no longer re-parses a
// growing log.
function offensiveRunCount(domain) {
  return readCounterFile(offensiveRunBudgetPath(domain));
}

function offensiveInfraFailureCount(domain) {
  return readCounterFile(offensiveInfraFailurePath(domain));
}

// Reserve one run by incrementing the monotonic counter (the caller holds the session
// lock). Returns false (fail closed) if the reservation can't be read or persisted.
function incrementOffensiveRun(domain) {
  const cur = offensiveRunCount(domain);
  if (!Number.isFinite(cur)) return false;
  return writeCounterFile(domain, offensiveRunBudgetPath(domain), cur + 1);
}

// #124-3: an infra failure (the container never ran) is REFUNDED from the run budget so
// it doesn't burn a genuine-run slot, and recorded in the separate, capped infra counter
// (which bounds infra-failure spin). ORDER + fail-closed matter: record the infra failure
// FIRST and only refund the run slot if it persisted, so a storage failure can never free
// the run slot WITHOUT counting the infra failure (which would let infra failures silently
// bypass the cap). Worst case on a partial write is an OVER-count (run slot stays
// consumed), never an under-count. Caller holds the session lock.
function refundOffensiveRunAsInfraFailure(domain) {
  const infra = offensiveInfraFailureCount(domain);
  if (!Number.isFinite(infra)) return; // corrupt counter already fails closed at the gate
  if (!writeCounterFile(domain, offensiveInfraFailurePath(domain), infra + 1)) return; // not counted → keep run slot
  const run = offensiveRunCount(domain);
  if (Number.isFinite(run) && run > 0) writeCounterFile(domain, offensiveRunBudgetPath(domain), run - 1);
}

// A legitimate session dir is a real directory Bob created — never a symlink. A
// symlinked session root would redirect scratch writes outside the canonical tree
// (realpath would resolve+accept it), so reject it before any scratch write.
function assertSessionDirReal(domain) {
  let st;
  try {
    st = fs.lstatSync(sessionDir(domain));
  } catch (e) {
    if (e && e.code === "ENOENT") return; // not created yet — we mkdir it ourselves
    throw new ToolError(ERROR_CODES.STATE_CONFLICT, "session dir is not accessible");
  }
  if (st.isSymbolicLink()) throw new ToolError(ERROR_CODES.STATE_CONFLICT, "session dir must not be a symlink");
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
      // Also clear the deferred SIGKILL so it can't fire on a closed/reused pid or
      // keep the event loop alive after the child has already exited.
      let settled = false;
      let killTimer = null;
      const finish = (result) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        if (killTimer) clearTimeout(killTimer);
        try { fs.closeSync(outFd); } catch {}
        try { fs.closeSync(errFd); } catch {}
        resolve(result);
      };
      const timer = setTimeout(() => {
        killed = true;
        try { if (child.pid) process.kill(-child.pid, "SIGTERM"); } catch {}
        defaultOffensiveDocker.kill(containerName, env); // F1: kill the CONTAINER, not just the client
        killTimer = setTimeout(() => { try { if (child.pid) process.kill(-child.pid, "SIGKILL"); } catch {} }, 5_000);
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
  egressProfileName = null,
  workTmpfsBytes,
  timeoutMs = DEFAULT_TIMEOUT_MS,
  docker = defaultOffensiveDocker,
  classify = null,
  sign = buildAndSignOffensiveRow,
}) {
  if (typeof domain !== "string" || !domain.trim()) rejectInvalid("domain is required");
  if (typeof toolId !== "string" || !toolId.trim()) rejectInvalid("toolId is required");
  // Reject a symlinked session root BEFORE anything writes through it — the
  // reservation below writes the audit log + budget counter under the session dir.
  assertSessionDirReal(domain);
  // forcedFlags are TRUSTED, server/spec-defined tokens the runner injects (e.g.
  // --max-redirs 0, -disable-update-check) — NEVER agent-supplied. Assert each is a
  // flag token (not a bare arg / command / the `--` separator) AND carries no URL
  // value, so a forced flag can't bypass the scope gate or smuggle a target.
  if (!Array.isArray(forcedFlags) || !forcedFlags.every((f) => typeof f === "string" && f.startsWith("-") && f !== "--")) {
    rejectInvalid("forcedFlags must be server-defined flag tokens (each starting with '-', never the '--' pass-through separator)");
  }
  for (const f of forcedFlags) {
    const inline = f.includes("=") ? f.slice(f.indexOf("=") + 1) : "";
    if (looksLikeUrl(inline)) rejectInvalid("forcedFlags must not carry a URL value (they are control flags, never targets)");
  }
  // Egress proxy (PR5a takes a raw url; PR5b resolves the named profile) must be a
  // well-formed http(s) proxy URL before it is handed to `docker --env`.
  if (egressProxyUrl != null && (typeof egressProxyUrl !== "string" || !/^https?:\/\/[^\s]+$/i.test(egressProxyUrl))) {
    rejectInvalid("egressProxyUrl must be an http(s) proxy URL");
  }
  // #124-2: record the RESOLVED named egress profile (not the literal "proxy"). PR5b
  // resolves session-bound named profiles via resolveAndAssertSessionEgressIdentity and
  // passes the profile name here; the runner stamps THAT into the audit row's
  // egress_profile so circuit-breaker / report consumers can tell which egress the
  // wide-open container used. A proxied run MUST name its profile — an anonymous proxy
  // (the old literal "proxy") is rejected.
  if (egressProfileName != null && (typeof egressProfileName !== "string" || !/^[a-zA-Z0-9_.-]{1,64}$/.test(egressProfileName))) {
    rejectInvalid("egressProfileName must be a short [a-zA-Z0-9_.-] profile name");
  }
  if (egressProxyUrl != null) {
    if (egressProfileName == null) {
      rejectInvalid("egressProxyUrl requires egressProfileName (the resolved egress profile identity)");
    }
    // "default" is the reserved DIRECT-egress profile (egress-profiles.js pins it to
    // proxy_url: null); stamping a proxied run as "default" would misbind it as direct
    // egress for audit/circuit consumers. The runner can't resolve the full named-profile
    // registry in PR-124 (PR5b does, binding name<->url via resolveAndAssertSessionEgressIdentity),
    // but it CAN reject this one universally-known inconsistency.
    if (egressProfileName === "default") {
      rejectInvalid("egressProfileName must not be the reserved 'default' (direct-egress) profile when a proxy URL is set");
    }
  }
  const cappedTimeout = Math.min(Math.max(Number(timeoutMs) || DEFAULT_TIMEOUT_MS, MIN_TIMEOUT_MS), MAX_TIMEOUT_MS);

  // 1) Flag allowlist (fail-closed) → parsed (flag,value) pairs (repeats preserved).
  const argvPairs = parseAllowlistedArgv(toolArgv, flagSpec);
  // 2) AIM-CHECK: scope-gate EVERY URL-flag value ACTUALLY in the command, BEFORE any
  // spawn. Repeated flags all run in the container, so all are checked — a Map that
  // kept only the last value would let `-u <in-scope> -u <evil>` attack evil.
  const urlFlagNames = flagSpec && flagSpec.url ? new Set(flagSpec.url) : new Set();
  // Fail CLOSED: scope-check every declared URL flag AND every value that looks like
  // a URL (scheme or protocol-relative) — an undeclared URL-bearing flag can't slip
  // out-of-scope traffic past an incomplete flagSpec.url.
  for (const { flag, value } of argvPairs) {
    if (urlFlagNames.has(flag) || looksLikeUrl(value)) {
      assertSafeRequestUrl(String(value), domain, SCOPE_VALIDATION_OPTS); // throws SCOPE_BLOCKED out of scope
    }
  }

  // 3) Build the docker argv NOW — it validates imageDigest / workTmpfsBytes /
  // command / names, so an invalid call throws BEFORE a budget slot is consumed.
  // Path STRINGS only here; no filesystem yet.
  const runId = mintRunId();
  const scratchDir = repoRunsDir(domain);
  const stdoutPath = path.join(scratchDir, `${runId}.stdout`);
  const stderrPath = path.join(scratchDir, `${runId}.stderr`);
  const cidfilePath = path.join(scratchDir, `${runId}.cid`);
  const dockerConfigDir = path.join(scratchDir, `${runId}.dockercfg`);
  const env = scrubbedDockerEnv(dockerConfigDir);
  const command = [toolArgv[0], ...forcedFlags, ...toolArgv.slice(1)];
  const { args } = buildOffensiveDockerRunArgv({ imageDigest, command, containerName: runId, networkName: runId, cidfilePath, workTmpfsBytes, egressProxyUrl });

  // 4) Reserve a run budget slot ATOMICALLY under the session lock (count +
  // audit-record write together), fail-closed on over-budget / audit failure.
  const startedAt = Date.now();
  const primaryUrl = argvPairs.find((p) => urlFlagNames.has(p.flag));
  const auditUrl = primaryUrl ? String(primaryUrl.value) : `https://${domain}/`;
  const reservation = withSessionLock(domain, () => {
    if (offensiveRunCount(domain) >= MAX_OFFENSIVE_RUNS) return { ok: false, reason: "offensive_run_budget_exhausted" };
    // #124-3: infra failures are refunded from the run budget, so they're capped
    // separately to bound infra-failure SPIN (a flaky network retrying forever). A
    // concurrent burst is ADDITIONALLY bounded by the run budget itself — each in-flight
    // run holds a run slot until refund, so at most MAX_OFFENSIVE_RUNS docker spawns are
    // in flight at once — so total thrash stays bounded without a per-run release. (See
    // the PR note: this trades exact-cap-under-a-50+-concurrent-burst, unreachable at
    // Bob's wave concurrency, for avoiding a per-run post-run lock write + crash-leak.)
    if (offensiveInfraFailureCount(domain) >= MAX_OFFENSIVE_INFRA_FAILURES) return { ok: false, reason: "offensive_infra_failure_budget_exhausted" };
    const auditOk = auditConfirmRequest({ domain, surfaceId: null, method: OFFENSIVE_RUN_AUDIT_METHOD, url: auditUrl, egressProfile: egressProfileName, status: null, scopeDecision: "allowed", error: null, startedAt, toolId });
    if (auditOk === false) return { ok: false, reason: "offensive_run_audit_failed" };
    if (!incrementOffensiveRun(domain)) return { ok: false, reason: "offensive_run_budget_write_failed" };
    return { ok: true };
  });
  if (!reservation.ok) {
    return blocked(domain, toolId, "blocked_by_infra", reservation.reason);
  }

  // 5) Create the filesystem scratch (post-reservation) + verify it's confined (the
  // symlinked-root reject already ran up-front, before the reservation wrote).
  fs.mkdirSync(scratchDir, { recursive: true });
  assertDirUnderSession(domain, scratchDir);
  fs.mkdirSync(dockerConfigDir, { recursive: true });

  const cleanupScratch = () => {
    for (const p of [stdoutPath, stderrPath, cidfilePath]) { try { fs.rmSync(p, { force: true }); } catch {} }
    try { fs.rmSync(dockerConfigDir, { recursive: true, force: true }); } catch {}
  };

  let runResult;
  try {
    docker.networkCreate(runId, env);
  } catch (e) {
    try { docker.networkRm(runId, env); } catch {} // tear down a partially-created network
    cleanupScratch();
    // #124-3: the container never ran — refund the run slot + record the infra failure.
    // Best-effort: `withSessionLock` is fail-fast (throws on cross-process contention), so
    // a bookkeeping lock-miss must not add a second error to an already-failed run; the
    // refund is itself fail-closed (run slot stays consumed on any miss).
    try { withSessionLock(domain, () => refundOffensiveRunAsInfraFailure(domain)); } catch {}
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
    // Teardown must never skip scratch deletion: a throwing (injectable) kill /
    // networkRm cannot leave raw output lingering on disk.
    try { docker.kill(runId, env); } catch {}        // F1: ensure the container is gone
    try { docker.networkRm(runId, env); } catch {}
    cleanupScratch();                                 // F7-cleanup: guaranteed last
  }

  if (runResult.spawn_error) {
    // #124-3: docker never started the container — refund the run slot + record the infra
    // failure (best-effort; fail-fast lock-miss must not mask the spawn error).
    try { withSessionLock(domain, () => refundOffensiveRunAsInfraFailure(domain)); } catch {}
    return blocked(domain, toolId, "blocked_by_infra", "offensive_spawn_failed", { failure_reason: runResult.spawn_error });
  }
  // A timeout is NOT refunded and NOT an infra failure: the container actually RAN
  // (consumed CPU/net + a real slot) and only failed to FINISH — a genuine run (#124-3).
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
    // Cap the classifier's reason — it is returned to the agent and must not relay
    // unbounded (or raw-output-bearing) text.
    const reason = verdict && typeof verdict.reason === "string" ? verdict.reason.slice(0, 120) : "oracle_negative";
    return blocked(domain, toolId, "blocked_by_defense", reason);
  }
  // Defense-in-depth: re-validate the oracle's target is in-scope before it is signed
  // into a durable row — even a server-side classify cannot sign an off-scope target.
  try {
    assertSafeRequestUrl(String(verdict.canonicalTarget), domain, SCOPE_VALIDATION_OPTS);
  } catch {
    return blocked(domain, toolId, "blocked_by_design", "oracle_target_out_of_scope");
  }

  // The content that will actually be SIGNED must itself pass the secret scan — a
  // classify that returns its own stdoutContent/stderrContent must not bypass the
  // backstop that ran on the raw captured bytes.
  const signStdout = verdict.stdoutContent != null ? String(verdict.stdoutContent) : stdoutText;
  const signStderr = verdict.stderrContent != null ? String(verdict.stderrContent) : stderrText;
  try {
    validateNoSensitiveMaterial(signStdout, "offensive_sign_stdout", { maxTextChars: STREAM_CAP_BYTES });
    validateNoSensitiveMaterial(signStderr, "offensive_sign_stderr", { maxTextChars: STREAM_CAP_BYTES });
  } catch {
    return blocked(domain, toolId, "blocked_operator_pii", "offensive_signed_content_contains_sensitive_value");
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
    stdoutContent: signStdout,
    stderrContent: signStderr,
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
  offensiveRunBudgetPath,
  offensiveInfraFailureCount,
  offensiveInfraFailurePath,
  mintRunId,
  defaultOffensiveDocker,
  MAX_OFFENSIVE_RUNS,
  MAX_OFFENSIVE_INFRA_FAILURES,
  MAX_TIMEOUT_MS,
  OFFENSIVE_RUN_AUDIT_METHOD,
};
