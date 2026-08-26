"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { EventEmitter } = require("node:events");
const { StringDecoder } = require("node:string_decoder");
const childProcess = require("node:child_process");

const MAX_BODY_BYTES = 32 * 1024;
const ID_RE = /^[A-Za-z0-9_-]{10,128}$/;
const RUN_SLUG_RE = /^[A-Za-z0-9_-]{16,64}$/;
const PROJECTION_KEY_RE = /^[A-Za-z0-9_-]{43}$/;
const SHA256_RE = /^[0-9a-f]{64}$/;
const SOURCE_COMMIT_RE = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;
const REPOSITORY_RE = /^https:\/\/github\.com\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)\.git$/;
const CONTRACT_RE = /^eip155:([1-9][0-9]*):(0x[0-9a-f]{40})$/;
const CONTROL_RE = /[\u0000-\u001f\u007f-\u009f]/u;
const DURABLE_STATUSES = Object.freeze([
  "queued",
  "running",
  "succeeded",
  "failed",
  "timed_out",
  "interrupted",
]);
const LIVE_STATUSES = Object.freeze(["queued", "running"]);
const TERMINAL_STATUSES = Object.freeze(["succeeded", "failed", "timed_out"]);
const DISPATCH_KEYS = Object.freeze([
  "schemaVersion",
  "assessmentId",
  "runId",
  "runSlug",
  "target",
  "targetDomain",
  "targetKind",
  "runMode",
  "autonomy",
  "objective",
  "accessPassword",
  "scope",
  "sourceRef",
  "kind",
  "retestOf",
  "projectionKey",
]);
const REQUIRED_DISPATCH_KEYS = Object.freeze([
  "schemaVersion",
  "assessmentId",
  "runId",
  "runSlug",
  "target",
  "targetDomain",
  "targetKind",
  "runMode",
  "autonomy",
  "objective",
  "accessPassword",
  "kind",
  "retestOf",
  "projectionKey",
]);
const CONTROL_RETRY_DELAYS_MS = Object.freeze([1000, 2000, 4000, 8000, 16000, 30000]);
const REPOSITORY_COMMAND_TIMEOUT_MS = 2 * 60 * 1000;
const DOCKER_COMMAND_TIMEOUT_MS = 15 * 1000;
const DEFAULT_MAX_LOG_BYTES = 16 * 1024 * 1024;
const LOG_TRUNCATION_MARKER = Buffer.from("\n[runner log truncated]\n", "utf8");

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function secretDigest(value) {
  return crypto.createHash("sha256").update(value).digest();
}

function authorized(authorizationHeader, secret) {
  const header = typeof authorizationHeader === "string" ? authorizationHeader : "";
  const configuredSecret = typeof secret === "string" ? secret : "";
  const validScheme = header.startsWith("Bearer ");
  const candidate = validScheme ? header.slice("Bearer ".length) : "";
  const providedDigest = secretDigest(candidate);
  const expectedDigest = secretDigest(configuredSecret);
  const equal = crypto.timingSafeEqual(providedDigest, expectedDigest);
  return equal && validScheme && configuredSecret.length > 0;
}

function invalid(code, error) {
  return { ok: false, code, error };
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function safeText(value, { maxLength, required = true } = {}) {
  if (typeof value !== "string") return false;
  if (required && value.length === 0) return false;
  return value.length <= maxLength && value === value.trim() && !CONTROL_RE.test(value);
}

function isExactHttpsEndpoint(value, pathname) {
  if (!safeText(value, { maxLength: 2048 })) return false;
  try {
    const endpoint = new URL(value);
    return (
      endpoint.protocol === "https:" &&
      endpoint.hostname.length > 0 &&
      endpoint.username === "" &&
      endpoint.password === "" &&
      endpoint.port === "" &&
      endpoint.search === "" &&
      endpoint.hash === "" &&
      endpoint.pathname === pathname
    );
  } catch {
    return false;
  }
}

function repositorySelector(target, repositoryName) {
  const safeName = repositoryName.replace(/[^A-Za-z0-9._-]+/gu, "-").replace(/^-+|-+$/gu, "") || "repo";
  return `repo-${safeName}-${sha256(target).slice(0, 8)}`;
}

function contractSelector(chainId, address) {
  const authority = JSON.stringify([["evm", chainId, address]]);
  return `sc-evm-${chainId}-${address.slice(2, 10)}-${sha256(authority).slice(0, 8)}`;
}

function validateTarget(body) {
  if (!safeText(body.target, { maxLength: 2048 }) || !safeText(body.targetDomain, { maxLength: 256 })) {
    return invalid("invalid_target", "target and targetDomain must be bounded canonical text");
  }

  if (body.targetKind !== "repo" && body.sourceRef !== undefined) {
    return invalid("invalid_source_ref", "sourceRef is only allowed for repo targets");
  }

  if (body.targetKind === "web") {
    let url;
    try {
      url = new URL(body.target);
    } catch {
      return invalid("invalid_target", "web target must be a valid HTTPS URL");
    }
    if (
      url.protocol !== "https:" ||
      url.username !== "" ||
      url.password !== "" ||
      url.port !== "" ||
      url.hostname !== body.targetDomain
    ) {
      return invalid("invalid_target", "web target must be HTTPS without userinfo and match targetDomain");
    }
    return { ok: true };
  }

  if (body.targetKind === "repo") {
    const match = REPOSITORY_RE.exec(body.target);
    if (!match || match[1] === "." || match[1] === ".." || match[2] === "." || match[2] === "..") {
      return invalid("invalid_target", "repo target must be an exact canonical GitHub clone URL");
    }
    const expected = repositorySelector(body.target, match[2]);
    if (body.targetDomain !== expected) {
      return invalid("invalid_target_domain", "repo targetDomain does not match its canonical selector");
    }
    if (!SOURCE_COMMIT_RE.test(body.sourceRef || "")) {
      return invalid("invalid_source_ref", "repo sourceRef must be an exact 40- or 64-hex commit");
    }
    return { ok: true };
  }

  if (body.targetKind === "contract") {
    const match = CONTRACT_RE.exec(body.target);
    if (!match || !Number.isSafeInteger(Number(match[1])) || Number(match[1]) <= 0) {
      return invalid("invalid_target", "contract target must be a canonical EVM CAIP-10 identity");
    }
    const expected = contractSelector(match[1], match[2]);
    if (body.targetDomain !== expected) {
      return invalid("invalid_target_domain", "contract targetDomain does not match its canonical selector");
    }
    return { ok: true };
  }

  return invalid("invalid_target_kind", "targetKind must be web, repo, or contract");
}

function validatePayload(body) {
  if (!isPlainObject(body)) return invalid("invalid_body", "payload must be a JSON object");
  const keys = Object.keys(body);
  const unsupported = keys.find((key) => !DISPATCH_KEYS.includes(key));
  if (unsupported) return invalid("unknown_field", `payload contains unsupported field: ${unsupported}`);
  const missing = REQUIRED_DISPATCH_KEYS.find((key) => !Object.hasOwn(body, key));
  if (missing) return invalid("missing_field", `payload is missing required field: ${missing}`);
  if (body.schemaVersion !== 1) return invalid("invalid_schema_version", "schemaVersion must be 1");
  if (!ID_RE.test(body.assessmentId || "")) {
    return invalid("invalid_assessment", "assessmentId must match [A-Za-z0-9_-]{10,128}");
  }
  if (!ID_RE.test(body.runId || "")) {
    return invalid("invalid_run", "runId must match [A-Za-z0-9_-]{10,128}");
  }
  if (!RUN_SLUG_RE.test(body.runSlug || "")) {
    return invalid("invalid_run_slug", "runSlug must match [A-Za-z0-9_-]{16,64}");
  }
  if (!safeText(body.runMode, { maxLength: 80 })) {
    return invalid("invalid_run_mode", "runMode must be non-empty bounded text without controls");
  }
  if (body.autonomy !== "operator-approved") {
    return invalid("invalid_autonomy", "autonomy must be operator-approved");
  }
  if (!safeText(body.objective, { maxLength: 4000 })) {
    return invalid("invalid_objective", "objective must be non-empty bounded text without controls");
  }
  if (!safeText(body.accessPassword, { maxLength: 256 }) || body.accessPassword.length < 8) {
    return invalid("invalid_access_password", "accessPassword must be 8-256 characters without controls");
  }
  if (body.scope !== undefined) {
    if (!isPlainObject(body.scope) || Object.keys(body.scope).length !== 1 || !Object.hasOwn(body.scope, "notes")) {
      return invalid("invalid_scope", "scope must contain only notes");
    }
    if (!safeText(body.scope.notes, { maxLength: 4000 })) {
      return invalid("invalid_scope", "scope notes must be non-empty bounded text without controls");
    }
  }
  if (body.sourceRef !== undefined && !safeText(body.sourceRef, { maxLength: 512 })) {
    return invalid("invalid_source_ref", "sourceRef must be non-empty bounded text without controls");
  }
  if (body.kind !== "assessment" && body.kind !== "retest") {
    return invalid("invalid_kind", "kind must be assessment or retest");
  }
  if (!Array.isArray(body.retestOf) || body.retestOf.length > 100) {
    return invalid("invalid_retest_of", "retestOf must contain at most 100 fingerprints");
  }
  const fingerprints = new Set();
  for (const fingerprint of body.retestOf) {
    if (typeof fingerprint !== "string" || !SHA256_RE.test(fingerprint) || fingerprints.has(fingerprint)) {
      return invalid("invalid_retest_of", "retestOf must contain unique lowercase SHA-256 fingerprints");
    }
    fingerprints.add(fingerprint);
  }
  if ((body.kind === "assessment" && body.retestOf.length !== 0) || (body.kind === "retest" && body.retestOf.length === 0)) {
    return invalid("kind_target_mismatch", "assessment kind must have no retest fingerprints and retest kind must have at least one");
  }
  if (!PROJECTION_KEY_RE.test(body.projectionKey || "")) {
    return invalid("invalid_projection_key", "projectionKey must be 43 base64url characters");
  }
  const target = validateTarget(body);
  if (!target.ok) return target;

  const value = {};
  for (const key of DISPATCH_KEYS) {
    if (Object.hasOwn(body, key)) value[key] = body[key];
  }
  return { ok: true, value };
}

function digestValidatedPayload(payload) {
  const canonical = {};
  for (const key of DISPATCH_KEYS) {
    if (!Object.hasOwn(payload, key)) continue;
    canonical[key] = key === "projectionKey" || key === "accessPassword"
      ? sha256(payload[key])
      : payload[key];
  }
  return sha256(JSON.stringify(canonical));
}

function canonicalDispatchDigest(payload) {
  const validated = validatePayload(payload);
  if (!validated.ok) throw new TypeError(validated.error);
  return digestValidatedPayload(validated.value);
}

function runnerPayloadFor(body) {
  const runnerPayload = {};
  for (const key of DISPATCH_KEYS) {
    if (key === "projectionKey" || !Object.hasOwn(body, key)) continue;
    runnerPayload[key] = body[key];
  }
  return runnerPayload;
}

function canonicalEventHash(runSlug, kind, phase, message) {
  return sha256(JSON.stringify({ runSlug, kind, phase, message }));
}

function createConvexControlPlaneSink({ url, secret, clientFactory } = {}) {
  if (!isExactHttpsEndpoint(url, "/") || !safeText(secret, { maxLength: 4096 })) {
    throw new Error("Convex control-plane URL must be an exact HTTPS origin and runner secret is required");
  }
  const makeClient = clientFactory || (() => {
    const { ConvexHttpClient } = require("convex/browser");
    return new ConvexHttpClient(url);
  });
  const client = makeClient();
  return async (update) => {
    const applyStatus = async (candidate) => {
      const result = await client.mutation("runs:setStatus", {
        secret,
        slug: candidate.runSlug,
        status: candidate.status,
        phase: candidate.phase,
        ...(candidate.status === "destroyed" ? { destroyedAt: candidate.at } : {}),
      });
      if (!result) throw new Error("control-plane run does not exist");
      if (!isPlainObject(result) || typeof result.status !== "string") {
        throw new Error("control-plane returned an invalid status result");
      }
      return result;
    };

    let effectiveUpdate = update;
    let statusResult = await applyStatus(update);
    if (
      update.status === "failed" &&
      (statusResult.status === "sealed" || statusResult.status === "destroyed")
    ) {
      effectiveUpdate = {
        runSlug: update.runSlug,
        status: "destroyed",
        phase: "report",
        at: update.at,
        event: {
          kind: "destroy",
          register: "breath",
          phase: "report",
          message: "Runner container destroyed.",
        },
      };
      if (statusResult.status === "sealed") statusResult = await applyStatus(effectiveUpdate);
    }
    if (statusResult.status !== effectiveUpdate.status) {
      const staleTerminal =
        effectiveUpdate.status === "failed"
          ? statusResult.status === "denied"
          : effectiveUpdate.status === "destroyed"
            ? ["failed", "denied"].includes(statusResult.status)
            : false;
      if (staleTerminal) return;
      throw new Error(
        `control-plane rejected ${effectiveUpdate.status} transition from ${statusResult.status}`,
      );
    }
    const event = effectiveUpdate.event;
    const eventHash = canonicalEventHash(
      effectiveUpdate.runSlug,
      event.kind,
      event.phase,
      event.message,
    );
    let failure = null;
    for (let attempt = 0; attempt < 3; attempt += 1) {
      const events = await client.query("runs:events", { slug: effectiveUpdate.runSlug });
      if (events.some((candidate) => candidate && candidate.eventHash === eventHash)) return;
      const seq = events.reduce((highest, candidate) => Math.max(highest, candidate.seq), 0) + 1;
      if (!Number.isSafeInteger(seq)) throw new Error("control-plane event sequence overflow");
      try {
        await client.mutation("runs:appendEvent", {
          secret,
          slug: effectiveUpdate.runSlug,
          seq,
          kind: event.kind,
          register: event.register,
          phase: event.phase,
          eventHash,
          payloadJson: JSON.stringify({ message: event.message }),
          at: effectiveUpdate.at,
        });
        return;
      } catch (error) {
        failure = error;
      }
    }
    throw failure || new Error("control-plane event append failed");
  };
}

function createStreamingRedactor(secrets, write) {
  const literals = [...new Set(secrets.filter((value) => typeof value === "string" && value.length > 0))]
    .sort((left, right) => right.length - left.length);
  const keep = Math.max(0, ...literals.map((value) => value.length - 1));
  const decoder = new StringDecoder("utf8");
  let pending = "";
  let ended = false;

  function redact(value) {
    const matches = [];
    for (const literal of literals) {
      let offset = value.indexOf(literal);
      while (offset >= 0) {
        matches.push([offset, offset + literal.length]);
        offset = value.indexOf(literal, offset + 1);
      }
    }
    if (matches.length === 0) return value;
    matches.sort((left, right) => left[0] - right[0] || right[1] - left[1]);
    let output = "";
    let cursor = 0;
    for (let index = 0; index < matches.length;) {
      const start = matches[index][0];
      let end = matches[index][1];
      index += 1;
      while (index < matches.length && matches[index][0] <= end) {
        end = Math.max(end, matches[index][1]);
        index += 1;
      }
      if (start < cursor) continue;
      output += `${value.slice(cursor, start)}[REDACTED]`;
      cursor = end;
    }
    return `${output}${value.slice(cursor)}`;
  }

  function safePrefixLength() {
    let boundary = Math.max(0, pending.length - keep);
    let changed = true;
    while (changed && boundary > 0) {
      changed = false;
      for (const literal of literals) {
        let offset = pending.indexOf(literal, Math.max(0, boundary - literal.length + 1));
        while (offset >= 0 && offset < boundary) {
          if (offset + literal.length > boundary) {
            boundary = offset;
            changed = true;
            break;
          }
          offset = pending.indexOf(literal, offset + 1);
        }
      }
    }
    return boundary;
  }

  function consume(text, flush) {
    pending += text;
    if (flush) {
      if (pending) write(redact(pending));
      pending = "";
      return;
    }
    const splitAt = safePrefixLength();
    if (splitAt === 0) return;
    write(redact(pending.slice(0, splitAt)));
    pending = pending.slice(splitAt);
  }

  return {
    push(chunk) {
      if (ended) return;
      consume(decoder.write(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk))), false);
    },
    end() {
      if (ended) return;
      ended = true;
      consume(decoder.end(), true);
    },
    clear() {
      literals.fill("");
      pending = "";
    },
  };
}

function ensurePrivateDirectory(directory) {
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  fs.chmodSync(directory, 0o700);
}

function sealRepositoryForRunner(directory) {
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const entryPath = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      sealRepositoryForRunner(entryPath);
      continue;
    }
    if (entry.isFile()) {
      const mode = fs.statSync(entryPath).mode;
      fs.chmodSync(entryPath, mode & 0o111 ? 0o555 : 0o444);
      continue;
    }
    if (!entry.isSymbolicLink()) {
      throw new Error("repository preflight produced an unsupported file type");
    }
  }
  // The run root stays mode 0700 on the host. Docker bind-mounts this exact
  // directory, so only the pinned container UID needs traversal beneath it.
  fs.chmodSync(directory, 0o555);
}

function removePreparedRepository(runRoot) {
  if (!fs.existsSync(runRoot)) return;
  const restoreDirectoryWrites = (directory) => {
    fs.chmodSync(directory, 0o700);
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      if (entry.isDirectory()) restoreDirectoryWrites(path.join(directory, entry.name));
    }
  };
  restoreDirectoryWrites(runRoot);
  fs.rmSync(runRoot, { recursive: true, force: true });
}

function syncDirectory(directory) {
  const fd = fs.openSync(directory, fs.constants.O_RDONLY | (fs.constants.O_DIRECTORY || 0));
  try {
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
}


function openPrivateAppendFile(file) {
  const flags =
    fs.constants.O_APPEND |
    fs.constants.O_CREAT |
    fs.constants.O_WRONLY |
    (fs.constants.O_NOFOLLOW || 0);
  const fd = fs.openSync(file, flags, 0o600);
  fs.fchmodSync(fd, 0o600);
  return fd;
}

function appendPrivateFile(file, content) {
  const fd = openPrivateAppendFile(file);
  try {
    fs.writeFileSync(fd, content);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  syncDirectory(path.dirname(file));
}

function durableRow(record, event, at) {
  return {
    schemaVersion: 1,
    idempotencyKey: record.idempotencyKey,
    requestDigest: record.requestDigest,
    runId: record.runId,
    runSlug: record.runSlug,
    targetKind: record.targetKind,
    kind: record.kind,
    status: record.status,
    generation: record.generation,
    acceptedAt: record.acceptedAt,
    queuedAt: record.queuedAt ?? null,
    startedAt: record.startedAt ?? null,
    finishedAt: record.finishedAt ?? null,
    exitCode: record.exitCode ?? null,
    controlPlanePending: record.controlPlanePending ?? null,
    event,
    at,
  };
}

function normalizedPendingUpdate(value, runSlug) {
  if (value === null || value === undefined) return null;
  if (!isPlainObject(value)) return null;
  if (
    Object.keys(value).length !== 5 ||
    !Object.hasOwn(value, "runSlug") ||
    !Object.hasOwn(value, "status") ||
    !Object.hasOwn(value, "phase") ||
    !Object.hasOwn(value, "at") ||
    !Object.hasOwn(value, "event") ||
    value.runSlug !== runSlug ||
    (value.status !== "destroyed" && value.status !== "failed") ||
    value.phase !== "report" ||
    !Number.isSafeInteger(value.at) ||
    value.at <= 0 ||
    !isPlainObject(value.event) ||
    Object.keys(value.event).length !== 4
  ) {
    return null;
  }
  const expected = value.status === "destroyed"
    ? {
        kind: "destroy",
        register: "breath",
        phase: "report",
        message: "Runner container destroyed.",
      }
    : {
        kind: "wait",
        register: "body",
        phase: "report",
        messages: ["Runner execution failed.", "Runner execution timed out."],
      };
  if (
    value.event.kind !== expected.kind ||
    value.event.register !== expected.register ||
    value.event.phase !== expected.phase ||
    (expected.message
      ? value.event.message !== expected.message
      : !expected.messages.includes(value.event.message))
  ) {
    return null;
  }
  return {
    runSlug: value.runSlug,
    status: value.status,
    phase: "report",
    at: value.at,
    event: {
      kind: value.event.kind,
      register: value.event.register,
      phase: value.event.phase,
      message: value.event.message,
    },
  };
}

function recordFromLedgerRow(row) {
  if (
    !isPlainObject(row) ||
    row.schemaVersion !== 1 ||
    !ID_RE.test(row.idempotencyKey || "") ||
    row.idempotencyKey !== row.runId ||
    !SHA256_RE.test(row.requestDigest || "") ||
    !RUN_SLUG_RE.test(row.runSlug || "") ||
    !DURABLE_STATUSES.includes(row.status) ||
    !Number.isSafeInteger(row.generation) ||
    row.generation < 1 ||
    !Number.isSafeInteger(row.acceptedAt)
  ) {
    return null;
  }
  return {
    idempotencyKey: row.idempotencyKey,
    requestDigest: row.requestDigest,
    runId: row.runId,
    runSlug: row.runSlug,
    targetKind: row.targetKind,
    kind: row.kind,
    status: row.status,
    generation: row.generation,
    acceptedAt: row.acceptedAt,
    queuedAt: Number.isSafeInteger(row.queuedAt) ? row.queuedAt : null,
    startedAt: Number.isSafeInteger(row.startedAt) ? row.startedAt : null,
    finishedAt: Number.isSafeInteger(row.finishedAt) ? row.finishedAt : null,
    exitCode: Number.isSafeInteger(row.exitCode) ? row.exitCode : null,
    controlPlanePending: normalizedPendingUpdate(row.controlPlanePending, row.runSlug),
    lastEvent: typeof row.event === "string" ? row.event : "loaded",
  };
}

function loadLedger(ledgerFile) {
  const ledger = new Map();
  let rows = 0;
  if (!fs.existsSync(ledgerFile)) return { ledger, rows };
  for (const line of fs.readFileSync(ledgerFile, "utf8").split("\n")) {
    if (!line.trim()) continue;
    rows += 1;
    try {
      const record = recordFromLedgerRow(JSON.parse(line));
      if (record) ledger.set(record.idempotencyKey, record);
    } catch {
      // Ignore a torn or malformed row; the previous durable row remains authoritative.
    }
  }
  return { ledger, rows };
}

function minimalDockerEnvironment(hostEnvironment) {
  const environment = {};
  for (const name of ["PATH", "HOME", "DOCKER_HOST", "DOCKER_CONFIG", "XDG_RUNTIME_DIR"]) {
    if (typeof hostEnvironment[name] === "string") environment[name] = hostEnvironment[name];
  }
  return environment;
}

function dockerLaunchSpec(record, runnerImageUri, containerEnv, hostEnvironment = process.env) {
  const runnerEnvironment = {
    BOB_PAYLOAD_JSON: JSON.stringify(runnerPayloadFor(record.payload)),
    BOB_PROJECTION_KEY: record.projectionKey,
    RUNNER_SECRET: containerEnv.RUNNER_SECRET || "",
    DEEPSEEK_API_KEY: containerEnv.DEEPSEEK_API_KEY || "",
    BOB_PROJECTION_URL: containerEnv.BOB_PROJECTION_URL || "",
    BOB_CONVEX_URL: containerEnv.BOB_CONVEX_URL || "",
    BOB_RUN_SLUG: record.runSlug,
    BOB_RUN_KIND: record.kind,
    BOB_RETEST_OF: record.payload.retestOf.join(","),
    BOB_REPORT_SLUG: `${record.runSlug}-report`,
  };
  const args = [
    "run",
    "--rm",
    "--pull=never",
    "--read-only",
    "--cap-drop=ALL",
    "--security-opt", "no-new-privileges:true",
    "--user", "65532:65532",
    "--pids-limit", "512",
    "--memory", "1536m",
    "--memory-swap", "1536m",
    "--cpus", "2",
    "--shm-size", "512m",
    "--tmpfs", "/workspace:rw,nosuid,nodev,size=1g,uid=65532,gid=65532,mode=0700",
    "--tmpfs", "/tmp:rw,nosuid,nodev,size=512m,uid=65532,gid=65532,mode=1777",
    "--name", `bob-run-${record.runSlug}`,
    "--label", `bob.dispatch.run-id=${record.runId}`,
    "--label", `bob.dispatch.run-slug=${record.runSlug}`,
    "--label", `bob.dispatch.generation=${record.generation}`,
  ];
  for (const name of Object.keys(runnerEnvironment)) args.push("-e", name);
  if (record.repoPath) args.push("--mount", `type=bind,src=${record.repoPath},dst=/workspace/target-repo,readonly`);
  args.push(runnerImageUri);
  return {
    args,
    env: {
      ...minimalDockerEnvironment(hostEnvironment),
      ...runnerEnvironment,
    },
  };
}

function runGit(spawnFn, args, timeoutMs) {
  const child = spawnFn("git", args, {
    encoding: "utf8",
    env: {
      PATH: process.env.PATH || "",
      HOME: os.tmpdir(),
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_TERMINAL_PROMPT: "0",
    },
    stdio: ["ignore", "pipe", "pipe"],
    timeout: timeoutMs,
    killSignal: "SIGKILL",
  });
  // Test adapters may return a completed spawn-like result. Production always
  // follows the asynchronous child-process branch below.
  if (child && Number.isInteger(child.status)) {
    if (child.status !== 0) throw new Error("repository preflight failed");
    return Promise.resolve(typeof child.stdout === "string" ? child.stdout.trim() : "");
  }
  if (!child || typeof child.once !== "function") {
    return Promise.reject(new Error("repository preflight failed"));
  }
  return new Promise((resolve, reject) => {
    const stdout = [];
    let stdoutBytes = 0;
    let settled = false;
    const finish = (error, value = "") => {
      if (settled) return;
      settled = true;
      if (error) reject(error);
      else resolve(value);
    };
    child.stdout?.on("data", (chunk) => {
      stdoutBytes += chunk.length;
      if (stdoutBytes > 1024 * 1024) {
        try { child.kill("SIGKILL"); } catch {}
        finish(new Error("repository preflight failed"));
        return;
      }
      stdout.push(Buffer.from(chunk));
    });
    child.stderr?.resume?.();
    child.once("error", () => finish(new Error("repository preflight failed")));
    child.once("close", (code) => {
      if (code !== 0) finish(new Error("repository preflight failed"));
      else finish(null, Buffer.concat(stdout).toString("utf8").trim());
    });
  });
}

async function prepareRepository(record, runsDir, spawnFn, commandTimeoutMs = REPOSITORY_COMMAND_TIMEOUT_MS) {
  const runRoot = path.join(runsDir, record.runSlug);
  const repoPath = path.join(runRoot, "target-repo");
  removePreparedRepository(runRoot);
  ensurePrivateDirectory(runRoot);
  try {
    await runGit(spawnFn, ["init", "--quiet", repoPath], commandTimeoutMs);
    await runGit(spawnFn, ["-C", repoPath, "remote", "add", "origin", record.payload.target], commandTimeoutMs);
    await runGit(spawnFn, ["-C", repoPath, "fetch", "--quiet", "--no-tags", "--depth=1", "origin", record.payload.sourceRef], commandTimeoutMs);
    await runGit(spawnFn, ["-C", repoPath, "checkout", "--quiet", "--detach", "FETCH_HEAD"], commandTimeoutMs);
    const resolved = await runGit(spawnFn, ["-C", repoPath, "rev-parse", "HEAD"], commandTimeoutMs);
    if (resolved !== record.payload.sourceRef) throw new Error("repository preflight resolved a different commit");
    sealRepositoryForRunner(repoPath);
    record.runRoot = runRoot;
    record.repoPath = repoPath;
  } catch (error) {
    removePreparedRepository(runRoot);
    throw error;
  }
}

function createService({
  secret,
  ledgerDir,
  runsDir,
  logsDir,
  runnerImageUri,
  containerEnv,
  maxConcurrent = 2,
  maxQueued = 8,
  maxQueueAgeMs = 15 * 60 * 1000,
  runTimeoutMs = 90 * 60 * 1000,
  ledgerCompactRows = 10000,
  repositoryCommandTimeoutMs = REPOSITORY_COMMAND_TIMEOUT_MS,
  maxLogBytes = DEFAULT_MAX_LOG_BYTES,
  controlPlaneSink,
  spawnFn = null,
  killFn = null,
  inspectContainerFn = null,
  waitContainerFn = null,
  removeContainerFn = null,
  prepareRepositoryFn = null,
  cleanupRepositoryFn = null,
  spawnProcessFn = childProcess.spawn,
  spawnSyncFn = childProcess.spawnSync,
  now = () => Date.now(),
  delay = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)),
  setTimeoutFn = setTimeout,
  clearTimeoutFn = clearTimeout,
  setIntervalFn = setInterval,
  clearIntervalFn = clearInterval,
} = {}) {
  if (typeof controlPlaneSink !== "function") throw new TypeError("controlPlaneSink is required");
  if (!isPlainObject(containerEnv)) throw new TypeError("containerEnv is required");
  for (const [name, value] of [
    ["DISPATCH_SECRET", secret],
    ["RUNNER_SECRET", containerEnv.RUNNER_SECRET],
    ["DEEPSEEK_API_KEY", containerEnv.DEEPSEEK_API_KEY],
  ]) {
    if (!safeText(value, { maxLength: 4096 })) throw new TypeError(`${name} is required and must be safe bounded text`);
  }
  if (!isExactHttpsEndpoint(containerEnv.BOB_PROJECTION_URL, "/api/findings")) {
    throw new TypeError("BOB_PROJECTION_URL must be an exact HTTPS /api/findings endpoint");
  }
  if (!isExactHttpsEndpoint(containerEnv.BOB_CONVEX_URL, "/")) {
    throw new TypeError("BOB_CONVEX_URL must be an exact HTTPS origin");
  }
  if (
    typeof runnerImageUri !== "string" ||
    !/@sha256:[0-9a-f]{64}$/u.test(runnerImageUri) ||
    CONTROL_RE.test(runnerImageUri)
  ) {
    throw new TypeError("runnerImageUri must be pinned by a lowercase SHA-256 digest");
  }
  for (const [name, value] of Object.entries({
    maxConcurrent,
    maxQueued,
    maxQueueAgeMs,
    runTimeoutMs,
    ledgerCompactRows,
    repositoryCommandTimeoutMs,
    maxLogBytes,
  })) {
    if (!Number.isSafeInteger(value) || value < 1) throw new TypeError(`${name} must be a positive safe integer`);
  }
  ensurePrivateDirectory(ledgerDir);
  ensurePrivateDirectory(runsDir);
  ensurePrivateDirectory(logsDir);
  const ledgerFile = path.join(ledgerDir, "dispatch.jsonl");
  const loaded = loadLedger(ledgerFile);
  const ledger = loaded.ledger;
  let ledgerRows = loaded.rows;
  const active = new Map();
  const queue = [];
  const pendingTasks = new Set();
  let tickTask = null;
  let closed = false;

  function track(promise) {
    const task = Promise.resolve(promise);
    pendingTasks.add(task);
    void task.then(
      () => pendingTasks.delete(task),
      () => pendingTasks.delete(task),
    );
    return task;
  }

  function compactLedger() {
    const temporary = `${ledgerFile}.tmp-${process.pid}-${crypto.randomBytes(8).toString("hex")}`;
    const content = [...ledger.values()]
      .map((record) => `${JSON.stringify(durableRow(record, record.lastEvent || "compacted", now()))}\n`)
      .join("");
    let published = false;
    try {
      const fd = fs.openSync(
        temporary,
        fs.constants.O_CREAT |
          fs.constants.O_EXCL |
          fs.constants.O_WRONLY |
          (fs.constants.O_NOFOLLOW || 0),
        0o600,
      );
      try {
        fs.writeFileSync(fd, content);
        fs.fsyncSync(fd);
      } finally {
        fs.closeSync(fd);
      }
      fs.renameSync(temporary, ledgerFile);
      fs.chmodSync(ledgerFile, 0o600);
      syncDirectory(path.dirname(ledgerFile));
      published = true;
    } finally {
      if (!published) {
        try { fs.unlinkSync(temporary); } catch {}
      }
    }
    ledgerRows = ledger.size;
  }

  function persist(record, event) {
    const at = now();
    record.lastEvent = event;
    ledger.set(record.idempotencyKey, record);
    appendPrivateFile(ledgerFile, `${JSON.stringify(durableRow(record, event, at))}\n`);
    ledgerRows += 1;
    if (ledgerRows >= ledgerCompactRows) compactLedger();
  }

  const defaultSpawn = (record, launch) => spawnProcessFn("docker", launch.args, {
    env: launch.env,
    stdio: ["ignore", "pipe", "pipe"],
  });
  const defaultKill = (record) => spawnSyncFn("docker", ["kill", `bob-run-${record.runSlug}`], {
    env: minimalDockerEnvironment(process.env),
    stdio: "ignore",
    timeout: DOCKER_COMMAND_TIMEOUT_MS,
    killSignal: "SIGKILL",
  });
  const defaultInspect = (record) => {
    const result = spawnSyncFn(
      "docker",
      ["inspect", "--format", "{{json .Config.Labels}}", `bob-run-${record.runSlug}`],
      {
        encoding: "utf8",
        env: minimalDockerEnvironment(process.env),
        stdio: ["ignore", "pipe", "pipe"],
        timeout: DOCKER_COMMAND_TIMEOUT_MS,
        killSignal: "SIGKILL",
        maxBuffer: 1024 * 1024,
      },
    );
    if (!result) throw new Error("container inspection returned no result");
    if (result.status !== 0) {
      const stderr = String(result.stderr || "");
      if (/No such (?:object|container):/iu.test(stderr)) return null;
      throw new Error("container inspection was unavailable");
    }
    let labels;
    try {
      labels = JSON.parse(String(result.stdout).trim());
    } catch {
      throw new Error("container inspection returned invalid labels");
    }
    if (
      labels?.["bob.dispatch.run-id"] !== record.runId ||
      labels?.["bob.dispatch.run-slug"] !== record.runSlug ||
      labels?.["bob.dispatch.generation"] !== String(record.generation)
    ) {
      throw new Error("container inspection labels do not match the durable dispatch");
    }
    return { labels };
  };
  const defaultRemoveContainer = (record) => new Promise((resolve) => {
    const name = `bob-run-${record.runSlug}`;
    let child;
    let timeout = null;
    let settled = false;
    const finish = (removed) => {
      if (settled) return;
      settled = true;
      if (timeout !== null) clearTimeoutFn(timeout);
      resolve(removed);
    };
    try {
      child = spawnProcessFn("docker", ["rm", "-f", name], {
        env: minimalDockerEnvironment(process.env),
        stdio: ["ignore", "ignore", "pipe"],
      });
    } catch {
      finish(false);
      return;
    }
    let stderr = "";
    child.stderr?.on("data", (chunk) => {
      stderr = `${stderr}${String(chunk)}`.slice(-1024);
    });
    child.once("error", () => finish(false));
    child.once("close", (code) => {
      finish(code === 0 || /No such container:/iu.test(stderr));
    });
    if (!settled) {
      timeout = setTimeoutFn(() => {
        try { child.kill?.("SIGKILL"); } catch {}
        finish(false);
      }, DOCKER_COMMAND_TIMEOUT_MS);
      if (typeof timeout?.unref === "function") timeout.unref();
    }
  });
  const removeContainer = removeContainerFn || defaultRemoveContainer;
  async function awaitContainerRemoval(record) {
    while (!closed) {
      for (let attempt = 0; attempt < 50; attempt += 1) {
        let removed = false;
        try {
          removed = await removeContainer(record) === true;
        } catch {
          removed = false;
        }
        if (removed) return true;
        if (attempt < 49) await delay(100);
      }
      if (!closed) await delay(1000);
    }
    return false;
  }
  const removeContainerAfterWait = (record, containerCode, monitor) => {
    track((async () => {
      if (await awaitContainerRemoval(record)) monitor.emit("close", containerCode);
    })());
  };
  const defaultWait = (record) => {
    const processChild = spawnProcessFn("docker", ["wait", `bob-run-${record.runSlug}`], {
      env: minimalDockerEnvironment(process.env),
      stdio: ["ignore", "pipe", "ignore"],
    });
    const monitor = new EventEmitter();
    monitor.kill = (signal = "SIGKILL") => {
      try { return processChild.kill(signal); } catch { return false; }
    };
    let output = "";
    let settled = false;
    const finish = (containerCode) => {
      if (settled) return;
      settled = true;
      removeContainerAfterWait(record, containerCode, monitor);
    };
    processChild.stdout?.on("data", (chunk) => { output += String(chunk); });
    processChild.once("error", () => finish(125));
    processChild.once("close", (code) => {
      const containerCode = code === 0 && /^-?\d+\s*$/u.test(output) ? Number(output.trim()) : 125;
      finish(containerCode);
    });
    return monitor;
  };
  const spawnRunner = spawnFn || defaultSpawn;
  const killRunner = killFn || defaultKill;
  const inspectContainer = inspectContainerFn || defaultInspect;
  const waitContainer = waitContainerFn || defaultWait;
  const prepareRepo = prepareRepositoryFn || (
    (record) => prepareRepository(record, runsDir, spawnProcessFn, repositoryCommandTimeoutMs)
  );
  const cleanupRepo = cleanupRepositoryFn || ((record) => {
    if (record.runRoot) removePreparedRepository(record.runRoot);
    else if (record.targetKind === "repo") {
      removePreparedRepository(path.join(runsDir, record.runSlug));
    }
  });

  function terminalResponse(record) {
    return {
      runId: record.runId,
      status: record.status,
      generation: record.generation,
      ...(record.exitCode === null || record.exitCode === undefined ? {} : { exitCode: record.exitCode }),
    };
  }

  function controlUpdate(record) {
    const at = record.finishedAt;
    if (record.status === "succeeded") {
      return {
        runSlug: record.runSlug,
        status: "destroyed",
        phase: "report",
        at,
        event: {
          kind: "destroy",
          register: "breath",
          phase: "report",
          message: "Runner container destroyed.",
        },
      };
    }
    const timedOut = record.status === "timed_out";
    return {
      runSlug: record.runSlug,
      status: "failed",
      phase: "report",
      at,
      event: {
        kind: "wait",
        register: "body",
        phase: "report",
        message: timedOut ? "Runner execution timed out." : "Runner execution failed.",
      },
    };
  }

  async function callControlPlane(update) {
    let timeout = null;
    try {
      await Promise.race([
        Promise.resolve().then(() => controlPlaneSink(update)),
        new Promise((_, reject) => {
          timeout = setTimeoutFn(
            () => reject(new Error("control-plane delivery timed out")),
            10_000,
          );
        }),
      ]);
    } finally {
      if (timeout !== null) clearTimeoutFn(timeout);
    }
  }

  async function deliverControlPlane(record, update) {
    let failure = null;
    for (let attempt = 0; attempt <= CONTROL_RETRY_DELAYS_MS.length; attempt += 1) {
      if (attempt > 0) await delay(CONTROL_RETRY_DELAYS_MS[attempt - 1]);
      try {
        await callControlPlane(update);
        record.controlPlanePending = null;
        persist(record, "control_plane_delivered");
        return true;
      } catch (error) {
        failure = error;
      }
    }
    record.controlPlanePending = update;
    persist(record, "control_plane_pending");
    return failure === null ? true : false;
  }

  async function retryPending() {
    retryReconciliation();
    for (const record of ledger.values()) {
      if (!record.controlPlanePending) continue;
      try {
        await callControlPlane(record.controlPlanePending);
        record.controlPlanePending = null;
        persist(record, "control_plane_delivered");
      } catch {
        // Keep the existing non-secret pending update for the next minute.
      }
    }
  }

  function attachLogCapture(record, child, logFd) {
    const literals = [
      secret,
      containerEnv.RUNNER_SECRET,
      containerEnv.DEEPSEEK_API_KEY,
      record.projectionKey,
      record.payload?.accessPassword,
    ];
    let logBytes = fs.fstatSync(logFd).size;
    let logTruncated = logBytes >= maxLogBytes;
    const append = (output) => {
      let offset = 0;
      try {
        while (offset < output.length) {
          const written = fs.writeSync(logFd, output, offset, output.length - offset);
          if (!Number.isSafeInteger(written) || written < 1) {
            throw new Error("runner log write made no progress");
          }
          offset += written;
        }
        return true;
      } catch {
        logTruncated = true;
        return false;
      }
    };
    const write = (text) => {
      if (logTruncated) return;
      const output = Buffer.from(text, "utf8");
      const remaining = maxLogBytes - logBytes;
      if (remaining <= 0) {
        logTruncated = true;
        return;
      }
      if (output.length <= remaining) {
        if (append(output)) logBytes += output.length;
        return;
      }
      const marker = LOG_TRUNCATION_MARKER.subarray(0, Math.min(remaining, LOG_TRUNCATION_MARKER.length));
      const bodyBytes = remaining - marker.length;
      if (bodyBytes > 0 && !append(output.subarray(0, bodyBytes))) return;
      if (marker.length > 0 && !append(marker)) return;
      logBytes = maxLogBytes;
      logTruncated = true;
    };
    // Redact each pipe independently so stderr interleaving cannot break a
    // literal split across stdout chunks. Feed both into a final redactor so a
    // literal split across the two pipes is also never persisted.
    const output = createStreamingRedactor(literals, write);
    const stdoutOutput = createStreamingRedactor(literals, (text) => output.push(text));
    const stderrOutput = createStreamingRedactor(literals, (text) => output.push(text));
    const onStdout = (chunk) => stdoutOutput.push(chunk);
    const onStderr = (chunk) => stderrOutput.push(chunk);
    child.stdout?.on("data", onStdout);
    child.stderr?.on("data", onStderr);
    record.closeLog = () => {
      stdoutOutput.end();
      stderrOutput.end();
      output.end();
      child.stdout?.off("data", onStdout);
      child.stderr?.off("data", onStderr);
      stdoutOutput.clear();
      stderrOutput.clear();
      output.clear();
      literals.fill("");
      try { fs.closeSync(logFd); } catch { /* already closed */ }
      record.closeLog = null;
    };
  }

  function clearTransientSecrets(record) {
    record.projectionKey = undefined;
    record.payload = undefined;
    if (record.launch?.env) {
      for (const name of Object.keys(record.launch.env)) record.launch.env[name] = "";
    }
    record.launch = undefined;
    record.child = undefined;
  }

  async function forceRemoveAndFinish(record, code) {
    if (record.forceRemovalTask) return record.forceRemovalTask;
    record.awaitingRemoval = true;
    record.forceRemovalTask = (async () => {
      try { record.child?.kill?.("SIGKILL"); } catch {}
      if (!(await awaitContainerRemoval(record))) return;
      record.awaitingRemoval = false;
      await finishRecord(record, code);
    })();
    return record.forceRemovalTask;
  }

  function armTimeout(record, timeoutMs) {
    const timer = setTimeoutFn(() => {
      record.timedOut = true;
      record.terminationTimeout = setTimeoutFn(() => {
        track(forceRemoveAndFinish(record, 124));
      }, DOCKER_COMMAND_TIMEOUT_MS);
      if (typeof record.terminationTimeout?.unref === "function") record.terminationTimeout.unref();
      track(Promise.resolve(killRunner(record)).catch(() => undefined));
    }, Math.max(0, timeoutMs));
    if (typeof timer?.unref === "function") timer.unref();
    record.timeout = timer;
  }

  async function finishRecord(record, code) {
    if (record.finishing) return;
    record.finishing = true;
    if (record.timeout) clearTimeoutFn(record.timeout);
    record.timeout = null;
    if (record.terminationTimeout) clearTimeoutFn(record.terminationTimeout);
    record.terminationTimeout = null;
    record.awaitingRemoval = false;
    record.forceRemovalTask = null;
    record.reconciliationPending = false;
    record.closeLog?.();
    try {
      await cleanupRepo(record);
    } catch {
      // Container state remains authoritative; cleanup is retried by tmpfs lifecycle.
    }
    record.exitCode = Number.isSafeInteger(code) ? code : null;
    record.status = record.timedOut ? "timed_out" : code === 0 ? "succeeded" : "failed";
    record.finishedAt = now();
    record.controlPlanePending = controlUpdate(record);
    persist(record, "finished");
    active.delete(record.idempotencyKey);
    clearTransientSecrets(record);
    requestTick();
    await deliverControlPlane(record, record.controlPlanePending);
  }

  function monitorRecord(record, child, timeoutMs) {
    record.child = child;
    armTimeout(record, timeoutMs);
    const complete = (code) => {
      if (record.awaitingRemoval) return;
      track(finishRecord(record, Number.isSafeInteger(code) ? code : 125));
    };
    child.once("error", () => complete(125));
    child.once("close", complete);
  }

  async function launchRecord(record) {
    record.status = "running";
    record.startedAt = now();
    record.finishedAt = null;
    record.exitCode = null;
    record.timedOut = false;
    record.finishing = false;
    persist(record, "started");
    let logFd = null;
    let child = null;
    try {
      if (record.targetKind === "repo") await prepareRepo(record);
      logFd = openPrivateAppendFile(path.join(logsDir, `${record.runId}.log`));
      record.launch = dockerLaunchSpec(record, runnerImageUri, containerEnv);
      const spawned = spawnRunner(record, record.launch);
      child = spawned && typeof spawned.then === "function" ? await spawned : spawned;
      attachLogCapture(record, child, logFd);
      logFd = null;
      monitorRecord(record, child, runTimeoutMs);
    } catch {
      if (logFd !== null) {
        try { fs.closeSync(logFd); } catch {}
      }
      if (child) {
        record.child = child;
        try { await Promise.resolve(killRunner(record)); } catch {}
        await forceRemoveAndFinish(record, 125);
      } else {
        await finishRecord(record, 125);
      }
    }
  }

  async function expireQueuedRecord(record) {
    record.status = "failed";
    record.exitCode = null;
    record.finishedAt = now();
    record.controlPlanePending = controlUpdate(record);
    persist(record, "queue_expired");
    clearTransientSecrets(record);
    await deliverControlPlane(record, record.controlPlanePending);
  }

  async function runTick() {
    while (!closed && active.size < maxConcurrent && queue.length > 0) {
      const record = queue.shift();
      if (now() - record.queuedAt > maxQueueAgeMs) {
        track(expireQueuedRecord(record));
        continue;
      }
      active.set(record.idempotencyKey, record);
      track(launchRecord(record));
    }
  }

  function requestTick() {
    if (tickTask || closed || queue.length === 0 || active.size >= maxConcurrent) return tickTask;
    tickTask = runTick().finally(() => {
      tickTask = null;
      if (!closed && active.size < maxConcurrent && queue.length > 0) requestTick();
    });
    track(tickTask);
    return tickTask;
  }

  function interrupt(record, event) {
    active.delete(record.idempotencyKey);
    record.reconciliationPending = false;
    record.status = "interrupted";
    record.finishedAt = now();
    record.exitCode = null;
    record.controlPlanePending = null;
    persist(record, event);
    try { cleanupRepo(record); } catch { /* deterministic tmpfs cleanup is best effort here */ }
    requestTick();
  }

  function reconcileRunningRecord(record) {
    active.set(record.idempotencyKey, record);
    record.finishing = false;
    record.timedOut = false;
    let container;
    try {
      container = inspectContainer(record);
    } catch {
      record.reconciliationPending = true;
      return;
    }
    if (!container) {
      interrupt(record, "boot_interrupted_missing_container");
      return;
    }
    let child;
    try {
      child = waitContainer(record, container);
    } catch {
      record.reconciliationPending = true;
      return;
    }
    record.reconciliationPending = false;
    const elapsed = Math.max(0, now() - (record.startedAt || now()));
    monitorRecord(record, child, Math.max(0, runTimeoutMs - elapsed));
  }

  function retryReconciliation() {
    for (const record of ledger.values()) {
      if (record.status === "running" && record.reconciliationPending) {
        reconcileRunningRecord(record);
      }
    }
  }

  function reconcile() {
    for (const record of ledger.values()) {
      if (record.status === "queued") {
        interrupt(record, "boot_interrupted_queued");
        continue;
      }
      if (record.status === "running") reconcileRunningRecord(record);
    }
  }

  function queueHasCapacity() {
    return queue.length < maxQueued;
  }

  function accept(payload, idempotencyKey, authorizationHeader) {
    if (!authorized(authorizationHeader, secret)) {
      return { status: 401, body: { error: "unauthorized" } };
    }
    const validated = validatePayload(payload);
    if (!validated.ok) {
      return { status: 400, body: { error: validated.error, code: validated.code } };
    }
    if (typeof idempotencyKey !== "string" || idempotencyKey !== validated.value.runId) {
      return {
        status: 400,
        body: { error: "Idempotency-Key must equal payload.runId", code: "invalid_idempotency_key" },
      };
    }
    const requestDigest = digestValidatedPayload(validated.value);
    const existing = ledger.get(idempotencyKey);
    if (existing) {
      if (existing.requestDigest !== requestDigest) {
        return {
          status: 409,
          body: { error: "Idempotency-Key was already used for a different request", code: "idempotency_conflict" },
        };
      }
      if (LIVE_STATUSES.includes(existing.status)) {
        return { status: 202, body: terminalResponse(existing) };
      }
      if (TERMINAL_STATUSES.includes(existing.status)) {
        return { status: 200, body: terminalResponse(existing) };
      }
      if (existing.status === "interrupted") {
        if (!queueHasCapacity()) {
          return {
            status: 429,
            headers: { "Retry-After": "60" },
            body: { error: "runner queue is full", code: "queue_full" },
          };
        }
        existing.generation += 1;
        existing.status = "queued";
        existing.queuedAt = now();
        existing.startedAt = null;
        existing.finishedAt = null;
        existing.exitCode = null;
        existing.payload = validated.value;
        existing.projectionKey = validated.value.projectionKey;
        existing.controlPlanePending = null;
        persist(existing, "replayed");
        queue.push(existing);
        requestTick();
        return { status: 202, body: terminalResponse(existing) };
      }
    }

    if (!queueHasCapacity()) {
      return {
        status: 429,
        headers: { "Retry-After": "60" },
        body: { error: "runner queue is full", code: "queue_full" },
      };
    }
    const acceptedAt = now();
    const record = {
      idempotencyKey,
      requestDigest,
      runId: validated.value.runId,
      runSlug: validated.value.runSlug,
      targetKind: validated.value.targetKind,
      kind: validated.value.kind,
      status: "queued",
      generation: 1,
      acceptedAt,
      queuedAt: acceptedAt,
      startedAt: null,
      finishedAt: null,
      exitCode: null,
      controlPlanePending: null,
      payload: validated.value,
      projectionKey: validated.value.projectionKey,
    };
    persist(record, "accepted");
    queue.push(record);
    requestTick();
    return { status: 202, body: terminalResponse(record) };
  }

  async function flush() {
    while (pendingTasks.size > 0) {
      await Promise.allSettled([...pendingTasks]);
    }
  }

  reconcile();
  const pendingInterval = setIntervalFn(() => track(retryPending()), 60 * 1000);
  if (typeof pendingInterval?.unref === "function") pendingInterval.unref();
  requestTick();

  return {
    accept,
    close() {
      closed = true;
      clearIntervalFn(pendingInterval);
    },
    flush,
    retryPending: () => track(retryPending()),
    snapshot: () => ({
      active: active.size,
      queued: queue.length,
      ledger: ledger.size,
      pendingControlPlane: [...ledger.values()].filter((record) => record.controlPlanePending).length,
    }),
    record: (idempotencyKey) => {
      const record = ledger.get(idempotencyKey);
      return record ? durableRow(record, record.lastEvent || "snapshot", now()) : null;
    },
  };
}

module.exports = {
  MAX_BODY_BYTES,
  authorized,
  canonicalDispatchDigest,
  canonicalEventHash,
  contractSelector,
  createConvexControlPlaneSink,
  createService,
  createStreamingRedactor,
  dockerLaunchSpec,
  prepareRepository,
  removePreparedRepository,
  repositorySelector,
  runnerPayloadFor,
  validatePayload,
};
