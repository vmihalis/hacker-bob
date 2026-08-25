"use strict";

// Hacker Bob dispatch service core. Dependency-free (Node >= 22).
//
// Accepts the www dispatch handoff (schemaVersion 1, see
// www/convex/assessments.ts submitRunnerRequest), dedupes by Idempotency-Key
// on a JSONL ledger, and spawns per-run runner containers with env-only
// secrets. Concurrency-capped with a FIFO queue; per-run wall-clock timeout
// kills the container. Fail-safe: a crashed service replays the ledger on
// boot and never double-spawns a run.

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const VALID_TARGET_KINDS = new Set(["web", "repo", "contract"]);
const VALID_RUN_KINDS = new Set(["assessment", "retest"]);
const RUN_SLUG_RE = /^[A-Za-z0-9_-]{8,64}$/;

function secretDigest(value) {
  return crypto.createHash("sha256").update(value).digest();
}

// Constant-time bearer check: hash both sides, XOR-fold the digests.
function authorized(authorizationHeader, secret) {
  if (!authorizationHeader || !secret) return false;
  if (!authorizationHeader.startsWith("Bearer ")) return false;
  const provided = authorizationHeader.slice("Bearer ".length);
  const providedDigest = secretDigest(provided);
  const expectedDigest = secretDigest(secret);
  let difference = 0;
  for (let i = 0; i < providedDigest.length; i++) {
    difference |= providedDigest[i] ^ expectedDigest[i];
  }
  return difference === 0;
}

function validatePayload(body) {
  if (body === null || typeof body !== "object" || Array.isArray(body)) {
    return { ok: false, code: "invalid_body", error: "payload must be a JSON object" };
  }
  if (body.schemaVersion !== 1) {
    return { ok: false, code: "invalid_schema_version", error: "schemaVersion must be 1" };
  }
  if (typeof body.assessmentId !== "string" || !body.assessmentId) {
    return { ok: false, code: "invalid_assessment", error: "assessmentId is required" };
  }
  if (typeof body.runId !== "string" || !body.runId) {
    return { ok: false, code: "invalid_run", error: "runId is required" };
  }
  if (typeof body.runSlug !== "string" || !RUN_SLUG_RE.test(body.runSlug)) {
    return { ok: false, code: "invalid_run_slug", error: "runSlug must match [A-Za-z0-9_-]{8,64}" };
  }
  if (!VALID_TARGET_KINDS.has(body.targetKind)) {
    return { ok: false, code: "invalid_target_kind", error: "unsupported targetKind" };
  }
  if (typeof body.target !== "string" || !body.target.startsWith("https://")) {
    return { ok: false, code: "invalid_target", error: "target must be an https URL" };
  }
  if (body.autonomy !== "operator-approved") {
    return { ok: false, code: "invalid_autonomy", error: "autonomy must be operator-approved" };
  }
  if (typeof body.objective !== "string" || !body.objective.trim()) {
    return { ok: false, code: "invalid_objective", error: "objective is required" };
  }
  if (!VALID_RUN_KINDS.has(body.kind)) {
    return { ok: false, code: "invalid_kind", error: "kind must be assessment or retest" };
  }
  if (
    body.retestOf !== undefined &&
    (!Array.isArray(body.retestOf) || body.retestOf.some((value) => typeof value !== "string"))
  ) {
    return { ok: false, code: "invalid_retest_of", error: "retestOf must be an array of strings" };
  }
  if (typeof body.projectionKey !== "string" || body.projectionKey.length < 32) {
    return { ok: false, code: "invalid_projection_key", error: "projectionKey is required" };
  }
  return { ok: true, value: body };
}

function loadLedger(ledgerDir) {
  const ledger = new Map();
  const file = path.join(ledgerDir, "dispatch.jsonl");
  if (!fs.existsSync(file)) return ledger;
  for (const line of fs.readFileSync(file, "utf8").split("\n")) {
    if (!line.trim()) continue;
    try {
      const row = JSON.parse(line);
      if (row && row.idempotencyKey) ledger.set(row.idempotencyKey, row);
    } catch {
      // A torn tail line from a crash is skipped; the run row is re-drivable.
    }
  }
  return ledger;
}

function createService({
  secret,
  ledgerDir,
  runsDir,
  logsDir,
  runnerImageUri,
  containerEnv,
  maxConcurrent = 2,
  runTimeoutMs = 90 * 60 * 1000,
  spawnFn = null,
  killFn = null,
}) {
  fs.mkdirSync(ledgerDir, { recursive: true });
  fs.mkdirSync(runsDir, { recursive: true });
  fs.mkdirSync(logsDir, { recursive: true });
  const ledgerFile = path.join(ledgerDir, "dispatch.jsonl");
  const ledger = loadLedger(ledgerDir);
  const active = new Map();
  const queue = [];

  const defaultSpawn = (record) => {
    const logPath = path.join(logsDir, `${record.runId}.log`);
    const logFd = fs.openSync(logPath, "a");
    const args = [
      "run",
      "--rm",
      "--name", `bob-run-${record.runSlug}`,
      "--env-file", record.envFile,
      "-v", `${record.payloadFile}:/opt/payload.json:ro`,
      "-e", "BOB_PAYLOAD_PATH=/opt/payload.json",
      runnerImageUri,
    ];
    const { spawn } = require("child_process");
    const child = spawn("docker", args, { stdio: ["ignore", logFd, logFd] });
    child.on("close", () => {
      try { fs.closeSync(logFd); } catch { /* already closed */ }
    });
    return child;
  };
  const defaultKill = (record) => {
    const { spawnSync } = require("child_process");
    return spawnSync("docker", ["kill", `bob-run-${record.runSlug}`], { stdio: "ignore" });
  };
  const spawnFnResolved = spawnFn || defaultSpawn;
  const killFnResolved = killFn || defaultKill;

  function appendLedger(row) {
    fs.appendFileSync(ledgerFile, `${JSON.stringify(row)}\n`);
  }

  function envFileFor(record) {
    const lines = [
      `RUNNER_SECRET=${containerEnv.RUNNER_SECRET || ""}`,
      `REPORTS_SECRET=${containerEnv.REPORTS_SECRET || ""}`,
      `DEEPSEEK_API_KEY=${containerEnv.DEEPSEEK_API_KEY || ""}`,
      `BOB_PROJECTION_URL=${containerEnv.BOB_PROJECTION_URL || ""}`,
      `BOB_CONVEX_URL=${containerEnv.BOB_CONVEX_URL || ""}`,
      `BOB_RUN_SLUG=${record.runSlug}`,
      `BOB_PROJECTION_KEY=${record.projectionKey}`,
      `BOB_RUN_KIND=${record.kind}`,
      `BOB_RETEST_OF=${(record.retestOf || []).join(",")}`,
      `BOB_REPORT_SLUG=${record.reportSlug || ""}`,
    ];
    const envFile = path.join(record.runDir, "env.list");
    fs.writeFileSync(envFile, `${lines.join("\n")}\n`, { encoding: "utf8", mode: 0o600 });
    return envFile;
  }

  function start(runId) {
    const record = active.get(runId);
    if (!record) return;
    record.status = "running";
    record.startedAt = Date.now();
    appendLedger({ ...record, event: "started" });
    const child = spawnFnResolved(record);
    record.child = child;
    const killer = setTimeout(() => {
      record.timedOut = true;
      killFnResolved(record);
    }, runTimeoutMs);
    child.on("exit", (code) => {
      clearTimeout(killer);
      active.delete(runId);
      appendLedger({
        ...record,
        event: "exited",
        exitCode: code,
        timedOut: record.timedOut === true,
      });
      tick();
    });
  }

  function tick() {
    while (active.size < maxConcurrent && queue.length > 0) {
      const next = queue.shift();
      active.set(next.runId, next);
      start(next.runId);
    }
  }

  function accept(payload, idempotencyKey, authorizationHeader) {
    if (!authorized(authorizationHeader, secret)) {
      return { status: 401, body: { error: "unauthorized" } };
    }
    if (!idempotencyKey || typeof idempotencyKey !== "string") {
      return { status: 400, body: { error: "Idempotency-Key header is required" } };
    }
    const existing = ledger.get(idempotencyKey);
    if (existing) {
      return { status: 202, body: existing.response };
    }
    const validated = validatePayload(payload);
    if (!validated.ok) {
      return { status: 400, body: { error: validated.error, code: validated.code } };
    }
    const runDir = path.join(runsDir, payload.runId);
    fs.mkdirSync(runDir, { recursive: true });
    const payloadFile = path.join(runDir, "payload.json");
    fs.writeFileSync(payloadFile, JSON.stringify(payload, null, 2), { encoding: "utf8", mode: 0o600 });
    const record = {
      idempotencyKey,
      runId: payload.runId,
      runSlug: payload.runSlug,
      projectionKey: payload.projectionKey,
      kind: payload.kind,
      retestOf: Array.isArray(payload.retestOf) ? payload.retestOf : [],
      reportSlug: payload.reportSlug || null,
      runDir,
      payloadFile,
      envFile: null,
      status: active.size < maxConcurrent ? "running" : "queued",
      acceptedAt: Date.now(),
      response: { runId: payload.runId, status: "accepted" },
    };
    record.envFile = envFileFor(record);
    appendLedger({ ...record, event: "accepted" });
    ledger.set(idempotencyKey, record);
    if (record.status === "running") {
      active.set(payload.runId, record);
      start(payload.runId);
    } else {
      queue.push(record);
    }
    return { status: 202, body: record.response };
  }

  return { accept, snapshot: () => ({ active: active.size, queued: queue.length, ledger: ledger.size }) };
}

module.exports = {
  authorized,
  createService,
  validatePayload,
};
