"use strict";

// Dispatch service contract tests: auth, idempotency, payload validation,
// concurrency queueing, timeout kill. All spawn behavior is injected.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { EventEmitter } = require("node:events");

const {
  authorized,
  createService,
  validatePayload,
} = require("../service.js");

const SECRET = "dispatch-test-secret";

function validPayload(overrides = {}) {
  return {
    schemaVersion: 1,
    assessmentId: "assess-1",
    runId: "run-1",
    runSlug: "runslug123456",
    target: "https://example.com",
    targetDomain: "example.com",
    targetKind: "web",
    runMode: "standard",
    autonomy: "operator-approved",
    objective: "Review the production attack surface",
    sourceRef: null,
    kind: "assessment",
    retestOf: [],
    projectionKey: "p".repeat(48),
    ...overrides,
  };
}

function tempDirs() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "bob-dispatch-"));
  return {
    root,
    ledgerDir: path.join(root, "ledger"),
    runsDir: path.join(root, "runs"),
    logsDir: path.join(root, "logs"),
  };
}

function fakeChild() {
  const child = new EventEmitter();
  child.killed = false;
  child.kill = () => {
    child.killed = true;
    child.emit("exit", 137);
  };
  child.on("exit", (code) => {
    if (!child.exitEmitted) child.exitEmitted = code;
  });
  return child;
}

function makeService({ maxConcurrent = 2, runTimeoutMs = 60000 } = {}) {
  const dirs = tempDirs();
  const spawned = [];
  const killed = [];
  const children = [];
  const service = createService({
    secret: SECRET,
    ledgerDir: dirs.ledgerDir,
    runsDir: dirs.runsDir,
    logsDir: dirs.logsDir,
    runnerImageUri: "runner-image:test",
    containerEnv: {
      RUNNER_SECRET: "runner-secret",
      REPORTS_SECRET: "reports-secret",
      DEEPSEEK_API_KEY: "deepseek-key",
      BOB_PROJECTION_URL: "https://projection.invalid/api/findings",
    },
    maxConcurrent,
    runTimeoutMs,
    spawnFn: (record) => {
      spawned.push(record);
      const child = fakeChild();
      children.push(child);
      return child;
    },
    killFn: (record) => {
      killed.push(record.runId);
      return { status: 0 };
    },
  });
  return { service, dirs, spawned, killed, children };
}

test("authorized is constant-time and rejects missing, malformed, and wrong secrets", () => {
  assert.equal(authorized(`Bearer ${SECRET}`, SECRET), true);
  assert.equal(authorized(null, SECRET), false);
  assert.equal(authorized("Basic abc", SECRET), false);
  assert.equal(authorized("Bearer wrong", SECRET), false);
  assert.equal(authorized(`Bearer ${SECRET}`, "other-secret"), false);
});

test("validatePayload accepts the v1 contract and rejects malformed variants", () => {
  assert.equal(validatePayload(validPayload()).ok, true);
  const cases = [
    [validPayload({ schemaVersion: 2 }), "invalid_schema_version"],
    [validPayload({ targetKind: "ip" }), "invalid_target_kind"],
    [validPayload({ target: "http://example.com" }), "invalid_target"],
    [validPayload({ autonomy: "deep" }), "invalid_autonomy"],
    [validPayload({ kind: "other" }), "invalid_kind"],
    [validPayload({ projectionKey: "short" }), "invalid_projection_key"],
    [validPayload({ retestOf: [1] }), "invalid_retest_of"],
    [null, "invalid_body"],
  ];
  for (const [payload, code] of cases) {
    const result = validatePayload(payload);
    assert.equal(result.ok, false);
    assert.equal(result.code, code);
  }
});

test("accept rejects a wrong bearer without side effects", () => {
  const { service, spawned } = makeService();
  const result = service.accept(validPayload(), "key-1", "Bearer wrong");
  assert.equal(result.status, 401);
  assert.equal(spawned.length, 0);
});

test("accept spawns once per idempotency key and replays the stored response", () => {
  const { service, spawned } = makeService();
  const first = service.accept(validPayload(), "key-1", `Bearer ${SECRET}`);
  const replay = service.accept(validPayload(), "key-1", `Bearer ${SECRET}`);
  assert.equal(first.status, 202);
  assert.deepEqual(replay.body, first.body);
  assert.equal(spawned.length, 1);
});

test("the runner env file carries secrets and per-run identity only", () => {
  const { service, spawned } = makeService();
  service.accept(validPayload(), "key-1", `Bearer ${SECRET}`);
  const env = fs.readFileSync(spawned[0].envFile, "utf8");
  assert.match(env, /^RUNNER_SECRET=runner-secret$/m);
  assert.match(env, /^DEEPSEEK_API_KEY=deepseek-key$/m);
  assert.match(env, /^BOB_RUN_SLUG=runslug123456$/m);
  assert.match(env, /^BOB_RUN_KIND=assessment$/m);
  assert.doesNotMatch(env, /CHANGE_ME|undefined/);
});

test("a ledger replay across service restarts never double-spawns", () => {
  const first = makeService();
  first.service.accept(validPayload(), "key-1", `Bearer ${SECRET}`);
  const second = createService({
    secret: SECRET,
    ledgerDir: first.dirs.ledgerDir,
    runsDir: first.dirs.runsDir,
    logsDir: first.dirs.logsDir,
    runnerImageUri: "runner-image:test",
    containerEnv: { RUNNER_SECRET: "runner-secret" },
    spawnFn: () => fakeChild(),
  });
  const replay = second.accept(validPayload(), "key-1", `Bearer ${SECRET}`);
  assert.equal(replay.status, 202);
  assert.equal(first.spawned.length, 1);
});

test("concurrency cap queues the second run until the first exits", async () => {
  const { service, spawned, children } = makeService({ maxConcurrent: 1 });
  service.accept(validPayload({ runId: "run-a", runSlug: "runslugaaa111" }), "key-a", `Bearer ${SECRET}`);
  service.accept(validPayload({ runId: "run-b", runSlug: "runslugbbb222" }), "key-b", `Bearer ${SECRET}`);
  assert.equal(spawned.length, 1);
  children[0].emit("exit", 0);
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(spawned.length, 2);
  assert.equal(spawned[1].runId, "run-b");
});

test("the timeout killer fires for a run that never exits", async () => {
  const { service, killed } = makeService({ maxConcurrent: 1, runTimeoutMs: 30 });
  service.accept(validPayload(), "key-1", `Bearer ${SECRET}`);
  await new Promise((resolve) => setTimeout(resolve, 80));
  assert.deepEqual(killed, ["run-1"]);
});
