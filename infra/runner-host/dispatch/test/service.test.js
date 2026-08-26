"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { EventEmitter } = require("node:events");
const { PassThrough } = require("node:stream");

const {
  authorized,
  canonicalDispatchDigest,
  canonicalEventHash,
  contractSelector,
  createConvexControlPlaneSink,
  createService,
  dockerLaunchSpec,
  repositorySelector,
  prepareRepository,
  removePreparedRepository,
  validatePayload,
} = require("../service.js");
const {
  createHttpServer,
  readJsonBody,
} = require("../server.js");

const SECRET = "dispatch-test-secret";
const RUNNER_SECRET = "runner-secret-value";
const DEEPSEEK_SECRET = "deepseek-secret-value";
const PROJECTION_KEY = "P".repeat(43);
const RETEST_FINGERPRINT = "a".repeat(64);
const CONTAINER_ENV = Object.freeze({
  RUNNER_SECRET,
  DEEPSEEK_API_KEY: DEEPSEEK_SECRET,
  BOB_PROJECTION_URL: "https://projection.invalid/api/findings",
  BOB_CONVEX_URL: "https://convex.invalid",
});

function validPayload(overrides = {}) {
  return {
    schemaVersion: 1,
    assessmentId: "assessment_123456",
    runId: "run_1234567890",
    runSlug: "runSlug_123456789",
    target: "https://example.com",
    targetDomain: "example.com",
    targetKind: "web",
    runMode: "standard",
    autonomy: "operator-approved",
    objective: "Review the production attack surface",
    accessPassword: "dispatch-access-password",
    kind: "assessment",
    retestOf: [],
    projectionKey: PROJECTION_KEY,
    ...overrides,
  };
}

function repoPayload(overrides = {}) {
  const target = "https://github.com/acme/api.git";
  return validPayload({
    runId: "repo_run_123456",
    runSlug: "repoRun_123456789",
    target,
    targetDomain: repositorySelector(target, "api"),
    targetKind: "repo",
    sourceRef: "0123456789abcdef0123456789abcdef01234567",
    ...overrides,
  });
}

function contractPayload(overrides = {}) {
  const target = "eip155:1:0x1234567890abcdef1234567890abcdef12345678";
  return validPayload({
    runId: "contract_run_1234",
    runSlug: "contractRun_123456",
    target,
    targetDomain: contractSelector("1", "0x1234567890abcdef1234567890abcdef12345678"),
    targetKind: "contract",
    ...overrides,
  });
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
  child.stdout = new PassThrough();
  child.stderr = new PassThrough();
  child.finish = (code) => {
    child.stdout.end();
    child.stderr.end();
    child.emit("close", code);
  };
  return child;
}

function fakeInterval() {
  return { unref() {} };
}

function makeHarness(t, overrides = {}) {
  const dirs = overrides.dirs || tempDirs();
  const spawned = [];
  const killed = [];
  const controlUpdates = [];
  const removals = [];
  const delays = [];
  const service = createService({
    secret: SECRET,
    ledgerDir: dirs.ledgerDir,
    runsDir: dirs.runsDir,
    logsDir: dirs.logsDir,
    runnerImageUri: "runner-image@sha256:" + "b".repeat(64),
    containerEnv: overrides.containerEnv || CONTAINER_ENV,
    maxConcurrent: overrides.maxConcurrent || 2,
    maxQueued: overrides.maxQueued || 8,
    maxQueueAgeMs: overrides.maxQueueAgeMs || 900000,
    runTimeoutMs: overrides.runTimeoutMs || 60000,
    maxLogBytes: overrides.maxLogBytes,
    ledgerCompactRows: overrides.ledgerCompactRows || 10000,
    now: overrides.now || (() => Date.now()),
    delay: overrides.delay || (async (milliseconds) => { delays.push(milliseconds); }),
    setIntervalFn: overrides.setIntervalFn || fakeInterval,
    clearIntervalFn: overrides.clearIntervalFn || (() => {}),
    setTimeoutFn: overrides.setTimeoutFn,
    clearTimeoutFn: overrides.clearTimeoutFn,
    controlPlaneSink: overrides.controlPlaneSink || (async (update) => { controlUpdates.push(update); }),
    spawnFn: overrides.spawnFn || ((record, launch) => {
      const child = fakeChild();
      spawned.push({ record, launch, child });
      return child;
    }),
    killFn: overrides.killFn || ((record) => {
      killed.push(record.runId);
      const spawnedRecord = spawned.find((candidate) => candidate.record.runId === record.runId);
      spawnedRecord?.child.finish(137);
    }),
    inspectContainerFn: overrides.inspectContainerFn,
    waitContainerFn: overrides.waitContainerFn,
    removeContainerFn: overrides.removeContainerFn || (async (record) => {
      removals.push(record.runId);
      return true;
    }),
    prepareRepositoryFn: overrides.prepareRepositoryFn,
    cleanupRepositoryFn: overrides.cleanupRepositoryFn,
  });
  t.after(() => {
    service.close();
    if (!overrides.keepDirs) fs.rmSync(dirs.root, { recursive: true, force: true });
  });
  return { service, dirs, spawned, killed, removals, controlUpdates, delays };
}

function accept(service, payload, authorization = `Bearer ${SECRET}`, idempotencyKey = payload?.runId) {
  return service.accept(payload, idempotencyKey, authorization);
}

async function finishAndFlush(harness, index, code) {
  harness.spawned[index].child.finish(code);
  await harness.service.flush();
}

test("authorized performs two digests for every bearer candidate", (t) => {
  const createHash = crypto.createHash;
  const digest = t.mock.method(crypto, "createHash", (...args) => createHash(...args));
  const cases = [
    { label: "valid", header: `Bearer ${SECRET}`, secret: SECRET, expected: true },
    { label: "wrong", header: "Bearer wrong", secret: SECRET, expected: false },
    { label: "empty", header: "Bearer ", secret: SECRET, expected: false },
    { label: "absent", header: undefined, secret: SECRET, expected: false },
    { label: "malformed", header: { bearer: SECRET }, secret: SECRET, expected: false },
    { label: "missing configuration", header: `Bearer ${SECRET}`, secret: undefined, expected: false },
  ];
  for (const candidate of cases) {
    assert.equal(authorized(candidate.header, candidate.secret), candidate.expected, candidate.label);
    assert.equal(digest.mock.callCount(), 2, `${candidate.label} must hash both sides`);
    digest.mock.resetCalls();
  }
});

test("validatePayload accepts exact web, repo, contract, and retest contracts", () => {
  assert.deepEqual(validatePayload(validPayload()).ok, true);
  assert.deepEqual(validatePayload(repoPayload()).ok, true);
  assert.deepEqual(validatePayload(contractPayload()).ok, true);
  assert.deepEqual(validatePayload(validPayload({
    kind: "retest",
    retestOf: [RETEST_FINGERPRINT],
  })).ok, true);
});

test("validatePayload rejects unknown, unbounded, noncanonical, and mismatched inputs", () => {
  const cases = [
    [validPayload({ reportSlug: "attacker-report" }), "unknown_field"],
    [validPayload({ assessmentId: "short" }), "invalid_assessment"],
    [validPayload({ runId: "short" }), "invalid_run"],
    [validPayload({ runSlug: "too-short" }), "invalid_run_slug"],
    [validPayload({ objective: "line one\nline two" }), "invalid_objective"],
    [validPayload({ objective: "x".repeat(4001) }), "invalid_objective"],
    [validPayload({ accessPassword: "short" }), "invalid_access_password"],
    [validPayload({ accessPassword: "x".repeat(257) }), "invalid_access_password"],
    [validPayload({ scope: { notes: "ok", extra: true } }), "invalid_scope"],
    [validPayload({ runMode: "x".repeat(81) }), "invalid_run_mode"],
    [validPayload({ projectionKey: "A".repeat(42) }), "invalid_projection_key"],
    [validPayload({ retestOf: [RETEST_FINGERPRINT, RETEST_FINGERPRINT] }), "invalid_retest_of"],
    [validPayload({ retestOf: [RETEST_FINGERPRINT] }), "kind_target_mismatch"],
    [validPayload({ kind: "retest", retestOf: [] }), "kind_target_mismatch"],
    [validPayload({ target: "https://user:pass@example.com" }), "invalid_target"],
    [validPayload({ targetDomain: "other.example" }), "invalid_target"],
    [validPayload({ sourceRef: "0".repeat(40) }), "invalid_source_ref"],
    [repoPayload({ sourceRef: "main" }), "invalid_source_ref"],
    [repoPayload({ target: "https://gitlab.com/acme/api.git" }), "invalid_target"],
    [repoPayload({ targetDomain: "repo-api-deadbeef" }), "invalid_target_domain"],
    [contractPayload({ target: "eip155:1:0x1234567890ABCDEF1234567890abcdef12345678" }), "invalid_target"],
    [contractPayload({ targetDomain: "sc-evm-1-deadbeef-deadbeef" }), "invalid_target_domain"],
    [contractPayload({ sourceRef: "0".repeat(40) }), "invalid_source_ref"],
    [null, "invalid_body"],
  ];
  for (const [payload, code] of cases) {
    const result = validatePayload(payload);
    assert.equal(result.ok, false, code);
    assert.equal(result.code, code);
  }
});

test("canonical dispatch digest is key-order independent and binds secret digests", () => {
  const payload = validPayload();
  const reordered = Object.fromEntries(Object.entries(payload).reverse());
  assert.equal(canonicalDispatchDigest(payload), canonicalDispatchDigest(reordered));
  assert.notEqual(
    canonicalDispatchDigest(payload),
    canonicalDispatchDigest(validPayload({ projectionKey: "Q".repeat(43) })),
  );
  assert.notEqual(
    canonicalDispatchDigest(payload),
    canonicalDispatchDigest(validPayload({ accessPassword: "different-access-password" })),
  );
  assert.match(canonicalDispatchDigest(payload), /^[0-9a-f]{64}$/);
});

test("accept requires runId idempotency, rejects digest conflicts, and replays live work", (t) => {
  const harness = makeHarness(t);
  const payload = validPayload();
  assert.equal(accept(harness.service, payload, `Bearer ${SECRET}`, "different_run_id").body.code, "invalid_idempotency_key");
  const first = accept(harness.service, payload);
  const replay = accept(harness.service, payload);
  const conflict = accept(harness.service, validPayload({ objective: "Different authorized objective" }));
  assert.equal(first.status, 202);
  assert.equal(replay.status, 202);
  assert.deepEqual(replay.body, first.body);
  assert.equal(conflict.status, 409);
  assert.equal(conflict.body.code, "idempotency_conflict");
  assert.equal(harness.spawned.length, 1);
});

test("terminal success and failure replay without another spawn", async (t) => {
  const success = makeHarness(t);
  const successPayload = validPayload();
  accept(success.service, successPayload);
  await finishAndFlush(success, 0, 0);
  const succeededReplay = accept(success.service, successPayload);
  assert.equal(succeededReplay.status, 200);
  assert.equal(succeededReplay.body.status, "succeeded");
  assert.equal(success.spawned.length, 1);

  const failed = makeHarness(t);
  const failedPayload = validPayload({ runId: "failed_run_12345", runSlug: "failedRun_1234567" });
  accept(failed.service, failedPayload);
  await finishAndFlush(failed, 0, 9);
  const failedReplay = accept(failed.service, failedPayload);
  assert.equal(failedReplay.status, 200);
  assert.equal(failedReplay.body.status, "failed");
  assert.equal(failed.spawned.length, 1);
});

test("queue capacity returns 429 before allocation and advances FIFO", async (t) => {
  const harness = makeHarness(t, { maxConcurrent: 1, maxQueued: 1 });
  const first = validPayload();
  const second = validPayload({ runId: "second_run_1234", runSlug: "secondRun_123456" });
  const third = validPayload({ runId: "third_run_12345", runSlug: "thirdRun_1234567" });
  accept(harness.service, first);
  accept(harness.service, second);
  const rejected = accept(harness.service, third);
  assert.equal(rejected.status, 429);
  assert.equal(rejected.headers["Retry-After"], "60");
  assert.equal(rejected.body.code, "queue_full");
  assert.equal(harness.spawned.length, 1);
  await finishAndFlush(harness, 0, 0);
  assert.equal(harness.spawned.length, 2);
  assert.equal(harness.spawned[1].record.runId, second.runId);
});

test("expired queued work does not block the next FIFO spawn on control-plane delivery", async (t) => {
  let clock = 1000;
  const order = [];
  let releaseExpiredDelivery;
  const expiredDelivery = new Promise((resolve) => {
    releaseExpiredDelivery = resolve;
  });
  const harness = makeHarness(t, {
    maxConcurrent: 1,
    maxQueued: 2,
    maxQueueAgeMs: 1000,
    now: () => clock,
    controlPlaneSink: async (update) => {
      order.push(`control:${update.runSlug}`);
      if (update.runSlug === "expiredRun_123456") await expiredDelivery;
    },
    spawnFn: (record, launch) => {
      order.push(`spawn:${record.runSlug}`);
      const child = fakeChild();
      harness.spawned.push({ record, launch, child });
      return child;
    },
  });
  const first = validPayload();
  const expired = validPayload({ runId: "expired_run_123", runSlug: "expiredRun_123456" });
  const next = validPayload({ runId: "next_run_123456", runSlug: "nextRun_123456789" });
  accept(harness.service, first);
  accept(harness.service, expired);
  clock = 1900;
  accept(harness.service, next);
  clock = 2101;
  harness.spawned[0].child.finish(0);
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(harness.service.record(expired.runId).status, "failed");
  assert.equal(harness.spawned[1].record.runId, next.runId);
  releaseExpiredDelivery();
  harness.spawned[1].child.finish(0);
  await harness.service.flush();
});

test("Docker launch keeps secrets out of argv, uses pinned pull policy, and mounts the repo", () => {
  const payload = repoPayload();
  const record = {
    payload,
    projectionKey: payload.projectionKey,
    runId: payload.runId,
    runSlug: payload.runSlug,
    kind: payload.kind,
    generation: 1,
    repoPath: "/run/bob-dispatch/repoRun_123456789/target-repo",
  };
  const spec = dockerLaunchSpec(record, "runner@sha256:" + "b".repeat(64), CONTAINER_ENV, {
    PATH: "/usr/bin",
    HOME: "/home/bob",
    DISPATCH_SECRET: SECRET,
  });
  assert.ok(spec.args.includes("--pull=never"));
  assert.ok(spec.args.includes("--read-only"));
  assert.ok(spec.args.includes("--cap-drop=ALL"));
  assert.deepEqual(spec.args.slice(spec.args.indexOf("--security-opt"), spec.args.indexOf("--security-opt") + 2), [
    "--security-opt", "no-new-privileges:true",
  ]);
  assert.deepEqual(spec.args.slice(spec.args.indexOf("--user"), spec.args.indexOf("--user") + 2), [
    "--user", "65532:65532",
  ]);
  assert.ok(spec.args.includes("/workspace:rw,nosuid,nodev,size=1g,uid=65532,gid=65532,mode=0700"));
  assert.ok(spec.args.includes("/tmp:rw,nosuid,nodev,size=512m,uid=65532,gid=65532,mode=1777"));
  assert.ok(spec.args.includes("type=bind,src=/run/bob-dispatch/repoRun_123456789/target-repo,dst=/workspace/target-repo,readonly"));
  assert.doesNotMatch(spec.args.join(" "), new RegExp(`${RUNNER_SECRET}|${DEEPSEEK_SECRET}|${PROJECTION_KEY}|${SECRET}|${payload.accessPassword}`, "u"));
  assert.equal(spec.env.BOB_PROJECTION_KEY, PROJECTION_KEY);
  assert.equal(spec.env.RUNNER_SECRET, RUNNER_SECRET);
  assert.equal(spec.env.DEEPSEEK_API_KEY, DEEPSEEK_SECRET);
  assert.equal(spec.env.DISPATCH_SECRET, undefined);
  const runnerPayload = JSON.parse(spec.env.BOB_PAYLOAD_JSON);
  assert.equal(runnerPayload.projectionKey, undefined);
  assert.equal(runnerPayload.accessPassword, payload.accessPassword);
  assert.equal(runnerPayload.sourceRef, payload.sourceRef);
});

test("service rejects noncanonical or non-TLS runner endpoints before startup", () => {
  const dirs = tempDirs();
  try {
    const invalidEnvironments = [
      { ...CONTAINER_ENV, BOB_PROJECTION_URL: "http://projection.invalid/api/findings" },
      { ...CONTAINER_ENV, BOB_PROJECTION_URL: "https://projection.invalid/api/findings?redirect=1" },
      { ...CONTAINER_ENV, BOB_PROJECTION_URL: "https://projection.invalid/other" },
      { ...CONTAINER_ENV, BOB_CONVEX_URL: "http://convex.invalid" },
      { ...CONTAINER_ENV, BOB_CONVEX_URL: "https://user@convex.invalid" },
      { ...CONTAINER_ENV, BOB_CONVEX_URL: "https://convex.invalid/other" },
    ];
    for (const containerEnv of invalidEnvironments) {
      assert.throws(
        () => createService({
          secret: SECRET,
          ledgerDir: dirs.ledgerDir,
          runsDir: dirs.runsDir,
          logsDir: dirs.logsDir,
          runnerImageUri: "runner-image@sha256:" + "b".repeat(64),
          containerEnv,
          controlPlaneSink: async () => {},
        }),
        /exact HTTPS/u,
      );
    }
  } finally {
    fs.rmSync(dirs.root, { recursive: true, force: true });
  }
});

test("CloudFormation restricts the 2 GiB host to one concurrent runner", () => {
  const template = fs.readFileSync(path.join(__dirname, "..", "..", "template.yaml"), "utf8");
  assert.match(template, /SmallInstanceSingleRun:/u);
  assert.match(template, /RuleCondition: !Equals \[!Ref InstanceType, t4g\.small\]/u);
  assert.match(template, /Assert: !Equals \[!Ref MaxConcurrentRuns, 1\]/u);
});

test("repository preflight verifies the exact commit and seals a runner-readable tree", async (t) => {
  const dirs = tempDirs();
  fs.mkdirSync(dirs.runsDir, { recursive: true });
  const payload = repoPayload();
  const record = { payload, runSlug: payload.runSlug };
  t.after(() => {
    removePreparedRepository(path.join(dirs.runsDir, record.runSlug));
    fs.rmSync(dirs.root, { recursive: true, force: true });
  });
  const calls = [];
  await prepareRepository(record, dirs.runsDir, (command, args, options) => {
    calls.push({ command, args, options });
    if (args[0] === "init") {
      fs.mkdirSync(path.join(args.at(-1), "nested"), { recursive: true });
      fs.writeFileSync(path.join(args.at(-1), "nested", "plain.js"), "plain\n", { mode: 0o600 });
      fs.writeFileSync(path.join(args.at(-1), "run.sh"), "#!/bin/sh\n", { mode: 0o700 });
    }
    return {
      status: 0,
      stdout: args.includes("rev-parse") ? `${payload.sourceRef}\n` : "",
      stderr: "",
    };
  });
  assert.deepEqual(calls.map((call) => call.command), ["git", "git", "git", "git", "git"]);
  assert.ok(calls.some((call) => call.args.includes(payload.target)));
  assert.ok(calls.some((call) => call.args.includes(payload.sourceRef)));
  assert.equal(calls.some((call) => Object.hasOwn(call.options, "shell")), false);
  assert.ok(calls.every((call) => call.options.timeout === 2 * 60 * 1000));
  assert.ok(calls.every((call) => call.options.killSignal === "SIGKILL"));
  assert.equal(fs.statSync(record.runRoot).mode & 0o777, 0o700);
  assert.equal(fs.statSync(record.repoPath).mode & 0o777, 0o555);
  assert.equal(fs.statSync(path.join(record.repoPath, "nested")).mode & 0o777, 0o555);
  assert.equal(fs.statSync(path.join(record.repoPath, "nested", "plain.js")).mode & 0o777, 0o444);
  assert.equal(fs.statSync(path.join(record.repoPath, "run.sh")).mode & 0o777, 0o555);
  assert.equal(record.repoPath, path.join(record.runRoot, "target-repo"));
  removePreparedRepository(record.runRoot);
  assert.equal(fs.existsSync(record.runRoot), false);
});

test("repo preflight completes before spawn and per-run secrets are cleared after exit", async (t) => {
  const order = [];
  const harness = makeHarness(t, {
    prepareRepositoryFn: async (record) => {
      order.push("prepare");
      record.repoPath = `/run/bob-dispatch/${record.runSlug}/target-repo`;
      record.runRoot = `/run/bob-dispatch/${record.runSlug}`;
    },
    cleanupRepositoryFn: async () => { order.push("cleanup"); },
    spawnFn: (record, launch) => {
      order.push("spawn");
      const child = fakeChild();
      harness.spawned.push({ record, launch, child });
      return child;
    },
  });
  accept(harness.service, repoPayload());
  await harness.service.flush();
  assert.deepEqual(order.slice(0, 2), ["prepare", "spawn"]);
  const record = harness.spawned[0].record;
  harness.spawned[0].child.finish(0);
  await harness.service.flush();
  assert.equal(record.projectionKey, undefined);
  assert.equal(record.payload, undefined);
  assert.ok(order.includes("cleanup"));
});

test("streaming logs redact configured and per-run secrets across chunk boundaries", async (t) => {
  const harness = makeHarness(t, { ledgerCompactRows: 3 });
  const payload = validPayload();
  accept(harness.service, payload);
  const child = harness.spawned[0].child;
  child.stdout.write("runner-secret-");
  child.stdout.write("value\n");
  child.stderr.write(`deepseek-${"secret-value"}\n`);
  child.stderr.write(PROJECTION_KEY.slice(0, 20));
  child.stderr.write(`${PROJECTION_KEY.slice(20)}\n`);
  child.stdout.write(`${payload.accessPassword}\n`);
  child.finish(0);
  await harness.service.flush();
  assert.equal(child.stdout.listenerCount("data"), 0);
  assert.equal(child.stderr.listenerCount("data"), 0);
  assert.equal(harness.spawned[0].record.child, undefined);

  const ledgerPath = path.join(harness.dirs.ledgerDir, "dispatch.jsonl");
  const logPath = path.join(harness.dirs.logsDir, `${payload.runId}.log`);
  const ledger = fs.readFileSync(ledgerPath, "utf8");
  const log = fs.readFileSync(logPath, "utf8");
  for (const literal of [SECRET, RUNNER_SECRET, DEEPSEEK_SECRET, PROJECTION_KEY, payload.accessPassword]) {
    assert.doesNotMatch(ledger, new RegExp(literal, "u"));
    assert.doesNotMatch(log, new RegExp(literal, "u"));
  }
  assert.match(log, /\[REDACTED\]/u);
  assert.equal(fs.statSync(ledgerPath).mode & 0o777, 0o600);
  assert.equal(fs.statSync(logPath).mode & 0o777, 0o600);
  const compactedRows = fs.readFileSync(ledgerPath, "utf8").trim().split("\n").map((line) => JSON.parse(line));
  assert.ok(compactedRows.length <= 2);
  assert.deepEqual([...new Set(compactedRows.map((row) => row.idempotencyKey))], [payload.runId]);
});

test("streaming logs preserve longest-match redaction across overlapping secret chunks", async (t) => {
  const overlappingSecret = `${RUNNER_SECRET}-suffix`;
  const harness = makeHarness(t, {
    containerEnv: { ...CONTAINER_ENV, DEEPSEEK_API_KEY: overlappingSecret },
  });
  const payload = validPayload();
  accept(harness.service, payload);
  const child = harness.spawned[0].child;
  child.stdout.write(RUNNER_SECRET);
  child.stdout.write("-suffix\n");
  child.finish(0);
  await harness.service.flush();

  const logPath = path.join(harness.dirs.logsDir, `${payload.runId}.log`);
  assert.equal(fs.readFileSync(logPath, "utf8"), "[REDACTED]\n");
});

test("streaming logs redact a secret split across stdout and stderr", async (t) => {
  const harness = makeHarness(t);
  const payload = validPayload();
  accept(harness.service, payload);
  const child = harness.spawned[0].child;
  const split = Math.floor(RUNNER_SECRET.length / 2);
  child.stdout.write(RUNNER_SECRET.slice(0, split));
  child.stderr.write(`${RUNNER_SECRET.slice(split)}\n`);
  child.finish(0);
  await harness.service.flush();

  const logPath = path.join(harness.dirs.logsDir, `${payload.runId}.log`);
  assert.equal(fs.readFileSync(logPath, "utf8"), "[REDACTED]\n");
});

test("stderr interleaving cannot expose a secret split across stdout chunks", async (t) => {
  const harness = makeHarness(t);
  const payload = validPayload();
  accept(harness.service, payload);
  const child = harness.spawned[0].child;
  const split = Math.floor(RUNNER_SECRET.length / 2);
  child.stdout.write(RUNNER_SECRET.slice(0, split));
  child.stderr.write("stderr between stdout chunks\n");
  child.stdout.write(`${RUNNER_SECRET.slice(split)}\n`);
  child.finish(0);
  await harness.service.flush();

  const logPath = path.join(harness.dirs.logsDir, `${payload.runId}.log`);
  const log = fs.readFileSync(logPath, "utf8");
  assert.doesNotMatch(log, new RegExp(RUNNER_SECRET, "u"));
  assert.match(log, /\[REDACTED\]/u);
  assert.match(log, /stderr between stdout chunks/u);
});

test("runner logs are bounded per run without buffering discarded output", async (t) => {
  const harness = makeHarness(t, { maxLogBytes: 64 });
  const payload = validPayload();
  accept(harness.service, payload);
  const child = harness.spawned[0].child;
  child.stdout.write("x".repeat(1024));
  child.finish(0);
  await harness.service.flush();

  const log = fs.readFileSync(path.join(harness.dirs.logsDir, `${payload.runId}.log`));
  assert.equal(log.length, 64);
  assert.match(log.toString("utf8"), /\[runner log truncated\]\n$/u);
});

test("a log open failure prevents the runner container from starting", async (t) => {
  const harness = makeHarness(t);
  fs.rmSync(harness.dirs.logsDir, { recursive: true, force: true });
  fs.writeFileSync(harness.dirs.logsDir, "not a directory");
  const payload = validPayload();
  accept(harness.service, payload);
  await harness.service.flush();

  assert.equal(harness.spawned.length, 0);
  assert.equal(harness.service.record(payload.runId).status, "failed");
  assert.equal(harness.controlUpdates.at(-1).status, "failed");
});

test("a post-spawn log setup failure kills the runner before recording failure", async (t) => {
  const harness = makeHarness(t);
  const originalFstatSync = fs.fstatSync;
  let failLogStat = true;
  t.mock.method(fs, "fstatSync", (...args) => {
    if (failLogStat) {
      failLogStat = false;
      throw new Error("forced log stat failure");
    }
    return Reflect.apply(originalFstatSync, fs, args);
  });
  const payload = validPayload();
  accept(harness.service, payload);
  await harness.service.flush();

  assert.equal(harness.spawned.length, 1);
  assert.deepEqual(harness.killed, [payload.runId]);
  assert.deepEqual(harness.removals, [payload.runId]);
  assert.equal(harness.service.record(payload.runId).status, "failed");
  assert.equal(harness.controlUpdates.at(-1).status, "failed");
});

test("restart reattaches a matching running container without spawning", async (t) => {

  const dirs = tempDirs();
  const first = makeHarness(t, { dirs, keepDirs: true, now: () => 1000, runTimeoutMs: 1000 });
  const payload = validPayload();
  accept(first.service, payload);
  first.service.close();

  const reattached = fakeChild();
  let spawned = 0;
  let remainingTimeout = null;
  const second = createService({
    secret: SECRET,
    ledgerDir: dirs.ledgerDir,
    runsDir: dirs.runsDir,
    logsDir: dirs.logsDir,
    runnerImageUri: "runner@sha256:" + "b".repeat(64),
    containerEnv: CONTAINER_ENV,
    controlPlaneSink: async () => {},
    inspectContainerFn: () => ({ labels: {} }),
    waitContainerFn: () => reattached,
    spawnFn: () => { spawned += 1; return fakeChild(); },
    now: () => 1600,
    runTimeoutMs: 1000,
    setTimeoutFn: (_callback, milliseconds) => {
      remainingTimeout = milliseconds;
      return fakeInterval();
    },
    clearTimeoutFn: () => {},
    setIntervalFn: fakeInterval,
    clearIntervalFn: () => {},
    delay: async () => {},
  });
  t.after(() => {
    second.close();
    fs.rmSync(dirs.root, { recursive: true, force: true });
  });
  assert.equal(second.snapshot().active, 1);
  assert.equal(spawned, 0);
  assert.equal(remainingTimeout, 400);
  reattached.finish(0);
  await second.flush();
  assert.equal(second.record(payload.runId).status, "succeeded");
  assert.equal(spawned, 0);
});
test("default reattach waits for confirmed container removal before reporting destroyed", async (t) => {
  const dirs = tempDirs();
  const first = makeHarness(t, { dirs, keepDirs: true, now: () => 1000 });
  const payload = validPayload();
  accept(first.service, payload);
  first.service.close();

  const timeline = [];
  const processCalls = [];
  let waitChild = null;
  let removeAttempts = 0;
  let removalTimeout = null;
  let removalKilled = 0;
  const second = createService({
    secret: SECRET,
    ledgerDir: dirs.ledgerDir,
    runsDir: dirs.runsDir,
    logsDir: dirs.logsDir,
    runnerImageUri: "runner@sha256:" + "b".repeat(64),
    containerEnv: CONTAINER_ENV,
    controlPlaneSink: async (update) => {
      timeline.push(`control:${update.status}`);
    },
    spawnFn: () => {
      throw new Error("reconciliation must not spawn a replacement");
    },
    spawnSyncFn: (_command, args) => {
      assert.equal(args[0], "inspect");
      return {
        status: 0,
        stdout: JSON.stringify({
          "bob.dispatch.run-id": payload.runId,
          "bob.dispatch.run-slug": payload.runSlug,
          "bob.dispatch.generation": "1",
        }),
      };
    },
    spawnProcessFn: (_command, args) => {
      processCalls.push(args.slice());
      const child = fakeChild();
      if (args[0] === "wait") {
        waitChild = child;
      } else if (args[0] === "rm") {
        removeAttempts += 1;
        timeline.push(`remove:${removeAttempts}`);
        if (removeAttempts === 1) {
          child.kill = () => {
            removalKilled += 1;
            timeline.push("remove:kill");
            return true;
          };
        } else {
          setImmediate(() => child.finish(0));
        }
      } else {
        throw new Error(`unexpected docker command ${args[0]}`);
      }
      return child;
    },
    now: () => 1600,
    runTimeoutMs: 1000,
    setTimeoutFn: (callback, milliseconds) => {
      if (milliseconds === 15_000) removalTimeout = callback;
      return fakeInterval();
    },
    clearTimeoutFn: () => {},
    setIntervalFn: fakeInterval,
    clearIntervalFn: () => {},
    delay: async () => {},
  });
  t.after(() => {
    second.close();
    fs.rmSync(dirs.root, { recursive: true, force: true });
  });

  assert.ok(waitChild);
  waitChild.stdout.write("0\n");
  waitChild.finish(0);
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(typeof removalTimeout, "function");
  removalTimeout();
  await second.flush();

  assert.deepEqual(processCalls.map((args) => args[0]), ["wait", "rm", "rm"]);
  assert.deepEqual(timeline, ["remove:1", "remove:kill", "remove:2", "control:destroyed"]);
  assert.equal(removalKilled, 1);
  assert.equal(second.record(payload.runId).status, "succeeded");
});

test("restart reserves the live slot and retries an unavailable container inspection", async (t) => {
  const dirs = tempDirs();
  const first = makeHarness(t, { dirs, keepDirs: true, now: () => 1000 });
  const payload = validPayload();
  accept(first.service, payload);
  first.service.close();

  let inspectionAvailable = false;
  let inspectionCalls = 0;
  let waitCalls = 0;
  const reattached = fakeChild();
  const second = createService({
    secret: SECRET,
    ledgerDir: dirs.ledgerDir,
    runsDir: dirs.runsDir,
    logsDir: dirs.logsDir,
    runnerImageUri: "runner@sha256:" + "b".repeat(64),
    containerEnv: CONTAINER_ENV,
    controlPlaneSink: async () => {},
    spawnFn: () => {
      throw new Error("an uncertain container must never spawn a replacement");
    },
    spawnSyncFn: (_command, args) => {
      assert.equal(args[0], "inspect");
      inspectionCalls += 1;
      if (!inspectionAvailable) {
        return { status: 1, stderr: "Cannot connect to the Docker daemon" };
      }
      return {
        status: 0,
        stdout: JSON.stringify({
          "bob.dispatch.run-id": payload.runId,
          "bob.dispatch.run-slug": payload.runSlug,
          "bob.dispatch.generation": "1",
        }),
      };
    },
    waitContainerFn: () => {
      waitCalls += 1;
      return reattached;
    },
    setIntervalFn: fakeInterval,
    clearIntervalFn: () => {},
    delay: async () => {},
  });
  t.after(() => {
    second.close();
    fs.rmSync(dirs.root, { recursive: true, force: true });
  });

  assert.equal(inspectionCalls, 1);
  assert.equal(waitCalls, 0);
  assert.equal(second.snapshot().active, 1);
  assert.equal(second.record(payload.runId).status, "running");
  assert.equal(accept(second, payload).status, 202);

  inspectionAvailable = true;
  await second.retryPending();
  assert.equal(inspectionCalls, 2);
  assert.equal(waitCalls, 1);
  reattached.finish(0);
  await second.flush();
  assert.equal(second.record(payload.runId).status, "succeeded");
});


test("restart marks a missing container interrupted and exact replay spawns generation two once", async (t) => {
  const dirs = tempDirs();
  const first = makeHarness(t, { dirs, keepDirs: true });
  const payload = validPayload();
  accept(first.service, payload);
  first.service.close();

  const spawned = [];
  const second = createService({
    secret: SECRET,
    ledgerDir: dirs.ledgerDir,
    runsDir: dirs.runsDir,
    logsDir: dirs.logsDir,
    runnerImageUri: "runner@sha256:" + "b".repeat(64),
    containerEnv: CONTAINER_ENV,
    controlPlaneSink: async () => {},
    spawnSyncFn: (_command, args) => {
      assert.equal(args[0], "inspect");
      return { status: 1, stderr: "Error: No such object: bob-run-missing" };
    },
    spawnFn: (record, launch) => {
      const child = fakeChild();
      spawned.push({ record, launch, child });
      return child;
    },
    setIntervalFn: fakeInterval,
    clearIntervalFn: () => {},
    delay: async () => {},
  });
  t.after(() => {
    second.close();
    fs.rmSync(dirs.root, { recursive: true, force: true });
  });
  assert.equal(second.record(payload.runId).status, "interrupted");
  const replay = accept(second, payload);
  const duplicate = accept(second, payload);
  assert.equal(replay.status, 202);
  assert.equal(duplicate.status, 202);
  assert.equal(second.record(payload.runId).generation, 2);
  assert.equal(spawned.length, 1);
});

test("timeout records timed_out and sends a failed control-plane witness", async (t) => {
  const harness = makeHarness(t, { runTimeoutMs: 20 });
  const payload = validPayload();
  accept(harness.service, payload);
  await new Promise((resolve) => setTimeout(resolve, 60));
  await harness.service.flush();
  assert.deepEqual(harness.killed, [payload.runId]);
  assert.equal(harness.service.record(payload.runId).status, "timed_out");
  assert.equal(harness.controlUpdates.at(-1).status, "failed");
  assert.equal(harness.controlUpdates.at(-1).event.message, "Runner execution timed out.");
});

test("timeout waits for confirmed container removal before terminal delivery", async (t) => {
  const timers = [];
  let containerKills = 0;
  let clientKills = 0;
  let removalCalls = 0;
  let confirmRemoval;
  const harness = makeHarness(t, {
    runTimeoutMs: 1000,
    setTimeoutFn: (callback, milliseconds) => {
      const timer = { callback, milliseconds, ...fakeInterval() };
      timers.push(timer);
      return timer;
    },
    clearTimeoutFn: () => {},
    killFn: () => {
      containerKills += 1;
    },
    removeContainerFn: () => {
      removalCalls += 1;
      if (removalCalls === 1) return Promise.resolve(false);
      return new Promise((resolve) => {
        confirmRemoval = resolve;
      });
    },
    spawnFn: () => {
      const child = fakeChild();
      child.kill = () => {
        clientKills += 1;
        return true;
      };
      return child;
    },
  });
  const payload = validPayload();
  accept(harness.service, payload);
  timers.find((timer) => timer.milliseconds === 1000).callback();
  assert.equal(containerKills, 1);
  timers.find((timer) => timer.milliseconds === 15_000).callback();
  await new Promise((resolve) => setImmediate(resolve));

  assert.equal(clientKills, 1);
  assert.equal(removalCalls, 2);
  assert.equal(typeof confirmRemoval, "function");
  assert.equal(harness.service.record(payload.runId).status, "running");
  assert.equal(harness.controlUpdates.length, 0);

  confirmRemoval(true);
  await harness.service.flush();
  assert.equal(harness.service.record(payload.runId).status, "timed_out");
  assert.equal(harness.controlUpdates.at(-1).status, "failed");
});

test("control-plane delivery retries, persists a safe pending update, and replays it", async (t) => {
  let failuresRemaining = 7;
  const delivered = [];
  const harness = makeHarness(t, {
    controlPlaneSink: async (update) => {
      if (failuresRemaining > 0) {
        failuresRemaining -= 1;
        throw new Error(`transient ${RUNNER_SECRET}`);
      }
      delivered.push(update);
    },
  });
  const payload = validPayload();
  accept(harness.service, payload);
  await finishAndFlush(harness, 0, 0);
  assert.deepEqual(harness.delays, [1000, 2000, 4000, 8000, 16000, 30000]);
  assert.equal(harness.service.record(payload.runId).controlPlanePending.status, "destroyed");
  const ledger = fs.readFileSync(path.join(harness.dirs.ledgerDir, "dispatch.jsonl"), "utf8");
  assert.doesNotMatch(ledger, new RegExp(`${RUNNER_SECRET}|${DEEPSEEK_SECRET}|${PROJECTION_KEY}`, "u"));
  await harness.service.retryPending();
  await harness.service.flush();
  assert.equal(delivered.length, 1);
  assert.equal(harness.service.record(payload.runId).controlPlanePending, null);
});

test("pending redrive skips a delivery that is already in flight", async (t) => {
  let deliveryCalls = 0;
  let releaseRetryDelay;
  const retryDelay = new Promise((resolve) => {
    releaseRetryDelay = resolve;
  });
  const harness = makeHarness(t, {
    controlPlaneSink: async () => {
      deliveryCalls += 1;
      if (deliveryCalls === 1) throw new Error("transient delivery failure");
    },
    delay: async () => retryDelay,
  });
  const payload = validPayload();
  accept(harness.service, payload);
  harness.spawned[0].child.finish(0);
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(deliveryCalls, 1);

  await harness.service.retryPending();
  assert.equal(deliveryCalls, 1);
  releaseRetryDelay();
  await harness.service.flush();
  assert.equal(deliveryCalls, 2);
  assert.equal(harness.service.record(payload.runId).controlPlanePending, null);
});
test("terminal ledger row contains the pending control update before delivery completes", async (t) => {
  let releaseDelivery;
  const delivery = new Promise((resolve) => {
    releaseDelivery = resolve;
  });
  const harness = makeHarness(t, {
    controlPlaneSink: async () => delivery,
  });
  const payload = validPayload();
  accept(harness.service, payload);
  harness.spawned[0].child.finish(0);
  await new Promise((resolve) => setImmediate(resolve));

  assert.equal(harness.service.record(payload.runId).controlPlanePending.status, "destroyed");
  const ledger = fs
    .readFileSync(path.join(harness.dirs.ledgerDir, "dispatch.jsonl"), "utf8")
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line));
  assert.equal(ledger.at(-1).event, "finished");
  assert.equal(ledger.at(-1).controlPlanePending.status, "destroyed");

  releaseDelivery();
  await harness.service.flush();
  assert.equal(harness.service.record(payload.runId).controlPlanePending, null);
});
test("hung control-plane delivery is bounded and persisted for retry", async (t) => {
  let attempts = 0;
  const harness = makeHarness(t, {
    controlPlaneSink: async () => {
      attempts += 1;
      return new Promise(() => {});
    },
    setTimeoutFn: (callback, milliseconds) => {
      if (milliseconds === 10_000) setImmediate(callback);
      return fakeInterval();
    },
    clearTimeoutFn: () => {},
  });
  const payload = validPayload();
  accept(harness.service, payload);
  await finishAndFlush(harness, 0, 0);

  assert.equal(attempts, 7);
  assert.equal(harness.service.record(payload.runId).status, "succeeded");
  assert.equal(harness.service.record(payload.runId).controlPlanePending.status, "destroyed");
});


test("Convex control-plane sink sends status then a canonical monotonic event", async () => {
  const calls = [];
  const client = {
    async mutation(name, args) {
      calls.push({ type: "mutation", name, args });
      return name === "runs:setStatus"
        ? { runId: "run-id", status: args.status, applied: true }
        : "event-id";
    },
    async query(name, args) {
      calls.push({ type: "query", name, args });
      return [{ seq: 2 }, { seq: 7 }];
    },
  };
  const sink = createConvexControlPlaneSink({
    url: "https://convex.example",
    secret: RUNNER_SECRET,
    clientFactory: () => client,
  });
  const update = {
    runSlug: "runSlug_123456789",
    status: "destroyed",
    phase: "report",
    at: 1770000000000,
    event: { kind: "destroy", register: "breath", phase: "report", message: "Runner container destroyed." },
  };
  await sink(update);
  assert.deepEqual(calls.map((call) => `${call.type}:${call.name}`), [
    "mutation:runs:setStatus",
    "query:runs:events",
    "mutation:runs:appendEvent",
  ]);
  const event = calls[2].args;
  assert.equal(event.seq, 8);
  assert.equal(event.payloadJson, JSON.stringify({ message: "Runner container destroyed." }));
  assert.equal(
    event.eventHash,
    canonicalEventHash(update.runSlug, update.event.kind, update.event.phase, update.event.message),
  );
});

test("Convex control-plane sink ignores malformed event sequence rows", async () => {
  let appendedSequence = null;
  const client = {
    async mutation(name, args) {
      if (name === "runs:setStatus") {
        return { runId: "run-id", status: args.status, applied: true };
      }
      appendedSequence = args.seq;
      return "event-id";
    },
    async query() {
      return [{ seq: "poison" }, { seq: Number.NaN }, { seq: -1 }, { seq: 7 }];
    },
  };
  const sink = createConvexControlPlaneSink({
    url: "https://convex.example",
    secret: RUNNER_SECRET,
    clientFactory: () => client,
  });
  await sink({
    runSlug: "runSlug_123456789",
    status: "destroyed",
    phase: "report",
    at: 1770000000000,
    event: { kind: "destroy", register: "breath", phase: "report", message: "Runner container destroyed." },
  });
  assert.equal(appendedSequence, 8);
});

test("Convex control-plane sink retries a concurrent sequence collision idempotently", async () => {
  const eventHash = canonicalEventHash(
    "runSlug_123456789",
    "destroy",
    "report",
    "Runner container destroyed.",
  );
  let queryCount = 0;
  const appendSequences = [];
  const client = {
    async mutation(name, args) {
      if (name === "runs:setStatus") {
        return { runId: "run-id", status: args.status, applied: true };
      }
      appendSequences.push(args.seq);
      if (appendSequences.length === 1) throw new Error("sequence already exists");
      return "event-id";
    },
    async query() {
      queryCount += 1;
      return queryCount === 1
        ? [{ seq: 7 }]
        : [{ seq: 7 }, { seq: 8, eventHash: "f".repeat(64) }];
    },
  };
  const sink = createConvexControlPlaneSink({
    url: "https://convex.example",
    secret: RUNNER_SECRET,
    clientFactory: () => client,
  });
  await sink({
    runSlug: "runSlug_123456789",
    status: "destroyed",
    phase: "report",
    at: 1770000000000,
    event: { kind: "destroy", register: "breath", phase: "report", message: "Runner container destroyed." },
  });
  assert.deepEqual(appendSequences, [8, 9]);
  assert.equal(queryCount, 2);
  assert.match(eventHash, /^[0-9a-f]{64}$/u);
});

test("Convex control-plane sink completes host teardown after a committed seal", async () => {
  const calls = [];
  const client = {
    async mutation(name, args) {
      calls.push({ type: "mutation", name, args });
      if (name === "runs:setStatus") {
        return args.status === "failed"
          ? { runId: "run-id", status: "sealed", applied: false }
          : { runId: "run-id", status: "destroyed", applied: true };
      }
      return "event-id";
    },
    async query(name, args) {
      calls.push({ type: "query", name, args });
      return [];
    },
  };
  const sink = createConvexControlPlaneSink({
    url: "https://convex.example",
    secret: RUNNER_SECRET,
    clientFactory: () => client,
  });
  await sink({
    runSlug: "runSlug_123456789",
    status: "failed",
    phase: "report",
    at: 1770000000000,
    event: { kind: "wait", register: "body", phase: "report", message: "Runner execution failed." },
  });
  assert.deepEqual(calls.map((call) => `${call.type}:${call.name}`), [
    "mutation:runs:setStatus",
    "mutation:runs:setStatus",
    "query:runs:events",
    "mutation:runs:appendEvent",
  ]);
  assert.deepEqual(calls[1].args, {
    secret: RUNNER_SECRET,
    slug: "runSlug_123456789",
    status: "destroyed",
    phase: "report",
    destroyedAt: 1770000000000,
  });
  assert.equal(calls[3].args.kind, "destroy");
  assert.equal(calls[3].args.payloadJson, JSON.stringify({ message: "Runner container destroyed." }));
});
test("Convex control-plane sink rejects an unexpected live status mismatch", async () => {
  const calls = [];
  const client = {
    async mutation(name, args) {
      calls.push({ type: "mutation", name, args });
      return { runId: "run-id", status: "running", applied: false };
    },
    async query(name, args) {
      calls.push({ type: "query", name, args });
      return [];
    },
  };
  const sink = createConvexControlPlaneSink({
    url: "https://convex.example",
    secret: RUNNER_SECRET,
    clientFactory: () => client,
  });
  await assert.rejects(
    sink({
      runSlug: "runSlug_123456789",
      status: "destroyed",
      phase: "report",
      at: 1770000000000,
      event: {
        kind: "destroy",
        register: "breath",
        phase: "report",
        message: "Runner container destroyed.",
      },
    }),
    /rejected destroyed transition from running/u,
  );
  assert.deepEqual(calls.map((call) => `${call.type}:${call.name}`), [
    "mutation:runs:setStatus",
  ]);
});

test("Convex control-plane sink rejects credential-bearing and non-TLS origins", () => {
  for (const url of [
    "http://convex.example",
    "https://runner@convex.example",
    "https://convex.example/other",
    "https://convex.example?redirect=1",
  ]) {
    assert.throws(
      () => createConvexControlPlaneSink({
        url,
        secret: RUNNER_SECRET,
        clientFactory: () => ({}),
      }),
      /exact HTTPS origin/u,
    );
  }
});

test("HTTP body reader enforces the 32 KiB raw-body cap", async () => {
  const request = new PassThrough();
  request.headers = {};
  const result = readJsonBody(request);
  request.end(Buffer.alloc(32 * 1024 + 1, 0x61));
  await assert.rejects(result, (error) => error.status === 413 && error.code === "payload_too_large");
});

test("HTTP boundary is minimal, non-cacheable, bounded, and contains service failures", async (t) => {
  const server = createHttpServer({
    snapshot() {
      throw new Error("health must not expose service state");
    },
    accept() {
      throw new Error(`disk failure ${RUNNER_SECRET}`);
    },
  });
  assert.equal(server.requestTimeout, 15_000);
  assert.equal(server.headersTimeout, 10_000);
  assert.equal(server.keepAliveTimeout, 5_000);
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  t.after(async () => {
    await new Promise((resolve) => server.close(resolve));
  });
  const address = server.address();
  const origin = `http://127.0.0.1:${address.port}`;

  const health = await fetch(`${origin}/health`);
  assert.equal(health.status, 200);
  assert.deepEqual(await health.json(), { status: "ok" });
  assert.equal(health.headers.get("cache-control"), "no-store");
  assert.equal(health.headers.get("x-content-type-options"), "nosniff");

  const failed = await fetch(`${origin}/dispatch`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${SECRET}`,
      "Content-Type": "application/json",
      "Idempotency-Key": "run_1234567890",
    },
    body: "{}",
  });
  assert.equal(failed.status, 503);
  const body = await failed.text();
  assert.equal(body, JSON.stringify({
    error: "dispatch service unavailable",
    code: "service_unavailable",
  }));
  assert.doesNotMatch(body, new RegExp(RUNNER_SECRET, "u"));
  assert.equal(failed.headers.get("cache-control"), "no-store");
});
