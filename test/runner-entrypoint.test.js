"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { EventEmitter } = require("node:events");

const TEST_SESSIONS_ROOT = fs.mkdtempSync(path.join(os.tmpdir(), "bob-runner-entrypoint-suite-"));
process.env.BOB_SESSIONS_ROOT = TEST_SESSIONS_ROOT;
const { PassThrough } = require("node:stream");

const entrypoint = require("../infra/runner/entrypoint.js");
const {
  writeFinalizationReceipt,
} = require("../mcp/finalization-receipt.js");

test.after(() => {
  fs.rmSync(TEST_SESSIONS_ROOT, { recursive: true, force: true });
});

const CORE_ROOT = path.resolve(__dirname, "..");
const ENVIRONMENT_KEYS = [
  "BOB_PAYLOAD_JSON",
  "BOB_PAYLOAD_PATH",
  "BOB_SESSIONS_ROOT",
  "BOB_ENGINE_ROOT",
  "BOB_CONVEX_URL",
  "BOB_RUN_SLUG",
  "BOB_RUN_KIND",
  "BOB_RETEST_OF",
  "BOB_REPORT_SLUG",
  "BOB_PROJECTION_URL",
  "BOB_PROJECTION_KEY",
  "RUNNER_SECRET",
  "DEEPSEEK_API_KEY",

];

function payload(overrides = {}) {
  return {
    schemaVersion: 1,
    assessmentId: "assessment-1",
    runId: "run-id-1234",
    runSlug: "runner-slug-1234",
    target: "https://example.com",
    targetDomain: "example.com",
    targetKind: "web",
    runMode: "standard",
    autonomy: "operator-approved",
    objective: "Review the authorized production attack surface",
    kind: "assessment",
    retestOf: [],
    ...overrides,
  };
}

async function withRunnerEnvironment(runPayload, fn) {
  const previous = Object.fromEntries(ENVIRONMENT_KEYS.map((key) => [key, process.env[key]]));
  const sessionsRoot = TEST_SESSIONS_ROOT;
  const sessionDirectory = path.join(sessionsRoot, runPayload.targetDomain);
  fs.rmSync(sessionDirectory, { recursive: true, force: true });
  const values = {
    BOB_PAYLOAD_JSON: JSON.stringify(runPayload),
    BOB_PAYLOAD_PATH: undefined,
    BOB_SESSIONS_ROOT: sessionsRoot,
    BOB_ENGINE_ROOT: CORE_ROOT,
    BOB_CONVEX_URL: "https://convex.example",
    BOB_RUN_SLUG: runPayload.runSlug,
    BOB_RUN_KIND: runPayload.kind,
    BOB_RETEST_OF: runPayload.retestOf.join(","),
    BOB_REPORT_SLUG: `${runPayload.runSlug}-report`,
    BOB_PROJECTION_URL: "https://projection.example/api/findings",
    BOB_PROJECTION_KEY: "P".repeat(43),
    RUNNER_SECRET: "runner-secret-value",
    DEEPSEEK_API_KEY: "deepseek-secret-value",
  };
  for (const [key, value] of Object.entries(values)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  fs.mkdirSync(sessionDirectory, { recursive: true });
  try {
    return await fn({ sessionsRoot });
  } finally {
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    fs.rmSync(sessionDirectory, { recursive: true, force: true });
  }
}

function writeCleanReceipt(runPayload) {
  const reportContent = "# Final report\n";
  fs.writeFileSync(
    path.join(TEST_SESSIONS_ROOT, runPayload.targetDomain, "report.md"),
    reportContent,
  );
  const reportContentHash = crypto.createHash("sha256").update(reportContent).digest("hex");
  return writeFinalizationReceipt(runPayload.targetDomain, {
    schemaVersion: 1,
    runSlug: runPayload.runSlug,
    targetDomain: runPayload.targetDomain,
    reportSlug: `${runPayload.runSlug}-report`,
    completedAt: "2026-08-25T12:00:00.000Z",
    freezeHash: "a".repeat(64),
    snapshotHash: "b".repeat(64),
    evidenceHash: "c".repeat(64),
    reportContentHash,
    artifact: {
      emitted: false,
      sha256: null,
      findingCount: 0,
    },
    projection: {
      required: true,
      succeeded: true,
      duplicate: false,
      projected: 0,
      reopened: 0,
      closed: 0,
    },
    consoleReport: {
      schemaVersion: 1,
      domain: runPayload.targetDomain,
      findings: [],
    },
  });
}

function fakeChild({ code = 0, stdout = "", stderr = "", beforeClose = null } = {}) {
  const child = new EventEmitter();
  child.stdout = new PassThrough();
  child.stderr = new PassThrough();
  setImmediate(() => {
    if (stdout) child.stdout.write(stdout);
    if (stderr) child.stderr.write(stderr);
    child.stdout.end();
    child.stderr.end();
    if (beforeClose) beforeClose();
    child.emit("close", code, null);
  });
  return child;
}

function recordingClient({ fail = null, events = [], closeError = null } = {}) {
  const calls = [];
  const queries = [];
  let closed = false;
  return {
    calls,
    queries,
    get closed() {
      return closed;
    },
    async query(name, args) {
      queries.push({ name, args });
      await new Promise((resolve) => setImmediate(resolve));
      if (fail && fail(name, args)) throw new Error(`forced ${name} failure`);
      if (name === "runs:events") return events;
      throw new Error(`unexpected query ${name}`);
    },
    async mutation(name, args) {
      calls.push({ name, args });
      await new Promise((resolve) => setImmediate(resolve));
      if (fail && fail(name, args)) throw new Error(`forced ${name} failure`);
      if (name === "reports:completeHostedRun") {
        return { status: "created", slug: `${args.runSlug}-report` };
      }
      if (name === "runs:setStatus") {
        return { runId: "run-id", status: args.status, applied: true };
      }
      return "id";
    },
    async close() {
      await new Promise((resolve) => setImmediate(resolve));
      closed = true;
      if (closeError) throw closeError;
    },
  };
}

function immediateDelay() {
  return new Promise((resolve) => setImmediate(resolve));
}

test("payload parsing rejects secrets and ignores the retired payload path", () => {
  const candidate = payload();
  process.env.BOB_PAYLOAD_PATH = "/tmp/retired-payload.json";
  assert.deepEqual(entrypoint.parsePayloadJson(JSON.stringify(candidate)), candidate);
  assert.throws(
    () => entrypoint.parsePayloadJson(JSON.stringify({ ...candidate, projectionKey: "secret" })),
    /unsupported field: projectionKey/,
  );
  assert.throws(() => entrypoint.parsePayloadJson(undefined), /BOB_PAYLOAD_JSON is required/);
  assert.throws(
    () => entrypoint.parsePayloadJson(JSON.stringify({ ...candidate, targetDomain: "other.example" })),
    /match targetDomain/,
  );
  assert.throws(
    () => entrypoint.parsePayloadJson(JSON.stringify({ ...candidate, sourceRef: "0".repeat(40) })),
    /only allowed for repo/,
  );
  const repo = {
    ...candidate,
    target: "https://github.com/acme/api.git",
    targetDomain: "repo-api-353c2715",
    targetKind: "repo",
    sourceRef: "0123456789abcdef0123456789abcdef01234567",
  };
  assert.deepEqual(entrypoint.parsePayloadJson(JSON.stringify(repo)), repo);
  assert.throws(
    () => entrypoint.parsePayloadJson(JSON.stringify({ ...repo, target: "https://gitlab.com/acme/api.git" })),
    /canonical GitHub clone URL/,
  );
  assert.throws(
    () => entrypoint.parsePayloadJson(JSON.stringify({ ...repo, targetDomain: "repo-api-deadbeef" })),
    /canonical selector/,
  );
  const contract = {
    ...candidate,
    target: "eip155:1:0x1234567890abcdef1234567890abcdef12345678",
    targetDomain: "sc-evm-1-12345678-424e3135",
    targetKind: "contract",
  };
  assert.deepEqual(entrypoint.parsePayloadJson(JSON.stringify(contract)), contract);
  assert.throws(
    () => entrypoint.parsePayloadJson(JSON.stringify({ ...contract, targetDomain: "sc-evm-1-deadbeef-deadbeef" })),
    /canonical selector/,
  );
  delete process.env.BOB_PAYLOAD_PATH;
});

test("taskFor makes the kind-specific initializer the exact first Bob call", () => {
  const web = entrypoint.initialToolCall(payload());
  assert.deepEqual(web, {
    name: "bob_init_session",
    args: {
      target_domain: "example.com",
      target_url: "https://example.com",
      deep_mode: false,
    },
  });

  const repoPayload = payload({
    target: "https://github.com/acme/api.git",
    targetDomain: "repo-api-353c2715",
    targetKind: "repo",
    sourceRef: "0123456789abcdef0123456789abcdef01234567",
  });
  assert.deepEqual(entrypoint.initialToolCall(repoPayload), {
    name: "bob_init_repo_session",
    args: {
      repo_path: "/workspace/target-repo",
      target_domain: "repo-api-353c2715",
      source_url: "https://github.com/acme/api.git",
      commit: "0123456789abcdef0123456789abcdef01234567",
      deep_mode: false,
    },
  });

  const contractPayload = payload({
    target: "eip155:1:0x1234567890abcdef1234567890abcdef12345678",
    targetDomain: "sc-evm-1-12345678-424e3135",
    targetKind: "contract",
  });
  assert.deepEqual(entrypoint.initialToolCall(contractPayload), {
    name: "bob_init_contract_session",
    args: {
      contracts: [{
        chain_family: "evm",
        chain_id: "1",
        address: "0x1234567890abcdef1234567890abcdef12345678",
      }],
      deep_mode: false,
    },
  });
  const task = entrypoint.taskFor(contractPayload);
  assert.match(task, /^Run one authorized automated Hacker Bob assessment\.\nYour first action MUST be the Bob MCP call bob_init_contract_session/);
  assert.match(task, /target_domain exactly "sc-evm-1-12345678-424e3135"/);
});

test("spawned runner streams output, polls asynchronously, and bounds its stderr tail", async () => {
  const stdoutWrites = [];
  const stderrWrites = [];
  const child = fakeChild({ stdout: "runner output", stderr: "x".repeat(4096) });
  let polls = 0;
  const poll = async () => {
    polls += 1;
  };
  poll.delay = immediateDelay;
  const result = await entrypoint.runSpawnedRunner(child, poll, {
    stdout: { write: (chunk) => stdoutWrites.push(Buffer.from(chunk)) },
    stderr: { write: (chunk) => stderrWrites.push(Buffer.from(chunk)) },
  });
  assert.equal(result.code, 0);
  assert.equal(Buffer.byteLength(result.stderrTail), 2048);
  assert.ok(polls >= 2);
  assert.equal(Buffer.concat(stdoutWrites).toString("utf8"), "runner output");
  assert.equal(Buffer.concat(stderrWrites).length, 4096);
});
test("a lifecycle polling failure terminates the still-running Codex child", async () => {
  const child = fakeChild();
  let killedWith = null;
  child.kill = (signal) => {
    killedWith = signal;
    child.finish(143);
    return true;
  };
  const poll = async () => {
    throw new Error("control plane unavailable");
  };
  poll.delay = immediateDelay;

  await assert.rejects(
    () => entrypoint.runSpawnedRunner(child, poll),
    /control plane unavailable/,
  );
  assert.equal(killedWith, "SIGKILL");
});


test("main awaits the observable lifecycle, verifies the receipt, and completes atomically", async (t) => {
  const runPayload = payload();
  await withRunnerEnvironment(runPayload, async ({ sessionsRoot }) => {
    writeCleanReceipt(runPayload);
    fs.writeFileSync(
      path.join(sessionsRoot, runPayload.targetDomain, "state.json"),
      `${JSON.stringify({ lifecycle_state: "REPORT" })}\n`,
    );
    const client = recordingClient();
    let spawnInvocation = null;
    let now = Date.UTC(2026, 7, 25, 12);
    t.mock.method(console, "log", () => {});
    t.mock.method(console, "error", () => {});

    const code = await entrypoint.main({
      clientFactory: async () => client,
      spawnFactory: (command, args, options) => {
        spawnInvocation = { command, args, options };
        return fakeChild();
      },
      clock: () => ++now,
      delay: immediateDelay,
    });

    assert.equal(code, 0);
    assert.equal(client.closed, true);
    assert.equal(spawnInvocation.command, "node");
    assert.equal(spawnInvocation.options.env.CODEX_HOME, "/opt/codex-home");
    assert.equal(spawnInvocation.options.stdio[1], "pipe");
    assert.deepEqual(Object.keys(spawnInvocation.options.env).sort(), [
      "BOB_PROJECTION_KEY",
      "BOB_PROJECTION_URL",
      "BOB_REPORT_SLUG",
      "BOB_RETEST_OF",
      "BOB_RUN_KIND",
      "BOB_RUN_SLUG",
      "BOB_SESSIONS_ROOT",
      "CODEX_HOME",
      "DEEPSEEK_API_KEY",
      "HOME",
      "PATH",
      "RUNNER_SECRET",
    ]);
    assert.equal(spawnInvocation.options.env.BOB_CONVEX_URL, undefined);
    assert.equal(spawnInvocation.options.env.BOB_PAYLOAD_JSON, undefined);
    assert.equal(spawnInvocation.args[0], "/opt/codex-home/run-codex.js");
    assert.match(spawnInvocation.args[1], /first action MUST be the Bob MCP call bob_init_session/);
    assert.deepEqual(client.queries, [{
      name: "runs:events",
      args: { slug: runPayload.runSlug },
    }]);
    const mutationNames = client.calls.map((call) => call.name);
    assert.deepEqual(mutationNames, [
      "runs:setStatus",
      "runs:setStatus",
      "runs:appendEvent",
      "runs:appendEvent",
      "runs:appendEvent",
      "runs:appendEvent",
      "runs:appendEvent",
      "runs:appendEvent",
      "runs:setStatus",
      "runs:appendEvent",
      "reports:completeHostedRun",
    ]);
    const statuses = client.calls
      .filter((call) => call.name === "runs:setStatus")
      .map((call) => call.args.status);
    assert.deepEqual(statuses, ["provisioning", "running", "sealing"]);
    assert.equal(statuses.includes("destroyed"), false);
    const events = client.calls.filter((call) => call.name === "runs:appendEvent").map((call) => call.args);
    assert.deepEqual(events.map((event) => event.seq), [1, 2, 3, 4, 5, 6, 7]);
    assert.deepEqual(events.map((event) => event.phase), [
      "setup",
      "open frontier",
      "claim freeze",
      "verify",
      "grade",
      "report",
      "report",
    ]);
    for (const event of events) {
      assert.match(event.eventHash, /^[0-9a-f]{64}$/);
      assert.deepEqual(Object.keys(JSON.parse(event.payloadJson)), ["message"]);
      assert.doesNotMatch(event.payloadJson, /example\.com|secret|token|key/i);
    }
    const completion = client.calls.find((call) => call.name === "reports:completeHostedRun").args;
    assert.equal(completion.secret, "runner-secret-value");
    assert.equal(completion.runSlug, runPayload.runSlug);
    assert.deepEqual(JSON.parse(completion.modelJson), {
      schemaVersion: 1,
      domain: runPayload.targetDomain,
      findings: [],
    });
    assert.equal(completion.freezeHash, "a".repeat(64));
    assert.match(completion.accessHash, /^[0-9a-f]{64}$/);
    assert.match(completion.accessSalt, /^[0-9a-f]{32}$/);
    assert.equal(completion.accessIter, 100000);
  });
});

test("hosted completion conflict marks the sealing run failed and closes", async (t) => {
  const runPayload = payload({ runSlug: "runner-completion-conflict" });
  await withRunnerEnvironment(runPayload, async ({ sessionsRoot }) => {
    writeCleanReceipt(runPayload);
    fs.writeFileSync(
      path.join(sessionsRoot, runPayload.targetDomain, "state.json"),
      `${JSON.stringify({ lifecycle_state: "REPORT" })}\n`,
    );
    const client = recordingClient({
      fail: (name) => name === "reports:completeHostedRun",
    });
    const errors = [];
    t.mock.method(console, "log", () => {});
    t.mock.method(console, "error", (message) => {
      errors.push(String(message));
    });

    const code = await entrypoint.main({
      clientFactory: async () => client,
      spawnFactory: () => fakeChild(),
      clock: () => Date.UTC(2026, 7, 25, 12),
      delay: immediateDelay,
    });

    assert.equal(code, 1);
    assert.equal(client.closed, true);
    assert.deepEqual(
      client.calls.filter((call) => call.name === "runs:setStatus").map((call) => call.args.status),
      ["provisioning", "running", "sealing", "failed"],
    );
    assert.equal(
      client.calls.filter((call) => call.name === "reports:completeHostedRun").length,
      1,
    );
    assert.equal(
      client.calls.filter((call) => call.name === "runs:appendEvent").at(-1).args.payloadJson,
      JSON.stringify({ message: "Runner execution failed." }),
    );
    assert.match(errors.at(-1), /reports:completeHostedRun/);
  });
});

test("replay resumes event sequence and committed completion survives client-close failure", async (t) => {
  const runPayload = payload({ runSlug: "runner-replay-events" });
  await withRunnerEnvironment(runPayload, async ({ sessionsRoot }) => {
    writeCleanReceipt(runPayload);
    fs.writeFileSync(
      path.join(sessionsRoot, runPayload.targetDomain, "state.json"),
      `${JSON.stringify({ lifecycle_state: "REPORT" })}\n`,
    );
    const client = recordingClient({
      events: [{ seq: 7, phase: "verify" }],
      closeError: new Error("forced close failure"),
    });
    const errors = [];
    let now = Date.UTC(2026, 7, 25, 12);
    t.mock.method(console, "log", () => {});
    t.mock.method(console, "error", (message) => errors.push(String(message)));

    const code = await entrypoint.main({
      clientFactory: async () => client,
      spawnFactory: () => fakeChild(),
      clock: () => ++now,
      delay: immediateDelay,
    });

    assert.equal(code, 0);
    assert.equal(client.closed, true);
    assert.deepEqual(
      client.calls
        .filter((call) => call.name === "runs:appendEvent")
        .map((call) => call.args.seq),
      [8, 9, 10],
    );
    assert.equal(
      client.calls.some((call) => call.name === "runs:setStatus" && call.args.status === "failed"),
      false,
    );
    assert.equal(client.calls.some((call) => call.name === "reports:completeHostedRun"), true);
    assert.match(errors.at(-1), /client close failed/);
  });
});


test("receipt verification accepts an emitted info artifact with no projected console findings", async () => {
  const runPayload = payload({ runSlug: "runner-emitted-artifact" });
  await withRunnerEnvironment(runPayload, async ({ sessionsRoot }) => {
    const directory = path.join(sessionsRoot, runPayload.targetDomain);
    const artifactPath = path.join(directory, "finding-artifact.json");
    const sidecarPath = path.join(directory, "finding-artifact.sha256");
    const reportPath = path.join(directory, "report.md");
    const reportContent = "# Final info-only report\n";
    fs.writeFileSync(reportPath, reportContent);
    const reportContentHash = crypto.createHash("sha256").update(reportContent).digest("hex");
    const artifactContent = `${JSON.stringify({
      schemaVersion: 1,
      findings: [{ ref_id: "F-1", severity: "info" }],
    }, null, 2)}\n`;
    const artifactHash = crypto.createHash("sha256").update(artifactContent).digest("hex");
    fs.writeFileSync(artifactPath, artifactContent);
    fs.writeFileSync(sidecarPath, `${artifactHash}  finding-artifact.json\n`);
    writeFinalizationReceipt(runPayload.targetDomain, {
      schemaVersion: 1,
      runSlug: runPayload.runSlug,
      targetDomain: runPayload.targetDomain,
      reportSlug: `${runPayload.runSlug}-report`,
      completedAt: "2026-08-25T12:00:00.000Z",
      freezeHash: "a".repeat(64),
      snapshotHash: "b".repeat(64),
      evidenceHash: "c".repeat(64),
      reportContentHash,
      artifact: {
        emitted: true,
        sha256: artifactHash,
        findingCount: 1,
      },
      projection: {
        required: true,
        succeeded: true,
        duplicate: false,
        projected: 0,
        reopened: 0,
        closed: 0,
      },
      consoleReport: {
        schemaVersion: 1,
        domain: runPayload.targetDomain,
        findings: [],
      },
    });

    const receipt = entrypoint.verifyFinalizationReceipt(runPayload);
    assert.equal(receipt.artifact.sha256, artifactHash);
    fs.appendFileSync(reportPath, "tampered\n");
    assert.throws(
      () => entrypoint.verifyFinalizationReceipt(runPayload),
      /finalized report hash does not match receipt/,
    );
    fs.writeFileSync(reportPath, reportContent);
    fs.rmSync(artifactPath);
    assert.throws(
      () => entrypoint.verifyFinalizationReceipt(runPayload),
      /emitted finding artifact or sidecar is missing/,
    );
  });
});

test("missing receipt fails before sealing, emits one fixed failure event, and closes the client", async (t) => {
  const runPayload = payload({ runSlug: "runner-missing-receipt" });
  await withRunnerEnvironment(runPayload, async () => {
    const client = recordingClient();
    const errors = [];
    t.mock.method(console, "log", () => {});
    t.mock.method(console, "error", (message) => {
      errors.push(String(message));
    });
    const code = await entrypoint.main({
      clientFactory: async () => client,
      spawnFactory: () => fakeChild(),
      clock: () => Date.UTC(2026, 7, 25, 12),
      delay: immediateDelay,
    });

    assert.equal(code, 1);
    assert.equal(client.closed, true);
    const statuses = client.calls
      .filter((call) => call.name === "runs:setStatus")
      .map((call) => call.args.status);
    assert.deepEqual(statuses, ["provisioning", "running", "failed"]);
    assert.equal(client.calls.some((call) => call.name === "reports:completeHostedRun"), false);
    const events = client.calls.filter((call) => call.name === "runs:appendEvent");
    assert.equal(events.length, 1);
    assert.equal(events[0].args.payloadJson, JSON.stringify({ message: "Runner execution failed." }));
    assert.equal(errors.length, 1);
    assert.doesNotMatch(errors[0], /runner-secret-value|projection-key-value|deepseek-secret-value/);
  });
});

test("awaited mutation failure marks the run failed without spawning and still closes", async (t) => {
  const runPayload = payload({ runSlug: "runner-status-failure" });
  await withRunnerEnvironment(runPayload, async () => {
    const client = recordingClient({
      fail: (name, args) => name === "runs:setStatus" && args.status === "running",
    });
    let spawned = false;
    t.mock.method(console, "error", () => {});
    const code = await entrypoint.main({
      clientFactory: async () => client,
      spawnFactory: () => {
        spawned = true;
        return fakeChild();
      },
      clock: () => Date.UTC(2026, 7, 25, 12),
      delay: immediateDelay,
    });
    assert.equal(code, 1);
    assert.equal(spawned, false);
    assert.equal(client.closed, true);
    assert.deepEqual(
      client.calls.filter((call) => call.name === "runs:setStatus").map((call) => call.args.status),
      ["provisioning", "running", "failed"],
    );
  });
});
