"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  runOffensiveTool,
  assertToolArgvAllowed,
  scrubbedDockerEnv,
  offensiveRunCount,
  MAX_OFFENSIVE_RUNS,
} = require("../mcp/lib/offensive-runner.js");
const { initSession } = require("../mcp/lib/session-state.js");
const { auditConfirmRequest } = require("../mcp/lib/offensive-http-common.js");

const DIGEST = "ghcr.io/bobnetsec/bob-offense@sha256:" + "b".repeat(64);

function withTempHome(fn) {
  const prev = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-offrunner-"));
  process.env.HOME = home;
  return Promise.resolve().then(() => fn(home)).finally(() => {
    if (prev === undefined) delete process.env.HOME; else process.env.HOME = prev;
    fs.rmSync(home, { recursive: true, force: true });
  });
}

function setup(domain) {
  JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}/` }));
}

function makeStubDocker({ runResult, writeStdout = "ok", writeStderr = "" } = {}) {
  const calls = { sweep: 0, networkCreate: [], networkRm: [], kill: [], run: [] };
  return {
    calls,
    sweep() { calls.sweep += 1; },
    networkCreate(name) { calls.networkCreate.push(name); },
    networkRm(name) { calls.networkRm.push(name); },
    kill(name) { calls.kill.push(name); },
    async run({ args, env, stdoutPath, stderrPath, containerName }) {
      calls.run.push({ args, env, containerName });
      fs.writeFileSync(stdoutPath, writeStdout);
      fs.writeFileSync(stderrPath, writeStderr);
      return runResult || { exit_code: 0, timed_out: false, out_bytes: Buffer.byteLength(writeStdout), err_bytes: Buffer.byteLength(writeStderr) };
    },
  };
}

const baseRun = (domain, overrides = {}) => ({
  domain,
  toolId: "bob_offensive_test",
  imageDigest: DIGEST,
  toolArgv: ["httpx", "-silent", "-u", `https://${domain}/`],
  flagAllowlist: ["-silent", "-u"],
  scopeUrlArgs: [`https://${domain}/`],
  ...overrides,
});

// ───────────────────────── pure helpers ─────────────────────────

test("scrubbedDockerEnv drops DOCKER_HOST/*_PROXY, keeps only PATH/HOME/DOCKER_CONFIG (F2)", () => {
  const env = scrubbedDockerEnv("/tmp/cfg");
  assert.deepEqual(Object.keys(env).sort(), ["DOCKER_CONFIG", "HOME", "PATH"]);
  assert.equal(env.DOCKER_CONFIG, "/tmp/cfg");
  assert.equal(env.DOCKER_HOST, undefined);
  assert.equal(env.HTTPS_PROXY, undefined);
});

test("assertToolArgvAllowed: fail-closed flag allowlist (F9)", () => {
  assert.doesNotThrow(() => assertToolArgvAllowed(["httpx", "-silent", "-u", "https://x"], new Set(["-silent", "-u"])));
  assert.throws(() => assertToolArgvAllowed(["httpx", "-exec", "id"], new Set(["-silent"])), /not in the tool flag allowlist/);
  assert.throws(() => assertToolArgvAllowed(["httpx", "--", "x"], new Set(["-silent"])), /pass-through separator/);
  assert.throws(() => assertToolArgvAllowed(["httpx", "roguebare"], new Set(["-silent"])), /not permitted/);
  assert.doesNotThrow(() => assertToolArgvAllowed(["httpx", "-u=https://x"], new Set(["-u"])));
});

// ───────────────────────── safety gates (no docker reached) ─────────────────────────

test("scope-gate: an out-of-scope URL arg is rejected BEFORE any docker call", () => withTempHome(async () => {
  const domain = "runner-scope.example.test";
  setup(domain);
  const docker = makeStubDocker();
  await assert.rejects(
    runOffensiveTool(baseRun(domain, { scopeUrlArgs: ["https://evil.example.com/"], docker })),
    (e) => /scope|blocked/i.test(e.message) || e.code === "SCOPE_BLOCKED" || e.scope_decision === "blocked",
  );
  assert.equal(docker.calls.run.length, 0, "docker must not be invoked on an out-of-scope target");
}));

test("flag allowlist: an unlisted flag blocks the run before docker", () => withTempHome(async () => {
  const domain = "runner-flag.example.test";
  setup(domain);
  const docker = makeStubDocker();
  await assert.rejects(
    runOffensiveTool(baseRun(domain, { toolArgv: ["httpx", "-exec", "id"], flagAllowlist: ["-silent"], docker })),
    /not in the tool flag allowlist/,
  );
  assert.equal(docker.calls.run.length, 0);
}));

test("run budget: fail-closed at MAX_OFFENSIVE_RUNS, docker not invoked (F3)", () => withTempHome(async () => {
  const domain = "runner-budget.example.test";
  setup(domain);
  for (let i = 0; i < MAX_OFFENSIVE_RUNS; i += 1) {
    auditConfirmRequest({ domain, surfaceId: null, method: "CONTAINER_RUN", url: `https://${domain}/`, status: null, scopeDecision: "allowed", startedAt: Date.now(), toolId: "bob_offensive_test" });
  }
  assert.ok(offensiveRunCount(domain) >= MAX_OFFENSIVE_RUNS);
  const docker = makeStubDocker();
  const r = await runOffensiveTool(baseRun(domain, { docker }));
  assert.equal(r.confirmed, false);
  assert.equal(r.reason, "offensive_run_budget_exhausted");
  assert.equal(docker.calls.run.length, 0);
}));

// ───────────────────────── run lifecycle + outcomes ─────────────────────────

test("PR5a default (no classifier): runs, never signs, returns no_oracle_classifier + masked summary", () => withTempHome(async () => {
  const domain = "runner-noclassify.example.test";
  setup(domain);
  const docker = makeStubDocker({ writeStdout: "matched: 0\n" });
  const r = await runOffensiveTool(baseRun(domain, { docker }));
  assert.equal(r.confirmed, false);
  assert.equal(r.reason, "no_oracle_classifier");
  assert.equal(r.row_written, false);
  // hardened argv + per-run network reached docker; env scrubbed
  assert.equal(docker.calls.run.length, 1);
  const { args, env, containerName } = docker.calls.run[0];
  assert.ok(containerName.startsWith("bob-off-"));
  assert.equal(args[args.indexOf("--network") + 1], containerName);
  assert.equal(args[args.indexOf("--pull") + 1], "never");
  assert.ok(args.includes(DIGEST));
  assert.equal(env.DOCKER_HOST, undefined);
  // per-run network created + torn down; container killed
  assert.deepEqual(docker.calls.networkCreate, [containerName]);
  assert.deepEqual(docker.calls.networkRm, [containerName]);
  assert.ok(docker.calls.kill.includes(containerName));
  // no raw response bytes in the return
  assert.equal(JSON.stringify(r).includes("matched: 0"), false);
}));

test("forced flags are injected into the container command (F9)", () => withTempHome(async () => {
  const domain = "runner-forced.example.test";
  setup(domain);
  const docker = makeStubDocker();
  await runOffensiveTool(baseRun(domain, { forcedFlags: ["-disable-update-check", "-no-interactsh"], docker }));
  const { args } = docker.calls.run[0];
  const imgIdx = args.indexOf(DIGEST);
  const command = args.slice(imgIdx + 1);
  assert.equal(command[0], "httpx");
  assert.ok(command.includes("-disable-update-check"));
  assert.ok(command.includes("-no-interactsh"));
}));

test("timeout → blocked_by_infra, container killed, no row", () => withTempHome(async () => {
  const domain = "runner-timeout.example.test";
  setup(domain);
  const docker = makeStubDocker({ runResult: { exit_code: null, timed_out: true } });
  const r = await runOffensiveTool(baseRun(domain, { docker }));
  assert.equal(r.confirmed, false);
  assert.equal(r.reason, "offensive_run_timed_out");
  assert.equal(r.row_written, false);
}));

test("spawn error → blocked_by_infra", () => withTempHome(async () => {
  const domain = "runner-spawnerr.example.test";
  setup(domain);
  const docker = makeStubDocker({ runResult: { exit_code: null, timed_out: false, spawn_error: "docker_not_in_path" } });
  const r = await runOffensiveTool(baseRun(domain, { docker }));
  assert.equal(r.confirmed, false);
  assert.equal(r.reason, "offensive_spawn_failed");
}));

test("redaction backstop: secret-shaped output blocks the run, never signs (F4)", () => withTempHome(async () => {
  const domain = "runner-secret.example.test";
  setup(domain);
  const docker = makeStubDocker({ writeStdout: "Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123456789\n" });
  let signed = false;
  const r = await runOffensiveTool(baseRun(domain, { docker, classify: () => ({ positive: true }), sign: () => { signed = true; return {}; } }));
  assert.equal(r.confirmed, false);
  assert.equal(r.reason, "offensive_output_contains_sensitive_value");
  assert.equal(signed, false, "must not sign a row from secret-bearing output");
}));

test("sign-on-positive: a positive classify signs via the (stubbed) signer; masked return (F12)", () => withTempHome(async () => {
  const domain = "runner-positive.example.test";
  setup(domain);
  const docker = makeStubDocker({ writeStdout: "template-x: matched\n" });
  const fakeRow = {
    run_id: "reflect-deadbeef", tool_id: "bob_offensive_test", target: `https://${domain}/x`,
    demonstrated_severity: "medium", command_hash: "c".repeat(64), stdout_hash: "d".repeat(64), stderr_hash: "e".repeat(64), exit_code: 0,
  };
  let signArgs = null;
  const r = await runOffensiveTool(baseRun(domain, {
    docker,
    classify: () => ({ positive: true, surfaceId: "surface:x", canonicalTarget: `https://${domain}/x`, relationBooleans: { template_matched: true } }),
    sign: (d, a) => { signArgs = a; return fakeRow; },
  }));
  assert.equal(r.confirmed, true);
  assert.equal(r.row_written, true);
  assert.equal(r.demonstrated_severity, "medium");
  assert.equal(r.run_id, "reflect-deadbeef");
  // server-derived attribution flowed to the signer (F11)
  assert.equal(signArgs.surfaceId, "surface:x");
  assert.equal(signArgs.canonicalTarget, `https://${domain}/x`);
  // no raw bytes in the masked return
  assert.equal(JSON.stringify(r).includes("template-x: matched"), false);
}));

test("negative classify → no row", () => withTempHome(async () => {
  const domain = "runner-negative.example.test";
  setup(domain);
  const docker = makeStubDocker();
  let signed = false;
  const r = await runOffensiveTool(baseRun(domain, { docker, classify: () => ({ positive: false, reason: "no_match" }), sign: () => { signed = true; return {}; } }));
  assert.equal(r.confirmed, false);
  assert.equal(r.reason, "no_match");
  assert.equal(signed, false);
}));
