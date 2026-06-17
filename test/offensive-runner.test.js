"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  runOffensiveTool,
  parseAllowlistedArgv,
  scrubbedDockerEnv,
  offensiveRunCount,
  MAX_OFFENSIVE_RUNS,
  OFFENSIVE_RUN_AUDIT_METHOD,
} = require("../mcp/lib/offensive-runner.js");
const { initSession } = require("../mcp/lib/session-state.js");
const { auditConfirmRequest } = require("../mcp/lib/offensive-http-common.js");
const { repoRunsDir } = require("../mcp/lib/paths.js");

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
      calls.run.push({ args, env, containerName, stdoutPath });
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
  flagSpec: { boolean: ["-silent"], value: ["-u"], url: ["-u"] },
  ...overrides,
});

const noLifecycle = (d) => d.calls.run.length === 0 && d.calls.networkCreate.length === 0 && d.calls.kill.length === 0;
const stdoutLeaves = (domain) => { try { return fs.readdirSync(repoRunsDir(domain)).filter((f) => f.endsWith(".stdout")); } catch { return []; } };

// ───────────────────────── pure helpers ─────────────────────────

test("scrubbedDockerEnv: FIXED PATH (not inherited) + only PATH/HOME/DOCKER_CONFIG (F2)", () => {
  const env = scrubbedDockerEnv("/tmp/cfg");
  assert.deepEqual(Object.keys(env).sort(), ["DOCKER_CONFIG", "HOME", "PATH"]);
  assert.equal(env.PATH, "/usr/local/bin:/usr/bin:/bin");
  assert.notEqual(env.PATH, process.env.PATH);
  assert.equal(env.DOCKER_HOST, undefined);
  assert.equal(env.HTTPS_PROXY, undefined);
});

test("parseAllowlistedArgv: boolean vs value flags, bare-arg smuggling closed (F9)", () => {
  const spec = { boolean: ["-silent"], value: ["-u"] };
  // value flag captures its value
  assert.deepEqual([...parseAllowlistedArgv(["httpx", "-u", "https://x"], spec)], [["-u", "https://x"]]);
  assert.deepEqual([...parseAllowlistedArgv(["httpx", "-u=https://x"], spec)], [["-u", "https://x"]]);
  // boolean flag consumes NO value → a following bare token is NOT authorized (the bug)
  assert.throws(() => parseAllowlistedArgv(["httpx", "-silent", "roguebare"], spec), /bare argument/);
  // bare arg / -- / unknown flag / boolean-with-value / value-without-value all rejected
  assert.throws(() => parseAllowlistedArgv(["httpx", "naked"], spec), /bare argument/);
  assert.throws(() => parseAllowlistedArgv(["httpx", "--", "x"], spec), /pass-through separator/);
  assert.throws(() => parseAllowlistedArgv(["httpx", "-exec", "id"], spec), /not in the tool flag allowlist/);
  assert.throws(() => parseAllowlistedArgv(["httpx", "-silent=1"], spec), /must not take a value/);
  assert.throws(() => parseAllowlistedArgv(["httpx", "-u", "-silent"], spec), /requires a value/);
  // a boolean flag followed by another allowlisted flag is fine
  assert.doesNotThrow(() => parseAllowlistedArgv(["httpx", "-silent", "-u", "https://x"], spec));
});

// ───────────────────────── safety gates (NO docker lifecycle reached) ─────────────────────────

test("scope-gate operates on the COMMAND's URL flag value, before any docker call (AIM)", () => withTempHome(async () => {
  const domain = "runner-scope.example.test";
  setup(domain);
  const docker = makeStubDocker();
  await assert.rejects(
    runOffensiveTool(baseRun(domain, { toolArgv: ["httpx", "-u", "https://evil.example.com/"], docker })),
    (e) => /scope|blocked/i.test(e.message) || e.code === "SCOPE_BLOCKED" || e.scope_decision === "blocked",
  );
  assert.ok(noLifecycle(docker), "no docker lifecycle on an out-of-scope target");
}));

test("flag allowlist: an unlisted flag blocks before any docker call (full lifecycle zero)", () => withTempHome(async () => {
  const domain = "runner-flag.example.test";
  setup(domain);
  const docker = makeStubDocker();
  await assert.rejects(
    runOffensiveTool(baseRun(domain, { toolArgv: ["httpx", "-exec", "id"], flagSpec: { boolean: ["-silent"], value: ["-u"], url: ["-u"] }, docker })),
    /not in the tool flag allowlist/,
  );
  assert.ok(noLifecycle(docker));
}));

test("run budget: fail-closed at MAX_OFFENSIVE_RUNS, no docker lifecycle (F3)", () => withTempHome(async () => {
  const domain = "runner-budget.example.test";
  setup(domain);
  for (let i = 0; i < MAX_OFFENSIVE_RUNS; i += 1) {
    auditConfirmRequest({ domain, surfaceId: null, method: OFFENSIVE_RUN_AUDIT_METHOD, url: `https://${domain}/`, status: null, scopeDecision: "allowed", startedAt: Date.now(), toolId: "x" });
  }
  assert.ok(offensiveRunCount(domain) >= MAX_OFFENSIVE_RUNS);
  const docker = makeStubDocker();
  const r = await runOffensiveTool(baseRun(domain, { docker }));
  assert.equal(r.reason, "offensive_run_budget_exhausted");
  assert.ok(noLifecycle(docker));
}));

// ───────────────────────── run lifecycle + outcomes ─────────────────────────

test("PR5a default (no classifier): runs, never signs, scratch deleted, masked, run recorded (F3 reserve)", () => withTempHome(async () => {
  const domain = "runner-noclassify.example.test";
  setup(domain);
  const docker = makeStubDocker({ writeStdout: "matched: 0\n" });
  const r = await runOffensiveTool(baseRun(domain, { docker }));
  assert.equal(r.confirmed, false);
  assert.equal(r.reason, "no_oracle_classifier");
  assert.equal(r.row_written, false);
  // hardened argv + per-run net reached docker; env scrubbed; container torn down
  assert.equal(docker.calls.run.length, 1);
  const { args, env, containerName } = docker.calls.run[0];
  assert.ok(containerName.startsWith("bob-off-"));
  assert.equal(args[args.indexOf("--network") + 1], containerName);
  assert.equal(args[args.indexOf("--pull") + 1], "never");
  assert.equal(env.DOCKER_HOST, undefined);
  assert.equal(env.PATH, "/usr/local/bin:/usr/bin:/bin");
  assert.deepEqual(docker.calls.networkCreate, [containerName]);
  assert.deepEqual(docker.calls.networkRm, [containerName]);
  assert.ok(docker.calls.kill.includes(containerName));
  // F7-cleanup: scratch files deleted; no raw bytes in the return
  assert.deepEqual(stdoutLeaves(domain), [], "scratch stdout deleted");
  assert.equal(JSON.stringify(r).includes("matched: 0"), false);
  // F3 reserve: the run wrote one CONTAINER_RUN audit record
  assert.equal(offensiveRunCount(domain), 1);
}));

test("large benign output (>4KB) is scanned, not rejected for length (C)", () => withTempHome(async () => {
  const domain = "runner-bigoutput.example.test";
  setup(domain);
  const docker = makeStubDocker({ writeStdout: "x".repeat(5000) });
  const r = await runOffensiveTool(baseRun(domain, { docker }));
  assert.equal(r.reason, "no_oracle_classifier", "5KB benign output must run, not be blocked for size");
}));

test("forced flags are injected into the container command (F9)", () => withTempHome(async () => {
  const domain = "runner-forced.example.test";
  setup(domain);
  const docker = makeStubDocker();
  await runOffensiveTool(baseRun(domain, { forcedFlags: ["-disable-update-check", "-no-interactsh"], docker }));
  const { args } = docker.calls.run[0];
  const command = args.slice(args.indexOf(DIGEST) + 1);
  assert.equal(command[0], "httpx");
  assert.ok(command.includes("-disable-update-check") && command.includes("-no-interactsh"));
}));

test("timeout → blocked, container killed + network removed + scratch deleted", () => withTempHome(async () => {
  const domain = "runner-timeout.example.test";
  setup(domain);
  const docker = makeStubDocker({ runResult: { exit_code: null, timed_out: true } });
  const r = await runOffensiveTool(baseRun(domain, { docker }));
  assert.equal(r.reason, "offensive_run_timed_out");
  assert.equal(docker.calls.kill.length, 1, "container killed on timeout");
  assert.equal(docker.calls.networkRm.length, 1, "network removed on timeout");
  assert.deepEqual(stdoutLeaves(domain), [], "scratch deleted on timeout");
}));

test("spawn error → blocked_by_infra, network torn down", () => withTempHome(async () => {
  const domain = "runner-spawnerr.example.test";
  setup(domain);
  const docker = makeStubDocker({ runResult: { exit_code: null, timed_out: false, spawn_error: "docker_not_in_path" } });
  const r = await runOffensiveTool(baseRun(domain, { docker }));
  assert.equal(r.reason, "offensive_spawn_failed");
  assert.equal(docker.calls.networkRm.length, 1);
}));

test("redaction backstop: secret-shaped output blocks, never signs (F4); scratch still deleted", () => withTempHome(async () => {
  const domain = "runner-secret.example.test";
  setup(domain);
  const docker = makeStubDocker({ writeStdout: "Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123456789\n" });
  let signed = false;
  const r = await runOffensiveTool(baseRun(domain, { docker, classify: () => ({ positive: true }), sign: () => { signed = true; return {}; } }));
  assert.equal(r.reason, "offensive_output_contains_sensitive_value");
  assert.equal(signed, false);
  assert.deepEqual(stdoutLeaves(domain), [], "scratch deleted even when output had secrets");
}));

test("sign-on-positive: positive classify signs via the (stubbed) signer; server-derived attribution; masked (F11/F12)", () => withTempHome(async () => {
  const domain = "runner-positive.example.test";
  setup(domain);
  const docker = makeStubDocker({ writeStdout: "template-x: matched\n" });
  const fakeRow = { run_id: "reflect-deadbeef", tool_id: "bob_offensive_test", target: `https://${domain}/x`, demonstrated_severity: "medium", command_hash: "c".repeat(64), stdout_hash: "d".repeat(64), stderr_hash: "e".repeat(64), exit_code: 0 };
  let signArgs = null;
  const r = await runOffensiveTool(baseRun(domain, {
    docker,
    classify: () => ({ positive: true, surfaceId: "surface:x", canonicalTarget: `https://${domain}/x`, relationBooleans: { template_matched: true } }),
    sign: (d, a) => { signArgs = a; return fakeRow; },
  }));
  assert.equal(r.confirmed, true);
  assert.equal(r.row_written, true);
  assert.equal(r.demonstrated_severity, "medium");
  assert.equal(signArgs.surfaceId, "surface:x");
  assert.equal(signArgs.canonicalTarget, `https://${domain}/x`);
  assert.equal(JSON.stringify(r).includes("template-x: matched"), false);
}));

test("negative classify → no row", () => withTempHome(async () => {
  const domain = "runner-negative.example.test";
  setup(domain);
  const docker = makeStubDocker();
  let signed = false;
  const r = await runOffensiveTool(baseRun(domain, { docker, classify: () => ({ positive: false, reason: "no_match" }), sign: () => { signed = true; return {}; } }));
  assert.equal(r.reason, "no_match");
  assert.equal(signed, false);
}));

test("forcedFlags must be server-defined flag tokens — a bare arg is rejected before docker", () => withTempHome(async () => {
  const domain = "runner-forcedguard.example.test";
  setup(domain);
  const docker = makeStubDocker();
  await assert.rejects(runOffensiveTool(baseRun(domain, { forcedFlags: ["id"], docker })), /server-defined flag tokens/);
  assert.ok(noLifecycle(docker));
}));

test("a positive verdict with an out-of-scope canonicalTarget is blocked, never signed", () => withTempHome(async () => {
  const domain = "runner-verdictscope.example.test";
  setup(domain);
  const docker = makeStubDocker({ writeStdout: "match" });
  let signed = false;
  const r = await runOffensiveTool(baseRun(domain, {
    docker,
    classify: () => ({ positive: true, surfaceId: "surface:x", canonicalTarget: "https://evil.example.com/x", relationBooleans: {} }),
    sign: () => { signed = true; return {}; },
  }));
  assert.equal(r.reason, "oracle_target_out_of_scope");
  assert.equal(signed, false);
}));
