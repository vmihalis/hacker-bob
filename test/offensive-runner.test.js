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
  offensiveRunBudgetPath,
  offensiveInfraFailureCount,
  offensiveInfraFailurePath,
  MAX_OFFENSIVE_RUNS,
  MAX_OFFENSIVE_INFRA_FAILURES,
} = require("../mcp/lib/offensive-runner.js");
const { initSession } = require("../mcp/lib/session-state.js");
const { repoRunsDir, httpAuditJsonlPath } = require("../mcp/lib/paths.js");

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
  flagSpec: { binary: "httpx", boolean: ["-silent"], value: ["-u"], url: ["-u"] },
  ...overrides,
});

const noLifecycle = (d) => d.calls.run.length === 0 && d.calls.networkCreate.length === 0 && d.calls.kill.length === 0;
const stdoutLeaves = (domain) => { try { return fs.readdirSync(repoRunsDir(domain)).filter((f) => f.endsWith(".stdout")); } catch { return []; } };
// the most recent CONTAINER_RUN audit record (the runner stamps each offensive run with
// method=CONTAINER_RUN; the normalizer drops `tool` but keeps `method` + egress_profile).
const lastContainerRunAudit = (domain) => {
  const lines = fs.readFileSync(httpAuditJsonlPath(domain), "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l));
  return lines.reverse().find((r) => r.method === "CONTAINER_RUN");
};

// ───────────────────────── pure helpers ─────────────────────────

test("scrubbedDockerEnv: FIXED PATH (not inherited) + only PATH/HOME/DOCKER_CONFIG (F2)", () => {
  const env = scrubbedDockerEnv("/tmp/cfg");
  assert.deepEqual(Object.keys(env).sort(), ["DOCKER_CONFIG", "HOME", "PATH"]);
  assert.equal(env.PATH, "/usr/local/bin:/usr/bin:/bin");
  assert.notEqual(env.PATH, process.env.PATH);
  assert.equal(env.DOCKER_HOST, undefined);
  assert.equal(env.HTTPS_PROXY, undefined);
});

test("parseAllowlistedArgv: boolean vs value flags, bare-arg smuggling closed, repeats preserved (F9)", () => {
  const spec = { boolean: ["-silent"], value: ["-u"] };
  // value flag captures its value (array of {flag,value} pairs)
  assert.deepEqual(parseAllowlistedArgv(["httpx", "-u", "https://x"], spec), [{ flag: "-u", value: "https://x" }]);
  assert.deepEqual(parseAllowlistedArgv(["httpx", "-u=https://x"], spec), [{ flag: "-u", value: "https://x" }]);
  // repeated value flags are NOT deduped (the container runs all of them)
  assert.deepEqual(parseAllowlistedArgv(["httpx", "-u", "a", "-u", "b"], spec), [{ flag: "-u", value: "a" }, { flag: "-u", value: "b" }]);
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
  // the container binary (toolArgv[0]) must be a bare name — no path/metacharacters
  assert.throws(() => parseAllowlistedArgv(["/bin/sh", "-silent"], spec), /bare \[a-zA-Z0-9._-\] token/);
  assert.throws(() => parseAllowlistedArgv(["rm;reboot", "-silent"], spec), /bare \[a-zA-Z0-9._-\] token/);
});

test("parseAllowlistedArgv: binds toolArgv[0] to spec.binary when declared (#124-1)", () => {
  const spec = { binary: "dalfox", boolean: ["-silent"], value: ["-u"] };
  // the declared binary matches → accepted
  assert.doesNotThrow(() => parseAllowlistedArgv(["dalfox", "-u", "https://x"], spec));
  // a DIFFERENT in-image binary under the same spec → rejected (the sh/curl scenario)
  assert.throws(() => parseAllowlistedArgv(["sh", "-u", "https://x"], spec), /does not match the tool's declared binary/);
  assert.throws(() => parseAllowlistedArgv(["httpx", "-silent"], spec), /declared binary/);
  // a malformed declared binary fails closed (can't smuggle a path as the declared binary)
  assert.throws(() => parseAllowlistedArgv(["x", "-silent"], { binary: "/bin/sh", boolean: ["-silent"] }), /bare \[a-zA-Z0-9._-\] binary name/);
  // no binary declared → only the bare-token shape check (PR5a inert back-compat)
  assert.doesNotThrow(() => parseAllowlistedArgv(["anybin", "-silent"], { boolean: ["-silent"] }));
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

test("scope-gate checks EVERY repeated URL flag — in-scope-then-out-of-scope is still blocked", () => withTempHome(async () => {
  const domain = "runner-repeated.example.test";
  setup(domain);
  const docker = makeStubDocker();
  await assert.rejects(
    runOffensiveTool(baseRun(domain, { toolArgv: ["httpx", "-u", `https://${domain}/`, "-u", "https://evil.example.com/"], docker })),
    (e) => /scope|blocked/i.test(e.message) || e.code === "SCOPE_BLOCKED" || e.scope_decision === "blocked",
  );
  assert.ok(noLifecycle(docker), "a repeated out-of-scope URL flag must block before docker");
}));

test("flag allowlist: an unlisted flag blocks before any docker call (full lifecycle zero)", () => withTempHome(async () => {
  const domain = "runner-flag.example.test";
  setup(domain);
  const docker = makeStubDocker();
  await assert.rejects(
    runOffensiveTool(baseRun(domain, { toolArgv: ["httpx", "-exec", "id"], flagSpec: { binary: "httpx", boolean: ["-silent"], value: ["-u"], url: ["-u"] }, docker })),
    /not in the tool flag allowlist/,
  );
  assert.ok(noLifecycle(docker));
}));

test("offensiveRunCount: monotonic counter (missing=0, value, malformed=fail-closed)", () => withTempHome(async () => {
  const domain = "runner-counter.example.test";
  setup(domain);
  assert.equal(offensiveRunCount(domain), 0, "missing counter file = 0");
  fs.writeFileSync(offensiveRunBudgetPath(domain), "7");
  assert.equal(offensiveRunCount(domain), 7);
  for (const bad of ["garbage", "7x", "0x10", "7\ntrailing", "-3"]) {
    fs.writeFileSync(offensiveRunBudgetPath(domain), bad);
    assert.equal(offensiveRunCount(domain), Number.POSITIVE_INFINITY, `${JSON.stringify(bad)} must fail closed`);
  }
}));

test("run budget: fail-closed at MAX (untrimmable counter, NOT the 5000-trimmed audit log) (F3)", () => withTempHome(async () => {
  const domain = "runner-budget.example.test";
  setup(domain);
  // Seed the monotonic counter at the cap — the budget does NOT read http-audit
  // (which trims at HTTP_AUDIT_LOG_MAX_RECORDS and would let the budget reset).
  fs.writeFileSync(offensiveRunBudgetPath(domain), String(MAX_OFFENSIVE_RUNS));
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
  // #124-2: a non-proxied run records the normalized "default" egress — NEVER the old
  // literal "proxy" (the normalizer coerces an absent egress_profile to "default").
  const audit = lastContainerRunAudit(domain);
  assert.equal(audit.egress_profile, "default");
  assert.notEqual(audit.egress_profile, "proxy");
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

test("forcedFlags reject the '--' pass-through separator", () => withTempHome(async () => {
  const domain = "runner-forceddd.example.test";
  setup(domain);
  const docker = makeStubDocker();
  await assert.rejects(runOffensiveTool(baseRun(domain, { forcedFlags: ["--"], docker })), /server-defined flag tokens/);
  assert.ok(noLifecycle(docker));
}));

test("scope-gate fails CLOSED on a URL-shaped value of an UNDECLARED url flag", () => withTempHome(async () => {
  // -H is a value flag NOT in flagSpec.url; its value still looks like a URL, so the
  // gate must scope-check it — an incomplete flagSpec.url cannot fail open.
  const domain = "runner-undeclared.example.test";
  setup(domain);
  const docker = makeStubDocker();
  await assert.rejects(
    runOffensiveTool(baseRun(domain, {
      toolArgv: ["httpx", "-u", `https://${domain}/`, "-H", "https://evil.example.com/"],
      flagSpec: { binary: "httpx", boolean: ["-silent"], value: ["-u", "-H"], url: ["-u"] },
      docker,
    })),
    (e) => /scope|blocked/i.test(e.message) || e.code === "SCOPE_BLOCKED" || e.scope_decision === "blocked",
  );
  assert.ok(noLifecycle(docker));
}));

test("scope-gate also catches a protocol-relative URL value (//host) on an undeclared flag", () => withTempHome(async () => {
  const domain = "runner-protorel.example.test";
  setup(domain);
  const docker = makeStubDocker();
  await assert.rejects(
    runOffensiveTool(baseRun(domain, {
      toolArgv: ["httpx", "-u", `https://${domain}/`, "-x", "//evil.example.com/"],
      flagSpec: { binary: "httpx", boolean: ["-silent"], value: ["-u", "-x"], url: ["-u"] },
      docker,
    })),
    (e) => /scope|blocked/i.test(e.message) || e.code === "SCOPE_BLOCKED" || e.scope_decision === "blocked",
  );
  assert.ok(noLifecycle(docker));
}));

test("forcedFlags carrying a URL value are rejected (can't bypass the scope gate)", () => withTempHome(async () => {
  const domain = "runner-forcedurl.example.test";
  setup(domain);
  const docker = makeStubDocker();
  await assert.rejects(runOffensiveTool(baseRun(domain, { forcedFlags: ["-u=https://evil.example.com/"], docker })), /must not carry a URL/);
  assert.ok(noLifecycle(docker));
}));

test("a malformed egressProxyUrl is rejected before any docker call", () => withTempHome(async () => {
  const domain = "runner-egress.example.test";
  setup(domain);
  const docker = makeStubDocker();
  await assert.rejects(runOffensiveTool(baseRun(domain, { egressProxyUrl: "not-a-url", docker })), /http\(s\) proxy URL/);
  assert.ok(noLifecycle(docker));
}));

test("networkCreate failure tears down the partial network + scratch", () => withTempHome(async () => {
  const domain = "runner-netfail.example.test";
  setup(domain);
  const docker = makeStubDocker();
  docker.networkCreate = (name) => { docker.calls.networkCreate.push(name); throw new Error("boom"); };
  const r = await runOffensiveTool(baseRun(domain, { docker }));
  assert.equal(r.reason, "offensive_network_create_failed");
  assert.equal(docker.calls.networkRm.length, 1, "partial network removed");
  assert.deepEqual(stdoutLeaves(domain), [], "scratch cleaned on network-create failure");
}));

test("signed content is secret-scanned: a classify returning secret stdoutContent is blocked", () => withTempHome(async () => {
  const domain = "runner-signscan.example.test";
  setup(domain);
  const docker = makeStubDocker({ writeStdout: "benign output" });
  let signed = false;
  const r = await runOffensiveTool(baseRun(domain, {
    docker,
    classify: () => ({ positive: true, surfaceId: "surface:x", canonicalTarget: `https://${domain}/x`, stdoutContent: "Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123456789", relationBooleans: {} }),
    sign: () => { signed = true; return {}; },
  }));
  assert.equal(r.reason, "offensive_signed_content_contains_sensitive_value");
  assert.equal(signed, false);
}));

// ───────────────────────── #124 runner mutations ─────────────────────────

test("declared binary mismatch: toolArgv[0] != flagSpec.binary blocks before any docker call (#124-1)", () => withTempHome(async () => {
  const domain = "runner-binary.example.test";
  setup(domain);
  const docker = makeStubDocker();
  // baseRun declares binary "httpx"; a live caller forwarding agent argv that names a
  // different in-image binary (curl) under the same tool_id must be rejected.
  await assert.rejects(
    runOffensiveTool(baseRun(domain, { toolArgv: ["curl", "-u", `https://${domain}/`], docker })),
    /does not match the tool's declared binary/,
  );
  assert.ok(noLifecycle(docker));
}));

test("egressProxyUrl WITHOUT egressProfileName is rejected — no anonymous proxy (#124-2)", () => withTempHome(async () => {
  const domain = "runner-egressname.example.test";
  setup(domain);
  const docker = makeStubDocker();
  await assert.rejects(
    runOffensiveTool(baseRun(domain, { egressProxyUrl: "http://proxy.internal:8080", docker })),
    /requires egressProfileName/,
  );
  assert.ok(noLifecycle(docker));
}));

test("a malformed egressProfileName is rejected before any docker call (#124-2)", () => withTempHome(async () => {
  const domain = "runner-egressbad.example.test";
  setup(domain);
  const docker = makeStubDocker();
  await assert.rejects(
    runOffensiveTool(baseRun(domain, { egressProxyUrl: "http://proxy.internal:8080", egressProfileName: "bad name!", docker })),
    /profile name/,
  );
  assert.ok(noLifecycle(docker));
}));

test("egressProfileName is recorded in the CONTAINER_RUN audit row, not the literal 'proxy' (#124-2)", () => withTempHome(async () => {
  const domain = "runner-egressrec.example.test";
  setup(domain);
  const docker = makeStubDocker();
  await runOffensiveTool(baseRun(domain, { egressProxyUrl: "http://proxy.internal:8080", egressProfileName: "corp-eu", docker }));
  const audit = lastContainerRunAudit(domain);
  assert.equal(audit.egress_profile, "corp-eu");
  assert.notEqual(audit.egress_profile, "proxy");
  // the proxy env actually reached the container argv (sandbox sets *_proxy env tokens)
  const { args } = docker.calls.run[0];
  assert.ok(args.some((t) => t === "https_proxy=http://proxy.internal:8080"));
}));

test("networkCreate failure REFUNDS the run budget + bumps the infra-failure counter (#124-3)", () => withTempHome(async () => {
  const domain = "runner-infrarefund.example.test";
  setup(domain);
  const docker = makeStubDocker();
  docker.networkCreate = (name) => { docker.calls.networkCreate.push(name); throw new Error("boom"); };
  const r = await runOffensiveTool(baseRun(domain, { docker }));
  assert.equal(r.reason, "offensive_network_create_failed");
  assert.equal(offensiveRunCount(domain), 0, "infra failure did NOT consume a genuine-run slot");
  assert.equal(offensiveInfraFailureCount(domain), 1, "infra failure counted separately");
}));

test("spawn error REFUNDS the run budget + bumps the infra counter (#124-3)", () => withTempHome(async () => {
  const domain = "runner-spawnrefund.example.test";
  setup(domain);
  const docker = makeStubDocker({ runResult: { exit_code: null, timed_out: false, spawn_error: "docker_not_in_path" } });
  const r = await runOffensiveTool(baseRun(domain, { docker }));
  assert.equal(r.reason, "offensive_spawn_failed");
  assert.equal(offensiveRunCount(domain), 0, "spawn error refunded");
  assert.equal(offensiveInfraFailureCount(domain), 1);
}));

test("a timeout CONSUMES the run budget (the container ran) — NOT counted as infra (#124-3)", () => withTempHome(async () => {
  const domain = "runner-timeoutbudget.example.test";
  setup(domain);
  const docker = makeStubDocker({ runResult: { exit_code: null, timed_out: true } });
  await runOffensiveTool(baseRun(domain, { docker }));
  assert.equal(offensiveRunCount(domain), 1, "a timeout ran → consumes a slot");
  assert.equal(offensiveInfraFailureCount(domain), 0, "a timeout is not an infra failure");
}));

test("infra-failure budget exhausted blocks new runs (separate cap) (#124-3)", () => withTempHome(async () => {
  const domain = "runner-infracap.example.test";
  setup(domain);
  fs.writeFileSync(offensiveInfraFailurePath(domain), String(MAX_OFFENSIVE_INFRA_FAILURES));
  const docker = makeStubDocker();
  const r = await runOffensiveTool(baseRun(domain, { docker }));
  assert.equal(r.reason, "offensive_infra_failure_budget_exhausted");
  assert.ok(noLifecycle(docker));
}));
