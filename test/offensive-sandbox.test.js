"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const {
  buildOffensiveDockerRunArgv,
  assertNoForbiddenDockerFlags,
  OFFENSIVE_DNS,
  DEFAULT_WORK_TMPFS_BYTES,
} = require("../mcp/domains/web/offensive-sandbox.js");

const DIGEST = "ghcr.io/bobnetsec/bob-offense@sha256:" + "a".repeat(64);
const RUN = "bob-off-9f8e7d6c5b4a3f2e1d0c";

function baseArgs(overrides = {}) {
  return {
    imageDigest: DIGEST,
    command: ["httpx", "-version"],
    containerName: RUN,
    networkName: RUN,
    cidfilePath: `/tmp/bob-sessions/x/offensive-scratch/${RUN}.cid`,
    ...overrides,
  };
}

function argvOf(overrides) {
  return buildOffensiveDockerRunArgv(baseArgs(overrides)).args;
}

// returns the value token that follows `flag` in args
function valAfter(args, flag) {
  const i = args.indexOf(flag);
  return i >= 0 ? args[i + 1] : undefined;
}

test("happy path: emits the full hardened wide-open argv", () => {
  const { command, args } = buildOffensiveDockerRunArgv(baseArgs());
  assert.equal(command, "docker");
  assert.equal(args[0], "run");
  assert.ok(args.includes("--rm"));
  // wide-open but per-run-isolated network + pinned DNS
  assert.equal(valAfter(args, "--network"), RUN);
  assert.equal(valAfter(args, "--dns"), OFFENSIVE_DNS);
  // mandatory hardened flags
  assert.equal(valAfter(args, "--cap-drop"), "ALL");
  assert.equal(valAfter(args, "--security-opt"), "no-new-privileges");
  assert.equal(valAfter(args, "--cgroupns"), "private");
  assert.equal(valAfter(args, "--ipc"), "private");
  assert.equal(valAfter(args, "--pull"), "never");
  assert.equal(valAfter(args, "--user"), "1000:1000");
  assert.equal(valAfter(args, "--pids-limit"), "1024");
  assert.ok(args.includes("--read-only"));
  assert.equal(valAfter(args, "--stop-timeout"), "5");
  // lifecycle handles
  assert.equal(valAfter(args, "--name"), RUN);
  assert.ok(valAfter(args, "--cidfile").endsWith(`${RUN}.cid`));
  // /tmp + /work are tmpfs; NO host bind mount
  assert.ok(args.some((t) => t.startsWith("/tmp:size=")));
  assert.ok(args.some((t) => t.includes("destination=/work") && t.includes(`tmpfs-size=${DEFAULT_WORK_TMPFS_BYTES}`) && t.includes("tmpfs-mode=1777")));
  assert.ok(!args.includes("-v"), "no host bind mount");
  // image is digest-pinned and precedes the command; command tokens follow
  const imgIdx = args.indexOf(DIGEST);
  assert.ok(imgIdx > 0, "image present");
  assert.deepEqual(args.slice(imgIdx + 1), ["httpx", "-version"]);
});

test("digest pin: rejects any mutable/non-digest image reference", () => {
  for (const bad of [
    "bob-offense:v1",
    "bob-offense:latest",
    "ghcr.io/x/bob-offense",
    "ghcr.io/x/bob-offense@sha256:short",
    "",
    null,
  ]) {
    assert.throws(() => argvOf({ imageDigest: bad }), /digest-pinned image/, `should reject ${JSON.stringify(bad)}`);
  }
});

test("command: rejects empty / non-array / empty-token argv", () => {
  for (const bad of [[], "httpx -version", ["httpx", ""], [123], null]) {
    assert.throws(() => argvOf({ command: bad }), /non-empty string command argv/);
  }
});

test("container/network names must be bob-off-<run_id> shaped", () => {
  assert.throws(() => argvOf({ containerName: "evil; rm -rf" }), /bob-off-<run_id> container/);
  assert.throws(() => argvOf({ containerName: "nginx" }), /bob-off-<run_id> container/);
  assert.throws(() => argvOf({ networkName: "host" }), /bob-off-<run_id> network/);
  assert.throws(() => argvOf({ networkName: "--privileged" }), /bob-off-<run_id> network/);
});

test("cidfile + workTmpfsBytes are validated", () => {
  assert.throws(() => argvOf({ cidfilePath: "" }), /cidfilePath/);
  assert.throws(() => argvOf({ workTmpfsBytes: 0 }), /positive workTmpfsBytes/);
  assert.throws(() => argvOf({ workTmpfsBytes: -1 }), /positive workTmpfsBytes/);
});

test("egress proxy: ALL proxy vars present iff a proxy url is supplied (never baked into the image)", () => {
  const PROXY_VARS = ["http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"];
  const without = argvOf();
  for (const v of PROXY_VARS) assert.ok(!without.some((t) => t.startsWith(`${v}=`)), `no ${v} by default`);
  const withProxy = argvOf({ egressProxyUrl: "http://egress.local:8080" });
  for (const v of PROXY_VARS) assert.ok(withProxy.includes(`${v}=http://egress.local:8080`), `${v} present with proxy`);
});

test("assertNoForbiddenDockerFlags: fail-closed backstop catches a dangerous argv", () => {
  const ok = buildOffensiveDockerRunArgv(baseArgs()).args;
  assert.doesNotThrow(() => assertNoForbiddenDockerFlags(ok));
  // each forbidden mutation throws
  assert.throws(() => assertNoForbiddenDockerFlags([...ok, "--privileged"]), /--privileged/);
  assert.throws(() => assertNoForbiddenDockerFlags([...ok, "--cap-add", "NET_ADMIN"]), /--cap-add/);
  assert.throws(() => assertNoForbiddenDockerFlags([...ok, "--pid", "host"]), /--pid/);
  assert.throws(() => assertNoForbiddenDockerFlags([...ok, "-v", "/var/run/docker.sock:/var/run/docker.sock"]), /bind-mount any host path/);
  assert.throws(() => assertNoForbiddenDockerFlags([...ok, "--security-opt", "seccomp=unconfined"]), /seccomp/);
  // a host/none network must be rejected
  const hostNet = ok.map((t, i) => (ok[i - 1] === "--network" ? "host" : t));
  assert.throws(() => assertNoForbiddenDockerFlags(hostNet), /per-run bob-off-\* network/);
  // a root user must be rejected
  const rootUser = ok.map((t, i) => (ok[i - 1] === "--user" ? "0:0" : t));
  assert.throws(() => assertNoForbiddenDockerFlags(rootUser), /--user 1000:1000/);
});
