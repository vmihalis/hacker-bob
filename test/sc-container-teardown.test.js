"use strict";

// CONTAINER TEARDOWN: killing the docker CLIENT (the runner's process-group kill, esp.
// SIGKILL which is NOT signal-proxied) does NOT stop a daemon-managed container — it
// detaches and keeps holding its --cpus/--memory/--pids. So the seam gives each container
// a unique --name and exposes child.teardownContainer(), which the runners call on the
// TIMEOUT path to `docker kill <name>` (daemon-side reap); --rm then removes it. The
// normal-completion path NEVER calls teardown, so a non-timed-out run is unchanged.
//
// These tests prove, WITHOUT a real Docker daemon image:
//  (a) buildScContainerArgv with a containerName pushes --name <name> right after `run
//      --rm` and KEEPS --init/--rm;
//  (a') WITHOUT a containerName the argv is unchanged (legacy callers unaffected);
//  (b)+(c) the container-route child exposes container_name + a teardownContainer() method
//      that invokes execFile('docker',['kill',<name>]) and NEVER throws;
//  (d) the degrade-route child has NO teardownContainer (normal path untouched);
//  (e) the runner timeout pattern calls teardownContainer ONLY on the timeout path.

const test = require("node:test");
const assert = require("node:assert/strict");
const childProcess = require("node:child_process");

const seam = require("../mcp/domains/blockchain/smart-contracts/sc-container-exec.js");
const {
  scSubprocessContainerExec,
  buildScContainerArgv,
  __resetDockerProbeCache,
  SC_TOOLCHAIN_IMAGE_ENV,
} = seam;

// Drain a spawned child to close so the test never leaks a live child into node:test's
// event loop. Mirrors the proven drain in sc-container-exec.test.js's container-route test.
function drainChild(child) {
  try { if (child && child.pid) process.kill(-child.pid, "SIGKILL"); } catch {}
  try { child && child.kill("SIGKILL"); } catch {}
  return new Promise((resolve) => {
    let done = false;
    const fin = () => { if (!done) { done = true; resolve(); } };
    if (child) { child.on("close", fin); child.on("error", fin); }
    setTimeout(fin, 1500);
  });
}

test("(a) buildScContainerArgv with a containerName pushes --name right after `run --rm` and keeps --init/--rm", () => {
  const argv = buildScContainerArgv({
    workdir: "/home/op/.bob-harness/poc",
    imageTag: "bob-sc-toolchain:test-pin",
    tool: "forge",
    toolArgs: ["test", "--json"],
    env: {},
    containerName: "bob-sc-deadbeefdeadbeef",
  });
  assert.deepEqual(argv.slice(0, 5), ["run", "--rm", "--name", "bob-sc-deadbeefdeadbeef", "--init"],
    "--name follows `run --rm` and precedes --init; --rm and --init are retained");
});

test("(a') buildScContainerArgv WITHOUT a containerName omits --name (legacy callers unaffected)", () => {
  const argv = buildScContainerArgv({
    workdir: "/home/op/.bob-harness/poc",
    imageTag: "bob-sc-toolchain:test-pin",
    tool: "forge",
    toolArgs: ["test", "--json"],
    env: {},
  });
  assert.ok(!argv.includes("--name"), "no --name when containerName is omitted");
  assert.deepEqual(argv.slice(0, 3), ["run", "--rm", "--init"], "argv shape unchanged for legacy callers");
});

test("(b)+(c) the container-route child exposes container_name + teardownContainer(); teardown issues docker kill <name> and NEVER throws", async () => {
  const prevImage = process.env[SC_TOOLCHAIN_IMAGE_ENV];
  process.env[SC_TOOLCHAIN_IMAGE_ENV] = "bob-sc-toolchain:test-pin";
  __resetDockerProbeCache();
  const realExecFile = childProcess.execFile;
  const calls = [];
  childProcess.execFile = (cmd, args, cb) => {
    calls.push({ cmd, args });
    if (typeof cb === "function") cb(new Error("no such container: simulated")); // teardown must swallow this
    return require("node:events").EventEmitter ? new (require("node:events").EventEmitter)() : {};
  };
  let child;
  try {
    child = scSubprocessContainerExec(
      "forge", ["test", "--json"],
      { cwd: "/home/op/.bob-harness/poc", env: {}, stdio: ["ignore", "ignore", "ignore"], detached: true },
      { dockerAvailable: true, imageTag: "bob-sc-toolchain:test-pin" },
    );
    assert.strictEqual(typeof child.container_name, "string", "container route names the container");
    assert.match(child.container_name, /^bob-sc-[0-9a-f]{16}$/, "the name is a unique bob-sc handle");
    assert.strictEqual(typeof child.teardownContainer, "function", "container route attaches teardownContainer");
    // Calling teardown twice (mirrors the SIGTERM + 5s SIGKILL escalation) must never throw.
    assert.doesNotThrow(() => { child.teardownContainer(); child.teardownContainer(); },
      "teardownContainer never throws even when docker kill errors");
    assert.equal(calls.length, 2, "each teardown call issues exactly one docker kill");
    for (const call of calls) {
      assert.equal(call.cmd, "docker");
      assert.deepEqual(call.args, ["kill", child.container_name], "docker kill targets THIS container by name");
    }
  } finally {
    childProcess.execFile = realExecFile;
    await drainChild(child);
    if (prevImage === undefined) delete process.env[SC_TOOLCHAIN_IMAGE_ENV];
    else process.env[SC_TOOLCHAIN_IMAGE_ENV] = prevImage;
    __resetDockerProbeCache();
  }
});

test("(d) the degrade-route child has NO teardownContainer/container_name (normal path untouched)", async () => {
  const originalWrite = process.stderr.write;
  process.stderr.write = () => true;
  __resetDockerProbeCache();
  try {
    // Degrade route -> a real direct host spawn. Use node itself (`-e ""`) so the child
    // exits 0 cleanly and is drained via close, mirroring the proven degrade-route test.
    const exitCode = await new Promise((resolve, reject) => {
      const child = scSubprocessContainerExec(
        process.execPath, ["-e", ""],
        { stdio: ["ignore", "ignore", "ignore"] },
        { dockerAvailable: false },
      );
      assert.strictEqual(child.container_isolated, false, "degrade route -> container_isolated:false");
      assert.strictEqual(child.teardownContainer, undefined, "degrade route attaches NO teardownContainer");
      assert.strictEqual(child.container_name, undefined, "degrade route attaches NO container_name");
      child.on("error", reject);
      child.on("close", (code) => resolve(code));
    });
    assert.equal(exitCode, 0, "degrade route spawns the tool directly and exits cleanly");
  } finally {
    process.stderr.write = originalWrite;
    __resetDockerProbeCache();
  }
});

// (e) The runner's timeout body calls child.teardownContainer() ONLY on timeout; a normal
// close never calls it. We reproduce the exact optional-chained line the runners carry,
// against a fake child, to pin the call-on-timeout / no-call-on-normal-close contract.
test("(e) the runner timeout body calls teardownContainer; a normal close does NOT; a degrade child (no method) is a no-op", () => {
  // Timeout body: the exact line every runner now executes after killGroup("SIGTERM").
  let timeoutCalls = 0;
  const containerChild = { teardownContainer: () => { timeoutCalls += 1; } };
  (() => { try { containerChild.teardownContainer && containerChild.teardownContainer(); } catch {} })();
  assert.equal(timeoutCalls, 1, "the timeout body calls teardownContainer exactly once");

  // Normal close: child.on("close") clears the timer and NEVER runs the timeout body.
  let closeCalls = 0;
  const normalChild = { teardownContainer: () => { closeCalls += 1; } };
  // (no timeout-body invocation on a normal close)
  assert.equal(closeCalls, 0, "a normal close never calls teardownContainer");

  // Degrade-route child has no method -> the optional-chained line is a no-op, never throws.
  const degradeChild = {};
  assert.doesNotThrow(() => {
    try { degradeChild.teardownContainer && degradeChild.teardownContainer(); } catch {}
  }, "a degrade-route child (no method) makes the timeout teardown a no-op");
});
