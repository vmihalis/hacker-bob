"use strict";

// fx-gate-bypass defense 1 — a second `node mcp/server.js` engine instance
// against the same HOME/session root must refuse to start. This is the
// direct regression test for the "spawn a second, ungated engine" vector:
// a prompt-injected model under `--dangerously-skip-permissions` controls
// its own subprocess env, so any BOB_AGENTCORE-keyed approval gate is inert
// on a rogue second instance -- the singleton lock never depends on that
// env var at all.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawn } = require("child_process");

const SERVER_PATH = path.join(__dirname, "..", "mcp", "server.js");
const READY_BANNER = /hacker-bob MCP server running \(stdio\)/;
const REFUSAL_BANNER = /refusing to start/;

function withTempHome(fn) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-engine-lock-"));
  return (async () => {
    try {
      return await fn(home);
    } finally {
      fs.rmSync(home, { recursive: true, force: true });
    }
  })();
}

// Spawns `node mcp/server.js` with the given HOME and resolves once either
// the ready banner or an early-exit is observed, or `timeoutMs` elapses.
//
// stdin MUST be an open pipe (never "ignore"/"/dev/null"): mcp/lib/transport.js's
// stdio server only stays alive while stdin stays open (exactly matching real
// usage, where the parent CLI keeps the MCP-server child's stdin open for the
// life of the interaction). An "ignore"d stdin hits immediate EOF and the
// process exits on its own almost right away -- with no relation to the
// singleton lock at all -- which would make this test pass or fail for the
// wrong reason. We open the pipe and deliberately never end() it.
function spawnEngine(home, { timeoutMs = 5000 } = {}) {
  const child = spawn(process.execPath, [SERVER_PATH], {
    env: { ...process.env, HOME: home },
    stdio: ["pipe", "pipe", "pipe"],
  });

  let stderr = "";
  let stdout = "";
  child.stdout.on("data", (chunk) => { stdout += chunk.toString("utf8"); });
  child.stderr.on("data", (chunk) => { stderr += chunk.toString("utf8"); });

  const outcome = new Promise((resolve) => {
    let settled = false;
    const settle = (result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(result);
    };

    const timer = setTimeout(() => {
      settle({ ready: true, exited: false, code: null, stderr, stdout });
    }, timeoutMs);

    const checkReady = () => {
      if (READY_BANNER.test(stderr)) {
        settle({ ready: true, exited: false, code: null, stderr, stdout });
      }
    };
    child.stderr.on("data", checkReady);

    // "close" (not "exit"): stdio pipes deliver "data" asynchronously on
    // POSIX and can still be draining when "exit" fires, so waiting for
    // "close" (which fires only after all stdio streams have ended)
    // guarantees `stderr`/`stdout` are fully accumulated before this
    // resolves.
    child.on("close", (code) => {
      settle({ ready: false, exited: true, code, stderr, stdout });
    });
    child.on("error", (error) => {
      settle({ ready: false, exited: true, code: null, error, stderr, stdout });
    });
  });

  return { child, outcome };
}

function killAndWait(child, { signal = "SIGTERM" } = {}) {
  return new Promise((resolve) => {
    if (child.exitCode != null || child.signalCode != null) {
      resolve();
      return;
    }
    child.once("close", () => resolve());
    child.kill(signal);
    // Belt-and-suspenders: force-kill if it ignores SIGTERM.
    setTimeout(() => {
      try { child.kill("SIGKILL"); } catch {}
    }, 3000).unref();
  });
}

test("a second `node mcp/server.js` against an already-locked session root refuses to start and exits non-zero", async () => {
  await withTempHome(async (home) => {
    const first = spawnEngine(home);
    const firstOutcome = await first.outcome;
    assert.equal(firstOutcome.exited, false, `first engine instance must not exit early: ${firstOutcome.stderr}`);
    assert.ok(firstOutcome.ready, "first engine instance must reach the ready banner");

    try {
      const second = spawnEngine(home);
      const secondOutcome = await second.outcome;
      assert.equal(secondOutcome.exited, true, "second engine instance must exit (not hang serving)");
      assert.notEqual(secondOutcome.code, 0, "second engine instance must exit non-zero");
      assert.ok(
        REFUSAL_BANNER.test(secondOutcome.stderr),
        `second engine instance must print a refusal message on stderr; got: ${secondOutcome.stderr}`,
      );
      assert.equal(
        READY_BANNER.test(secondOutcome.stderr),
        false,
        "second engine instance must never reach the ready banner",
      );
    } finally {
      await killAndWait(first.child);
    }
  });
});

test("a crash-left same-host lock is reclaimed only after its owner PID is absent", async () => {
  await withTempHome(async (home) => {
    const first = spawnEngine(home);
    const firstOutcome = await first.outcome;
    assert.ok(firstOutcome.ready, "first engine instance must reach the ready banner");

    await killAndWait(first.child, { signal: "SIGKILL" });
    const lockPath = path.join(home, "hacker-bob-sessions", ".engine.lock");
    assert.equal(fs.existsSync(lockPath), true, "SIGKILL must leave the lock for recovery");

    const second = spawnEngine(home);
    const secondOutcome = await second.outcome;
    try {
      assert.equal(
        secondOutcome.exited,
        false,
        `fresh engine must reclaim the exact dead-owner lock: ${secondOutcome.stderr}`,
      );
      assert.ok(secondOutcome.ready, "fresh engine must reach the ready banner after recovery");
      const recovered = JSON.parse(fs.readFileSync(lockPath, "utf8"));
      assert.equal(recovered.version, 1);
      assert.equal(recovered.pid, second.child.pid);
      assert.equal(recovered.hostname, os.hostname());
    } finally {
      await killAndWait(second.child);
    }
  });
});

test("same-host live, foreign-host dead, malformed, and linked lock ownership fail closed", async () => {
  const fixtures = [
    {
      name: "same-host live owner",
      payload: {
        version: 1,
        pid: process.pid,
        hostname: os.hostname(),
        timestamp: new Date().toISOString(),
        token: "live-owner-token-0001",
      },
    },
    {
      name: "foreign-host dead owner",
      payload: {
        version: 1,
        pid: 999999,
        hostname: "foreign-host.invalid",
        timestamp: new Date().toISOString(),
        token: "foreign-owner-token-0001",
      },
    },
  ];

  for (const fixture of fixtures) {
    await withTempHome(async (home) => {
      const previousHome = process.env.HOME;
      process.env.HOME = home;
      delete require.cache[require.resolve("../mcp/lib/engine-lock.js")];
      const { acquireEngineSingletonLock } = require("../mcp/lib/engine-lock.js");
      const { engineLockPath } = require("../mcp/lib/paths.js");
      try {
        fs.mkdirSync(path.dirname(engineLockPath()), { recursive: true, mode: 0o700 });
        fs.writeFileSync(
          engineLockPath(),
          `${JSON.stringify(fixture.payload)}\n`,
          { mode: 0o600 },
        );
        assert.equal(acquireEngineSingletonLock(), false, fixture.name);
        assert.deepEqual(JSON.parse(fs.readFileSync(engineLockPath(), "utf8")), fixture.payload);
      } finally {
        fs.rmSync(engineLockPath(), { force: true });
        process.env.HOME = previousHome;
        delete require.cache[require.resolve("../mcp/lib/engine-lock.js")];
      }
    });
  }

  await withTempHome(async (home) => {
    const previousHome = process.env.HOME;
    process.env.HOME = home;
    delete require.cache[require.resolve("../mcp/lib/engine-lock.js")];
    const { acquireEngineSingletonLock } = require("../mcp/lib/engine-lock.js");
    const { engineLockPath } = require("../mcp/lib/paths.js");
    try {
      fs.mkdirSync(path.dirname(engineLockPath()), { recursive: true, mode: 0o700 });
      fs.writeFileSync(engineLockPath(), "not-json\n", { mode: 0o600 });
      assert.equal(acquireEngineSingletonLock(), false, "malformed ownership must not be guessed");
    } finally {
      fs.rmSync(engineLockPath(), { force: true });
      process.env.HOME = previousHome;
      delete require.cache[require.resolve("../mcp/lib/engine-lock.js")];
    }
  });

  await withTempHome(async (home) => {
    const previousHome = process.env.HOME;
    process.env.HOME = home;
    delete require.cache[require.resolve("../mcp/lib/engine-lock.js")];
    const { acquireEngineSingletonLock } = require("../mcp/lib/engine-lock.js");
    const { engineLockPath } = require("../mcp/lib/paths.js");
    const sibling = path.join(home, "dead-owner.json");
    try {
      fs.mkdirSync(path.dirname(engineLockPath()), { recursive: true, mode: 0o700 });
      fs.writeFileSync(sibling, `${JSON.stringify({
        version: 1,
        pid: 999999,
        hostname: os.hostname(),
        timestamp: new Date().toISOString(),
        token: "linked-owner-token-0001",
      })}\n`, { mode: 0o600 });
      fs.linkSync(sibling, engineLockPath());
      assert.equal(acquireEngineSingletonLock(), false, "hard-linked ownership must fail closed");
      assert.equal(fs.existsSync(engineLockPath()), true);
    } finally {
      fs.rmSync(engineLockPath(), { force: true });
      fs.rmSync(sibling, { force: true });
      process.env.HOME = previousHome;
      delete require.cache[require.resolve("../mcp/lib/engine-lock.js")];
    }
  });
});

test("a legacy same-host dead-owner record is migrated by exact recovery", async () => {
  await withTempHome(async (home) => {
    const previousHome = process.env.HOME;
    process.env.HOME = home;
    delete require.cache[require.resolve("../mcp/lib/engine-lock.js")];
    const {
      acquireEngineSingletonLock,
      releaseEngineSingletonLock,
    } = require("../mcp/lib/engine-lock.js");
    const { engineLockPath } = require("../mcp/lib/paths.js");
    try {
      fs.mkdirSync(path.dirname(engineLockPath()), { recursive: true, mode: 0o700 });
      fs.writeFileSync(engineLockPath(), `${JSON.stringify({
        pid: 999999,
        hostname: os.hostname(),
        timestamp: new Date().toISOString(),
        token: "999999-legacy-dead-owner-token",
      })}\n`, { mode: 0o600 });
      assert.equal(acquireEngineSingletonLock(), true);
      const migrated = JSON.parse(fs.readFileSync(engineLockPath(), "utf8"));
      assert.equal(migrated.version, 1);
      assert.equal(migrated.pid, process.pid);
    } finally {
      releaseEngineSingletonLock();
      fs.rmSync(engineLockPath(), { force: true });
      process.env.HOME = previousHome;
      delete require.cache[require.resolve("../mcp/lib/engine-lock.js")];
    }
  });
});

test("a fresh `node mcp/server.js` acquires the lock after the prior holder releases it cleanly (SIGTERM)", async () => {
  await withTempHome(async (home) => {
    const first = spawnEngine(home);
    const firstOutcome = await first.outcome;
    assert.ok(firstOutcome.ready, "first engine instance must reach the ready banner");

    await killAndWait(first.child);

    const second = spawnEngine(home);
    const secondOutcome = await second.outcome;
    try {
      assert.equal(secondOutcome.exited, false, `fresh engine instance must not exit early: ${secondOutcome.stderr}`);
      assert.ok(secondOutcome.ready, "fresh engine instance must acquire the now-released lock and reach the ready banner");
    } finally {
      await killAndWait(second.child);
    }
  });
});

test("acquireEngineSingletonLock returns false (never throws) when another process already holds the lock file", async () => {
  await withTempHome(async (home) => {
    const previousHome = process.env.HOME;
    process.env.HOME = home;
    delete require.cache[require.resolve("../mcp/lib/engine-lock.js")];
    const {
      acquireEngineSingletonLock,
      releaseEngineSingletonLock,
    } = require("../mcp/lib/engine-lock.js");
    const { engineLockPath } = require("../mcp/lib/paths.js");
    const { writeFileExclusiveAtomic } = require("../mcp/lib/storage.js");
    try {
      // Simulate "another process already holds the lock": write the lock
      // file directly via the SAME primitive acquireEngineSingletonLock uses,
      // bypassing this process's own in-memory heldLock bookkeeping entirely
      // (a real second process would have no shared in-memory state either).
      const preExisting = writeFileExclusiveAtomic(
        engineLockPath(),
        `${JSON.stringify({ pid: 999999, hostname: "other-host", timestamp: new Date().toISOString(), token: "other-token" }, null, 2)}\n`,
        { mode: 0o600 },
      );
      assert.equal(preExisting, true, "test setup: fixture lock file must be created");

      assert.equal(
        acquireEngineSingletonLock(),
        false,
        "acquire must return false (fail closed), not throw, when the lock file is already held by someone else",
      );
    } finally {
      releaseEngineSingletonLock();
      fs.rmSync(engineLockPath(), { force: true });
      process.env.HOME = previousHome;
      delete require.cache[require.resolve("../mcp/lib/engine-lock.js")];
    }
  });
});

test("acquireEngineSingletonLock/releaseEngineSingletonLock: in-process double-acquire refuses, release allows re-acquire", async () => {
  await withTempHome(async (home) => {
    const previousHome = process.env.HOME;
    process.env.HOME = home;
    // Fresh require per HOME swap is unnecessary -- engineLockPath() reads
    // os.homedir() (and therefore process.env.HOME) at CALL time, not at
    // require time, so re-requiring the already-cached module is fine.
    delete require.cache[require.resolve("../mcp/lib/engine-lock.js")];
    const {
      acquireEngineSingletonLock,
      releaseEngineSingletonLock,
      _isEngineSingletonLockHeldForTest,
    } = require("../mcp/lib/engine-lock.js");
    try {
      assert.equal(_isEngineSingletonLockHeldForTest(), false);
      assert.equal(acquireEngineSingletonLock(), true, "first acquire must succeed");
      assert.equal(_isEngineSingletonLockHeldForTest(), true);

      assert.throws(
        () => acquireEngineSingletonLock(),
        /already held by this process/,
        "a second acquire by the SAME process (without release) must throw, not silently re-acquire",
      );

      releaseEngineSingletonLock();
      assert.equal(_isEngineSingletonLockHeldForTest(), false);

      assert.equal(acquireEngineSingletonLock(), true, "acquire after release must succeed");
      releaseEngineSingletonLock();
    } finally {
      releaseEngineSingletonLock();
      process.env.HOME = previousHome;
      delete require.cache[require.resolve("../mcp/lib/engine-lock.js")];
    }
  });
});
