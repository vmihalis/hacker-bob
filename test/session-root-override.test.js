"use strict";

// Operator-configured, per-workspace session roots.
//
// fx-gate-bypass defense 1 (mcp/lib/engine-lock.js) elects ONE engine per
// session root. The defense it actually encodes is "no two engines over the
// SAME session state": a second engine booting against shared state would have
// fresh in-process gate state (circuit breakers, request budgets, terminal
// blocks) and could drive that state past gates the first engine enforces.
//
// BOB_SESSIONS_ROOT lets an operator give each Claude Code workspace its own
// DISJOINT root. Two engines on disjoint roots share no session state at all,
// so the defense holds by construction while concurrency becomes possible —
// and the singleton lock stays exactly as strong WITHIN each root.
//
// The override is BOOT-FROZEN (read from the env once at paths.js module load)
// and FAIL-CLOSED (an unsafe value throws at boot; it never silently falls
// back to the default root, which would let two workspaces collide unnoticed).

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { execFileSync, spawn } = require("node:child_process");

const REPO_ROOT = path.join(__dirname, "..");
const PATHS_MODULE = path.join(REPO_ROOT, "mcp", "core", "io", "paths.js");
const ENGINE_LOCK_MODULE = path.join(REPO_ROOT, "mcp", "core", "io", "engine-lock.js");

function withTempDir(prefix, fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  return (async () => {
    try {
      return await fn(dir);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  })();
}

// Runs `script` in a FRESH node process so paths.js module-load resolution
// (the boot freeze) happens under exactly the supplied env. Returns
// { status, stdout, stderr }; never throws on a non-zero exit.
function runNode(script, env) {
  try {
    const stdout = execFileSync(process.execPath, ["-e", script], {
      env: { ...process.env, ...env },
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
    return { status: 0, stdout, stderr: "" };
  } catch (error) {
    return {
      status: error.status == null ? -1 : error.status,
      stdout: error.stdout == null ? "" : String(error.stdout),
      stderr: error.stderr == null ? "" : String(error.stderr),
    };
  }
}

// Acquires the REAL engine singleton lock in a child process and holds it
// until told to release. Resolves once the child reports its acquire result.
function holdEngineLock(env) {
  const script = `
    const { acquireEngineSingletonLock, releaseEngineSingletonLock } = require(${JSON.stringify(ENGINE_LOCK_MODULE)});
    const { engineLockPath, sessionsRoot } = require(${JSON.stringify(PATHS_MODULE)});
    const acquired = acquireEngineSingletonLock();
    process.stdout.write(JSON.stringify({
      acquired,
      root: sessionsRoot(),
      lock: engineLockPath(),
    }) + "\\n");
    process.on("SIGTERM", () => { releaseEngineSingletonLock(); process.exit(0); });
    setInterval(() => {}, 1000);
  `;
  const child = spawn(process.execPath, ["-e", script], {
    env: { ...process.env, ...env },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stdout = "";
  let stderr = "";
  child.stdout.on("data", (chunk) => { stdout += chunk.toString("utf8"); });
  child.stderr.on("data", (chunk) => { stderr += chunk.toString("utf8"); });

  const report = new Promise((resolve) => {
    let settled = false;
    const settle = (value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(value);
    };
    const timer = setTimeout(() => settle({ acquired: null, stderr, timedOut: true }), 10000);
    child.stdout.on("data", () => {
      const line = stdout.split("\n").find((entry) => entry.trim());
      if (!line) return;
      try {
        settle({ ...JSON.parse(line), stderr });
      } catch { /* wait for a complete line */ }
    });
    child.on("close", () => settle({ acquired: null, stderr, exited: true }));
    child.on("error", () => settle({ acquired: null, stderr, exited: true }));
  });

  return { child, report };
}

function killAndWait(child) {
  return new Promise((resolve) => {
    if (child.exitCode != null || child.signalCode != null) {
      resolve();
      return;
    }
    child.once("close", () => resolve());
    child.kill("SIGTERM");
    setTimeout(() => { try { child.kill("SIGKILL"); } catch {} }, 3000).unref();
  });
}

// (a) Default (no env set) is byte-identical to today.
test("with no BOB_SESSIONS_ROOT set, sessionsRoot() is byte-identical to ~/hacker-bob-sessions", async () => {
  await withTempDir("bob-root-default-", async (home) => {
    const script = `
      const { sessionsRoot, engineLockPath } = require(${JSON.stringify(PATHS_MODULE)});
      process.stdout.write(JSON.stringify({ root: sessionsRoot(), lock: engineLockPath() }));
    `;
    const result = runNode(script, { HOME: home, BOB_SESSIONS_ROOT: undefined });
    assert.equal(result.status, 0, result.stderr);
    const observed = JSON.parse(result.stdout);
    assert.equal(observed.root, path.join(home, "hacker-bob-sessions"));
    assert.equal(observed.lock, path.join(home, "hacker-bob-sessions", ".engine.lock"));
    // The default resolver must NOT create anything as a side effect.
    assert.equal(fs.existsSync(observed.root), false, "default resolution must not create the root");
  });
});

// (b) A valid override redirects sessionsRoot + engineLockPath.
test("a valid BOB_SESSIONS_ROOT redirects sessionsRoot() and engineLockPath()", async () => {
  await withTempDir("bob-root-valid-", async (home) => {
    await withTempDir("bob-root-alt-", async (altParent) => {
      const override = path.join(altParent, "workspace-a-sessions");
      const script = `
        const { sessionsRoot, engineLockPath, sessionDir } = require(${JSON.stringify(PATHS_MODULE)});
        process.stdout.write(JSON.stringify({
          root: sessionsRoot(),
          lock: engineLockPath(),
          session: sessionDir("example.com"),
        }));
      `;
      const result = runNode(script, { HOME: home, BOB_SESSIONS_ROOT: override });
      assert.equal(result.status, 0, result.stderr);
      const observed = JSON.parse(result.stdout);
      assert.equal(observed.root, override);
      assert.equal(observed.lock, path.join(override, ".engine.lock"));
      assert.equal(observed.session, path.join(override, "example.com"));
      // Created 0700 when absent.
      const stats = fs.lstatSync(override);
      assert.equal(stats.isDirectory(), true);
      assert.equal(stats.mode & 0o077, 0, "an auto-created override root must be 0700");
      // The default root is untouched.
      assert.equal(fs.existsSync(path.join(home, "hacker-bob-sessions")), false);
    });
  });
});

// (2) BOOT-FROZEN: a mid-process env mutation must not redirect the root.
test("the override is boot-frozen: mutating process.env after load does not move the session root", async () => {
  await withTempDir("bob-root-freeze-", async (home) => {
    await withTempDir("bob-root-freeze-alt-", async (altParent) => {
      const booted = path.join(altParent, "booted-root");
      const escape = path.join(altParent, "escape-root");
      fs.mkdirSync(escape, { recursive: true, mode: 0o700 });
      const script = `
        const { sessionsRoot } = require(${JSON.stringify(PATHS_MODULE)});
        const before = sessionsRoot();
        process.env.BOB_SESSIONS_ROOT = ${JSON.stringify(escape)};
        const afterSet = sessionsRoot();
        delete process.env.BOB_SESSIONS_ROOT;
        const afterDelete = sessionsRoot();
        process.stdout.write(JSON.stringify({ before, afterSet, afterDelete }));
      `;
      const result = runNode(script, { HOME: home, BOB_SESSIONS_ROOT: booted });
      assert.equal(result.status, 0, result.stderr);
      const observed = JSON.parse(result.stdout);
      assert.equal(observed.before, booted);
      assert.equal(observed.afterSet, booted, "a mid-process env set must not redirect audit-graded writes");
      assert.equal(observed.afterDelete, booted, "a mid-process env delete must not fall back to the default root");
    });
  });
});

// (c) THE CONCURRENCY PROOF: two engines on DISJOINT roots both acquire.
test("two engines on DISJOINT session roots BOTH acquire the singleton lock concurrently", async () => {
  await withTempDir("bob-root-concurrent-", async (home) => {
    await withTempDir("bob-root-concurrent-a-", async (rootA) => {
      await withTempDir("bob-root-concurrent-b-", async (rootB) => {
        const workspaceA = path.join(rootA, "sessions");
        const workspaceB = path.join(rootB, "sessions");
        const first = holdEngineLock({ HOME: home, BOB_SESSIONS_ROOT: workspaceA });
        const firstReport = await first.report;
        try {
          assert.equal(firstReport.acquired, true, `first engine must acquire: ${firstReport.stderr}`);
          assert.equal(firstReport.root, workspaceA);

          const second = holdEngineLock({ HOME: home, BOB_SESSIONS_ROOT: workspaceB });
          const secondReport = await second.report;
          try {
            assert.equal(
              secondReport.acquired,
              true,
              `a SECOND engine on a disjoint root must also acquire (concurrency): ${secondReport.stderr}`,
            );
            assert.equal(secondReport.root, workspaceB);
            // Two distinct lock files, both live at the same time.
            assert.notEqual(firstReport.lock, secondReport.lock);
            assert.equal(fs.existsSync(firstReport.lock), true);
            assert.equal(fs.existsSync(secondReport.lock), true);
          } finally {
            await killAndWait(second.child);
          }
        } finally {
          await killAndWait(first.child);
        }
      });
    });
  });
});

// (d) THE DEFENSE, INTACT: two engines on the SAME root still mutually exclude.
test("two engines on the SAME overridden session root still mutually exclude", async () => {
  await withTempDir("bob-root-same-", async (home) => {
    await withTempDir("bob-root-same-alt-", async (altParent) => {
      const shared = path.join(altParent, "shared-sessions");
      const first = holdEngineLock({ HOME: home, BOB_SESSIONS_ROOT: shared });
      const firstReport = await first.report;
      try {
        assert.equal(firstReport.acquired, true, `first engine must acquire: ${firstReport.stderr}`);

        const second = holdEngineLock({ HOME: home, BOB_SESSIONS_ROOT: shared });
        const secondReport = await second.report;
        try {
          assert.equal(
            secondReport.acquired,
            false,
            "a second engine over the SAME session state must be refused — the override must not weaken defense 1",
          );
        } finally {
          await killAndWait(second.child);
        }
      } finally {
        await killAndWait(first.child);
      }
    });
  });
});

// The same-root exclusion must also hold when the override is the DEFAULT root
// spelled explicitly: an override equal to the default is the same root, so the
// lock — not a path-shape rule — is what keeps them apart.
test("an override naming exactly the default root is accepted and still shares the default root's lock", async () => {
  await withTempDir("bob-root-equal-", async (home) => {
    const explicitDefault = path.join(home, "hacker-bob-sessions");
    const first = holdEngineLock({ HOME: home, BOB_SESSIONS_ROOT: explicitDefault });
    const firstReport = await first.report;
    try {
      assert.equal(firstReport.acquired, true, `explicit-default override must boot: ${firstReport.stderr}`);
      assert.equal(firstReport.root, explicitDefault);

      const second = holdEngineLock({ HOME: home, BOB_SESSIONS_ROOT: undefined });
      const secondReport = await second.report;
      try {
        assert.equal(
          secondReport.acquired,
          false,
          "an implicit-default engine must collide with an explicit-default engine — same root, same lock",
        );
      } finally {
        await killAndWait(second.child);
      }
    } finally {
      await killAndWait(first.child);
    }
  });
});

// (e) FAIL-CLOSED: every unsafe override throws at boot, never falls back.
test("an unsafe BOB_SESSIONS_ROOT fails closed at boot and never falls back to the default root", async () => {
  await withTempDir("bob-root-unsafe-", async (home) => {
    await withTempDir("bob-root-unsafe-alt-", async (altParent) => {
      const defaultRoot = path.join(home, "hacker-bob-sessions");
      fs.mkdirSync(defaultRoot, { recursive: true, mode: 0o700 });

      const groupWritable = path.join(altParent, "group-writable");
      fs.mkdirSync(groupWritable, { recursive: true, mode: 0o700 });
      fs.chmodSync(groupWritable, 0o770);

      const otherWritable = path.join(altParent, "other-writable");
      fs.mkdirSync(otherWritable, { recursive: true, mode: 0o700 });
      fs.chmodSync(otherWritable, 0o707);

      const realTarget = path.join(altParent, "symlink-target");
      fs.mkdirSync(realTarget, { recursive: true, mode: 0o700 });
      const symlinked = path.join(altParent, "symlinked-root");
      fs.symlinkSync(realTarget, symlinked);

      const notADirectory = path.join(altParent, "regular-file");
      fs.writeFileSync(notADirectory, "not a directory\n", { mode: 0o600 });

      const cases = [
        { name: "relative path", value: "relative/sessions", reason: /absolute path/ },
        { name: "bare relative name", value: "sessions", reason: /absolute path/ },
        { name: "nested inside the default root", value: path.join(defaultRoot, "workspace-a"), reason: /nested/ },
        { name: "deeply nested inside the default root", value: path.join(defaultRoot, "a", "b"), reason: /nested/ },
        { name: "ancestor of the default root", value: home, reason: /nested/ },
        // "/" is an ancestor of every root; whichever assertion fires first
        // (ownership on a root-owned "/", otherwise nesting) it must fail closed.
        { name: "filesystem root (ancestor of everything)", value: path.parse(home).root, reason: /owned by the user|nested/ },
        { name: "group-writable", value: groupWritable, reason: /group or other/ },
        { name: "other-writable", value: otherWritable, reason: /group or other/ },
        { name: "symlink", value: symlinked, reason: /symlink/ },
        { name: "existing regular file", value: notADirectory, reason: /created|real directory/ },
      ];

      const script = `
        const { sessionsRoot } = require(${JSON.stringify(PATHS_MODULE)});
        process.stdout.write("BOOTED:" + sessionsRoot());
      `;

      for (const testCase of cases) {
        const result = runNode(script, { HOME: home, BOB_SESSIONS_ROOT: testCase.value });
        assert.notEqual(result.status, 0, `${testCase.name}: must fail closed at boot`);
        assert.equal(
          result.stdout.includes("BOOTED:"),
          false,
          `${testCase.name}: must never boot (silent fallback would let two workspaces collide unnoticed)`,
        );
        assert.match(result.stderr, /BOB_SESSIONS_ROOT is not a safe session root/, testCase.name);
        assert.match(result.stderr, testCase.reason, `${testCase.name}: operator message must name the cause`);
      }

      // A whitespace-only value is treated as "unset", exactly like the
      // existing BOUNTY_TELEMETRY_DIR precedent — not as an unsafe value.
      const blank = runNode(script, { HOME: home, BOB_SESSIONS_ROOT: "   " });
      assert.equal(blank.status, 0, blank.stderr);
      assert.equal(blank.stdout, `BOOTED:${defaultRoot}`);
    });
  });
});

// The refusal must be actionable for the operator who set it, and must say it
// is operator config (an agent cannot change the engine's boot env).
test("the fail-closed message tells the operator where the override lives", async () => {
  await withTempDir("bob-root-msg-", async (home) => {
    const script = `require(${JSON.stringify(PATHS_MODULE)});`;
    const result = runNode(script, { HOME: home, BOB_SESSIONS_ROOT: "not/absolute" });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /\.mcp\.json/);
    assert.match(result.stderr, /agent cannot change the engine's boot env/);
    assert.match(result.stderr, /refuses to boot rather than silently fall back/);
  });
});

// The engine binary itself (not just the library) must refuse to serve.
test("`node mcp/server.js` refuses to start under an unsafe BOB_SESSIONS_ROOT", async () => {
  await withTempDir("bob-root-server-", async (home) => {
    const result = runNode(
      `require(${JSON.stringify(path.join(REPO_ROOT, "mcp", "server.js"))}).startServer();`,
      { HOME: home, BOB_SESSIONS_ROOT: path.join(home, "hacker-bob-sessions", "nested") },
    );
    assert.notEqual(result.status, 0, "the engine must not serve on an unsafe root");
    assert.match(result.stderr, /BOB_SESSIONS_ROOT is not a safe session root/);
    assert.equal(
      /hacker-bob MCP server running \(stdio\)/.test(result.stderr),
      false,
      "the engine must never reach the ready banner",
    );
  });
});

// No agent-callable tool may relocate the session root: it is operator boot
// config only. Guard the tool registry against a future regression.
test("no MCP tool exposes a session-root override knob", () => {
  const registry = require("../mcp/core/dispatch/tool-registry.js");
  const serialized = JSON.stringify(registry.TOOL_MANIFEST || registry.TOOLS || []);
  assert.equal(
    /BOB_SESSIONS_ROOT|sessions_root|session_root/i.test(serialized),
    false,
    "the session root is operator boot configuration; no tool may accept it as input",
  );
});

// Sanity: the git-tracked source must not carry a literal control character
// (the NUL guard is written as an escape, not as a raw byte).
test("paths.js carries no raw control characters", () => {
  const source = fs.readFileSync(PATHS_MODULE, "utf8");
  const offending = [...source].some((character) => {
    const code = character.charCodeAt(0);
    return code < 0x20 && character !== "\n" && character !== "\t" || code === 0x7f;
  });
  assert.equal(offending, false);
});

// Belt-and-suspenders: engine-lock.js must keep its own root assertions. The
// override validates at boot; the lock must not start trusting that.
test("engine-lock.js still asserts its own session-root safety", () => {
  const source = fs.readFileSync(ENGINE_LOCK_MODULE, "utf8");
  assert.match(source, /must be a real directory/);
  assert.match(source, /must be owned by this user/);
  assert.match(source, /must not be writable by group or other users/);
  assert.match(source, /assertSessionRootIdentity/);
});

// The install surface should be able to discover the knob; keep the name
// stable so operator docs and the installer cannot drift apart silently.
test("the override env var name is stable", () => {
  const source = fs.readFileSync(PATHS_MODULE, "utf8");
  assert.match(source, /const SESSIONS_ROOT_ENV_VAR = "BOB_SESSIONS_ROOT";/);
  execFileSync(process.execPath, ["--check", PATHS_MODULE], { stdio: "ignore" });
});
