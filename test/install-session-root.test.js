const test = require("node:test");
const assert = require("node:assert/strict");
const { execFileSync, spawn } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const {
  installLifecycleCustodianTestDouble,
} = require("./fixtures/lifecycle-custodian-test-port.js");

installLifecycleCustodianTestDouble();

const { installProject } = require("../scripts/install.js");
const { doctorProject, uninstallProject } = require("../scripts/lifecycle.js");
const {
  SESSIONS_ROOT_ENV_VAR,
  bobMcpServerEntry,
  defaultSessionsRoot,
  isBobManagedMcpServerEntry,
  resolveWorkspaceSessionsRoot,
  workspaceSessionsRoot,
} = require("../scripts/lib/workspace-sessions-root.js");

const ROOT = path.join(__dirname, "..");

// WHY THIS FILE EXISTS
//
// mcp/lib/engine-lock.js elects exactly ONE engine per session root. That is the
// fx-gate-bypass defense: a second engine over the SAME session state boots with
// fresh in-process gate state (circuit breakers, request budgets, terminal
// blocks) and could drive that state past gates the first engine enforces. So
// two Claude Code workspaces could never run engines at the same time — they
// shared one hardcoded root.
//
// The installer now gives each workspace its own DISJOINT root. These tests pin
// the install-side half of that contract: the roots are disjoint and stable, the
// generated config actually carries them, engines on them really do run
// concurrently while same-root exclusion is untouched, and an upgrade never
// silently orphans sessions already sitting in the shared default root.

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function withTestHome(tempHome, run) {
  const previousHome = process.env.HOME;
  process.env.HOME = tempHome;
  try {
    return run();
  } finally {
    if (previousHome === undefined) delete process.env.HOME;
    else process.env.HOME = previousHome;
  }
}

function install(workspace, tempHome) {
  return withTestHome(tempHome, () => installProject(workspace, {
    sourceRoot: ROOT,
    installerSource: "install.sh",
    adapter: "claude",
    activateCodex: false,
  }));
}

function makeSandbox() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "bob-session-root-"));
  const home = path.join(root, "home");
  fs.mkdirSync(home, { recursive: true });
  return {
    root,
    home,
    workspace(name) {
      const dir = path.join(root, name);
      fs.mkdirSync(dir, { recursive: true });
      return dir;
    },
    cleanup() {
      fs.rmSync(root, { recursive: true, force: true });
    },
  };
}

function configuredSessionsRoot(workspace) {
  const entry = readJson(path.join(workspace, ".mcp.json")).mcpServers["hacker-bob"];
  return entry.env ? entry.env[SESSIONS_ROOT_ENV_VAR] : null;
}

// Nesting — not mere inequality — is what makes two roots share state. A root
// inside another root is the same state under a second engine.
function strictlyNested(left, right) {
  if (left === right) return true;
  return left.startsWith(right + path.sep) || right.startsWith(left + path.sep);
}

test("two installed workspaces get disjoint session roots, stamped into .mcp.json and settings.json", () => {
  const sandbox = makeSandbox();
  try {
    const one = sandbox.workspace("ws-one");
    const two = sandbox.workspace("ws-two");
    install(one, sandbox.home);
    install(two, sandbox.home);

    const rootOne = configuredSessionsRoot(one);
    const rootTwo = configuredSessionsRoot(two);
    assert.ok(rootOne, "workspace one must carry a BOB_SESSIONS_ROOT");
    assert.ok(rootTwo, "workspace two must carry a BOB_SESSIONS_ROOT");
    assert.notEqual(rootOne, rootTwo);
    assert.equal(strictlyNested(rootOne, rootTwo), false, "workspace roots must be disjoint");

    // Disjoint from the default root too — mcp/lib/paths.js refuses a root that
    // is strictly nested with it, so a nested derivation would fail at boot.
    const sharedDefault = path.join(sandbox.home, "hacker-bob-sessions");
    assert.equal(strictlyNested(rootOne, sharedDefault), false);
    assert.equal(strictlyNested(rootTwo, sharedDefault), false);

    // Created up front at 0700 so the root already satisfies the ownership/mode
    // assertions engine-lock.js and paths.js apply.
    for (const root of [rootOne, rootTwo]) {
      const stats = fs.lstatSync(root);
      assert.ok(stats.isDirectory() && !stats.isSymbolicLink());
      assert.equal(stats.mode & 0o022, 0);
    }

    // The host side must agree with the engine: .claude/hooks/agent-run-stop.js
    // requires mcp/lib/paths.js directly, and the session guards resolve the
    // roots they protect from the environment.
    assert.equal(readJson(path.join(one, ".claude", "settings.json")).env[SESSIONS_ROOT_ENV_VAR], rootOne);
    assert.equal(readJson(path.join(two, ".claude", "settings.json")).env[SESSIONS_ROOT_ENV_VAR], rootTwo);
  } finally {
    sandbox.cleanup();
  }
});

test("the derived root is stable across re-installs of the same workspace", () => {
  const sandbox = makeSandbox();
  try {
    const workspace = sandbox.workspace("ws-stable");
    install(workspace, sandbox.home);
    const first = configuredSessionsRoot(workspace);
    install(workspace, sandbox.home);
    const second = configuredSessionsRoot(workspace);

    // An unstable root would orphan every session from the previous install.
    assert.equal(second, first);
    assert.equal(first, workspaceSessionsRoot(workspace, { home: sandbox.home }));
  } finally {
    sandbox.cleanup();
  }
});

test("engines on two installed workspaces run CONCURRENTLY, and same-root exclusion is unchanged", async () => {
  const sandbox = makeSandbox();
  const children = [];
  try {
    const one = sandbox.workspace("ws-lock-one");
    const two = sandbox.workspace("ws-lock-two");
    install(one, sandbox.home);
    install(two, sandbox.home);

    // Runs the REAL acquireEngineSingletonLock out of the installed workspace,
    // booted with exactly the env the installer generated.
    const probe = (workspace) => [
      "-e",
      "const lock = require(process.argv[1] + '/mcp/lib/engine-lock.js');"
      + "const paths = require(process.argv[1] + '/mcp/lib/paths.js');"
      + "const acquired = lock.acquireEngineSingletonLock();"
      + "process.stdout.write(JSON.stringify({ root: paths.sessionsRoot(), acquired }) + '\\n');"
      + "if (!acquired) process.exit(0);"
      + "setInterval(() => {}, 1000);",
      workspace,
    ];
    const envFor = (workspace) => ({
      ...process.env,
      HOME: sandbox.home,
      [SESSIONS_ROOT_ENV_VAR]: configuredSessionsRoot(workspace),
    });
    const firstLine = (child) => new Promise((resolve, reject) => {
      let buffer = "";
      child.stdout.on("data", (chunk) => {
        buffer += chunk.toString("utf8");
        const index = buffer.indexOf("\n");
        if (index !== -1) resolve(JSON.parse(buffer.slice(0, index)));
      });
      child.on("error", reject);
      child.on("exit", (code) => reject(new Error(`probe exited early with ${code}: ${buffer}`)));
    });

    const engineOne = spawn(process.execPath, probe(one), { env: envFor(one), stdio: ["ignore", "pipe", "pipe"] });
    children.push(engineOne);
    const resultOne = await firstLine(engineOne);
    assert.equal(resultOne.acquired, true);
    assert.equal(resultOne.root, configuredSessionsRoot(one));

    const engineTwo = spawn(process.execPath, probe(two), { env: envFor(two), stdio: ["ignore", "pipe", "pipe"] });
    children.push(engineTwo);
    const resultTwo = await firstLine(engineTwo);
    // THE POINT OF THE WHOLE CHANGE: a second workspace's engine boots while the
    // first is live, because the two share no session state whatsoever.
    assert.equal(resultTwo.acquired, true);
    assert.equal(resultTwo.root, configuredSessionsRoot(two));
    assert.notEqual(resultTwo.root, resultOne.root);

    // ...and the defense is untouched WITHIN a root: a second engine over the
    // SAME session state is still refused.
    const sameRoot = execFileSync(process.execPath, probe(one), {
      env: envFor(one),
      encoding: "utf8",
    });
    assert.deepEqual(JSON.parse(sameRoot.trim()), {
      root: configuredSessionsRoot(one),
      acquired: false,
    });
  } finally {
    for (const child of children) child.kill("SIGKILL");
    sandbox.cleanup();
  }
});

test("an upgrade never silently orphans sessions already in the shared default root", () => {
  const sandbox = makeSandbox();
  try {
    const workspace = sandbox.workspace("ws-upgrade");
    install(workspace, sandbox.home);

    // Rewind to the pre-override shape: an installed workspace with no
    // BOB_SESSIONS_ROOT anywhere, and real sessions in the shared default root.
    const mcpPath = path.join(workspace, ".mcp.json");
    const mcp = readJson(mcpPath);
    delete mcp.mcpServers["hacker-bob"].env;
    fs.writeFileSync(mcpPath, `${JSON.stringify(mcp, null, 2)}\n`, "utf8");
    const settingsPath = path.join(workspace, ".claude", "settings.json");
    const settings = readJson(settingsPath);
    delete settings.env;
    fs.writeFileSync(settingsPath, `${JSON.stringify(settings, null, 2)}\n`, "utf8");
    for (const stale of fs.readdirSync(sandbox.home)) {
      if (stale.startsWith("hacker-bob-sessions-")) {
        fs.rmSync(path.join(sandbox.home, stale), { recursive: true, force: true });
      }
    }
    const sharedDefault = path.join(sandbox.home, "hacker-bob-sessions");
    fs.mkdirSync(path.join(sharedDefault, "example.com"), { recursive: true });
    fs.writeFileSync(path.join(sharedDefault, "example.com", "state.json"), "{}\n", "utf8");

    const upgraded = install(workspace, sandbox.home);
    assert.equal(upgraded.sessionsRootSource, "shared_default");
    assert.equal(upgraded.sessionsRoot, defaultSessionsRoot({ home: sandbox.home }));
    // No env is written: behavior is byte-identical to a pre-override install,
    // and the in-flight sessions stay reachable.
    assert.equal(configuredSessionsRoot(workspace), null);
    assert.equal(readJson(settingsPath).env, undefined);
    assert.ok(fs.existsSync(path.join(sharedDefault, "example.com", "state.json")));

    // The documented one-line migration: move the sessions to the per-workspace
    // root the installer named, re-run, and the workspace flips over.
    const candidate = upgraded.sessionsRootCandidate;
    fs.mkdirSync(candidate, { recursive: true, mode: 0o700 });
    fs.renameSync(path.join(sharedDefault, "example.com"), path.join(candidate, "example.com"));
    const migrated = install(workspace, sandbox.home);
    assert.equal(migrated.sessionsRootSource, "derived");
    assert.equal(configuredSessionsRoot(workspace), candidate);
    assert.ok(fs.existsSync(path.join(candidate, "example.com", "state.json")));
  } finally {
    sandbox.cleanup();
  }
});

test("an operator-pinned session root is preserved verbatim across re-install", () => {
  const sandbox = makeSandbox();
  try {
    const workspace = sandbox.workspace("ws-pinned");
    install(workspace, sandbox.home);

    // Operator config — the whole point is that the root is set by the operator
    // in the installer-managed .mcp.json env, never by an agent.
    const pinned = path.join(sandbox.home, "operator-chosen-root");
    const mcpPath = path.join(workspace, ".mcp.json");
    const mcp = readJson(mcpPath);
    mcp.mcpServers["hacker-bob"].env = { [SESSIONS_ROOT_ENV_VAR]: pinned };
    fs.writeFileSync(mcpPath, `${JSON.stringify(mcp, null, 2)}\n`, "utf8");

    const result = install(workspace, sandbox.home);
    assert.equal(result.sessionsRootSource, "operator_pinned");
    assert.equal(configuredSessionsRoot(workspace), pinned);
    assert.equal(readJson(path.join(workspace, ".claude", "settings.json")).env[SESSIONS_ROOT_ENV_VAR], pinned);
  } finally {
    sandbox.cleanup();
  }
});

test("doctor and uninstall still recognize a Bob-managed entry that carries the env block", () => {
  const sandbox = makeSandbox();
  try {
    const workspace = sandbox.workspace("ws-lifecycle");
    install(workspace, sandbox.home);
    assert.ok(configuredSessionsRoot(workspace), "precondition: the entry carries an env block");

    const doctor = withTestHome(sandbox.home, () => doctorProject(workspace, {
      sourceRoot: ROOT,
      onAdapterResolution: () => {},
    }));
    assert.ok(
      doctor.checks.some((check) => check.id === "claude_mcp_server_config" && check.status === "ok"),
      `doctor must accept the env-carrying entry: ${JSON.stringify(doctor.checks.filter((c) => c.status === "error"))}`,
    );

    withTestHome(sandbox.home, () => uninstallProject(workspace, {
      sourceRoot: ROOT,
      dryRun: false,
      onAdapterResolution: () => {},
    }));
    const after = fs.existsSync(path.join(workspace, ".mcp.json"))
      ? readJson(path.join(workspace, ".mcp.json"))
      : {};
    assert.equal(after.mcpServers && after.mcpServers["hacker-bob"], undefined);
  } finally {
    sandbox.cleanup();
  }
});

test("the session guards protect the configured root, not just the default one", () => {
  const sandbox = makeSandbox();
  try {
    const configured = path.join(sandbox.home, "hacker-bob-sessions-guarded-0123456789ab");
    fs.mkdirSync(path.join(configured, "example.com"), { recursive: true, mode: 0o700 });
    const payload = JSON.stringify({
      tool_name: "Write",
      tool_input: { file_path: path.join(configured, "example.com", "report.md"), content: "x" },
    });
    const run = (env) => {
      try {
        execFileSync("bash", [path.join(ROOT, ".claude", "hooks", "session-write-guard.sh")], {
          input: payload,
          env: { ...process.env, HOME: sandbox.home, CLAUDE_PROJECT_DIR: sandbox.root, ...env },
          encoding: "utf8",
        });
        return 0;
      } catch (error) {
        return error.status;
      }
    };

    // Moving the session root must not turn the write guard into a no-op: an
    // audit-graded file under the CONFIGURED root is still MCP-write-only.
    assert.equal(run({ [SESSIONS_ROOT_ENV_VAR]: configured }), 2);

    // Discovery also works off the workspace config alone, so the guard holds
    // even if the host never exports the variable to hooks.
    fs.writeFileSync(
      path.join(sandbox.root, ".mcp.json"),
      `${JSON.stringify({
        mcpServers: { "hacker-bob": { command: "node", args: ["x"], env: { [SESSIONS_ROOT_ENV_VAR]: configured } } },
      }, null, 2)}\n`,
      "utf8",
    );
    assert.equal(run({}), 2);
  } finally {
    sandbox.cleanup();
  }
});

test("session-root resolution and the Bob-managed entry matcher hold their contracts", () => {
  const sandbox = makeSandbox();
  try {
    const workspace = sandbox.workspace("ws-unit");

    // A fresh workspace derives; nothing else is consulted.
    assert.deepEqual(
      resolveWorkspaceSessionsRoot({ targetAbs: workspace, home: sandbox.home }),
      { sessionsRoot: workspaceSessionsRoot(workspace, { home: sandbox.home }), source: "derived" },
    );

    // A relative pin is not a usable root and must never be adopted.
    assert.equal(
      resolveWorkspaceSessionsRoot({
        targetAbs: workspace,
        pinned: ["relative/sessions", "", null],
        home: sandbox.home,
      }).source,
      "derived",
    );

    // Distinct workspaces never collide.
    assert.notEqual(
      workspaceSessionsRoot(path.join(sandbox.root, "a"), { home: sandbox.home }),
      workspaceSessionsRoot(path.join(sandbox.root, "b"), { home: sandbox.home }),
    );

    const serverPath = path.join(workspace, "mcp", "server.js");
    assert.equal(isBobManagedMcpServerEntry(bobMcpServerEntry({ serverPath }), { serverPath }), true);
    assert.equal(
      isBobManagedMcpServerEntry(bobMcpServerEntry({ serverPath, sessionsRoot: "/tmp/root" }), { serverPath }),
      true,
    );
    // An operator-added env key means the entry is no longer purely Bob's:
    // doctor must not claim it and uninstall must not delete it.
    assert.equal(
      isBobManagedMcpServerEntry(
        { command: "node", args: [serverPath], env: { [SESSIONS_ROOT_ENV_VAR]: "/tmp/root", OPERATOR: "1" } },
        { serverPath },
      ),
      false,
    );
    assert.equal(
      isBobManagedMcpServerEntry({ command: "node", args: ["/elsewhere/server.js"] }, { serverPath }),
      false,
    );
  } finally {
    sandbox.cleanup();
  }
});
