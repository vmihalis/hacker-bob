"use strict";

// HIGH-1 (shadow-test poison): the invariant runner must pin forge to the EXACT generated
// file (--match-path) and anchor the match filters to the full identifier (^...$), so a
// dishonest agent's shadow .t.sol whose contract/test name merely CONTAINS the generated
// name is never selected. These tests exercise runFoundryTest's arg-builder directly: the
// no-fork-endpoint refused envelope exposes the built `command`, so we can assert the flags
// without a real forge binary. The standalone bob_foundry_run path (no matchPath/anchorMatch)
// must stay UNANCHORED with NO --match-path (single-surface unregressed).

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const { runFoundryTest } = require("../mcp/domains/blockchain/smart-contracts/foundry-runner.js");

// Drive runFoundryTest down the no-fork-endpoints refused path so the returned envelope
// carries the built command verbatim. A bogus chain_id with a private fork_url is policy-
// rejected to zero endpoints, so we never spawn forge. The harness only needs to be a real
// directory under HOME with a test/ subdir (assertHarnessPath + ensureHarnessTestDir are not
// on this code path — only assertHarnessPath is, via runFoundryTest).
function withHarness(fn) {
  const previousHome = process.env.HOME;
  // Realpath the temp HOME so isUnderHome (which realpaths os.homedir()==process.env.HOME on
  // POSIX) compares apples to apples on macOS where /var is a symlink to /private/var.
  const home = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "bob-foundry-matchpath-")));
  process.env.HOME = home;
  const harness = path.join(home, "harness");
  fs.mkdirSync(path.join(harness, "test", "bob-invariants"), { recursive: true });
  try {
    return fn(harness, home);
  } finally {
    if (previousHome === undefined) delete process.env.HOME;
    else process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

async function builtCommand(harness, opts) {
  const result = await runFoundryTest({
    workdir: harness,
    chainId: 999999, // no endpoints -> refused, command exposed
    forkUrls: ["http://127.0.0.1:8545"], // private -> policy-rejected to zero
    ...opts,
  });
  assert.equal(result.ok, false);
  assert.ok(Array.isArray(result.command), "refused envelope exposes the built command");
  return result.command;
}

test("INVARIANT path: --match-path pins the EXACT generated file and the filters are anchored ^...$", async () => {
  await withHarness(async (harness) => {
    const writtenPath = path.join(harness, "test", "bob-invariants", "BobInvariantTest_x.t.sol");
    const cmd = await builtCommand(harness, {
      matchTest: "testBobInvariant_x",
      matchContract: "BobInvariantTest_x",
      matchPath: writtenPath,
      anchorMatch: true,
    });
    const mp = cmd.indexOf("--match-path");
    assert.ok(mp >= 0, "--match-path present on the invariant path");
    assert.equal(cmd[mp + 1], writtenPath, "--match-path is the EXACT generated file");
    const mc = cmd.indexOf("--match-contract");
    assert.equal(cmd[mc + 1], "^BobInvariantTest_x$", "contract filter anchored to the full identifier");
    const mt = cmd.indexOf("--match-test");
    assert.equal(cmd[mt + 1], "^testBobInvariant_x$", "test filter anchored to the full identifier");
  });
});

test("a same-named SHADOW contract is NOT matched: the anchored ^Contract$ filter does not match a superstring", async () => {
  await withHarness(async (harness) => {
    const cmd = await builtCommand(harness, {
      matchContract: "BobInvariantTest_x",
      anchorMatch: true,
    });
    const mc = cmd.indexOf("--match-contract");
    const anchored = cmd[mc + 1];
    assert.equal(anchored, "^BobInvariantTest_x$");
    // The anchored regex matches ONLY the exact name, never a shadow superstring.
    const re = new RegExp(anchored);
    assert.equal(re.test("BobInvariantTest_x"), true, "matches the generated contract");
    assert.equal(re.test("EvilBobInvariantTest_x"), false, "does NOT match a prefixed shadow");
    assert.equal(re.test("BobInvariantTest_xEvil"), false, "does NOT match a suffixed shadow");
  });
});

test("STANDALONE bob_foundry_run path is unregressed: NO --match-path, filters stay UNANCHORED (substring match preserved)", async () => {
  await withHarness(async (harness) => {
    const cmd = await builtCommand(harness, {
      matchTest: "testX",
      matchContract: "MyTest",
      // matchPath omitted, anchorMatch defaults false
    });
    assert.equal(cmd.indexOf("--match-path"), -1, "no --match-path on the standalone path");
    const mc = cmd.indexOf("--match-contract");
    assert.equal(cmd[mc + 1], "MyTest", "contract filter UNANCHORED (caller-supplied substring)");
    const mt = cmd.indexOf("--match-test");
    assert.equal(cmd[mt + 1], "testX", "test filter UNANCHORED (caller-supplied substring)");
  });
});

test("an agent --match-path via extra_args is STILL rejected by the allowlist (match_path is runner-controlled, never extra_args)", async () => {
  await withHarness(async (harness) => {
    await assert.rejects(
      () => runFoundryTest({
        workdir: harness,
        matchTest: "testX",
        extraArgs: ["--match-path", "/etc/passwd"],
      }),
      /not in the forge allowlist/,
      "extra_args --match-path is refused even though the runner emits its own --match-path",
    );
  });
});
