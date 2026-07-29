"use strict";

// INDEPENDENT, BLACK-BOX round-trip test for the install drift guard.
//
// WHY THIS FILE EXISTS ALONGSIDE test/install-drift.test.js: that suite was
// written by the same agent that wrote the guard and imports its internals, so
// it can only see the failures its author already imagined. This file never
// requires scripts/lib/install-drift.js, scripts/install.js, or any adapter. It
// drives the SHIPPED CLI -- bin/hacker-bob.js install / update -- as a
// SUBPROCESS against a throwaway directory under os.tmpdir(), and judges the
// result only by what an operator can actually see: the bytes on disk and the
// bytes the run printed to stdout.
//
// The scenario that motivated the whole change: install, hand-edit an installed
// agent file, re-install, and the edit must still be reachable AND the run must
// have SAID where it went. Loud is the requirement, not merely recoverable.
//
// Three things this test deliberately probes that an in-process test cannot:
//
//   1. ORDERING. The guard's own comment claims the preservation notice is the
//      last thing printed. That is true of `install`, but bin/hacker-bob.js
//      prints its own epilogue after printInstallSummary on the `update` path,
//      so the notice is NOT last there. This file asserts the REAL full stdout
//      of the REAL process on both verbs.
//   2. $HOME. The codex/kimi/generic-mcp copy stack (family B) writes under
//      $HOME, not only into the workspace. $HOME is redirected and searched.
//   3. UPGRADE. A same-version reinstall short-circuits on digest equality and
//      never consults the ownership receipt at all. The one branch the receipt
//      exists for -- shipped content genuinely changed, destination is still
//      Bob's own bytes -- is only reachable from a source tree whose content
//      differs, so this file installs from a mutated COPY of the source.
//
// Everything asserted here was observed live against the real CLI before it was
// written down. No assertion is derived from reading the implementation.

const test = require("node:test");
const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const ROOT = path.resolve(__dirname, "..");
const LIFECYCLE_CUSTODIAN_TEST_PRELOAD = path.join(
  __dirname,
  "fixtures",
  "lifecycle-custodian-test-preload.js",
);
const ORIGINAL_NODE_OPTIONS = process.env.NODE_OPTIONS;
process.env.NODE_OPTIONS = [
  `--require=${LIFECYCLE_CUSTODIAN_TEST_PRELOAD}`,
  ORIGINAL_NODE_OPTIONS,
].filter(Boolean).join(" ");
test.after(() => {
  if (ORIGINAL_NODE_OPTIONS === undefined) delete process.env.NODE_OPTIONS;
  else process.env.NODE_OPTIONS = ORIGINAL_NODE_OPTIONS;
});

// ---------------------------------------------------------------------------
// The operator-visible interface this file is allowed to couple to.
//
// These two banners ARE the loudness contract -- they are what an operator
// reads on their screen -- so matching them exactly is the point, not a
// coupling accident. They are matched CASE-SENSITIVELY and in full for a
// concrete reason found while writing this test: a second install prints
//
//     (pinned by BOB_SESSIONS_ROOT in this workspace's config; operator-owned,
//      preserved verbatim)
//
// on the clean path. A test that searched for /preserved/i would therefore
// report a preservation notice on a run that preserved nothing, and the
// idempotence counter-case would be worthless.
// ---------------------------------------------------------------------------
const PRESERVED_BANNER = /^LOCAL EDITS PRESERVED \(\d+\)/mu;
const DRIFT_LIMIT_BANNER = /^DRIFT GUARD LIMIT REACHED \(\d+\)/mu;

// ---------------------------------------------------------------------------
// NON-VACUITY FLOORS. Invariant 6: a check that iterates a collection is
// satisfied by an empty one. Every walk below reports how many files it
// actually visited and every count is floored against one of these hardcoded
// numbers. Each floor is set BELOW the value observed live on this tree, so
// ordinary content churn does not break it, but a walk that silently saw
// nothing fails instead of passing.
// ---------------------------------------------------------------------------
const MIN_INSTALLED_FILES = 500;        // observed live: 10228
const MIN_CLAUDE_AGENT_FILES = 15;      // observed live: 21
const MIN_CLAUDE_RULE_FILES = 2;        // observed live: 2
const MIN_CODEX_HOME_FILES = 8;         // observed live: 16
const MIN_SOURCE_COPY_ENTRIES = 1000;   // observed live: >2200
const MIN_STDOUT_LINES = 20;            // observed live: 60+

// The only two files an idempotent run is allowed to rewrite: both carry an
// `updated_at` wall-clock stamp, so byte-identity is impossible for them by
// construction. The list length is asserted, so a future run that quietly adds
// a third churning file cannot be waved through by extending this array.
const TIMESTAMPED_INSTALL_METADATA = Object.freeze([
  ".claude/bob/install.json",
  ".hacker-bob/install.json",
]);
const EXPECTED_TIMESTAMPED_METADATA_COUNT = 2;

// Files every Claude install must land. Checked by existence AND by a floored
// directory count, because "the directory exists" is the vacuous version of
// this check.
const REQUIRED_INSTALLED_PATHS = Object.freeze([
  ".claude/agents/report-writer.md",
  ".claude/rules/evaluating.md",
  ".claude/rules/reporting.md",
  ".claude/commands/bob-update.md",
  ".claude/commands/bob-egress.md",
  ".claude/settings.json",
  ".claude/bob/VERSION",
  ".hacker-bob/VERSION",
  ".hacker-bob/install.json",
  ".mcp.json",
  "mcp/server.js",
]);

// The agent file the original defect destroyed. This test edits exactly this
// file for the headline scenario.
const EDITED_AGENT = ".claude/agents/report-writer.md";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function marker(label) {
  return `BOB-ROUNDTRIP-MARKER-${label}-${crypto.randomUUID()}`;
}

function makeSandbox(prefix) {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), `bob-roundtrip-${prefix}-`));
  const workspace = path.join(tempRoot, "workspace");
  const home = path.join(tempRoot, "home");
  fs.mkdirSync(workspace, { recursive: true });
  fs.mkdirSync(home, { recursive: true });
  // INVARIANT 4: the installer only ever runs against a throwaway directory
  // under os.tmpdir(). Prove it rather than assert it in a comment.
  assert.ok(
    path.resolve(tempRoot).startsWith(path.resolve(fs.realpathSync(os.tmpdir())))
      || path.resolve(tempRoot).startsWith(path.resolve(os.tmpdir())),
    `sandbox must live under os.tmpdir(): ${tempRoot}`,
  );
  assert.ok(!path.resolve(tempRoot).startsWith(ROOT), "sandbox must not live inside the repo");
  return { tempRoot, workspace, home };
}

// Drives the REAL CLI as a subprocess. Returns the full stdout/stderr the
// operator would have seen.
function runInstaller(args, { home, sourceRoot = ROOT }) {
  const env = { ...process.env, HOME: home };
  // Adapter auto-detection reads these; clear them so the host running the
  // tests cannot change which adapter is installed.
  delete env.CLAUDE_PROJECT_DIR;
  delete env.CODEX_HOME;
  delete env.KIMI_PROJECT_DIR;
  const cli = path.join(sourceRoot, "bin", "hacker-bob.js");
  const result = spawnSync(process.execPath, [cli, ...args], {
    cwd: sourceRoot,
    env,
    encoding: "utf8",
    maxBuffer: 32 * 1024 * 1024,
  });
  assert.equal(
    result.status,
    0,
    `${path.basename(cli)} ${args.join(" ")} exited ${result.status}\n`
    + `--- stdout ---\n${result.stdout}\n--- stderr ---\n${result.stderr}`,
  );
  const lines = result.stdout.split("\n");
  assert.ok(
    lines.length >= MIN_STDOUT_LINES,
    `installer printed only ${lines.length} stdout lines (floor ${MIN_STDOUT_LINES}); `
    + "a run this quiet means the assertions below would be reading an empty screen",
  );
  return { stdout: result.stdout, stderr: result.stderr, lines };
}

// Every regular file under `root`, keyed by a POSIX-separated relative path --
// the same spelling the installer prints. Symlinks are recorded as their
// target so a link swapped for a file is a visible difference, not a silent one.
function walkTree(root) {
  const files = new Map();
  const walk = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) => (
      a.name < b.name ? -1 : a.name > b.name ? 1 : 0
    ))) {
      const abs = path.join(dir, entry.name);
      const rel = path.relative(root, abs).split(path.sep).join("/");
      if (entry.isSymbolicLink()) {
        files.set(rel, `symlink:${fs.readlinkSync(abs)}`);
        continue;
      }
      if (entry.isDirectory()) {
        walk(abs);
        continue;
      }
      if (!entry.isFile()) continue;
      files.set(rel, crypto.createHash("sha256").update(fs.readFileSync(abs)).digest("hex"));
    }
  };
  if (fs.existsSync(root)) walk(root);
  return files;
}

function snapshot(root, { floor, label }) {
  const files = walkTree(root);
  assert.ok(
    files.size >= floor,
    `${label}: walked ${files.size} files under ${root}, below the hardcoded floor of ${floor}. `
    + "An empty walk satisfies every per-file assertion below vacuously.",
  );
  return files;
}

// Returns { added, removed, changed } as sorted arrays of relative paths.
function diffSnapshots(before, after) {
  const keys = new Set([...before.keys(), ...after.keys()]);
  const added = [];
  const removed = [];
  const changed = [];
  for (const key of [...keys].sort()) {
    const a = before.get(key);
    const b = after.get(key);
    if (a === b) continue;
    if (a === undefined) added.push(key);
    else if (b === undefined) removed.push(key);
    else changed.push(key);
  }
  return { added, removed, changed };
}

// Locates a marker string anywhere under `root`. Returns the relative paths
// holding it plus the number of files actually read, so the caller can floor it.
function findMarker(root, needle) {
  const holders = [];
  let visited = 0;
  const walk = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const abs = path.join(dir, entry.name);
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) {
        walk(abs);
        continue;
      }
      if (!entry.isFile()) continue;
      visited += 1;
      if (fs.readFileSync(abs).includes(needle)) {
        holders.push(path.relative(root, abs).split(path.sep).join("/"));
      }
    }
  };
  if (fs.existsSync(root)) walk(root);
  return { holders, visited };
}

// The operator has to be able to FIND the preserved copy. The installer prints
// workspace-relative paths for files inside the target and absolute paths for
// files it wrote under $HOME, so both spellings count as "named".
function assertRunNamesPath(stdout, root, relativePath, context) {
  const absolute = path.join(root, ...relativePath.split("/"));
  const named = stdout.includes(relativePath) || stdout.includes(absolute);
  assert.ok(
    named,
    `${context}: the run never printed where it put ${relativePath}. `
    + "A preserved file the run does not mention is not a warning, it is a hiding place.\n"
    + `--- stdout ---\n${stdout}`,
  );
}

function assertQuietRun(stdout, context) {
  assert.ok(
    !PRESERVED_BANNER.test(stdout),
    `${context}: the run printed a preservation banner with nothing to preserve.\n--- stdout ---\n${stdout}`,
  );
  assert.ok(
    !DRIFT_LIMIT_BANNER.test(stdout),
    `${context}: the run reported an incomplete-protection limit on a clean path.\n--- stdout ---\n${stdout}`,
  );
}

function appendLine(filePath, line) {
  fs.appendFileSync(filePath, `\n${line}\n`, "utf8");
}

// ---------------------------------------------------------------------------
// A COPY of the source tree, so an UPGRADE can be simulated honestly: install
// from the copy, change what the copy ships, install again. Same-version
// reinstalls never exercise the ownership receipt, because an unchanged file's
// incoming bytes equal its on-disk bytes and the write short-circuits before
// the receipt is consulted.
//
// Two facts about this copy, both established by running it:
//   - the top-level node_modules must be a REAL directory. A symlink is
//     rejected with "Runtime dependency source ancestry was rejected", and
//     omitting it fails earlier still with "Cannot find module 'psl'".
//   - NESTED node_modules (mcp/node_modules, packages/*/node_modules) are not
//     read by the installer: a copy without them still reports the full
//     "dependency files 9533" line, so they are skipped to keep the copy small.
// ---------------------------------------------------------------------------
let sharedSourceCopy = null;

function sourceCopy() {
  if (sharedSourceCopy) return sharedSourceCopy;
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bob-roundtrip-source-"));
  const destination = path.join(tempRoot, "source");
  let entries = 0;
  fs.cpSync(ROOT, destination, {
    recursive: true,
    dereference: false,
    filter(src) {
      const base = path.basename(src);
      if (base === ".git") return false;
      if (base === "node_modules" && path.dirname(src) !== ROOT) return false;
      entries += 1;
      return true;
    },
  });
  assert.ok(
    entries >= MIN_SOURCE_COPY_ENTRIES,
    `source copy saw only ${entries} entries (floor ${MIN_SOURCE_COPY_ENTRIES}); `
    + "a truncated copy would make every upgrade assertion below meaningless",
  );
  assert.ok(
    fs.statSync(path.join(destination, "node_modules")).isDirectory(),
    "the copied source needs a real node_modules directory",
  );
  sharedSourceCopy = { tempRoot, destination };
  return sharedSourceCopy;
}

test.after(() => {
  if (sharedSourceCopy) fs.rmSync(sharedSourceCopy.tempRoot, { recursive: true, force: true });
  sharedSourceCopy = null;
});

// ---------------------------------------------------------------------------
// 1. THE GATE. A real install cycle must not destroy a hand edit, and must say
//    where it put it.
// ---------------------------------------------------------------------------

test("a hand-edited agent file survives a real install cycle and the run names where it went", () => {
  const { tempRoot, workspace, home } = makeSandbox("gate");
  const needle = marker("GATE");
  try {
    // --- 1. install into an empty target ------------------------------------
    const first = runInstaller(["install", "--adapter", "claude", workspace], { home });
    assertQuietRun(first.stdout, "first install into an empty directory");

    const installed = snapshot(workspace, { floor: MIN_INSTALLED_FILES, label: "first install" });
    let requiredSeen = 0;
    for (const relativePath of REQUIRED_INSTALLED_PATHS) {
      assert.ok(installed.has(relativePath), `first install did not land ${relativePath}`);
      requiredSeen += 1;
    }
    assert.equal(
      requiredSeen,
      REQUIRED_INSTALLED_PATHS.length,
      "the required-path loop did not visit every declared path",
    );
    const agentCount = [...installed.keys()].filter((key) => key.startsWith(".claude/agents/")).length;
    const ruleCount = [...installed.keys()].filter((key) => key.startsWith(".claude/rules/")).length;
    assert.ok(
      agentCount >= MIN_CLAUDE_AGENT_FILES,
      `installed ${agentCount} Claude agent definitions, below the floor of ${MIN_CLAUDE_AGENT_FILES}`,
    );
    assert.ok(
      ruleCount >= MIN_CLAUDE_RULE_FILES,
      `installed ${ruleCount} Claude rules, below the floor of ${MIN_CLAUDE_RULE_FILES}`,
    );

    // --- 2. hand-edit an installed agent file -------------------------------
    const editedAbs = path.join(workspace, ...EDITED_AGENT.split("/"));
    const shippedBytes = fs.readFileSync(editedAbs);
    appendLine(editedAbs, needle);
    const editedDigest = crypto.createHash("sha256")
      .update(fs.readFileSync(editedAbs)).digest("hex");
    assert.notEqual(editedDigest, installed.get(EDITED_AGENT), "the hand edit did not change the file");

    // --- 3. re-install from the same source ---------------------------------
    const second = runInstaller(["update", "--adapter", "claude", workspace], { home });

    // --- 4. the marker must still be reachable ------------------------------
    const found = findMarker(workspace, needle);
    assert.ok(
      found.visited >= MIN_INSTALLED_FILES,
      `marker search read only ${found.visited} files (floor ${MIN_INSTALLED_FILES})`,
    );
    assert.ok(
      found.holders.length >= 1,
      "the operator's edit is GONE: no file under the workspace still contains the marker. "
      + `Searched ${found.visited} files.\n--- update stdout ---\n${second.stdout}`,
    );

    // --- 5. and the run must have NAMED the place it put it -----------------
    const inPlaceHoldsMarker = found.holders.includes(EDITED_AGENT);
    if (!inPlaceHoldsMarker) {
      assert.ok(
        PRESERVED_BANNER.test(second.stdout),
        "the edit was moved out of the installed path but the run printed no preservation banner: "
        + `recoverable, not loud.\n--- update stdout ---\n${second.stdout}`,
      );
      let namedCount = 0;
      for (const holder of found.holders) {
        assertRunNamesPath(second.stdout, workspace, holder, "preserved copy");
        namedCount += 1;
      }
      assert.ok(namedCount >= 1, "no preserved path was checked against the run output");

      // Bob's own version has to be back in place, or the operator lost the
      // upgrade instead of the edit.
      assert.ok(fs.existsSync(editedAbs), "the installed path was left empty after preservation");
      assert.equal(
        crypto.createHash("sha256").update(fs.readFileSync(editedAbs)).digest("hex"),
        crypto.createHash("sha256").update(shippedBytes).digest("hex"),
        "the installed path does not hold the shipped bytes after preservation",
      );
    }

    // --- ORDERING, against the REAL process stdout --------------------------
    // The notice must sit at the END of the run, not buried mid-scroll. It is
    // NOT literally last on the `update` path: bin/hacker-bob.js prints its own
    // restart epilogue after printInstallSummary returns. That is the observed
    // behaviour and it is pinned here so a future change to either side is
    // visible.
    const bannerIndex = second.lines.findIndex((line) => /^LOCAL EDITS PRESERVED \(/u.test(line));
    const doneIndex = second.lines.findIndex((line) => /^Done\. /u.test(line));
    assert.ok(doneIndex >= 0, `the update never printed a "Done." line\n${second.stdout}`);
    assert.ok(bannerIndex > doneIndex, "the preservation notice was printed before the summary finished");

    const lastNamedIndex = second.lines.reduce(
      (best, line, index) => (found.holders.some((holder) => line.includes(holder)) ? index : best),
      -1,
    );
    assert.ok(lastNamedIndex > bannerIndex, "the preserved path was not named inside the notice block");
    const trailing = second.lines.slice(lastNamedIndex + 1).filter((line) => line.trim() !== "");
    let trailingChecked = 0;
    for (const line of trailing) {
      // Only the notice's own closing advice and the CLI's restart epilogue may
      // follow the preserved path. Anything else means the warning is being
      // pushed off the operator's screen.
      assert.match(
        line,
        /^(?:\s+Re-apply anything you still want|Update complete\.)/u,
        `unexpected output after the preservation notice: ${JSON.stringify(line)}`,
      );
      trailingChecked += 1;
    }
    assert.ok(
      trailingChecked >= 1,
      "expected the CLI restart epilogue after the notice; the ordering claim is unproven without it",
    );
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// 2. IDEMPOTENCE. A guard that fires on everything is as useless as one that
//    never fires.
// ---------------------------------------------------------------------------

test("a second install with no local edit changes nothing on disk and says nothing new", () => {
  const { tempRoot, workspace, home } = makeSandbox("idempotent");
  try {
    assert.equal(
      TIMESTAMPED_INSTALL_METADATA.length,
      EXPECTED_TIMESTAMPED_METADATA_COUNT,
      "the churn exemption list changed size; a new churning file needs justification, not an entry",
    );

    const first = runInstaller(["install", "--adapter", "claude", workspace], { home });
    const before = snapshot(workspace, { floor: MIN_INSTALLED_FILES, label: "first install" });

    const second = runInstaller(["install", "--adapter", "claude", workspace], { home });
    const after = snapshot(workspace, { floor: MIN_INSTALLED_FILES, label: "second install" });

    const { added, removed, changed } = diffSnapshots(before, after);
    assert.deepEqual(added, [], "a clean re-install created files that were not there before");
    assert.deepEqual(removed, [], "a clean re-install removed files");
    let changedChecked = 0;
    for (const key of changed) {
      assert.ok(
        TIMESTAMPED_INSTALL_METADATA.includes(key),
        `a clean re-install rewrote ${key}, which is not one of the timestamped metadata files`,
      );
      changedChecked += 1;
    }
    assert.equal(changedChecked, changed.length, "the changed-file loop did not visit every changed file");
    // Non-vacuity for the comparison itself: the two metadata files must exist
    // in BOTH snapshots, otherwise "nothing unexpected changed" could be true
    // because nothing was compared.
    let metadataSeen = 0;
    for (const key of TIMESTAMPED_INSTALL_METADATA) {
      assert.ok(before.has(key), `${key} missing from the first snapshot`);
      assert.ok(after.has(key), `${key} missing from the second snapshot`);
      metadataSeen += 1;
    }
    assert.equal(metadataSeen, EXPECTED_TIMESTAMPED_METADATA_COUNT);

    // NOT ONE preservation line.
    assertQuietRun(second.stdout, "clean re-install");

    // And nothing new said, either. The only line the second run adds is the
    // session-root pin note -- which contains the word "preserved" and is
    // exactly the decoy a case-insensitive banner search would trip on.
    const firstLines = new Set(first.lines);
    const newLines = second.lines.filter((line) => line.trim() !== "" && !firstLines.has(line));
    let newLinesChecked = 0;
    for (const line of newLines) {
      assert.doesNotMatch(line, /LOCAL EDITS PRESERVED/u, `clean re-install said: ${line}`);
      assert.doesNotMatch(line, /DRIFT GUARD LIMIT/u, `clean re-install said: ${line}`);
      newLinesChecked += 1;
    }
    assert.equal(newLinesChecked, newLines.length);
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// 3. A FILE THE OPERATOR DELETED. Restored, without a spurious warning.
// ---------------------------------------------------------------------------

test("files the operator deleted are restored on the next install with no spurious warning", () => {
  const { tempRoot, workspace, home } = makeSandbox("deleted");
  const deleted = Object.freeze([EDITED_AGENT, ".claude/rules/reporting.md"]);
  try {
    runInstaller(["install", "--adapter", "claude", workspace], { home });
    const before = snapshot(workspace, { floor: MIN_INSTALLED_FILES, label: "install" });

    let deletedCount = 0;
    for (const relativePath of deleted) {
      const abs = path.join(workspace, ...relativePath.split("/"));
      assert.ok(before.has(relativePath), `${relativePath} was never installed, so deleting it proves nothing`);
      fs.rmSync(abs);
      assert.ok(!fs.existsSync(abs), `${relativePath} was not actually removed`);
      deletedCount += 1;
    }
    assert.equal(deletedCount, 2, "the delete loop must remove exactly the two declared files");

    const second = runInstaller(["update", "--adapter", "claude", workspace], { home });
    const after = snapshot(workspace, { floor: MIN_INSTALLED_FILES, label: "restore install" });

    let restoredCount = 0;
    for (const relativePath of deleted) {
      assert.equal(
        after.get(relativePath),
        before.get(relativePath),
        `${relativePath} was not restored byte-for-byte`,
      );
      restoredCount += 1;
    }
    assert.equal(restoredCount, deleted.length);

    const { added, removed, changed } = diffSnapshots(before, after);
    assert.deepEqual(added, [], "restoring a deleted file left extra files behind");
    assert.deepEqual(removed, [], "the restore run removed files");
    for (const key of changed) {
      assert.ok(TIMESTAMPED_INSTALL_METADATA.includes(key), `the restore run rewrote ${key}`);
    }

    assertQuietRun(second.stdout, "restoring an operator-deleted file");
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// 4-6. UPGRADE. The branch a same-version reinstall can never reach.
// ---------------------------------------------------------------------------

test("a genuine upgrade replaces Bob's own untouched file quietly", () => {
  const { tempRoot, workspace, home } = makeSandbox("upgrade-clean");
  const sourceRoot = sourceCopy().destination;
  const shipped = marker("SHIPPED-V2");
  try {
    runInstaller(["install", "--adapter", "claude", workspace], { home, sourceRoot });
    const before = snapshot(workspace, { floor: MIN_INSTALLED_FILES, label: "install from source copy" });

    // The shipped content genuinely changes between the two runs. The operator
    // never touches the installed file, so its bytes still match the receipt --
    // this is the "recorded digest authorizes the overwrite" branch.
    appendLine(path.join(sourceRoot, ...EDITED_AGENT.split("/")), shipped);

    const second = runInstaller(["update", "--adapter", "claude", workspace], { home, sourceRoot });
    const after = snapshot(workspace, { floor: MIN_INSTALLED_FILES, label: "upgrade" });

    const installedAgent = fs.readFileSync(path.join(workspace, ...EDITED_AGENT.split("/")), "utf8");
    assert.ok(installedAgent.includes(shipped), "the upgrade did not land the new shipped bytes");
    assert.notEqual(after.get(EDITED_AGENT), before.get(EDITED_AGENT), "the upgraded file did not change");

    const { added, removed, changed } = diffSnapshots(before, after);
    assert.deepEqual(added, [], "the upgrade left a preserved copy behind for a file nobody edited");
    assert.deepEqual(removed, []);
    assert.ok(changed.includes(EDITED_AGENT), "the upgraded file is missing from the change set");
    let unexpected = 0;
    for (const key of changed) {
      if (key === EDITED_AGENT || TIMESTAMPED_INSTALL_METADATA.includes(key)) continue;
      unexpected += 1;
    }
    assert.equal(unexpected, 0, `the upgrade rewrote unrelated files: ${changed.join(", ")}`);

    assertQuietRun(second.stdout, "upgrading a file the operator never touched");
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});

test("a genuine upgrade preserves the operator's edit and still lands the new shipped bytes", () => {
  const { tempRoot, workspace, home } = makeSandbox("upgrade-edited");
  const sourceRoot = sourceCopy().destination;
  const target = ".claude/agents/chain-builder.md";
  const shipped = marker("SHIPPED-V3");
  const local = marker("OPERATOR");
  try {
    runInstaller(["install", "--adapter", "claude", workspace], { home, sourceRoot });
    snapshot(workspace, { floor: MIN_INSTALLED_FILES, label: "install from source copy" });

    appendLine(path.join(workspace, ...target.split("/")), local);
    appendLine(path.join(sourceRoot, ...target.split("/")), shipped);

    const second = runInstaller(["update", "--adapter", "claude", workspace], { home, sourceRoot });

    const found = findMarker(workspace, local);
    assert.ok(
      found.visited >= MIN_INSTALLED_FILES,
      `marker search read only ${found.visited} files (floor ${MIN_INSTALLED_FILES})`,
    );
    assert.ok(
      found.holders.length >= 1,
      `the operator's edit to ${target} is gone after an upgrade\n--- stdout ---\n${second.stdout}`,
    );
    assert.ok(
      PRESERVED_BANNER.test(second.stdout),
      `the upgrade moved the operator's edit without a banner\n--- stdout ---\n${second.stdout}`,
    );
    let namedCount = 0;
    for (const holder of found.holders) {
      assertRunNamesPath(second.stdout, workspace, holder, "preserved copy on upgrade");
      namedCount += 1;
    }
    assert.ok(namedCount >= 1);

    // The whole point of preserving instead of refusing: the operator keeps the
    // edit AND gets the new release.
    const installedAgent = fs.readFileSync(path.join(workspace, ...target.split("/")), "utf8");
    assert.ok(installedAgent.includes(shipped), "the upgrade did not land the new shipped bytes");
    assert.ok(!installedAgent.includes(local), "the installed path still holds the operator's edit");
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});

test("an install.json carrying no ownership record fails safe and preserves rather than assuming clean", () => {
  const { tempRoot, workspace, home } = makeSandbox("no-receipt");
  const sourceRoot = sourceCopy().destination;
  const target = ".claude/agents/balanced-verifier.md";
  const shipped = marker("SHIPPED-V4");
  try {
    runInstaller(["install", "--adapter", "claude", workspace], { home, sourceRoot });

    // Simulate an upgrade from a Bob that predates the ownership receipt: the
    // install.json on disk carries no per-file digests at all. Nothing else is
    // touched, and the file edited here is the installer's own metadata, not a
    // private structure -- an older release simply never wrote the key.
    const metadataPath = path.join(workspace, ".hacker-bob", "install.json");
    const metadata = JSON.parse(fs.readFileSync(metadataPath, "utf8"));
    const ownershipKeys = Object.keys(metadata).filter((key) => /ownership/u.test(key));
    assert.ok(
      ownershipKeys.length >= 1,
      "install.json carries no ownership key at all, so removing one proves nothing "
      + `(keys: ${Object.keys(metadata).join(", ")})`,
    );
    let strippedKeys = 0;
    for (const key of ownershipKeys) {
      if (key === "mcp_top_level_runtime_ownership") continue; // a different, pre-existing record
      delete metadata[key];
      strippedKeys += 1;
    }
    assert.ok(strippedKeys >= 1, "no per-file ownership record was found to strip");
    fs.writeFileSync(metadataPath, `${JSON.stringify(metadata, null, 2)}\n`, "utf8");

    // Shipped content changes, the operator changed NOTHING. With no record,
    // the guard cannot tell Bob's own bytes from local work, and must preserve.
    appendLine(path.join(sourceRoot, ...target.split("/")), shipped);
    const before = snapshot(workspace, { floor: MIN_INSTALLED_FILES, label: "pre-upgrade" });

    const second = runInstaller(["update", "--adapter", "claude", workspace], { home, sourceRoot });
    const after = snapshot(workspace, { floor: MIN_INSTALLED_FILES, label: "post-upgrade" });

    assert.ok(
      PRESERVED_BANNER.test(second.stdout),
      "with no ownership record the installer overwrote without a word: it assumed clean instead of failing safe\n"
      + `--- stdout ---\n${second.stdout}`,
    );

    const { added } = diffSnapshots(before, after);
    assert.ok(
      added.length >= 1,
      "nothing was set aside, so 'fail safe' was not what happened",
    );
    let namedCount = 0;
    for (const key of added) {
      assertRunNamesPath(second.stdout, workspace, key, "fail-safe preserved copy");
      namedCount += 1;
    }
    assert.equal(namedCount, added.length, "not every newly created file was named by the run");
    // The preserved copy must hold the bytes that were on disk before the run.
    const preservedForTarget = added.filter((key) => key.startsWith(target));
    assert.ok(
      preservedForTarget.length >= 1,
      `expected a preserved copy beside ${target}, got: ${added.join(", ")}`,
    );
    let verified = 0;
    for (const key of preservedForTarget) {
      assert.equal(
        after.get(key),
        before.get(target),
        `${key} does not carry the bytes that were installed at ${target}`,
      );
      verified += 1;
    }
    assert.ok(verified >= 1);
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// 7. $HOME. The second copy stack writes outside the workspace entirely.
// ---------------------------------------------------------------------------

test("an edit to a file the installer wrote under $HOME is preserved and named in the run output", () => {
  const { tempRoot, workspace, home } = makeSandbox("home");
  const needle = marker("HOME");
  const homeTarget = path.join(home, ".codex", "skills", "bob-status", "SKILL.md");
  try {
    const first = runInstaller(["install", "--adapter", "codex", workspace], { home });
    assertQuietRun(first.stdout, "first codex install");

    const homeBefore = snapshot(home, { floor: MIN_CODEX_HOME_FILES, label: "codex $HOME install" });
    assert.ok(
      fs.existsSync(homeTarget),
      `the codex install wrote nothing to ${homeTarget}; this test would be checking the wrong stack`,
    );

    appendLine(homeTarget, needle);
    const second = runInstaller(["install", "--adapter", "codex", workspace], { home });

    const found = findMarker(home, needle);
    assert.ok(
      found.visited >= MIN_CODEX_HOME_FILES,
      `$HOME marker search read only ${found.visited} files (floor ${MIN_CODEX_HOME_FILES})`,
    );
    assert.ok(
      found.holders.length >= 1,
      `the edit under $HOME is gone; searched ${found.visited} files\n--- stdout ---\n${second.stdout}`,
    );
    assert.ok(
      PRESERVED_BANNER.test(second.stdout),
      `an edit under $HOME was moved with no banner\n--- stdout ---\n${second.stdout}`,
    );
    let namedCount = 0;
    for (const holder of found.holders) {
      assertRunNamesPath(second.stdout, home, holder, "$HOME preserved copy");
      namedCount += 1;
    }
    assert.ok(namedCount >= 1);

    // A file under $HOME is outside the install target, so the run has to print
    // an ABSOLUTE path -- a workspace-relative one would be unresolvable.
    let absoluteMentions = 0;
    for (const holder of found.holders) {
      if (second.stdout.includes(path.join(home, ...holder.split("/")))) absoluteMentions += 1;
    }
    assert.equal(
      absoluteMentions,
      found.holders.length,
      "a preserved file outside the workspace was named by a relative path the operator cannot resolve",
    );

    // Bob's own copy is back at the installed path.
    const homeAfter = walkTree(home);
    assert.ok(homeAfter.has(".codex/skills/bob-status/SKILL.md"), "the installed $HOME path was left empty");
    assert.equal(
      homeAfter.get(".codex/skills/bob-status/SKILL.md"),
      homeBefore.get(".codex/skills/bob-status/SKILL.md"),
      "the installed $HOME path does not hold the shipped bytes after preservation",
    );

    // On the `install` verb the notice really is the last thing on screen --
    // bin/hacker-bob.js only adds its restart epilogue on `update`. Pinning
    // both verbs is the point: the guard's own comment claims "last" without
    // that distinction.
    const trailing = second.lines
      .slice(second.lines.findIndex((line) => /^LOCAL EDITS PRESERVED \(/u.test(line)) + 1)
      .filter((line) => line.trim() !== "");
    assert.ok(trailing.length >= 1, "the preservation banner printed no body");
    assert.match(
      trailing[trailing.length - 1],
      /^\s+Re-apply anything you still want/u,
      `on the install verb the notice must be the last output; got: ${JSON.stringify(trailing.slice(-3))}`,
    );
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});
