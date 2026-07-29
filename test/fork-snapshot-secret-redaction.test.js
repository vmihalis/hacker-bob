"use strict";

// fx-gate-bypass defense 5 — infra/aws/kyberfork/scripts/fork-snapshot.sh must never
// write an unredacted $ARCHIVE_RPC value to its persistent-looking LOG_FILE, and that
// LOG_FILE must never survive past the script's own run (success or failure). This
// spawns the REAL script (bash) against a fake `anvil` binary on PATH that mimics
// anvil's CLI flags and echoes the fork URL back (the exact leak shape this defense
// guards against), then inspects the script's own stdout/stderr plus the system tmp
// dir for any leftover kyberfork-anvil-log.* file.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawnSync } = require("child_process");

const SCRIPT_PATH = path.join(__dirname, "..", "infra", "aws", "kyberfork", "scripts", "fork-snapshot.sh");
const SECRET_RPC = "https://archive.example.com/v1/SUPERSECRETKEY123";
const REDACTED = "[REDACTED-ARCHIVE_RPC]";

function writeFakeAnvil(dir, body) {
  const anvilPath = path.join(dir, "anvil");
  fs.writeFileSync(anvilPath, `#!/usr/bin/env bash\n${body}\n`, { mode: 0o755 });
  return anvilPath;
}

function listLeftoverLogFiles() {
  const tmpDir = os.tmpdir();
  return fs.readdirSync(tmpDir).filter((name) => name.startsWith("kyberfork-anvil-log."));
}

function runScript(workDir, fakeAnvilDir) {
  return spawnSync("bash", [SCRIPT_PATH], {
    cwd: workDir,
    env: { ...process.env, ARCHIVE_RPC: SECRET_RPC, PATH: `${fakeAnvilDir}:${process.env.PATH}` },
    encoding: "utf8",
    // The script's own "no dump produced" branch polls for up to 30 x 1s
    // before giving up (see fork-snapshot.sh's `for _ in $(seq 1 30)` dump
    // wait loop), so this must comfortably exceed that.
    timeout: 45000,
  });
}

test("fork-snapshot.sh: success path produces OUT_FILE, redacts the secret, and leaves no LOG_FILE on disk", () => {
  const fakeAnvilDir = fs.mkdtempSync(path.join(os.tmpdir(), "bob-fork-snapshot-anvil-"));
  const workDir = fs.mkdtempSync(path.join(os.tmpdir(), "bob-fork-snapshot-work-"));
  const before = new Set(listLeftoverLogFiles());
  try {
    writeFakeAnvil(fakeAnvilDir, `
FORK_URL=""
DUMP_STATE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --fork-url) FORK_URL="$2"; shift 2 ;;
    --dump-state) DUMP_STATE="$2"; shift 2 ;;
    *) shift ;;
  esac
done
echo "Fetching fork data from $FORK_URL"
echo "Listening on 127.0.0.1:8545"
trap 'echo "{\\"fake\\":\\"dump\\"}" > "$DUMP_STATE"; exit 0' TERM
while true; do sleep 1; done
`);

    const result = runScript(workDir, fakeAnvilDir);
    assert.equal(result.status, 0, `expected clean exit; stderr=${result.stderr}`);
    assert.equal(fs.existsSync(path.join(workDir, "kyberswap-fork.json")), true, "OUT_FILE must be produced");
    assert.equal(result.stdout.includes(SECRET_RPC), false, "stdout must never contain the raw secret");
    assert.equal(result.stderr.includes(SECRET_RPC), false, "stderr must never contain the raw secret");

    const after = listLeftoverLogFiles();
    const newLeftovers = after.filter((name) => !before.has(name));
    assert.deepEqual(newLeftovers, [], `no kyberfork-anvil-log.* file may persist after a successful run; found: ${newLeftovers}`);
  } finally {
    fs.rmSync(fakeAnvilDir, { recursive: true, force: true });
    fs.rmSync(workDir, { recursive: true, force: true });
  }
});

test("fork-snapshot.sh: anvil dying before readiness redacts the secret in the displayed log and leaves no LOG_FILE on disk", () => {
  const fakeAnvilDir = fs.mkdtempSync(path.join(os.tmpdir(), "bob-fork-snapshot-anvil-"));
  const workDir = fs.mkdtempSync(path.join(os.tmpdir(), "bob-fork-snapshot-work-"));
  const before = new Set(listLeftoverLogFiles());
  try {
    writeFakeAnvil(fakeAnvilDir, `
FORK_URL=""
while [ $# -gt 0 ]; do
  case "$1" in
    --fork-url) FORK_URL="$2"; shift 2 ;;
    *) shift ;;
  esac
done
echo "connection failed to $FORK_URL: ECONNREFUSED"
exit 1
`);

    const result = runScript(workDir, fakeAnvilDir);
    assert.notEqual(result.status, 0, "must exit non-zero when anvil dies before becoming ready");
    assert.equal(fs.existsSync(path.join(workDir, "kyberswap-fork.json")), false);
    assert.equal(result.stderr.includes(SECRET_RPC), false, "stderr must never contain the raw secret, even on the displayed failure log");
    assert.ok(result.stderr.includes(REDACTED), `stderr must show the redacted placeholder; got: ${result.stderr}`);

    const after = listLeftoverLogFiles();
    const newLeftovers = after.filter((name) => !before.has(name));
    assert.deepEqual(newLeftovers, [], `no kyberfork-anvil-log.* file may persist after this failure path; found: ${newLeftovers}`);
  } finally {
    fs.rmSync(fakeAnvilDir, { recursive: true, force: true });
    fs.rmSync(workDir, { recursive: true, force: true });
  }
});

test("fork-snapshot.sh: anvil ready but no dump produced redacts the secret and leaves no LOG_FILE on disk", () => {
  const fakeAnvilDir = fs.mkdtempSync(path.join(os.tmpdir(), "bob-fork-snapshot-anvil-"));
  const workDir = fs.mkdtempSync(path.join(os.tmpdir(), "bob-fork-snapshot-work-"));
  const before = new Set(listLeftoverLogFiles());
  try {
    writeFakeAnvil(fakeAnvilDir, `
FORK_URL=""
while [ $# -gt 0 ]; do
  case "$1" in
    --fork-url) FORK_URL="$2"; shift 2 ;;
    *) shift ;;
  esac
done
echo "Fetching fork data from $FORK_URL"
echo "Listening on 127.0.0.1:8545"
trap 'exit 0' TERM
while true; do sleep 1; done
`);

    const result = runScript(workDir, fakeAnvilDir);
    assert.notEqual(result.status, 0, "must exit non-zero when the dump file is never produced");
    assert.equal(fs.existsSync(path.join(workDir, "kyberswap-fork.json")), false);
    assert.equal(result.stderr.includes(SECRET_RPC), false);
    assert.ok(result.stderr.includes(REDACTED), `stderr must show the redacted placeholder; got: ${result.stderr}`);

    const after = listLeftoverLogFiles();
    const newLeftovers = after.filter((name) => !before.has(name));
    assert.deepEqual(newLeftovers, [], `no kyberfork-anvil-log.* file may persist after this failure path; found: ${newLeftovers}`);
  } finally {
    fs.rmSync(fakeAnvilDir, { recursive: true, force: true });
    fs.rmSync(workDir, { recursive: true, force: true });
  }
});
