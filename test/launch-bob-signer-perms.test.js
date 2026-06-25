"use strict";

// The operator launcher's custody intent, testable on a same-uid box without a
// real second uid. The launcher's load-bearing fact is WHO owns the session tree
// (a dedicated signer uid); its modes/owner are rendered from a single in-repo
// source of truth (signing-key-custody.js) so the launcher cannot drift from the
// modes the server actually mints.
// Asserts:
//   * the rendered custody plan: session dir 0700, ed25519 private key 0400,
//     symmetric key 0600, all owned by the signer uid;
//   * octalModeString formats modes the way chmod expects;
//   * the plan covers BOTH signing secrets (verdict key + handoff-provenance key);
//   * the launcher script reads the perms from the helper (no hand-typed modes)
//     and fail-closes when the signer uid is not separate from the current uid.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const { execFileSync } = require("child_process");

const custody = require("../mcp/lib/signing-key-custody.js");

const REPO_ROOT = path.join(__dirname, "..");
const LAUNCHER = path.join(REPO_ROOT, "scripts", "launch-bob-signer.sh");

test("custody plan: session dir 0700, ed25519 key 0400, symmetric key 0600, signer-owned", () => {
  const plan = custody.renderCustodyPlan("/home/bob-signer/hacker-bob-sessions", 7777);
  assert.equal(plan.sessions_root.mode, 0o700, "session root must be owner-only 0700");
  assert.equal(plan.sessions_root.owner, "7777");
  assert.equal(plan.sessions_root.recursive_owner, true);

  const byBase = new Map(plan.secrets.map((s) => [s.basename, s]));
  const priv = byBase.get(".handoff-signing-key-ed25519.json");
  const sym = byBase.get(".handoff-signing-key.json");
  assert.ok(priv, "plan must cover the ed25519 verdict-ledger private key");
  assert.ok(sym, "plan must cover the symmetric handoff-provenance key");
  assert.equal(priv.mode, 0o400, "ed25519 private key intended mode is owner-read-only 0400");
  assert.equal(sym.mode, 0o600, "symmetric key intended mode is owner read/write 0600");
  assert.equal(priv.owner, "7777");
  assert.equal(sym.owner, "7777");
});

test("custody plan covers BOTH signing secrets behind one boundary", () => {
  assert.deepEqual(
    [...custody.SIGNING_SECRET_BASENAMES].sort(),
    [".handoff-signing-key-ed25519.json", ".handoff-signing-key.json"].sort(),
  );
});

test("octalModeString formats modes the way chmod expects", () => {
  assert.equal(custody.octalModeString(0o700), "0700");
  assert.equal(custody.octalModeString(0o600), "0600");
  assert.equal(custody.octalModeString(0o400), "0400");
});

test("renderCustodyPlan fails closed on a missing root or owner", () => {
  assert.throws(() => custody.renderCustodyPlan("", 7777), /sessions root/);
  assert.throws(() => custody.renderCustodyPlan("/x", null), /signer uid/);
  assert.throws(() => custody.renderCustodyPlan("/x", ""), /signer uid/);
});

test("launcher renders perms from the in-repo source of truth (no hand-typed modes)", () => {
  const src = fs.readFileSync(LAUNCHER, "utf8");
  // The dir mode the launcher chmods with must come from the helper, not a literal.
  assert.match(src, /signing-key-custody\.js/, "launcher must read perms from the custody helper");
  assert.match(src, /octalModeString\(c\.SIGNING_KEY_DIR_MODE\)/, "launcher must render the dir mode from the helper");
  // The launcher sets the operator env contract in the SERVER environment.
  assert.match(src, /BOB_SANDBOX_ISOLATION_ACK/);
  assert.match(src, /BOB_SANDBOX_SIGNER_UID/);
  assert.match(src, /i-run-the-bob-signer-under-a-separate-os-uid/);
});

test("launcher hardening: chown -Rh, getent/dscl HOME (no eval), agent-uid export", () => {
  const src = fs.readFileSync(LAUNCHER, "utf8");
  // chown is recursive AND -h (operate on symlinks themselves, never targets).
  assert.match(src, /chown -Rh /, "chown must use -Rh so a symlink cannot redirect the recursive chown");
  assert.doesNotMatch(src, /chown -R\s+["$]/, "the bare chown -R (symlink-following) must be gone");
  // The chmod is symlink-safe: a [ -L SESSIONS_ROOT ] refusal must precede the
  // chmod so a symlink swapped in after the owner/mode stat cannot redirect the
  // mode change off-tree (TOCTOU). POSIX chmod follows symlinks for the mode and
  // has no portable -h, so the refusal is the cross-platform close.
  const symlinkRefusalIdx = src.indexOf("is a symlink; refusing to chmod");
  const chmodIdx = src.indexOf('chmod "${DIR_MODE}"');
  assert.ok(symlinkRefusalIdx > 0, "the launcher must refuse a symlinked SESSIONS_ROOT before chmod");
  assert.ok(chmodIdx > 0, "the launcher must chmod the session root");
  assert.ok(symlinkRefusalIdx < chmodIdx, "the [ -L ] symlink refusal must precede the chmod (TOCTOU-safe)");
  assert.match(src, /if \[ -L "\$\{SESSIONS_ROOT\}" \]; then/, "the symlink refusal must lstat SESSIONS_ROOT itself");
  // HOME resolution must be a bounded passwd lookup, never eval on a user string.
  assert.doesNotMatch(src, /eval echo/, "HOME resolution must not eval a user-controlled string");
  assert.match(src, /getent passwd /, "HOME must resolve via getent on linux");
  assert.match(src, /dscl \. -read /, "HOME must resolve via dscl on darwin (no getent)");
  // SIGNER_USER is validated to a clean username before any lookup.
  assert.match(src, /BOB_SIGNER_USER has invalid characters/, "SIGNER_USER must be character-validated");
  // The new agent-uid env is derived from SUDO_UID/invoking uid, exported, and
  // preserved across the sudo drop into the server env.
  assert.match(src, /export BOB_SANDBOX_AGENT_UID="\$\{SUDO_UID:-\$\{CURRENT_UID\}\}"/, "agent uid must be derived from SUDO_UID/CURRENT_UID and exported");
  assert.match(src, /--preserve-env=[^\n]*BOB_SANDBOX_AGENT_UID/, "agent uid must survive the sudo drop");
});

test("launcher refuses a foreign-owned SESSIONS_ROOT before chowning as root (priv-esc guard)", () => {
  // A separate (non-current) signer uid passes the same-uid gate; a pre-existing
  // SESSIONS_ROOT owned by the CURRENT uid (not the signer uid) must be refused
  // BEFORE any chown -R runs over it. BOB_SIGNER_HOME points the resolver at a
  // temp tree so no real passwd lookup is needed.
  const tmpHome = fs.mkdtempSync(path.join(require("os").tmpdir(), "bob-launcher-foreign-"));
  fs.mkdirSync(path.join(tmpHome, "hacker-bob-sessions"), { recursive: true, mode: 0o777 });
  const myUid = typeof process.getuid === "function" ? process.getuid() : 0;
  const signerUid = String(myUid + 99); // a uid the current process does not own
  let stderr = "";
  let exitCode = 0;
  try {
    execFileSync("bash", [LAUNCHER], {
      env: {
        ...process.env,
        BOB_SIGNER_USER: "bob-signer-test",
        BOB_SANDBOX_SIGNER_UID: signerUid,
        BOB_SIGNER_HOME: tmpHome,
      },
      stdio: ["ignore", "ignore", "pipe"],
    });
  } catch (err) {
    exitCode = err.status == null ? 1 : err.status;
    stderr = err.stderr ? err.stderr.toString("utf8") : "";
  } finally {
    fs.rmSync(tmpHome, { recursive: true, force: true });
  }
  assert.notEqual(exitCode, 0, "launcher must exit non-zero (fail closed) on a foreign-owned tree");
  assert.match(stderr, /refusing to chown -R as root over a foreign tree/, "launcher must name the foreign-owner refusal");
});

test("launcher first-run: a NON-EXISTENT SESSIONS_ROOT is not refused by the foreign-owner die (no lockout)", () => {
  // LOW 2: previously `mkdir -p` ran as root, creating a root-owned SESSIONS_ROOT, and the
  // foreign-owner refusal (owner != signer uid) aborted a clean first run BEFORE the chown.
  // The fix provisions a freshly-created root as signer-owned BEFORE the refusal block, so a
  // first run never trips the foreign-owner die. On the dev box (not root, signer user does
  // not exist) the chown-on-create fails AFTER mkdir -> the launcher dies on THAT, never on
  // the foreign-owner refusal. Asserting the foreign-owner message is ABSENT proves the
  // first-run path provisioned the fresh root before reaching the refusal block.
  const tmpHome = fs.mkdtempSync(path.join(require("os").tmpdir(), "bob-launcher-firstrun-"));
  // Deliberately do NOT create hacker-bob-sessions; the launcher must create it.
  const sessionsRoot = path.join(tmpHome, "hacker-bob-sessions");
  assert.equal(fs.existsSync(sessionsRoot), false, "precondition: the session root does not exist");
  const myUid = typeof process.getuid === "function" ? process.getuid() : 0;
  const signerUid = String(myUid + 99); // separate from the current uid (passes the same-uid gate)
  let stderr = "";
  let exitCode = 0;
  try {
    execFileSync("bash", [LAUNCHER], {
      env: {
        ...process.env,
        BOB_SIGNER_USER: "bob-signer-test",
        BOB_SANDBOX_SIGNER_UID: signerUid,
        BOB_SIGNER_HOME: tmpHome,
      },
      stdio: ["ignore", "ignore", "pipe"],
    });
  } catch (err) {
    exitCode = err.status == null ? 1 : err.status;
    stderr = err.stderr ? err.stderr.toString("utf8") : "";
  } finally {
    fs.rmSync(tmpHome, { recursive: true, force: true });
  }
  // It still exits non-zero on the dev box (the chown to a non-existent user fails), but it
  // must NOT be the foreign-owner refusal — a clean first run is not locked out by it.
  assert.doesNotMatch(
    stderr, /refusing to chown -R as root over a foreign tree/,
    "a freshly-created root must be provisioned signer-owned BEFORE the foreign-owner refusal (no first-run lockout)",
  );
  // The non-zero exit on the dev box is the chown-on-create failing for a non-existent user,
  // which PROVES the first-run branch ran (mkdir then chown) before the refusal block.
  assert.notEqual(exitCode, 0, "dev box: the chown-on-create to a non-existent user fails (proving the first-run branch ran)");
});

test("launcher first-run ordering: the chown-on-create precedes the foreign-owner refusal in the script", () => {
  // Source-level ordering assertion (the dev box cannot exercise a real second uid): the
  // freshly-created-root chown must appear BEFORE the foreign-owner stat/refusal block.
  const src = fs.readFileSync(LAUNCHER, "utf8");
  const firstRunIdx = src.indexOf("chown freshly-created");
  const refusalIdx = src.indexOf("refusing to chown -R as root over a foreign tree");
  assert.ok(firstRunIdx > 0, "the launcher must chown a freshly-created root on first run");
  assert.ok(refusalIdx > 0, "the foreign-owner refusal must still be present (preserved for pre-existing trees)");
  assert.ok(firstRunIdx < refusalIdx, "the freshly-created-root chown must precede the foreign-owner refusal");
  // The fresh-root chown must be gated strictly on non-existence so a PRE-EXISTING tree
  // still goes through the full refusal (no security regression).
  assert.match(src, /if \[ ! -d "\$\{SESSIONS_ROOT\}" \]; then/, "the chown-on-create must be gated on the root not existing");
});

test("HIGH-2: the launcher's stat-detection yields the REAL owner uid + octal mode on this host (GNU or BSD)", () => {
  // Drive the EXACT stat-detection block from the launcher against a fixture dir on
  // the host (darwin/BSD in dev, linux/GNU in CI). It must report the real owner uid
  // and octal mode regardless of platform. This guards against the GNU `stat -f`
  // =--file-system mis-read (which would put garbage in ROOT_OWNER_UID/ROOT_PERM and
  // defeat the foreign-owner + writable refusals on linux).
  const src = fs.readFileSync(LAUNCHER, "utf8");
  // Pull the launcher's stat-detection block verbatim from the script so this test
  // exercises the SAME code the launcher runs (not a hand-copied paraphrase).
  const startMarker = "if stat -c '%u'";
  const endMarker = '|| die "could not stat mode of';
  const startIdx = src.indexOf(startMarker);
  const endLineEnd = src.indexOf("\n", src.indexOf(endMarker));
  assert.ok(startIdx > 0 && endLineEnd > startIdx, "launcher must contain the stat-detection block");
  const detectionBlock = src.slice(startIdx, endLineEnd);
  // GNU (`stat -c`) must be probed BEFORE BSD (`stat -f`): on GNU, `stat -f` means
  // --file-system and exits 0 with the WRONG value, so a BSD-first chain mis-reads.
  const gnuIdx = detectionBlock.indexOf("stat -c '%u'");
  const bsdIdx = detectionBlock.indexOf("stat -f '%u'");
  assert.ok(gnuIdx >= 0 && bsdIdx >= 0, "the block must probe both GNU and BSD stat");
  assert.ok(gnuIdx < bsdIdx, "GNU (stat -c) must be probed BEFORE BSD (stat -f) so GNU never reaches the --file-system form");
  assert.doesNotMatch(src, /stat -f '%u'[^\n]*\|\| stat -c '%u'/, "the BSD-first `stat -f ... || stat -c` chain (the GNU mis-read) must be gone");

  const tmpDir = fs.mkdtempSync(path.join(require("os").tmpdir(), "bob-stat-fixture-"));
  fs.chmodSync(tmpDir, 0o700);
  try {
    const script = `${detectionBlock}\nprintf '%s %s\\n' "$ROOT_OWNER_UID" "$ROOT_PERM"\n`;
    const out = execFileSync("bash", ["-c", script], {
      env: { ...process.env, SESSIONS_ROOT: tmpDir },
      stdio: ["ignore", "pipe", "pipe"],
    }).toString("utf8").trim();
    const [ownerUid, perm] = out.split(/\s+/);
    const expectedOwner = String(typeof process.getuid === "function" ? process.getuid() : 0);
    assert.equal(ownerUid, expectedOwner, "stat-detection must report the REAL owner uid (not the filesystem value)");
    assert.equal(perm, "700", "stat-detection must report the REAL octal mode (700)");
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("HIGH-2: the stat-detection DIES (fail-closed) when SESSIONS_ROOT does not exist", () => {
  const src = fs.readFileSync(LAUNCHER, "utf8");
  const startMarker = "if stat -c '%u'";
  const endMarker = '|| die "could not stat mode of';
  const startIdx = src.indexOf(startMarker);
  const endLineEnd = src.indexOf("\n", src.indexOf(endMarker));
  const detectionBlock = src.slice(startIdx, endLineEnd);
  // A genuine stat failure (a non-existent path) must DIE, not silently produce the
  // wrong field. Provide a die() shim and a non-existent SESSIONS_ROOT.
  const script = `set -euo pipefail\ndie() { echo "die: $*" >&2; exit 7; }\n${detectionBlock}\necho "SHOULD_NOT_REACH"\n`;
  let exitCode = 0;
  let stderr = "";
  try {
    execFileSync("bash", ["-c", script], {
      env: { ...process.env, SESSIONS_ROOT: "/no/such/bob/sessions/root/here" },
      stdio: ["ignore", "pipe", "pipe"],
    });
  } catch (err) {
    exitCode = err.status == null ? 1 : err.status;
    stderr = err.stderr ? err.stderr.toString("utf8") : "";
  }
  assert.notEqual(exitCode, 0, "a genuine stat failure must DIE (fail-closed)");
  assert.match(stderr, /die:/, "the failure must route through die(), not silently produce garbage");
});

test("HIGH-3: the launcher preserves AND exports BOB_SC_TOOLCHAIN_IMAGE across the sudo drop", () => {
  const src = fs.readFileSync(LAUNCHER, "utf8");
  // The SC container-isolation channel must survive the sudo env-strip: it must be
  // in --preserve-env (else sudo strips it -> silent host-as-signer degrade) AND
  // conditionally exported before the exec (matching the attestation-mode pattern).
  assert.match(src, /--preserve-env=[^\n]*BOB_SC_TOOLCHAIN_IMAGE/, "BOB_SC_TOOLCHAIN_IMAGE must be in --preserve-env so sudo does not strip it");
  assert.match(src, /if \[ -n "\$\{BOB_SC_TOOLCHAIN_IMAGE:-\}" \]; then\s*\n\s*export BOB_SC_TOOLCHAIN_IMAGE/, "BOB_SC_TOOLCHAIN_IMAGE must be conditionally exported before the exec");
  // The export must precede the exec (so the env var is set when sudo preserves it).
  const exportIdx = src.indexOf("export BOB_SC_TOOLCHAIN_IMAGE");
  const execIdx = src.indexOf("exec sudo -u");
  assert.ok(exportIdx > 0 && execIdx > exportIdx, "the BOB_SC_TOOLCHAIN_IMAGE export must precede the exec sudo line");
});

test("launcher fail-closes when the signer uid is not separate from the current uid", () => {
  // Run the launcher declaring the CURRENT uid as the signer uid. It must abort
  // before launching the server (the same-uid case has no isolation to establish).
  const myUid = typeof process.getuid === "function" ? String(process.getuid()) : "0";
  let stderr = "";
  let exitCode = 0;
  try {
    execFileSync("bash", [LAUNCHER], {
      env: {
        ...process.env,
        BOB_SIGNER_USER: "nonexistent-signer-user",
        BOB_SANDBOX_SIGNER_UID: myUid,
      },
      stdio: ["ignore", "ignore", "pipe"],
    });
  } catch (err) {
    exitCode = err.status == null ? 1 : err.status;
    stderr = err.stderr ? err.stderr.toString("utf8") : "";
  }
  assert.notEqual(exitCode, 0, "launcher must exit non-zero (fail closed)");
  assert.match(stderr, /SEPARATE uid/, "launcher must name the same-uid abort reason");
});
