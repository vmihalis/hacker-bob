"use strict";

// Shared, allowlist-guarded PATH probe (scripts/lib/command-exists.js). This is
// the single sink for `command -v <name>`, consumed by scripts/install.js (and,
// transitively, scripts/lifecycle.js) and adapters/index.js. Two properties must
// hold simultaneously:
//   1. INJECTION-SAFE — a value carrying any shell metacharacter is rejected
//      before the shell runs (fail-closed), so it can never break out of the
//      `command -v` word and execute arbitrary code.
//   2. NO false negatives on real executable names — including DOTTED names like
//      `jwt_tool.py` / `python3.11`. (Regression guard: the original fix used
//      /^[a-z0-9_-]+$/i, which excluded `.` and silently broke the
//      commandExists("jwt_tool.py") fallback in jwtToolExists()/jwtToolAvailable().)

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  commandExists,
  isSafeCommandName,
} = require("../scripts/lib/command-exists.js");

const INJECTION_PAYLOADS = [
  "foo; rm -rf /",
  "$(touch /tmp/x)",
  "`id`",
  "a|b",
  "a&&b",
  "a||b",
  "a&b",
  "a b",
  "a>b",
  "a<b",
  "a/b",
  "a'b",
  'a"b',
  "a\\b",
  "a\nb",
  "a*b",
  "a(b)",
  "a{b}",
  "a=b",
  "a~b",
  "$PATH",
  "../bin/sh",
];

const VALID_NAMES = [
  "node",
  "jwt_tool",
  "jwt_tool.py", // the dotted name the original fix regressed
  "python3",
  "python3.11",
  "sub-finder",
  "Amass",
  "x",
];

test("isSafeCommandName accepts dotted/letter/digit/_/- names and rejects everything else", () => {
  for (const name of VALID_NAMES) {
    assert.equal(isSafeCommandName(name), true, `${JSON.stringify(name)} must be accepted`);
  }
  for (const payload of INJECTION_PAYLOADS) {
    assert.equal(isSafeCommandName(payload), false, `${JSON.stringify(payload)} must be rejected`);
  }
  // Non-strings and empty strings are rejected, not coerced.
  for (const bad of [null, undefined, 42, {}, [], "", " "]) {
    assert.equal(isSafeCommandName(bad), false, `${JSON.stringify(bad)} must be rejected`);
  }
});

test("commandExists never lets an injected command reach the shell", () => {
  // Each payload, if interpolated unguarded into `sh -c "command -v <payload>"`,
  // would execute the injected `touch`. The guard must reject it (return false)
  // BEFORE the shell runs, so the sentinel is never created.
  const sentinelDir = fs.mkdtempSync(path.join(os.tmpdir(), "cmd-inj-"));
  try {
    const sentinel = path.join(sentinelDir, "PWNED");
    // A payload that, unguarded, would create the sentinel.
    const payload = `x; touch ${sentinel}`;
    assert.equal(commandExists(payload), false, "injection payload must be rejected");
    assert.equal(fs.existsSync(sentinel), false, "the shell must never have executed the injected touch");

    // Backtick + $() forms too.
    assert.equal(commandExists(`x\`touch ${sentinel}\``), false);
    assert.equal(commandExists(`x$(touch ${sentinel})`), false);
    assert.equal(fs.existsSync(sentinel), false, "no command-substitution form may execute");
  } finally {
    fs.rmSync(sentinelDir, { recursive: true, force: true });
  }
});

test("commandExists resolves a real dotted executable name on PATH (jwt_tool.py regression guard)", () => {
  // Create an executable literally named `jwt_tool.py`, put its dir on PATH, and
  // confirm commandExists finds it. Pre-fix (regex without `.`) this returned
  // false even though the command exists — the silent jwt_tool.py regression.
  const binDir = fs.mkdtempSync(path.join(os.tmpdir(), "cmd-bin-"));
  const previousPath = process.env.PATH;
  try {
    const exe = path.join(binDir, "jwt_tool.py");
    fs.writeFileSync(exe, "#!/bin/sh\nexit 0\n");
    fs.chmodSync(exe, 0o755);
    process.env.PATH = `${binDir}${path.delimiter}${previousPath}`;

    assert.equal(commandExists("jwt_tool.py"), true, "a dotted executable on PATH must be detected");
    // A valid-but-absent name still returns false (the probe really runs).
    assert.equal(commandExists("definitely-not-a-real-command-xyz"), false);
  } finally {
    process.env.PATH = previousPath;
    fs.rmSync(binDir, { recursive: true, force: true });
  }
});

test("commandExists detects a command that is genuinely present", () => {
  // `sh` is guaranteed present (the probe itself uses it).
  assert.equal(commandExists("sh"), true);
});
