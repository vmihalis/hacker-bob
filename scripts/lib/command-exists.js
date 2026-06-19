"use strict";

const { spawnSync } = require("child_process");

// Single source of truth for "is this command on PATH?" used by the installer,
// the doctor/lifecycle checks, and the adapter probes. It interpolates its
// argument into a shell string (`command -v <name>`), so the argument is
// validated against a strict allowlist FIRST — otherwise a value containing a
// shell metacharacter (`;`, `|`, `$()`, backticks, whitespace, redirects, …)
// would break out of the `command -v` word and execute arbitrary code.
//
// Executable names are [A-Za-z0-9._-]: letters, digits, dot (e.g. `jwt_tool.py`,
// `python3.11`), underscore, and hyphen. None of those are shell metacharacters
// in an unquoted word, so a value that matches the allowlist is passed to
// `command -v` as exactly one harmless token. Anything else is rejected before
// the shell ever runs, fail-closed (returns false). Centralizing the check here
// is the point: previously this sink was duplicated (scripts/install.js and
// adapters/index.js), so guarding one copy left the other exposed.
const SAFE_COMMAND_NAME = /^[a-z0-9._-]+$/i;

function isSafeCommandName(command) {
  return typeof command === "string" && SAFE_COMMAND_NAME.test(command);
}

function commandExists(command) {
  if (!isSafeCommandName(command)) return false;
  const result = spawnSync("sh", ["-c", `command -v ${command}`], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "ignore"],
  });
  return result.status === 0;
}

module.exports = { commandExists, isSafeCommandName, SAFE_COMMAND_NAME };
