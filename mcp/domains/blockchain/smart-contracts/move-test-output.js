"use strict";

// Move unit test output parser. Used by both aptos-runner.js and sui-runner.js
// because `aptos move test` and `sui move test` both shell out to the same
// Move unit test framework underneath, which writes a uniform line-based
// status report:
//
//   Running Move unit tests
//   [ PASS    ] 0x42::module::test_one
//   [ FAIL    ] 0x42::module::test_two
//   [ TIMEOUT ] 0x42::module::test_three
//   Test result: FAILED. Total tests: 3; passed: 1; failed: 1; timed_out: 1
//
// Status tokens are uppercase with variable internal spacing inside the
// brackets. The failure line may be followed by indented diagnostic lines
// describing the abort/error; we capture the first non-empty diagnostic line
// per failed test as the `reason`.
//
// Aptos 1.10+ introduced `--output-json` for unit tests but earlier versions
// and Sui both still emit only the human-readable form. Parsing the
// human-readable output keeps the verifier resilient across CLI versions.

const MOVE_TESTS_CAP = 100;
const { redactTextSensitiveValues } = require("../../../redaction.js");

// Regex captures: 1=status token (PASS|FAIL|TIMEOUT|SKIP), 2=test id like
// 0x42::module::test_name, optional trailing `;` text after the id (Sui adds
// "; ABORTED at code 100 in mymod" inline). The leading [ ] brackets must
// have at least one inner space; some CLIs print "[PASS]" without internal
// padding. Both forms are accepted.
const STATUS_LINE_RE = /^\[\s*(PASS|FAIL|TIMEOUT|SKIP)\s*\]\s+(\S+)(?:\s*;\s*(.*))?$/;
const TOTAL_LINE_RE = /Test result:\s*(\w+)\.\s*Total tests:\s*(\d+)/i;

function parseMoveTestStdout(stdout) {
  const tests = [];
  let total = 0;
  let passed = 0;
  let failed = 0;
  let timedOut = 0;
  let truncated = false;
  let resultLineFound = false;

  if (typeof stdout !== "string" || stdout.length === 0) {
    return { ok: false, reason: "empty_stdout", tests, total, passed, failed, timed_out: timedOut, truncated, result_line_found: false };
  }

  const lines = stdout.split(/\r?\n/);
  let pendingFailure = null;
  for (const rawLine of lines) {
    const line = rawLine.replace(/\[[0-9;]*m/g, ""); // strip ANSI color codes
    const trimmed = line.trim();

    const totalMatch = TOTAL_LINE_RE.exec(trimmed);
    if (totalMatch) {
      resultLineFound = true;
      // We could parse passed/failed/timed_out from the line, but the per-test
      // counts are more authoritative. Total here is a sanity check.
      continue;
    }

    const match = STATUS_LINE_RE.exec(trimmed);
    if (!match) {
      // Diagnostic capture for the most recent failed test. Move CLIs frame
      // the failure with box-drawing characters (┌─ ─┐ │ └─ ─┘) and a header
      // line that just repeats the test name. We want the first content line
      // that actually describes the failure (e.g. "error[E11001]: ..." or
      // "aborted with code 100"). Strategy: skip lines that contain ONLY
      // box-drawing chars + whitespace + the test name, and capture the
      // first line with substantive text.
      if (pendingFailure && trimmed.length > 0 && tests.length > 0) {
        const last = tests[tests.length - 1];
        // Strip box-drawing chars to test if line has substantive ASCII text.
        const stripped = trimmed.replace(/[─-╿]/g, "").trim();
        // Skip the box-header line which echoes the test_id between ──── ────.
        const isBoxHeader = stripped.length === 0
          || (last.test_id && stripped === last.test_id.split("::").pop())
          || (last.test_id && stripped === last.test_id);
        if (!isBoxHeader && stripped.length > 0 && last.test_id === pendingFailure && !last.reason) {
          last.reason = redactTextSensitiveValues(stripped).slice(0, 1024);
          pendingFailure = null;
        }
      }
      continue;
    }

    const status = match[1].toUpperCase();
    const testId = match[2];
    const inlineReason = match[3] || null;

    let normalizedStatus;
    if (status === "PASS") {
      normalizedStatus = "Pass";
      passed += 1;
      pendingFailure = null;
    } else if (status === "FAIL") {
      normalizedStatus = "Fail";
      failed += 1;
      pendingFailure = testId;
    } else if (status === "TIMEOUT") {
      normalizedStatus = "Fail";
      failed += 1;
      timedOut += 1;
      pendingFailure = testId;
    } else {
      normalizedStatus = "Skipped";
      pendingFailure = null;
    }
    total += 1;

    if (tests.length < MOVE_TESTS_CAP) {
      tests.push({
        test_id: testId,
        status: normalizedStatus,
        status_raw: status,
        reason: inlineReason ? redactTextSensitiveValues(inlineReason).slice(0, 1024) : null,
      });
    } else {
      truncated = true;
    }
  }

  if (total === 0 && !resultLineFound) {
    return { ok: false, reason: "no_test_lines", tests, total, passed, failed, timed_out: timedOut, truncated, result_line_found: false };
  }

  return {
    ok: true,
    tests,
    total,
    passed,
    failed,
    timed_out: timedOut,
    truncated,
    result_line_found: resultLineFound,
  };
}

module.exports = {
  MOVE_TESTS_CAP,
  STATUS_LINE_RE,
  TOTAL_LINE_RE,
  parseMoveTestStdout,
};
