"use strict";

// Cargo test output parser. Used by both substrate-runner.js (ink! contracts)
// and cosmwasm-runner.js (cw-multi-test integrations) because both shell out
// to `cargo test`, which emits a uniform line-based status report:
//
//   running 5 tests
//   test foo::bar ... ok
//   test foo::baz ... FAILED
//   test slow_test ... ignored
//
//   failures:
//
//   ---- foo::baz stdout ----
//   thread 'foo::baz' panicked at 'assertion failed: ...', src/lib.rs:42:9
//   note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
//
//   failures:
//       foo::baz
//
//   test result: FAILED. 4 passed; 1 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.05s
//
// Status tokens are `ok` (lowercase), `FAILED` (uppercase), `ignored` (lowercase).
// The result line uses `ok` for all-pass and `FAILED` for any failure.

const CARGO_TESTS_CAP = 100;
const { redactTextSensitiveValues } = require("../../../redaction.js");

// Regex captures: 1=test_name (e.g., "foo::bar"), 2=status token. The leading
// "test " literal is required; we accept arbitrary whitespace between the name
// and the "..." separator because cargo right-pads to align columns.
const STATUS_LINE_RE = /^test\s+(\S+)\s+\.\.\.\s+(ok|FAILED|ignored)\b/;
// Result line is uniform across cargo versions:
//   "test result: ok. N passed; M failed; ..."
//   "test result: FAILED. N passed; M failed; ..."
const TOTAL_LINE_RE = /^test result:\s*(ok|FAILED)\.\s*(\d+)\s+passed/i;
// Failure detail block opens with "---- TEST_ID stdout ----" and ends at the
// next blank line. We capture the first non-empty line as the failure reason.
const FAILURE_BLOCK_RE = /^----\s+(\S+)\s+stdout\s+----\s*$/;

function parseCargoTestStdout(stdout) {
  const tests = [];
  let total = 0;
  let passed = 0;
  let failed = 0;
  let ignored = 0;
  let truncated = false;
  let resultLineFound = false;

  if (typeof stdout !== "string" || stdout.length === 0) {
    return { ok: false, reason: "empty_stdout", tests, total, passed, failed, ignored, truncated, result_line_found: false };
  }

  const lines = stdout.split(/\r?\n/);
  // First pass: capture status lines. We track the test_id → tests[] index so
  // the failure-detail second pass can attach reasons.
  const idIndex = new Map();
  let inFailureBlock = null; // test_id whose failure detail we're collecting
  for (const rawLine of lines) {
    const line = rawLine.replace(/\x1b\[[0-9;]*m/g, ""); // strip ANSI
    const trimmed = line.trim();

    const totalMatch = TOTAL_LINE_RE.exec(trimmed);
    if (totalMatch) {
      resultLineFound = true;
      continue;
    }

    const failBlock = FAILURE_BLOCK_RE.exec(trimmed);
    if (failBlock) {
      inFailureBlock = failBlock[1];
      continue;
    }

    const status = STATUS_LINE_RE.exec(trimmed);
    if (status) {
      inFailureBlock = null; // a status line ends any failure-block capture
      const testId = status[1];
      const tok = status[2];
      let normalizedStatus;
      if (tok === "ok") {
        normalizedStatus = "Pass";
        passed += 1;
      } else if (tok === "FAILED") {
        normalizedStatus = "Fail";
        failed += 1;
      } else {
        normalizedStatus = "Skipped";
        ignored += 1;
      }
      total += 1;
      if (tests.length < CARGO_TESTS_CAP) {
        idIndex.set(testId, tests.length);
        tests.push({
          test_id: testId,
          status: normalizedStatus,
          status_raw: tok,
          reason: null,
        });
      } else {
        truncated = true;
      }
      continue;
    }

    // Inside a failure block, capture the first substantive line as the reason.
    if (inFailureBlock && trimmed.length > 0) {
      const idx = idIndex.get(inFailureBlock);
      if (idx != null) {
        const entry = tests[idx];
        if (entry && !entry.reason) {
          entry.reason = redactTextSensitiveValues(trimmed).slice(0, 1024);
        }
      }
      // Don't unset inFailureBlock — multiple lines may follow; we only keep
      // the first one to stay terse. A blank line ends the block; the next
      // "---- ... stdout ----" or status line resets state.
      continue;
    }

    // Blank line ends a failure block.
    if (inFailureBlock && trimmed.length === 0) {
      inFailureBlock = null;
    }
  }

  if (total === 0 && !resultLineFound) {
    return { ok: false, reason: "no_test_lines", tests, total, passed, failed, ignored, truncated, result_line_found: false };
  }

  return {
    ok: true,
    tests,
    total,
    passed,
    failed,
    ignored,
    truncated,
    result_line_found: resultLineFound,
  };
}

module.exports = {
  CARGO_TESTS_CAP,
  STATUS_LINE_RE,
  TOTAL_LINE_RE,
  FAILURE_BLOCK_RE,
  parseCargoTestStdout,
};
