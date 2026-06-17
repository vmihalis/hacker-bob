"use strict";

// Guard tests for the SHARED offensive capture/sign writer
// (mcp/lib/offensive-capture-writer.js), extracted from the IDOR producer. These
// lock the hardening added in response to the PR #120 review:
//   - path traversal via an unvalidated runIdPrefix (the prefix flows into the
//     capture-file path),
//   - relationBooleans clobbering a reserved proof-contract field before signing,
//   - an over-wide export surface (only the disciplined build+sign entry is public).
// The happy-path build+sign+append is already exercised byte-identically through
// the IDOR producer suite (test/offensive-idor-producer.test.js), so these focus on
// the new guards, which all reject BEFORE any filesystem/session work.

const test = require("node:test");
const assert = require("node:assert/strict");

const writer = require("../mcp/lib/offensive-capture-writer.js");

function buildArgs(over = {}) {
  return {
    runIdPrefix: "reflect",
    // a tool_id that IS in OFFENSIVE_TOOL_DEMONSTRATED_CEILING, so the prefix /
    // reserved-key / boolean guards (which run after the registry check) are reached
    // by the tests that exercise them.
    toolId: "bob_http_idor_confirm",
    method: "GET",
    canonicalTarget: "https://app.example.test/api/x",
    surfaceId: "surface:x",
    identityTag: "probe",
    stdoutContent: "{}",
    stderrContent: "{}",
    relationBooleans: {},
    ...over,
  };
}

test("offensive-capture-writer exports ONLY the high-level build+sign entry", () => {
  assert.equal(typeof writer.buildAndSignOffensiveRow, "function");
  for (const internal of [
    "newRunId", "commandHashOf", "resolveCaptureDirSecure",
    "writeCaptureAndHash", "appendSignedRowHardened", "sha256OfFileFd",
  ]) {
    assert.equal(writer[internal], undefined, `${internal} must stay module-internal`);
  }
  assert.deepEqual(Object.keys(writer), ["buildAndSignOffensiveRow"]);
});

test("buildAndSignOffensiveRow rejects a runIdPrefix that is not a clean lowercase token (path-traversal guard)", () => {
  for (const bad of ["../etc", "a/b", "idor-x", "Idor", "1foo", "foo_bar", "", "foo.bar", "..", "a/../b", "x ", "a\tb"]) {
    assert.throws(
      () => writer.buildAndSignOffensiveRow("d.test", buildArgs({ runIdPrefix: bad })),
      /runIdPrefix/,
      `must reject runIdPrefix ${JSON.stringify(bad)}`,
    );
  }
  for (const bad of [123, null, undefined, {}, ["reflect"]]) {
    assert.throws(
      () => writer.buildAndSignOffensiveRow("d.test", buildArgs({ runIdPrefix: bad })),
      /runIdPrefix/,
      `must reject non-string runIdPrefix ${JSON.stringify(bad)}`,
    );
  }
});

test("buildAndSignOffensiveRow refuses relationBooleans that override a reserved proof-contract field", () => {
  for (const reserved of [
    "version", "target_domain", "run_id", "tool_id", "target", "offensive_outcome",
    "dry_run", "timed_out", "command_hash", "exit_code", "stdout_hash", "stderr_hash",
    "demonstrated_severity", "surface_id", "row_mac",
  ]) {
    assert.throws(
      () => writer.buildAndSignOffensiveRow("d.test", buildArgs({ relationBooleans: { [reserved]: "x" } })),
      /reserved offensive-row field/,
      `must reject relationBooleans override of ${reserved}`,
    );
  }
});

test("buildAndSignOffensiveRow rejects a tool_id absent from the demonstrated-severity registry (registry-bound signer)", () => {
  for (const bad of ["bob_http_unregistered_producer", "bob_unknown", "", "BOB_HTTP_IDOR_CONFIRM", "bob_http_idor_confirm "]) {
    assert.throws(
      () => writer.buildAndSignOffensiveRow("d.test", buildArgs({ toolId: bad })),
      /unknown offensive tool_id/,
      `must reject unregistered tool_id ${JSON.stringify(bad)}`,
    );
  }
});

test("buildAndSignOffensiveRow refuses a non-boolean relationBooleans value (MAC-covered proof material)", () => {
  for (const value of ["true", 1, 0, null, {}, ["x"], "../etc"]) {
    assert.throws(
      () => writer.buildAndSignOffensiveRow("d.test", buildArgs({ relationBooleans: { p0_stable: value } })),
      /must be a boolean/,
      `must reject non-boolean relation value ${JSON.stringify(value)}`,
    );
  }
});
