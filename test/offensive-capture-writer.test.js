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
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const writer = require("../mcp/lib/offensive-capture-writer.js");
const { initSession } = require("../mcp/lib/session-state.js");
const {
  ensureHandoffSigningKey,
  readHandoffSigningPublicKey,
  readHandoffSigningKey,
  resolveOffensiveRowVerifier,
} = require("../mcp/lib/handoff-signing-key.js");
const { withSessionLock } = require("../mcp/lib/storage.js");
const { verifyRowWithMac, OFFENSIVE_ROW_MAC_CONTEXT } = require("../mcp/lib/offensive-row-mac.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-capture-writer-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    if (previousHome === undefined) delete process.env.HOME;
    else process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

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

test("buildAndSignOffensiveRow rejects an unknown demonstratedSeverityOverride (fails closed, before any write)", () => {
  for (const bad of ["", "sev", "MEDIUM", "lowish", 123, {}, true, ["low"]]) {
    assert.throws(
      () => writer.buildAndSignOffensiveRow("d.test", buildArgs({ demonstratedSeverityOverride: bad })),
      /demonstratedSeverityOverride must be a known severity/,
      `must reject demonstratedSeverityOverride ${JSON.stringify(bad)}`,
    );
  }
});

test("buildAndSignOffensiveRow: demonstratedSeverityOverride can only LOWER the registry ceiling, never raise it", () => {
  withTempHome(() => {
    const domain = "clamp.example.test";
    initSession({ target_domain: domain, target_url: `https://${domain}/` });
    ensureHandoffSigningKey(domain);
    // bob_http_idor_confirm's registry ceiling is "medium". The clamp uses Math.max over the
    // DESCENDING SEVERITY_VALUES, so the override can only move toward a higher index = lower severity.
    const lowered = withSessionLock(domain, () =>
      writer.buildAndSignOffensiveRow(domain, buildArgs({ demonstratedSeverityOverride: "low" })));
    assert.equal(lowered.demonstrated_severity, "low", "override 'low' must lower medium -> low");
    const raised = withSessionLock(domain, () =>
      writer.buildAndSignOffensiveRow(domain, buildArgs({ demonstratedSeverityOverride: "critical" })));
    assert.equal(raised.demonstrated_severity, "medium", "override 'critical' must NOT raise above the medium ceiling");
    const none = withSessionLock(domain, () =>
      writer.buildAndSignOffensiveRow(domain, buildArgs({})));
    assert.equal(none.demonstrated_severity, "medium", "no override keeps the registry ceiling");
  });
});

test("buildAndSignOffensiveRow mints a v2 ed25519 row_mac that verifies with the PUBLIC key only", () => {
  withTempHome(() => {
    const domain = "ed25519row.example.test";
    initSession({ target_domain: domain, target_url: `https://${domain}/` });
    const row = withSessionLock(domain, () => writer.buildAndSignOffensiveRow(domain, buildArgs()));

    assert.equal(row.row_mac.version, 2, "new rows carry the v2 envelope");
    assert.equal(row.row_mac.scheme, "ed25519", "new rows are ed25519-signed");
    assert.equal(typeof row.row_mac.signature, "string");
    assert.equal(row.row_mac.digest, undefined, "an ed25519 envelope has no hmac digest");

    // The verifier holds ONLY the public key — no secret — and accepts the row.
    const pub = readHandoffSigningPublicKey(domain);
    assert.equal(verifyRowWithMac(OFFENSIVE_ROW_MAC_CONTEXT, row, { scheme: "ed25519", publicKey: pub.publicKey }), true);

    // The symmetric key alone CANNOT verify the ed25519 row.
    const hmacKey = readHandoffSigningKey(domain);
    assert.equal(verifyRowWithMac(OFFENSIVE_ROW_MAC_CONTEXT, row, { scheme: "hmac-sha256", key: hmacKey }), false);

    // The combined bundle the verify sites use (public + symmetric) accepts it via scheme dispatch.
    assert.equal(verifyRowWithMac(OFFENSIVE_ROW_MAC_CONTEXT, row, resolveOffensiveRowVerifier(domain)), true);
  });
});

test("SEVERITY_VALUES is DESCENDING (most-severe first) — the invariant the can-only-lower clamp depends on", () => {
  // offensive-capture-writer's `SEVERITY_VALUES[Math.max(overrideIdx, registryIdx)]` can only LOWER
  // severity BECAUSE SEVERITY_VALUES is ordered most-severe (index 0) to least-severe (a higher index
  // = less severe, so Math.max picks the less-severe value). If anyone reorders it or inserts a tier,
  // the clamp would silently invert and an override could RAISE the signed ceiling. Lock the ordering
  // so a regression fails loudly HERE, not by mis-signing a row in production.
  const { SEVERITY_VALUES } = require("../mcp/lib/constants.js");
  assert.deepEqual(
    SEVERITY_VALUES,
    ["critical", "high", "medium", "low", "info"],
    "SEVERITY_VALUES must stay descending; the offensive severity clamp's can-only-lower property depends on it",
  );
});
