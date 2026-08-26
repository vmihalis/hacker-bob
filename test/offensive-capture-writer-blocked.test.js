"use strict";

// The shared offensive writer can sign the NEGATIVE-CONTROL leg of a finding
// differential: a blocked_by_defense / blocked_by_infra row from a REAL executed
// observation (the server denied a safe variant that actually ran). The
// offensiveOutcome param is registry-bounded and fail-closed:
//   - exploited_safely / blocked_by_defense / blocked_by_infra are signable,
//   - blocked_by_design / blocked_operator_pii (pre-request refusals, no executed
//     observation) and any arbitrary string are REJECTED before any write,
//   - demonstrated_severity stays registry-derived and surface_id stamped on every
//     outcome, and exit_code stays 0 (a server-denied response is a completed
//     execution, not a process failure), so a blocked row is as non-forgeable as the
//     positive and resolveExecutedRow's non-error preconditions still hold.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const { buildAndSignOffensiveRow } = require("../mcp/domains/web/offensive-capture-writer.js");
const { initSession } = require("../mcp/core/session/session-state.js");
const { ensureHandoffSigningKey } = require("../mcp/core/ledger-integrity/index.js");
const { verifyRowWithMac, OFFENSIVE_ROW_MAC_CONTEXT } = require("../mcp/core/ledger-integrity/index.js");
const { resolveOffensiveRowVerifier } = require("../mcp/core/ledger-integrity/index.js");
const { withSessionLock } = require("../mcp/core/io/storage.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-writer-blocked-"));
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
    runIdPrefix: "idor",
    toolId: "bob_http_idor_confirm", // registry ceiling = medium
    method: "GET",
    canonicalTarget: "https://app.example.test/api/x",
    surfaceId: "surface:x",
    identityTag: "control",
    stdoutContent: "{}",
    stderrContent: "{}",
    ...over,
  };
}

function sign(domain, over) {
  return withSessionLock(domain, () => buildAndSignOffensiveRow(domain, buildArgs(over)));
}

for (const outcome of ["blocked_by_defense", "blocked_by_infra"]) {
  test(`buildAndSignOffensiveRow signs a ${outcome} row: MAC verifies, severity registry-derived, surface stamped, exit_code 0`, () => withTempHome(() => {
    const domain = "writer-blocked.example.test";
    initSession({ target_domain: domain, target_url: `https://${domain}/` });
    ensureHandoffSigningKey(domain);
    const row = sign(domain, { offensiveOutcome: outcome });
    assert.equal(row.offensive_outcome, outcome);
    assert.equal(row.demonstrated_severity, "medium", "severity stays registry-derived, not raised by the blocked leg");
    assert.equal(row.surface_id, "surface:x");
    assert.equal(row.dry_run, false);
    assert.equal(row.timed_out, false);
    assert.equal(row.exit_code, 0, "a server-denied response is a completed execution, not a process failure");
    assert.ok(
      verifyRowWithMac(OFFENSIVE_ROW_MAC_CONTEXT, row, resolveOffensiveRowVerifier(domain)),
      "the blocked row verifies its MAC",
    );
  }));
}

test("buildAndSignOffensiveRow still defaults to exploited_safely when offensiveOutcome is omitted", () => withTempHome(() => {
  const domain = "writer-default.example.test";
  initSession({ target_domain: domain, target_url: `https://${domain}/` });
  ensureHandoffSigningKey(domain);
  const row = sign(domain, {});
  assert.equal(row.offensive_outcome, "exploited_safely");
}));

test("buildAndSignOffensiveRow REJECTS an out-of-set offensiveOutcome fail-closed (before any write)", () => {
  for (const bad of [
    "blocked_by_design", "blocked_operator_pii", "exploited_unsafely",
    "EXPLOITED_SAFELY", "exploited_safely ", "confirmed", "", null, 1, {}, true,
  ]) {
    assert.throws(
      () => buildAndSignOffensiveRow("d.test", buildArgs({ offensiveOutcome: bad })),
      /offensiveOutcome must be one of/,
      `must reject offensiveOutcome ${JSON.stringify(bad)}`,
    );
  }
});

test("a blocked outcome cannot inflate severity: a high override is still bounded by the medium registry ceiling", () => withTempHome(() => {
  const domain = "writer-blocked-clamp.example.test";
  initSession({ target_domain: domain, target_url: `https://${domain}/` });
  ensureHandoffSigningKey(domain);
  const row = sign(domain, { offensiveOutcome: "blocked_by_defense", demonstratedSeverityOverride: "critical" });
  assert.equal(row.demonstrated_severity, "medium", "the per-tool ceiling holds for the blocked leg too");
}));
