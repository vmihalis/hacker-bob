"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const path = require("node:path");

// Wire the IDOR-oracle measurement harness into the test suite. scripts/measure-idor-oracle.js is the
// sole empirical justification for the #13/#14 confidence-signal demotion: it asserts the producer
// stays SOUND (0 false mints across the control corpus — including the explicit-shared, same-tenant,
// multi-alias-readback, and proof-read-shared controls) while recall rises, and that every soft-gated
// fixture emits exactly its predicted confidence signals. Running it in CI stops the policy foundation
// from rotting silently: any change that makes a control FALSE-MINT, or that breaks a predicted
// soft-gate signal, flips the harness's regression gate to a non-zero exit and fails this test.
test("measure-idor-oracle.js regression gate passes (0 control mints, every fixture matches its prediction)", () => {
  const script = path.join(__dirname, "..", "scripts", "measure-idor-oracle.js");
  const result = spawnSync(process.execPath, [script], {
    cwd: path.join(__dirname, ".."),
    encoding: "utf8",
    timeout: 120000,
  });
  assert.equal(
    result.status,
    0,
    `harness exited with status ${result.status}\n--- stdout ---\n${result.stdout}\n--- stderr ---\n${result.stderr}`,
  );
  assert.match(result.stdout, /REGRESSION GATE: ✅ PASS/);
});
