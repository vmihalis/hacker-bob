"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  verifyReproReproduction,
  readReproVerifiedSummary,
  RESULT_VERIFIED_PASS,
  RESULT_REFUTED,
  RESULT_INCONCLUSIVE,
} = require("../mcp/lib/repro-replay-verifier.js");
const { reproVerifiedJsonlPath, isAuditGradedPath } = require("../mcp/lib/paths.js");

const DOMAIN = "repo-muparser-test";

// A real ASAN crash with a /src root-cause frame (the muparser/oss-fuzz-25402 shape).
const ASAN_CRASH = `==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x511
    #0 0x4f1c2a in mu::ParserBase::ParseCmdCodeBulk(int, int) const /src/muparser/src/muParserBase.cpp:1242:10
SUMMARY: AddressSanitizer: heap-buffer-overflow /src/muparser/src/muParserBase.cpp:1242:10`;
const CLEAN = "All tests passed\n12/12 ok";
// A banner with NO /src frame (only a lib frame) — crashed, but unattributable.
const BANNER_NO_SRC = "==2==ERROR: AddressSanitizer: SEGV on unknown address\n    #0 0x10 in (<unknown>)";

async function withTempHome(fn) {
  const prev = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-repro-verifier-"));
  process.env.HOME = home;
  try { return await fn(home); } finally { process.env.HOME = prev; fs.rmSync(home, { recursive: true, force: true }); }
}

// Fake runner: a run WITH a checkout is the control/fix tree; without is the vuln tree.
function makeRunner({ vuln, control }) {
  let n = 0;
  return async ({ checkout }) => {
    n += 1;
    const o = checkout ? control : vuln;
    if (o.error) return { run_id: `R-${n}`, error: o.error };
    return { run_id: `R-${n}`, exit_code: o.text.includes("ERROR") ? 1 : 0, stdout_text: "", stderr_text: o.text };
  };
}

const CMD = ["sh", "-lc", "g++ -fsanitize=address -Iinclude poc.cpp src/*.cpp -o poc && ./poc crash.txt"];

async function run(opts) {
  return verifyReproReproduction(
    { target_domain: DOMAIN, finding_id: "F-3", command: CMD, control_ref: "322716256d60e316c9a3b905a387be36d4e47368" },
    { repoDockerRunFn: makeRunner(opts) },
  );
}

test("VERIFIED: crashes the vuln tree, quiet on the fix tree -> verified_pass + ledger", async () => {
  await withTempHome(async () => {
    const r = await run({ vuln: { text: ASAN_CRASH }, control: { text: CLEAN } });
    assert.equal(r.result, RESULT_VERIFIED_PASS);
    assert.equal(r.crash_class, "heap-buffer-overflow");
    const sum = readReproVerifiedSummary(DOMAIN);
    assert.equal(sum.verified_pass_count, 1);
    assert.ok(sum.verified_by_finding["F-3"]);
    assert.equal(sum.verified_by_finding["F-3"].command_hash, r.command_hash);
  });
});

test("FORGERY DEFEATED: a printf'd banner fires on BOTH trees -> no flip -> refuted", async () => {
  await withTempHome(async () => {
    // The same forged banner is printed regardless of tree (checkout has no effect on printf).
    const r = await run({ vuln: { text: ASAN_CRASH }, control: { text: ASAN_CRASH } });
    assert.equal(r.result, RESULT_REFUTED);
    assert.match(r.reason, /also crashes the upstream-fix tree/);
    assert.equal(readReproVerifiedSummary(DOMAIN).verified_pass_count, 0);
  });
});

test("REFUTED: vuln tree does not crash on re-execution (claim not reproduced)", async () => {
  await withTempHome(async () => {
    const r = await run({ vuln: { text: CLEAN }, control: { text: CLEAN } });
    assert.equal(r.result, RESULT_REFUTED);
    assert.match(r.reason, /did not crash/);
  });
});

test("REFUTED: a crash with no /src frame is unattributable", async () => {
  await withTempHome(async () => {
    const r = await run({ vuln: { text: BANNER_NO_SRC }, control: { text: CLEAN } });
    assert.equal(r.result, RESULT_REFUTED);
    assert.match(r.reason, /no \/src-resolved root-cause frame/);
  });
});

test("INCONCLUSIVE: a degraded re-execution is not scored as a miss", async () => {
  await withTempHome(async () => {
    const r = await run({ vuln: { error: "docker_unavailable" }, control: { text: CLEAN } });
    assert.equal(r.result, RESULT_INCONCLUSIVE);
    assert.equal(readReproVerifiedSummary(DOMAIN).inconclusive_count, 1);
  });
});

test("INTEGRITY: the repro-verified ledger is audit-graded (agent Write blocked)", async () => {
  await withTempHome(() => {
    assert.equal(isAuditGradedPath(reproVerifiedJsonlPath(DOMAIN), DOMAIN), true);
  });
});
