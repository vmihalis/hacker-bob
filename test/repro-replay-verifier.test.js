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
const { persistingRunner } = require("./helpers/repro-run-pair.js");

const DOMAIN = "repo-muparser-test";

// A real ASAN crash with a /src root-cause frame (the muparser/oss-fuzz-25402 shape).
const ASAN_CRASH = `==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x511
    #0 0x4f1c2a in mu::ParserBase::ParseCmdCodeBulk(int, int) const /src/muparser/src/muParserBase.cpp:1242:10
SUMMARY: AddressSanitizer: heap-buffer-overflow /src/muparser/src/muParserBase.cpp:1242:10`;
const CLEAN = "All tests passed\n12/12 ok";
// A banner with NO /src frame (only a lib frame) — crashed, but unattributable.
const BANNER_NO_SRC = "==2==ERROR: AddressSanitizer: SEGV on unknown address\n    #0 0x10 in (<unknown>)";

// A UBSan runtime-error in its DEFAULT (non-halt, no-stack) mode: the banner line
// itself carries the /src-attributable location. A non-ASAN signal that the extended
// parser must recognize so the differential can mint on a flip.
const UBSAN_CRASH = "/src/muparser/src/muParserBase.cpp:1242:10: runtime error: signed integer overflow: 2147483647 + 1 cannot be represented in type int";
// A UBSan runtime-error rooted in a non-/src (relative/stdin) path — recognized as a
// crash signal but with NO repo-attributable frame, so the differential cannot mint it.
const UBSAN_NO_SRC = "expr.c:1:1: runtime error: load of misaligned address for type int";
// A TSan data-race WARNING banner with no-0x frames and a /src root-cause frame.
const TSAN_CRASH = [
  "==================",
  "WARNING: ThreadSanitizer: data race (pid=12)",
  "  Write of size 4 at 0x7b0400000040 by thread T1:",
  "    #0 increment /src/race.c:14:7 (race+0x4a1b2c)",
  "    #1 LLVMFuzzerTestOneInput /src/harness.cc:9 (race+0x5b2)",
].join("\n");

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

async function run(opts, findingId = "F-3") {
  // Persist each run as a genuine repo-command-runs row + capture files so
  // readReproVerifiedSummary's read-time re-adjudication can re-resolve a minted
  // verified_pass (a bare verdict line citing nonexistent runs is no longer trusted).
  return verifyReproReproduction(
    { target_domain: DOMAIN, finding_id: findingId, command: CMD, control_ref: "322716256d60e316c9a3b905a387be36d4e47368" },
    { repoDockerRunFn: persistingRunner(DOMAIN, makeRunner(opts)) },
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

test("INCONCLUSIVE: a control that does not crash but exits non-zero (failed build/run) is not a false flip", async () => {
  await withTempHome(async () => {
    // The vuln tree crashes with a /src frame; the control (fix) tree prints no
    // sanitizer banner but exits non-zero — e.g. the fix changed an API and the
    // harness failed to build, so the bug was never exercised. The absence of a
    // crash there must NOT be read as a clean flip.
    const runner = async ({ checkout }) => (
      checkout
        ? { run_id: "RC", exit_code: 2, stdout_text: "", stderr_text: "make: *** [all] Error 2\n" }
        : { run_id: "RV", exit_code: 1, stdout_text: "", stderr_text: ASAN_CRASH }
    );
    const r = await verifyReproReproduction(
      { target_domain: DOMAIN, finding_id: "F-9", command: CMD, control_ref: "322716256d60e316c9a3b905a387be36d4e47368" },
      { repoDockerRunFn: runner },
    );
    assert.equal(r.result, RESULT_INCONCLUSIVE);
    assert.match(r.reason, /exited 2 with no sanitizer banner/);
    assert.equal(readReproVerifiedSummary(DOMAIN).verified_pass_count, 0);
  });
});

test("INCONCLUSIVE: a degraded re-execution is not scored as a miss", async () => {
  await withTempHome(async () => {
    const r = await run({ vuln: { error: "docker_unavailable" }, control: { text: CLEAN } });
    assert.equal(r.result, RESULT_INCONCLUSIVE);
    assert.equal(readReproVerifiedSummary(DOMAIN).inconclusive_count, 1);
  });
});

// The differential adjudication is SIGNAL-AGNOSTIC: once sanitizer-report.js recognizes
// a banner as a crash with a /src frame, the flip (fires on vuln, quiet on fix) mints a
// verified_pass regardless of WHICH sanitizer produced it. These prove the extended
// oracle recognition end-to-end for the non-ASAN signals (UBSan / TSan) — same gate, no
// adjudicateDifferential change.

test("NEW SIGNAL: a UBSan runtime-error flips (vuln crashes, fix quiet) -> verified_pass", async () => {
  await withTempHome(async () => {
    const r = await verifyReproReproduction(
      { target_domain: DOMAIN, finding_id: "F-UB", command: CMD, control_ref: "322716256d60e316c9a3b905a387be36d4e47368" },
      { repoDockerRunFn: persistingRunner(DOMAIN, makeRunner({ vuln: { text: UBSAN_CRASH }, control: { text: CLEAN } })) },
    );
    assert.equal(r.result, RESULT_VERIFIED_PASS);
    assert.equal(r.crash_class, "runtime-error");
    const sum = readReproVerifiedSummary(DOMAIN);
    assert.equal(sum.verified_pass_count, 1);
    assert.ok(sum.verified_by_finding["F-UB"]);
  });
});

test("NEW SIGNAL: a TSan data race flips (vuln races, fix quiet) -> verified_pass", async () => {
  await withTempHome(async () => {
    const r = await verifyReproReproduction(
      { target_domain: DOMAIN, finding_id: "F-TS", command: CMD, control_ref: "322716256d60e316c9a3b905a387be36d4e47368" },
      { repoDockerRunFn: persistingRunner(DOMAIN, makeRunner({ vuln: { text: TSAN_CRASH }, control: { text: CLEAN } })) },
    );
    assert.equal(r.result, RESULT_VERIFIED_PASS);
    assert.equal(r.crash_class, "data race");
    assert.equal(readReproVerifiedSummary(DOMAIN).verified_pass_count, 1);
  });
});

test("NON-FORGEABLE: the SAME UBSan banner on BOTH trees -> no flip -> refuted", async () => {
  await withTempHome(async () => {
    // A printf'd / always-fires UBSan banner is identical on both trees -> no flip.
    const r = await verifyReproReproduction(
      { target_domain: DOMAIN, finding_id: "F-UB2", command: CMD, control_ref: "322716256d60e316c9a3b905a387be36d4e47368" },
      { repoDockerRunFn: makeRunner({ vuln: { text: UBSAN_CRASH }, control: { text: UBSAN_CRASH } }) },
    );
    assert.equal(r.result, RESULT_REFUTED);
    assert.match(r.reason, /also crashes the upstream-fix tree/);
    assert.equal(readReproVerifiedSummary(DOMAIN).verified_pass_count, 0);
  });
});

test("NON-FORGEABLE: the SAME TSan banner on BOTH trees -> no flip -> refuted", async () => {
  await withTempHome(async () => {
    const r = await verifyReproReproduction(
      { target_domain: DOMAIN, finding_id: "F-TS2", command: CMD, control_ref: "322716256d60e316c9a3b905a387be36d4e47368" },
      { repoDockerRunFn: makeRunner({ vuln: { text: TSAN_CRASH }, control: { text: TSAN_CRASH } }) },
    );
    assert.equal(r.result, RESULT_REFUTED);
    assert.match(r.reason, /also crashes the upstream-fix tree/);
    assert.equal(readReproVerifiedSummary(DOMAIN).verified_pass_count, 0);
  });
});

test("NON-FORGEABLE: a UBSan signal with NO /src frame is unattributable -> refuted", async () => {
  await withTempHome(async () => {
    // A "runtime error:" rooted in a relative/system path has no repo-attributable
    // frame, so it cannot mint even with a clean control.
    const r = await verifyReproReproduction(
      { target_domain: DOMAIN, finding_id: "F-UB3", command: CMD, control_ref: "322716256d60e316c9a3b905a387be36d4e47368" },
      { repoDockerRunFn: makeRunner({ vuln: { text: UBSAN_NO_SRC }, control: { text: CLEAN } }) },
    );
    assert.equal(r.result, RESULT_REFUTED);
    assert.match(r.reason, /no \/src-resolved root-cause frame/);
    assert.equal(readReproVerifiedSummary(DOMAIN).verified_pass_count, 0);
  });
});

test("INTEGRITY: the repro-verified ledger is audit-graded (agent Write blocked)", async () => {
  await withTempHome(() => {
    assert.equal(isAuditGradedPath(reproVerifiedJsonlPath(DOMAIN), DOMAIN), true);
  });
});
