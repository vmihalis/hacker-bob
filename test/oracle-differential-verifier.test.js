"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  verifyOracleDifferential,
  readReproVerifiedSummary,
  RESULT_VERIFIED_PASS,
  RESULT_REFUTED,
  RESULT_INCONCLUSIVE,
} = require("../mcp/domains/repo/repro-replay-verifier.js");
const { reproVerifiedJsonlPath, isAuditGradedPath } = require("../mcp/core/io/paths.js");
const { persistingRunner } = require("./helpers/repro-run-pair.js");

const DOMAIN = "repo-muparser-oracle-test";

// A real ASAN crash with a /src root-cause frame (the muparser/oss-fuzz-25402 shape).
const ASAN_CRASH = `==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x511
    #0 0x4f1c2a in mu::ParserBase::ParseCmdCodeBulk(int, int) const /src/muparser/src/muParserBase.cpp:1242:10
SUMMARY: AddressSanitizer: heap-buffer-overflow /src/muparser/src/muParserBase.cpp:1242:10`;
const CLEAN = "All tests passed\n12/12 ok";
// A banner with NO /src frame (only a lib frame) — crashed, but unattributable.
const BANNER_NO_SRC = "==2==ERROR: AddressSanitizer: SEGV on unknown address\n    #0 0x10 in (<unknown>)";

const VULN_PATCH = `--- a/src/muParserBase.cpp
+++ b/src/muParserBase.cpp
@@ -1240,3 +1240,3 @@
-    if (idx < bufSize)
+    if (idx <= bufSize)
         buf[idx] = val;`;
const FIX_PATCH = `--- a/src/muParserBase.cpp
+++ b/src/muParserBase.cpp
@@ -1240,3 +1240,3 @@
-    if (idx <= bufSize)
+    if (idx < bufSize)
         buf[idx] = val;`;
const FIX_REF = "322716256d60e316c9a3b905a387be36d4e47368";

async function withTempHome(fn) {
  const prev = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-oracle-verifier-"));
  process.env.HOME = home;
  try { return await fn(home); } finally { process.env.HOME = prev; fs.rmSync(home, { recursive: true, force: true }); }
}

// Fake runner: oracle-vuln is the self_patch checkout (vuln_patch applied), oracle-fix
// is the upstream_fix checkout (fix_ref + fix_patch). We discriminate on checkout.kind
// — exactly the differential the verifier controls. We also assert the verifier sent
// the patch bytes through so the two trees are genuinely distinct executions.
function makeRunner({ vuln, control }) {
  let n = 0;
  return async ({ checkout, checkout_patch }) => {
    n += 1;
    assert.ok(checkout && typeof checkout.kind === "string", "oracle differential must checkout both trees");
    assert.ok(typeof checkout_patch === "string" && checkout_patch.trim(), "oracle differential must carry a patch on both trees");
    const isFix = checkout.kind === "upstream_fix";
    const o = isFix ? control : vuln;
    if (o.error) return { run_id: `R-${n}`, error: o.error };
    return { run_id: `R-${n}`, exit_code: o.text.includes("ERROR") ? 1 : 0, stdout_text: "", stderr_text: o.text };
  };
}

const CMD = ["sh", "-lc", "g++ -fsanitize=address -Iinclude poc.cpp src/*.cpp -o poc && ./poc crash.txt"];

async function run(opts, overrides = {}) {
  // Persist each run as a genuine repo-command-runs row + capture files so a minted
  // oracle verified_pass survives readReproVerifiedSummary's read-time re-adjudication
  // (oracle records skip the vuln-row command_hash re-bind — the vuln run is checkout-
  // wrapped — but the flip + capture-hash integrity still bind the verdict).
  return verifyOracleDifferential(
    {
      target_domain: DOMAIN,
      finding_id: "F-3",
      command: CMD,
      vuln_patch: VULN_PATCH,
      fix_ref: FIX_REF,
      fix_patch: FIX_PATCH,
      ...overrides,
    },
    { repoDockerRunFn: persistingRunner(DOMAIN, makeRunner(opts)) },
  );
}

test("VERIFIED: faults on the vuln-patch tree, clean on the fix-patch tree -> value_state_confirmed + ledger", async () => {
  await withTempHome(async () => {
    const r = await run({ vuln: { text: ASAN_CRASH }, control: { text: CLEAN } });
    assert.equal(r.result, RESULT_VERIFIED_PASS);
    assert.equal(r.crash_class, "heap-buffer-overflow");
    const sum = readReproVerifiedSummary(DOMAIN);
    assert.equal(sum.verified_pass_count, 1);
    assert.ok(sum.verified_by_finding["F-3"]);
    assert.equal(sum.verified_by_finding["F-3"].command_hash, r.command_hash);
    // The verified_pass is minted on the SAME ledger as the repro gate, with the same
    // hash-binding (command_hash over argv, results_hash over the body).
    assert.ok(/^[0-9a-f]{64}$/.test(r.command_hash));
    assert.ok(/^[0-9a-f]{64}$/.test(r.results_hash));
  });
});

test("REFUTED: oracle-vuln does not fault (invariant did not fail on the vuln tree)", async () => {
  await withTempHome(async () => {
    const r = await run({ vuln: { text: CLEAN }, control: { text: CLEAN } });
    assert.equal(r.result, RESULT_REFUTED);
    assert.match(r.reason, /did not crash/);
    assert.equal(readReproVerifiedSummary(DOMAIN).verified_pass_count, 0);
  });
});

test("REFUTED: a forged banner that fires on BOTH trees -> no flip -> refuted", async () => {
  await withTempHome(async () => {
    const r = await run({ vuln: { text: ASAN_CRASH }, control: { text: ASAN_CRASH } });
    assert.equal(r.result, RESULT_REFUTED);
    assert.match(r.reason, /also crashes the oracle-fix tree/);
    assert.equal(readReproVerifiedSummary(DOMAIN).verified_pass_count, 0);
  });
});

test("REFUTED: a vuln-tree fault with no /src frame is unattributable", async () => {
  await withTempHome(async () => {
    const r = await run({ vuln: { text: BANNER_NO_SRC }, control: { text: CLEAN } });
    assert.equal(r.result, RESULT_REFUTED);
    assert.match(r.reason, /no \/src-resolved root-cause frame/);
    assert.equal(readReproVerifiedSummary(DOMAIN).verified_pass_count, 0);
  });
});

test("INCONCLUSIVE: fix-build-degraded (non-zero exit, no banner) is not a false flip", async () => {
  await withTempHome(async () => {
    // oracle-vuln faults with a /src frame; oracle-fix prints no banner but exits
    // non-zero — e.g. the fix_patch failed to build, so the bug was never exercised.
    const runner = async ({ checkout }) => (
      checkout.kind === "upstream_fix"
        ? { run_id: "RC", exit_code: 2, stdout_text: "", stderr_text: "make: *** [all] Error 2\n" }
        : { run_id: "RV", exit_code: 1, stdout_text: "", stderr_text: ASAN_CRASH }
    );
    const r = await verifyOracleDifferential(
      { target_domain: DOMAIN, finding_id: "F-9", command: CMD, vuln_patch: VULN_PATCH, fix_ref: FIX_REF, fix_patch: FIX_PATCH },
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

test("INTEGRITY: the oracle differential mints onto the audit-graded repro ledger", async () => {
  await withTempHome(() => {
    assert.equal(isAuditGradedPath(reproVerifiedJsonlPath(DOMAIN), DOMAIN), true);
  });
});

test("self_patch vuln tree applies vuln_patch onto fix_ref by default (precise inverse)", async () => {
  await withTempHome(async () => {
    const seen = [];
    const runner = async (args) => {
      seen.push({ kind: args.checkout.kind, ref: args.checkout.ref, patch: args.checkout_patch });
      return { run_id: `R${seen.length}`, exit_code: args.checkout.kind === "upstream_fix" ? 0 : 1, stdout_text: "", stderr_text: args.checkout.kind === "upstream_fix" ? CLEAN : ASAN_CRASH };
    };
    await verifyOracleDifferential(
      { target_domain: DOMAIN, finding_id: "F-1", command: CMD, vuln_patch: VULN_PATCH, fix_ref: FIX_REF, fix_patch: FIX_PATCH },
      { repoDockerRunFn: runner },
    );
    const vuln = seen.find((s) => s.kind === "self_patch");
    const fix = seen.find((s) => s.kind === "upstream_fix");
    assert.ok(vuln && fix);
    assert.equal(vuln.ref, FIX_REF); // default base for the self_patch vuln tree
    assert.equal(vuln.patch, VULN_PATCH);
    assert.equal(fix.ref, FIX_REF);
    assert.equal(fix.patch, FIX_PATCH);
  });
});
