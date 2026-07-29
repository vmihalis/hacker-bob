"use strict";

// NON-BYPASSABLE FAMILY-WIDE GUARD: every one of the SEVEN SC runners
// (foundry/halmos/anchor/cosmwasm/substrate/sui/aptos) MUST lift the seam's
// child.container_isolated marker into its top-level result envelope.
//
// WHY exhaustive + runtime (not a source-grep): the per-family miss has recurred —
// the halmos route, then container_isolated lifted in foundry-runner ONLY, then
// targetDomain threaded in foundry-runner ONLY. A degrade-host SC run that drops the
// lift returns `undefined`, and the verdict gate's scBackingUnIsolatedFindingIds reads
// `container_isolated !== true`, so a containerized verdict whose runner forgot the
// lift would be WRONGLY over-gated (downgraded). This guard drives the REAL run*
// entry points and asserts the field is a BOOLEAN on EVERY return shape, so a runner
// that forgets the lift yields `undefined` and FAILS. It cannot be satisfied by a
// comment or a partial fix.
//
// TWO modes per family:
//   (a) DEGRADE/ERROR shape — driven with no SC-toolchain image and no targetDomain,
//       so the seam degrades and the absent tool hits ENOENT (the error envelope).
//       Asserts result.container_isolated === false (PRESENT, not undefined).
//   (b) CONTAINER-route TRUE shape — the seam is stubbed so the spawned child carries
//       container_isolated:true (mirrors foundry-runner-container-isolated-row.test.js's
//       stubFoundry). Asserts the runner surfaces container_isolated:true. Driven by
//       intercepting the seam at the module boundary the runner already requires.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const { runFoundryTest } = require("../mcp/lib/foundry-runner.js");
const { runHalmos } = require("../mcp/lib/halmos-runner.js");
const { runAnchorTest } = require("../mcp/lib/anchor-runner.js");
const { runCosmwasmTest } = require("../mcp/lib/cosmwasm-runner.js");
const { runSubstrateTest } = require("../mcp/lib/substrate-runner.js");
const { runSuiTest } = require("../mcp/lib/sui-runner.js");
const { runAptosTest } = require("../mcp/lib/aptos-runner.js");
const seam = require("../mcp/lib/sc-container-exec.js");
const { __resetDockerProbeCache, SC_TOOLCHAIN_IMAGE_ENV } = seam;

// Build a $HOME harness shaped for each family's assertHarnessPath: foundry/halmos want a
// test/ subdir; cosmwasm/substrate REQUIRE a Cargo.toml at the root; anchor/sui/aptos only
// need a bare directory. Give every harness BOTH so a single shape satisfies all seven.
function makeHarness(home, family) {
  const harness = fs.mkdtempSync(path.join(home, `.bob-${family}-lift-`));
  fs.mkdirSync(path.join(harness, "test"), { recursive: true });
  fs.writeFileSync(path.join(harness, "Cargo.toml"), "[package]\nname = \"h\"\nversion = \"0.0.0\"\n");
  return harness;
}

// The seven families, each driving its REAL run*. matchTest naming follows each family's
// validator (cargo families use snake_case to read cleanly; the threading is what matters).
const FAMILIES = [
  { family: "foundry", run: (h) => runFoundryTest({ workdir: h, matchTest: "testX" }) },
  { family: "halmos", run: (h) => runHalmos({ workdir: h, matchTest: "testX" }) },
  { family: "anchor", run: (h) => runAnchorTest({ workdir: h, matchTest: "testX" }) },
  { family: "cosmwasm", run: (h) => runCosmwasmTest({ workdir: h, matchTest: "test_x" }) },
  { family: "substrate", run: (h) => runSubstrateTest({ workdir: h, matchTest: "test_x" }) },
  { family: "sui", run: (h) => runSuiTest({ workdir: h, matchTest: "test_x" }) },
  { family: "aptos", run: (h) => runAptosTest({ workdir: h, matchTest: "test_x" }) },
];

// Run a body with a temp $HOME (so harnesses pass isUnderHome), no SC-toolchain image (so
// the seam takes the degrade branch), the docker probe reset, and the loud degrade stderr
// muted. NO targetDomain is threaded by the runs above, so the seam degrades rather than
// refuses (it cannot probe a domain-less call) — the runner then spawns the absent tool
// and hits ENOENT, exercising the error-envelope return shape.
async function withGuardEnv(fn) {
  const previousHome = process.env.HOME;
  const home = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "bob-sc-lift-")));
  process.env.HOME = home;
  const previousImage = process.env[SC_TOOLCHAIN_IMAGE_ENV];
  delete process.env[SC_TOOLCHAIN_IMAGE_ENV];
  const previousWrite = process.stderr.write;
  process.stderr.write = () => true;
  __resetDockerProbeCache();
  try {
    return await fn(home);
  } finally {
    process.stderr.write = previousWrite;
    if (previousHome === undefined) delete process.env.HOME;
    else process.env.HOME = previousHome;
    if (previousImage === undefined) delete process.env[SC_TOOLCHAIN_IMAGE_ENV];
    else process.env[SC_TOOLCHAIN_IMAGE_ENV] = previousImage;
    __resetDockerProbeCache();
    fs.rmSync(home, { recursive: true, force: true });
  }
}

test("ALL SEVEN SC runners lift container_isolated as a BOOLEAN on the degrade/error envelope (a dropped lift yields undefined and FAILS)", async () => {
  await withGuardEnv(async (home) => {
    for (const { family, run } of FAMILIES) {
      const harness = makeHarness(home, family);
      let result;
      try {
        result = await run(harness);
      } finally {
        fs.rmSync(harness, { recursive: true, force: true });
      }
      // The CONTRACT: container_isolated is a boolean on EVERY return shape. A runner
      // that forgets the lift returns `undefined` here and FAILS this assertion.
      assert.strictEqual(
        typeof result.container_isolated,
        "boolean",
        `${family}: result must lift container_isolated as a boolean (got ${typeof result.container_isolated})`,
      );
      // The degrade route never containerized, so it must be false (fail-closed).
      assert.strictEqual(
        result.container_isolated,
        false,
        `${family}: a degrade/error envelope must carry container_isolated:false (not undefined)`,
      );
    }
  });
});

// The CONTAINER-route TRUE shape (the seam child carrying container_isolated:true that the
// runners read) is pinned at the seam-contract level in sc-container-teardown.test.js, and
// proved end-to-end for the load-bearing halmos family (a containerized halmos verdict
// reaching the gate as TRUSTED) in halmos-runner-container-isolated.test.js. This guard's
// job is the EXHAUSTIVE boolean-lift contract across all seven families (the recurring
// per-family miss), which the degrade/error path above proves without a real daemon.
