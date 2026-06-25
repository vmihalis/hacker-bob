"use strict";

// HIGH-1 NON-BYPASSABLE REGRESSION GUARD over the WHOLE SC family.
//
// The host-as-signer refuse (shouldRefuseHostAsSignerScRun) can only fire when a
// non-empty targetDomain reaches the seam baseOpts (sc-container-exec.js: it returns
// false on a domain-less call, since it cannot probe). foundry-runner already threaded
// targetDomain; the other six (halmos/anchor/cosmwasm/substrate/sui/aptos) did NOT, so
// for them the refuse silently returned false and the SC tool ran host-as-signer EVEN ON
// AN ISOLATED BOX. This per-family miss recurred three times (halmos route, then
// container_isolated, then targetDomain). This guard drives the REAL run* entry points
// for ALL SEVEN families and proves the refuse-relevant targetDomain genuinely reaches
// the seam per family -- a RUNTIME SPY + ROUTED registry, NOT a brittle source-grep. A
// runner that drops targetDomain would DEGRADE (spawn the tool, hit ENOENT) instead of
// REFUSE, so the test distinguishes refuse-fired (threaded) from degrade (dropped).
//
// The existing sc-container-exec.test.js routing guard calls the seam DIRECTLY with a
// hand-built baseOpts -- it can never catch a runner that drops targetDomain. This guard
// drives runFoundryTest/runHalmos/.../runAptosTest themselves.

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
const {
  setRouteSpy,
  ROUTED_SC_RUNNERS,
  __resetDockerProbeCache,
  SC_TOOLCHAIN_IMAGE_ENV,
} = require("../mcp/lib/sc-container-exec.js");
const { handoffSigningPrivateKeyPath } = require("../mcp/lib/paths.js");
const {
  SANDBOX_ATTESTATION_MODE_ENV,
  SANDBOX_SIGNER_UID_ENV,
  SANDBOX_AGENT_UID_ENV,
} = require("../mcp/lib/sandbox-isolation-attest.js");

const DOMAIN = "sc-thread.example.com";

// Build a $HOME harness shaped for each family's assertHarnessPath. foundry/halmos want a
// test/ subdir convention; cosmwasm/substrate REQUIRE a Cargo.toml at the root; anchor/sui
// /aptos only need a bare directory. We give every harness BOTH (a test/ subdir AND a
// Cargo.toml) so a single shape satisfies all seven -- the threading proof does not depend
// on the harness contents, only on reaching the seam.
function makeHarness(home, family) {
  const harness = fs.mkdtempSync(path.join(home, `.bob-${family}-harness-`));
  fs.mkdirSync(path.join(harness, "test"), { recursive: true });
  fs.writeFileSync(path.join(harness, "Cargo.toml"), "[package]\nname = \"h\"\nversion = \"0.0.0\"\n");
  return harness;
}

// The seven families, each driving its REAL run* with a non-empty target_domain. The
// refuse-fired outcome surfaces a per-family reason (foundry maps the refused code to
// sc_isolation_refused; the others surface <tool>_spawn_failed when the seam throws the
// refusal before spawning). `seamTool` is the bin name the seam records in the route
// registry (cosmwasm + substrate both spawn "cargo").
const FAMILIES = [
  { family: "foundry", seamTool: "forge", refuseReason: "sc_isolation_refused", run: (h) => runFoundryTest({ workdir: h, matchTest: "testX", targetDomain: DOMAIN }) },
  { family: "halmos", seamTool: "halmos", refuseReason: "halmos_spawn_failed", run: (h) => runHalmos({ workdir: h, matchTest: "testX", targetDomain: DOMAIN }) },
  { family: "anchor", seamTool: "anchor", refuseReason: "anchor_spawn_failed", run: (h) => runAnchorTest({ workdir: h, matchTest: "testX", targetDomain: DOMAIN }) },
  { family: "cosmwasm", seamTool: "cargo", refuseReason: "cargo_spawn_failed", run: (h) => runCosmwasmTest({ workdir: h, matchTest: "test_x", targetDomain: DOMAIN }) },
  { family: "substrate", seamTool: "cargo", refuseReason: "cargo_spawn_failed", run: (h) => runSubstrateTest({ workdir: h, matchTest: "test_x", targetDomain: DOMAIN }) },
  { family: "sui", seamTool: "sui", refuseReason: "sui_spawn_failed", run: (h) => runSuiTest({ workdir: h, matchTest: "test_x", targetDomain: DOMAIN }) },
  { family: "aptos", seamTool: "aptos", refuseReason: "aptos_spawn_failed", run: (h) => runAptosTest({ workdir: h, matchTest: "test_x", targetDomain: DOMAIN }) },
];

// ASYNC-AWARE env scope. The runners are async; the seam's isolation probe runs DURING
// the awaited spawn, so the env/stub MUST stay installed until the awaited work resolves
// (a synchronous try/finally would restore before the probe runs and mis-read the box as
// not-isolated). withEnv awaits fn().
async function withEnv(overrides, fn) {
  const keys = Object.keys(overrides);
  const prev = {};
  for (const k of keys) prev[k] = process.env[k];
  for (const k of keys) {
    if (overrides[k] === undefined) delete process.env[k];
    else process.env[k] = overrides[k];
  }
  try {
    return await fn();
  } finally {
    for (const k of keys) {
      if (prev[k] === undefined) delete process.env[k];
      else process.env[k] = prev[k];
    }
  }
}

// Stub the STRUCTURAL Mechanism-A isolated signer the live probe reads (owner-only 0400
// key owned by this process == declared signer, distinct non-root declared agent uid, not
// root) so probeVerdictLedgerKeyIsolation reports isolated:true. Without the threaded
// targetDomain the refuse would NOT fire even with this stub -- which is exactly what this
// guard catches.
async function withStructuralIsolatedKey(signerUid, agentUid, fn) {
  const realLstat = fs.lstatSync;
  const realGetuid = process.getuid;
  const keyPath = handoffSigningPrivateKeyPath(DOMAIN);
  fs.lstatSync = function stubLstat(p) {
    if (p === keyPath) return { uid: signerUid, mode: 0o400, isFile: () => true };
    return realLstat.apply(fs, arguments);
  };
  process.getuid = () => signerUid;
  return withEnv({
    [SANDBOX_SIGNER_UID_ENV]: String(signerUid),
    [SANDBOX_AGENT_UID_ENV]: String(agentUid),
  }, async () => {
    try {
      return await fn();
    } finally {
      fs.lstatSync = realLstat;
      process.getuid = realGetuid;
    }
  });
}

// Run a body with a temp $HOME (so harnesses pass isUnderHome), no SC-toolchain image (so
// the container route is unavailable and the seam takes the refuse/degrade branch),
// enforce mode, the docker probe reset, and the loud degrade/refusal stderr muted.
async function withGuardEnv(fn) {
  const previousHome = process.env.HOME;
  // Realpath the temp HOME so isUnderHome (which realpaths os.homedir()) compares apples
  // to apples -- on macOS /var is a symlink to /private/var, and a lexical harness path
  // under /var would fail the realpathed-home startsWith check otherwise.
  const home = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "bob-sc-thread-")));
  process.env.HOME = home;
  const previousWrite = process.stderr.write;
  process.stderr.write = () => true;
  __resetDockerProbeCache();
  try {
    return await withEnv({
      [SANDBOX_ATTESTATION_MODE_ENV]: "enforce",
      [SC_TOOLCHAIN_IMAGE_ENV]: undefined,
    }, () => fn(home));
  } finally {
    process.stderr.write = previousWrite;
    if (previousHome === undefined) delete process.env.HOME;
    else process.env.HOME = previousHome;
    __resetDockerProbeCache();
    fs.rmSync(home, { recursive: true, force: true });
  }
}

test("ALL SEVEN SC runners thread targetDomain into the seam: the host-as-signer refuse FIRES per family on an isolated box (no image)", async () => {
  await withGuardEnv(async (home) => {
    const seen = [];
    const startIndex = ROUTED_SC_RUNNERS.length;
    setRouteSpy((rec) => seen.push(rec));
    try {
      await withStructuralIsolatedKey(424242, 1000, async () => {
        for (const { family, refuseReason, run } of FAMILIES) {
          const harness = makeHarness(home, family);
          let result;
          try {
            result = await run(harness);
          } finally {
            fs.rmSync(harness, { recursive: true, force: true });
          }
          // OBSERVABLE EFFECT of threading: the runner surfaces the refuse outcome. If
          // targetDomain did NOT reach the seam, shouldRefuseHostAsSignerScRun returns
          // false and the runner would instead DEGRADE (spawn the tool, hit ENOENT ->
          // <tool>_not_in_path) -- a DIFFERENT reason -- so this assertion fails for a
          // runner that drops targetDomain.
          assert.equal(
            result.reason,
            refuseReason,
            `${family}: the refuse must fire (reason=${refuseReason}); a dropped targetDomain would degrade instead`,
          );
          if (family === "foundry") {
            assert.equal(result.container_isolated, false, "a refused run is never containerized");
          }
        }
      });
    } finally {
      setRouteSpy(null);
    }

    // REGISTRY BACKSTOP (runtime, spy-independent): recordRoute(bin,"refuse") is appended
    // ONLY when shouldRefuseHostAsSignerScRun returned true, which REQUIRES targetDomain
    // reached baseOpts. So route:"refuse" recorded for every SC seam tool is a runtime,
    // registry-backed proof the refuse-relevant targetDomain genuinely reached the seam
    // per family. cosmwasm + substrate both route as "cargo".
    const refusedTools = new Set(
      seen.filter((r) => r.route === "refuse").map((r) => r.tool),
    );
    for (const tool of ["forge", "halmos", "anchor", "cargo", "sui", "aptos"]) {
      assert.ok(refusedTools.has(tool), `${tool}: the seam recorded route:"refuse" (targetDomain reached baseOpts)`);
    }
    // Registry-backed, spy-independent: the same routes are appended to ROUTED_SC_RUNNERS.
    const registryRefused = new Set(
      ROUTED_SC_RUNNERS.slice(startIndex).filter((r) => r.route === "refuse").map((r) => r.tool),
    );
    for (const tool of ["forge", "halmos", "anchor", "cargo", "sui", "aptos"]) {
      assert.ok(registryRefused.has(tool), `${tool}: ROUTED_SC_RUNNERS recorded a refuse route`);
    }
  });
});

test("NEGATIVE control: a runner driven with an EMPTY target_domain DEGRADES (does NOT refuse) -- the guard detects a dropped/empty domain", async () => {
  await withGuardEnv(async (home) => {
    const seen = [];
    setRouteSpy((rec) => seen.push(rec));
    try {
      await withStructuralIsolatedKey(424242, 1000, async () => {
        const harness = makeHarness(home, "halmos-neg");
        let result;
        try {
          // Empty target_domain mirrors the handler's `typeof x === "string" ? x : null`
          // producing a falsy value; shouldRefuseHostAsSignerScRun returns false (cannot
          // probe a domain-less call) -> DEGRADE, not refuse. The degrade spawns halmos,
          // which is not in PATH in CI -> halmos_not_in_path (NOT halmos_spawn_failed).
          result = await runHalmos({ workdir: harness, matchTest: "testX", targetDomain: "" });
        } finally {
          fs.rmSync(harness, { recursive: true, force: true });
        }
        assert.notEqual(
          result.reason,
          "halmos_spawn_failed",
          "an empty target_domain must NOT trigger the refuse (it degrades instead)",
        );
        assert.equal(
          result.reason,
          "halmos_not_in_path",
          "the degrade route spawns halmos (absent in CI) -> halmos_not_in_path",
        );
      });
    } finally {
      setRouteSpy(null);
    }
    // The seam recorded a DEGRADE for this run, never a refuse -- proving the refuse is
    // gated on a non-empty threaded targetDomain.
    const routes = new Set(seen.filter((r) => r.tool === "halmos").map((r) => r.route));
    assert.ok(routes.has("degrade"), "an empty target_domain routes through the seam as a degrade");
    assert.ok(!routes.has("refuse"), "an empty target_domain never records a refuse route");
  });
});
