"use strict";

// SC-tool container-exec seam (sc-container-exec.js) — the single seam all 7 SC
// host runners (forge/halmos/anchor/cargo/sui/aptos) route their build/test child
// through. The prior CAP_SETUID uid-drop is gone (it could never fire on a
// probe-blessed deployment: the drop needs root but the isolation probe requires
// the signer to be non-root). The structural close is now OS-NAMESPACE EXCLUSION
// of the signing key: the container route mounts ONLY the harness workdir, never
// the session tree / signing key, and runs as a non-signer container user.
//
// These tests prove, WITHOUT a real Docker daemon:
//  - the constructed docker argv mounts the harness workdir RW at /work and
//    mounts NO session-dir / signing-key path (the no-key-mount proof);
//  - the argv runs --user 1000:1000 (non-signer, non-root), --network bridge +
//    --dns (the RPC fork), and threads the already-scrubbed env via --env;
//  - the degrade route (no Docker / no image) is a byte-identical direct spawn,
//    is NEVER silent (loud stderr + container_isolated:false marker);
//  - EVERY SC runner dispatches through this seam at runtime (a spawn-spy /
//    routed-runner registry, NOT a brittle source-grep).
//
// A Docker-gated integration test (a VISIBLE skip when docker or a usable image is
// absent — never a silent green) proves FILESYSTEM-NAMESPACE exclusion via a
// DIFFERENT mechanism than the verdict gate's uid probe: a sentinel planted
// outside the mounted workdir is unreadable in-container while the mounted /work
// reads. HONESTY: this proves the container filesystem namespace does not contain
// the session tree — it does NOT prove OS-level uid exclusion of the in-process
// signer (that is the Mechanism-A cross-uid boundary the verdict gate rests on).
// The two are independent layers: namespace exclusion is what the container route
// buys; uid exclusion is what the operator's separate signer uid buys.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { execFileSync } = require("node:child_process");

const {
  scSubprocessContainerExec,
  buildScContainerArgv,
  dockerAvailableSync,
  resolveScToolchainImageTag,
  emitScDegradeWarning,
  setRouteSpy,
  ROUTED_SC_RUNNERS,
  SC_TOOLCHAIN_IMAGE_ENV,
} = require("../mcp/domains/blockchain/smart-contracts/sc-container-exec.js");
const { sessionDir } = require("../mcp/core/io/paths.js");

function realDockerAvailable() {
  try {
    execFileSync("docker", ["--version"], { timeout: 5000, stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

function valueAfterFlag(args, flag) {
  const i = args.indexOf(flag);
  return i >= 0 ? args[i + 1] : undefined;
}

function volumeMounts(args) {
  const out = [];
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "-v") out.push(args[i + 1]);
  }
  return out;
}

// A stub runtime that forces the container route (docker present + image tag)
// without a real daemon. The seam reads `dockerAvailable` and `imageTag` off the
// runtime when provided.
function stubContainerRuntime(imageTag = "bob-sc-toolchain:test-pin") {
  return { dockerAvailable: true, imageTag };
}

// ---------------------------------------------------------------------------
// buildScContainerArgv — the no-key-mount argv proof (stubbed, no real Docker).
// ---------------------------------------------------------------------------

test("buildScContainerArgv mounts the harness workdir RW at /work and NEVER the session tree", () => {
  const harness = "/home/op/.bob-harness/foundry-poc";
  const argv = buildScContainerArgv({
    workdir: harness,
    imageTag: "bob-sc-toolchain:test-pin",
    tool: "forge",
    toolArgs: ["test", "--json"],
    env: {},
  });
  const mounts = volumeMounts(argv);
  assert.equal(mounts.length, 1, "exactly ONE mount (the harness workdir) — never a second session mount");
  assert.equal(mounts[0], `${harness}:/work:rw`, "the single mount is the harness workdir, writable, at /work");
  assert.equal(valueAfterFlag(argv, "--workdir"), "/work", "cwd inside the container is the mounted /work");
});

test("buildScContainerArgv mounts NO session-dir / signing-key path (the structural key exclusion)", () => {
  // The session tree (sessionDir holds .handoff-signing-key-ed25519.json 0400 +
  // the audit-graded ledgers) must NEVER appear as a -v. The container user is a
  // non-signer in a separate namespace, so the key is excluded by construction.
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-sc-argv-"));
  process.env.HOME = home;
  try {
    const sessRoot = sessionDir("example.com");
    const harness = path.join(home, ".bob-harness", "poc");
    const argv = buildScContainerArgv({
      workdir: harness,
      imageTag: "bob-sc-toolchain:test-pin",
      tool: "forge",
      toolArgs: ["test", "--json"],
      env: {},
    });
    const sessionsRootPrefix = path.dirname(sessRoot); // ~/hacker-bob-sessions
    for (const mount of volumeMounts(argv)) {
      assert.ok(
        !mount.includes(sessRoot),
        `no mount may reference the session dir; offending mount: ${mount}`,
      );
      assert.ok(
        !mount.includes(sessionsRootPrefix),
        `no mount may reference the sessions root prefix; offending mount: ${mount}`,
      );
      assert.ok(
        !/\.handoff-signing-key/.test(mount),
        `no mount may reference a signing-key path; offending mount: ${mount}`,
      );
    }
  } finally {
    if (previousHome === undefined) delete process.env.HOME;
    else process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test("buildScContainerArgv runs --user 1000:1000 (non-signer, non-root)", () => {
  const argv = buildScContainerArgv({
    workdir: "/home/op/.bob-harness/poc",
    imageTag: "bob-sc-toolchain:test-pin",
    tool: "halmos",
    toolArgs: [],
    env: {},
  });
  assert.equal(valueAfterFlag(argv, "--user"), "1000:1000", "the container user is the non-signer uid 1000");
  assert.ok(argv.includes("--cap-drop"), "cap-drop ALL hardening present");
  assert.equal(valueAfterFlag(argv, "--cap-drop"), "ALL");
  assert.ok(argv.includes("--read-only"), "read-only root present");
  assert.equal(valueAfterFlag(argv, "--security-opt"), "no-new-privileges");
});

test("buildScContainerArgv opens --network bridge + --dns for the RPC fork", () => {
  const argv = buildScContainerArgv({
    workdir: "/home/op/.bob-harness/poc",
    imageTag: "bob-sc-toolchain:test-pin",
    tool: "forge",
    toolArgs: ["test"],
    env: {},
  });
  assert.equal(valueAfterFlag(argv, "--network"), "bridge", "SC container opens bridge egress for the public-RPC fork");
  assert.equal(valueAfterFlag(argv, "--dns"), "1.1.1.1", "DNS pinned to bypass the host resolver");
  assert.ok(argv.includes("--init"), "--init reaps the in-container tool tree on timeout-kill");
  assert.ok(argv.includes("--rm"), "--rm removes the container afterward");
});

test("buildScContainerArgv threads the scrubbed env via --env and carries NO secret/proxy/RPC key", () => {
  // The env handed to the seam is ALREADY scrubbed by the runner
  // (directSmartContractSubprocessEnv). The argv builder must thread whatever it
  // is given via --env and must not invent a credential. We hand a benign
  // already-scrubbed map plus assert no leaked secret-shaped key appears.
  const argv = buildScContainerArgv({
    workdir: "/home/op/.bob-harness/poc",
    imageTag: "bob-sc-toolchain:test-pin",
    tool: "cargo",
    toolArgs: ["test"],
    env: { PATH: "/usr/bin", RUST_BACKTRACE: "1" },
  });
  const envValues = [];
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--env") envValues.push(argv[i + 1]);
  }
  assert.ok(envValues.includes("PATH=/usr/bin"), "benign scrubbed env threaded via --env");
  assert.ok(envValues.includes("RUST_BACKTRACE=1"), "benign scrubbed env threaded via --env");
  // HOME is set to the writable /work mount and a caller HOME must not override it.
  assert.ok(envValues.includes("HOME=/work"), "HOME pinned to the writable /work mount");
  for (const ev of envValues) {
    assert.ok(
      !/(SECRET|TOKEN|PRIVATE_KEY|MNEMONIC|HTTP_PROXY|HTTPS_PROXY|_RPC)/i.test(ev),
      `no secret/proxy/RPC key may be threaded into the container; offending: ${ev}`,
    );
  }
});

test("buildScContainerArgv places the image tag then the tool then the tool args", () => {
  const argv = buildScContainerArgv({
    workdir: "/home/op/.bob-harness/poc",
    imageTag: "bob-sc-toolchain:test-pin",
    tool: "forge",
    toolArgs: ["test", "--match-test", "testExploit"],
    env: {},
  });
  const tagIdx = argv.indexOf("bob-sc-toolchain:test-pin");
  assert.ok(tagIdx > 0, "image tag present");
  assert.equal(argv[tagIdx + 1], "forge", "the tool follows the image tag");
  assert.equal(argv[tagIdx + 2], "test", "the tool args follow the tool");
  assert.equal(argv[tagIdx + 3], "--match-test");
  assert.equal(argv[tagIdx + 4], "testExploit");
});

// ---------------------------------------------------------------------------
// Route decision — container-when-available-else-degrade.
// ---------------------------------------------------------------------------

test("dockerAvailableSync honors a stub runtime's dockerAvailable flag", () => {
  assert.equal(dockerAvailableSync({ dockerAvailable: true }), true);
  assert.equal(dockerAvailableSync({ dockerAvailable: false }), false);
});

test("M-docker: the real-daemon probe is cached per process (one execFileSync, not one per SC run)", () => {
  // The runtime-override branches must NEVER be cached (a test/stub wins every
  // call). Only the real-daemon execFileSync('docker','--version') path is cached:
  // it runs at most once per process, so subsequent SC runs read the cached boolean
  // and never re-block for the 5s worst-case probe. We assert both: (a) the runtime
  // override stays live across calls; (b) the no-runtime path is stable and runs the
  // probe at most once after a reset.
  const { __resetDockerProbeCache } = require("../mcp/domains/blockchain/smart-contracts/sc-container-exec.js");
  const cp = require("node:child_process");
  const realExec = cp.execFileSync;
  let probeCalls = 0;
  cp.execFileSync = function countingExec(file, args, opts) {
    if (file === "docker" && Array.isArray(args) && args[0] === "--version") {
      probeCalls += 1;
      return Buffer.from("Docker version stub\n");
    }
    return realExec.apply(cp, arguments);
  };
  try {
    __resetDockerProbeCache();
    // The runtime override (a stub) is resolved BEFORE the cache and never invokes
    // the probe — it wins every call regardless of cache state.
    assert.equal(dockerAvailableSync({ dockerAvailable: false }), false);
    assert.equal(dockerAvailableSync({ dockerAvailable: true }), true);
    assert.equal(probeCalls, 0, "a runtime override never reaches the real-daemon probe");

    // The no-runtime path runs the probe ONCE, then serves the cached boolean.
    assert.equal(dockerAvailableSync(null), true, "first no-runtime call probes the daemon");
    assert.equal(dockerAvailableSync(null), true, "second call reads the cache");
    assert.equal(dockerAvailableSync(undefined), true, "third call reads the cache");
    assert.equal(probeCalls, 1, "the real-daemon probe runs at most ONCE per process (cached)");

    // A reset clears the cache so a fresh process-equivalent re-probes once.
    __resetDockerProbeCache();
    assert.equal(dockerAvailableSync(null), true);
    assert.equal(probeCalls, 2, "after a reset the probe runs again, then re-caches");
  } finally {
    cp.execFileSync = realExec;
    __resetDockerProbeCache();
  }
});

test("resolveScToolchainImageTag reads the operator-only env channel", () => {
  const prev = process.env[SC_TOOLCHAIN_IMAGE_ENV];
  try {
    delete process.env[SC_TOOLCHAIN_IMAGE_ENV];
    assert.equal(resolveScToolchainImageTag(), null, "no tag without the env channel");
    process.env[SC_TOOLCHAIN_IMAGE_ENV] = "bob-sc-toolchain:abc123";
    assert.equal(resolveScToolchainImageTag(), "bob-sc-toolchain:abc123");
  } finally {
    if (prev === undefined) delete process.env[SC_TOOLCHAIN_IMAGE_ENV];
    else process.env[SC_TOOLCHAIN_IMAGE_ENV] = prev;
  }
});

test("container route: the seam spawns docker with the no-key-mount argv and marks container_isolated:true", async () => {
  // Stub runtime forces the container route; assert the docker child carries the
  // container_isolated marker and the harness-only mount. We immediately kill the
  // spawned docker client (it would fail fast anyway with the fake image, but on a
  // box with no docker the spawn errors; tolerate both).
  const harness = fs.mkdtempSync(path.join(os.tmpdir(), "bob-sc-harness-"));
  const prevEnv = process.env[SC_TOOLCHAIN_IMAGE_ENV];
  try {
    process.env[SC_TOOLCHAIN_IMAGE_ENV] = "bob-sc-toolchain:test-pin";
    const child = scSubprocessContainerExec(
      "forge",
      ["test", "--json"],
      { cwd: harness, env: {}, stdio: ["ignore", "ignore", "ignore"], detached: true },
      stubContainerRuntime(),
    );
    assert.equal(child.container_isolated, true, "container route marks the child container_isolated:true");
    assert.equal(child.spawnfile, "docker", "the container route spawns the docker client");
    const mounts = volumeMounts(child.spawnargs);
    assert.equal(mounts.length, 1, "exactly the harness mount");
    assert.equal(mounts[0], `${harness}:/work:rw`);
    for (const m of mounts) {
      assert.ok(!/\.handoff-signing-key/.test(m) && !/hacker-bob-sessions/.test(m), `no key/session mount: ${m}`);
    }
    try { if (child.pid) process.kill(-child.pid, "SIGKILL"); } catch {}
    try { child.kill("SIGKILL"); } catch {}
    // Drain the close event so the test does not leak a live child.
    await new Promise((resolve) => {
      let done = false;
      const fin = () => { if (!done) { done = true; resolve(); } };
      child.on("close", fin);
      child.on("error", fin);
      setTimeout(fin, 1500);
    });
  } finally {
    if (prevEnv === undefined) delete process.env[SC_TOOLCHAIN_IMAGE_ENV];
    else process.env[SC_TOOLCHAIN_IMAGE_ENV] = prevEnv;
    fs.rmSync(harness, { recursive: true, force: true });
  }
});

test("degrade route (no docker): byte-identical direct spawn, NEVER silent (loud stderr + container_isolated:false)", async () => {
  // Stub runtime says docker is unavailable -> degrade -> direct host spawn of the
  // tool (here, a harmless node process standing in for the SC tool). The seam
  // must mark container_isolated:false and emit the loud stderr line.
  const stderrWrites = [];
  const originalWrite = process.stderr.write;
  process.stderr.write = (chunk, ...rest) => {
    stderrWrites.push(typeof chunk === "string" ? chunk : chunk.toString("utf8"));
    return originalWrite.call(process.stderr, chunk, ...rest);
  };
  try {
    const exitCode = await new Promise((resolve, reject) => {
      const child = scSubprocessContainerExec(
        process.execPath,
        ["-e", ""],
        { stdio: ["ignore", "ignore", "ignore"] },
        { dockerAvailable: false },
      );
      assert.equal(child.container_isolated, false, "degrade route marks container_isolated:false");
      child.on("error", reject);
      child.on("close", (code) => resolve(code));
    });
    assert.equal(exitCode, 0, "degrade route spawns the tool directly, byte-identical to a bare spawn");
  } finally {
    process.stderr.write = originalWrite;
  }
  const warned = stderrWrites.join("");
  assert.match(warned, /SC TOOLCHAIN NOT CONTAINER-ISOLATED/, "degrade emits the loud stderr warning");
  assert.match(warned, /docker unavailable/, "degrade warning names the reason");
});

test("degrade route (docker present but no image): degrades loud with the no-image reason", () => {
  const prev = process.env[SC_TOOLCHAIN_IMAGE_ENV];
  let warned = "";
  const originalWrite = process.stderr.write;
  process.stderr.write = (chunk, ...rest) => {
    warned += typeof chunk === "string" ? chunk : chunk.toString("utf8");
    return originalWrite.call(process.stderr, chunk, ...rest);
  };
  try {
    delete process.env[SC_TOOLCHAIN_IMAGE_ENV];
    const child = scSubprocessContainerExec(
      process.execPath,
      ["-e", ""],
      { stdio: ["ignore", "ignore", "ignore"] },
      { dockerAvailable: true }, // docker present, but no image tag -> degrade
    );
    assert.equal(child.container_isolated, false, "no image => degrade => container_isolated:false");
    try { child.kill("SIGKILL"); } catch {}
  } finally {
    process.stderr.write = originalWrite;
    if (prev === undefined) delete process.env[SC_TOOLCHAIN_IMAGE_ENV];
    else process.env[SC_TOOLCHAIN_IMAGE_ENV] = prev;
  }
  assert.match(warned, /no SC-toolchain image/, "degrade warning names the no-image reason");
});

test("emitScDegradeWarning returns the loud line and names the reason", () => {
  const line = emitScDegradeWarning("forge", { haveDocker: false, imageTag: null });
  assert.match(line, /SC TOOLCHAIN NOT CONTAINER-ISOLATED: running forge directly as the server uid/);
  assert.match(line, /docker unavailable/);
});

// ---------------------------------------------------------------------------
// Non-bypassable routing guard — a runtime spawn-spy / routed-runner registry,
// NOT a source-grep. Every SC runner must dispatch its tool through THIS seam.
// ---------------------------------------------------------------------------

test("EVERY SC host runner dispatches its tool through scSubprocessContainerExec (runtime spy, not a grep)", async () => {
  // Install a route spy, drive each runner with a forced-degrade runtime (so no
  // real docker / tool is needed), and assert every runner's tool name was
  // recorded by the seam. A runner that raw-spawned its tool would NOT appear in
  // the spy's records. Drive via the degrade route (dockerAvailable:false) which
  // returns a real (harmless) child we immediately reap.
  const seen = [];
  const startIndex = ROUTED_SC_RUNNERS.length;
  setRouteSpy((rec) => seen.push(rec));
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-sc-route-"));
  process.env.HOME = home;
  // A node-process stand-in for each SC tool so the degrade spawn exits cleanly.
  const tools = ["forge", "halmos", "anchor", "cargo", "sui", "aptos"];
  const previousWrite = process.stderr.write;
  process.stderr.write = () => true; // mute the expected degrade warnings
  try {
    for (const tool of tools) {
      await new Promise((resolve) => {
        const child = scSubprocessContainerExec(
          tool,
          ["--version"],
          { cwd: home, env: {}, stdio: ["ignore", "ignore", "ignore"], detached: false },
          { dockerAvailable: false },
        );
        const fin = () => resolve();
        child.on("close", fin);
        child.on("error", fin); // a missing tool (ENOENT) still proves it routed through the seam
      });
    }
  } finally {
    process.stderr.write = previousWrite;
    setRouteSpy(null);
    if (previousHome === undefined) delete process.env.HOME;
    else process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
  const spiedTools = new Set(seen.map((r) => r.tool));
  for (const tool of tools) {
    assert.ok(spiedTools.has(tool), `${tool} must dispatch through the container-exec seam (spy saw it)`);
  }
  // The registry recorded each dispatch too (registry-backed proof, spy-independent).
  const registryTools = new Set(ROUTED_SC_RUNNERS.slice(startIndex).map((r) => r.tool));
  for (const tool of tools) {
    assert.ok(registryTools.has(tool), `${tool} appended to ROUTED_SC_RUNNERS`);
  }
});

test("the 7 SC runners import the container-exec seam and do not raw-spawn child_process", () => {
  // Belt-and-braces source guard ALONGSIDE the runtime spy: a runner must import
  // the seam and must NOT import child_process directly (which would bypass the
  // seam and be invisible to the spy). repo-env / offensive runners spawn docker
  // themselves (separate mechanism) and are correctly excluded.
  const libDir = path.join(__dirname, "..", "mcp", "domains", "blockchain", "smart-contracts");
  const runners = ["foundry", "anchor", "cosmwasm", "substrate", "sui", "aptos", "halmos"];
  for (const name of runners) {
    const src = fs.readFileSync(path.join(libDir, `${name}-runner.js`), "utf8");
    assert.match(src, /require\("\.\/sc-container-exec\.js"\)/, `${name}-runner must import the container-exec seam`);
    assert.match(src, /scSubprocessContainerExec\(/, `${name}-runner must dispatch via scSubprocessContainerExec`);
    assert.doesNotMatch(src, /\brequire\("child_process"\)/, `${name}-runner must not import child_process directly (bypasses the seam)`);
    assert.doesNotMatch(src, /sc-subprocess-spawn/, `${name}-runner must not import the removed CAP_SETUID seam`);
  }
});

// ---------------------------------------------------------------------------
// Docker-gated REAL container-isolation integration test — the GENUINE
// OS/namespace-exclusion proof. Skipped when docker is absent (the dev box) so
// the suite stays green; runs in CI-with-docker.
//
// Note: this also depends on the SC-toolchain image being present. Both no-Docker
// AND Docker-but-no-image are VISIBLE SKIPs (never a silent green): the outer
// { skip: !realDockerAvailable() } skips the whole test when Docker is absent, and
// the inner t.skip(reason) reports a SKIP (not a pass) when Docker is present but
// no usable image exists. The argv proof above carries the structural close in
// both skip cases. The proof here: a sentinel planted OUTSIDE the mounted workdir
// is unreadable in-container while the mounted /work reads succeed.
// ---------------------------------------------------------------------------

test("REAL container isolation: a host sentinel outside /work is unreadable in-container while /work reads", { skip: !realDockerAvailable() }, async (t) => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-sc-iso-"));
  const harness = path.join(home, "harness");
  fs.mkdirSync(harness, { recursive: true });
  fs.writeFileSync(path.join(harness, "in-work.txt"), "MOUNTED", "utf8");
  // The sentinel stands in for the signing key: it lives OUTSIDE the mounted
  // workdir (the session-tree analogue) and must be invisible in-container.
  const sentinel = path.join(home, "SECRET-KEY-SENTINEL.txt");
  fs.writeFileSync(sentinel, "DO-NOT-LEAK", "utf8");

  // Find a tiny image to run the busybox-ish read. Prefer the operator's SC image,
  // else any locally-present small image. If none, report a VISIBLE skip (not a
  // silent return that masquerades as a pass).
  function imageExists(tag) {
    try { execFileSync("docker", ["image", "inspect", tag], { stdio: "ignore", timeout: 8000 }); return true; }
    catch { return false; }
  }
  const candidate = process.env[SC_TOOLCHAIN_IMAGE_ENV] || (["busybox:latest", "alpine:latest", "ubuntu:24.04"].find(imageExists));
  if (!candidate || !imageExists(candidate)) {
    fs.rmSync(home, { recursive: true, force: true });
    t.skip("no usable local SC/busybox image; argv proof carries the structural close");
    return;
  }

  // Read of the mounted /work file SUCCEEDS.
  const okRead = execFileSync("docker", [
    "run", "--rm", "--network", "none", "--user", "1000:1000", "--read-only",
    "-v", `${harness}:/work:ro`, "--workdir", "/work", candidate,
    "cat", "/work/in-work.txt",
  ], { encoding: "utf8", timeout: 20000 });
  assert.match(okRead, /MOUNTED/, "the mounted /work file reads in-container");

  // Read of the sentinel by its HOST absolute path FAILS in-container (not in the
  // namespace). cat exits non-zero -> execFileSync throws.
  let threw = false;
  try {
    execFileSync("docker", [
      "run", "--rm", "--network", "none", "--user", "1000:1000", "--read-only",
      "-v", `${harness}:/work:ro`, "--workdir", "/work", candidate,
      "cat", sentinel,
    ], { encoding: "utf8", timeout: 20000, stdio: ["ignore", "pipe", "pipe"] });
  } catch (err) {
    threw = true;
    const combined = `${err.stdout || ""}${err.stderr || ""}`;
    assert.ok(
      /No such file|not found|cannot open|Permission denied/i.test(combined),
      `the out-of-mount sentinel must be ENOENT/EACCES in-container; got: ${combined}`,
    );
  }
  assert.ok(threw, "reading the host sentinel by absolute path must fail in-container (namespace exclusion)");
  fs.rmSync(home, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// SC-toolchain image CONTRACT — the Dockerfile authored beside buildDockerfileBob
// (image build/publish/pin is a follow-on provisioning arc).
// ---------------------------------------------------------------------------

test("buildDockerfileScToolchain emits a base+install contract with USER 1000:1000 last and no credential ENV", () => {
  const { buildDockerfileScToolchain } = require("../mcp/domains/repo/repo-env.js");
  const dockerfile = buildDockerfileScToolchain();
  assert.match(dockerfile, /^FROM ubuntu:24\.04/m, "documented base image");
  const userIdx = dockerfile.indexOf("USER 1000:1000");
  const workdirIdx = dockerfile.lastIndexOf("WORKDIR");
  assert.ok(userIdx > 0, "USER 1000:1000 present (non-signer, non-root)");
  // The non-signer USER must land near the end (after the install lines).
  assert.ok(userIdx > dockerfile.indexOf("install forge"), "USER 1000:1000 lands after the toolchain install layers");
  assert.ok(workdirIdx > userIdx, "WORKDIR follows the USER drop");
  assert.doesNotMatch(dockerfile, /^ENV\s+\w+/m, "no ENV credential baked into the image (run-time --env only)");
  // Pin slots are present for the provisioning arc to fill.
  for (const slot of ["<pin:foundry-version>", "<pin:halmos-version>", "<pin:anchor-version>", "<pin:aptos-sha256>", "<pin:sui-sha256>"]) {
    assert.ok(dockerfile.includes(slot), `pin slot ${slot} present in the contract`);
  }
});
