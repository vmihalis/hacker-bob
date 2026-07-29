"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const childProcess = require("node:child_process");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const packageRoot = path.resolve(__dirname, "..");
// The fixture retains every absolute ancestor. A shared TMPDIR would turn
// unrelated parallel-test directory churn into a false ancestry rejection.
const fixtureWorkspace = fs.realpathSync(
  fs.mkdtempSync(path.join(packageRoot, ".native-fixture-test-")),
);
const shippedBinary = path.join(
  packageRoot,
  "dist",
  "bob-darwin-launcher-fixture",
);
const binary = path.join(fixtureWorkspace, "bob-darwin-launcher-fixture");
fs.copyFileSync(shippedBinary, binary, fs.constants.COPYFILE_EXCL);
fs.chmodSync(binary, 0o755);
process.once("exit", () => {
  fs.rmSync(fixtureWorkspace, { force: true, recursive: true });
});

const nativeRecordModule = require("../lib/native-fixture-record.js");
const {
  DARWIN_NATIVE_FIXTURE_ENTRY_COUNT,
  DARWIN_NATIVE_FIXTURE_CONTRACT_PRODUCTION_BLOCKERS,
  DARWIN_NATIVE_FIXTURE_CONTRACT_RECORD_DOMAIN,
  DARWIN_NATIVE_FIXTURE_CONTRACT_RECORD_VERSION,
  normalizeDarwinNativeFixtureContractRecord,
} = nativeRecordModule;
const {
  DARWIN_NATIVE_FIXTURE_UNDEFINED_SYMBOL_ALLOWLIST,
  assertExactDarwinNativeFixtureUndefinedSymbols,
} = require("../lib/native-binary-symbol-contract.js");

const linkedSource = path.join(packageRoot, "native", "darwin-launcher-fixture.c");
const privilegedExecutorSource = path.resolve(
  __dirname,
  "..",
  "native",
  "darwin-privileged-launch-executor.source.c",
);
const MANIFEST_RELATIVE = "config/native-launch-fixture.manifest";
const ROOT_DOMAIN = "hacker-bob/instrument-darwin-native-fixture-root-identity/v1";
const WALK_DOMAIN = "hacker-bob/instrument-darwin-native-fixture-openat-walk/v1";
const FD_DOMAIN = "hacker-bob/instrument-darwin-native-fixture-fd-enumeration/v1";
const ENTRY_SPECS = Object.freeze([
  Object.freeze({ relative: "bin", type: "d" }),
  Object.freeze({ relative: "bin/node", type: "f" }),
  Object.freeze({ relative: "config", type: "d" }),
  Object.freeze({ relative: "config/worker.json", type: "f" }),
  Object.freeze({ relative: "lib", type: "d" }),
  Object.freeze({ relative: "lib/worker.js", type: "f" }),
  Object.freeze({ relative: "native", type: "d" }),
  Object.freeze({ relative: "native/driver.node", type: "f" }),
]);

if (process.platform !== "darwin" || process.arch !== "arm64"
    || typeof process.getuid !== "function" || process.getuid() === 0) {
  throw new Error("native fixture tests require a non-root Darwin arm64 process");
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function contractDigest(label) {
  return sha256(`darwin-native-fixture-test:${label}`);
}

// A minimal PATH rather than a wholly empty environment. `xcrun --find
// codesign` shells out to xcodebuild to resolve a tool outside the toolchain
// directory, and with environ empty that lookup fails (exit 72) — so the
// fixture build died on a runner while the developer machines that had already
// resolved it stayed green. Still hermetic: one absolute, fixed value, nothing
// inherited from the caller.
const BUILD_TOOL_ENV = Object.freeze({ PATH: "/usr/bin:/bin" });

function runBuildTool(tool, args) {
  const result = childProcess.spawnSync(tool, args, {
    encoding: "utf8",
    env: BUILD_TOOL_ENV,
    stdio: ["ignore", "pipe", "pipe"],
  });
  if (result.status !== 0) {
    throw new Error(`test-only native fixture build failed: ${path.basename(tool)}`);
  }
  return result.stdout.trim();
}

function resolveBuildTool(name) {
  const resolved = runBuildTool("/usr/bin/xcrun", ["--find", name]);
  if (!path.isAbsolute(resolved)) throw new Error("test-only build tool path is not absolute");
  return resolved;
}

function buildTestOnlyPhaseBinary() {
  const directory = fs.realpathSync(
    fs.mkdtempSync(path.join(fixtureWorkspace, "phase-binary-")),
  );
  const output = path.join(directory, "bob-darwin-launcher-test-only-phase");
  const sdk = runBuildTool("/usr/bin/xcrun", ["--sdk", "macosx", "--show-sdk-path"]);
  const clang = resolveBuildTool("clang");
  const codesign = resolveBuildTool("codesign");
  runBuildTool(clang, [
    "-std=c17",
    "-O2",
    "-Wall",
    "-Wextra",
    "-Werror",
    "-Wpedantic",
    "-Wno-deprecated-declarations",
    "-fstack-protector-strong",
    "-D_FORTIFY_SOURCE=2",
    "-DHB_TEST_ONLY_PHASE_BARRIER=1",
    "-fPIE",
    "-mmacosx-version-min=13.0",
    "-isysroot",
    sdk,
    "-Wl,-pie",
    "-Wl,-fatal_warnings",
    "-o",
    output,
    linkedSource,
  ]);
  runBuildTool(codesign, ["--force", "--sign", "-", "--timestamp=none", output]);
  fs.chmodSync(output, 0o755);
  return { directory, output };
}

function statGeneration(target) {
  const result = childProcess.spawnSync("/usr/bin/stat", ["-f", "%v", target], {
    encoding: "utf8",
    env: {},
    stdio: ["ignore", "pipe", "pipe"],
  });
  if (result.status !== 0 || !/^\d+\n?$/u.test(result.stdout)) {
    throw new Error("Darwin fixture generation stat failed");
  }
  return BigInt(result.stdout.trim());
}

function timespec(nanoseconds) {
  const billion = 1_000_000_000n;
  return [nanoseconds / billion, nanoseconds % billion];
}

function identity(target) {
  const status = fs.lstatSync(target, { bigint: true });
  const [mtimeSeconds, mtimeNanoseconds] = timespec(status.mtimeNs);
  const [ctimeSeconds, ctimeNanoseconds] = timespec(status.ctimeNs);
  return Object.freeze({
    dev: status.dev,
    ino: status.ino,
    uid: status.uid,
    gid: status.gid,
    mode: status.mode & 0o7777n,
    nlink: status.nlink,
    size: status.size,
    generation: statGeneration(target),
    mtimeSeconds,
    mtimeNanoseconds,
    ctimeSeconds,
    ctimeNanoseconds,
  });
}

function identityFields(value) {
  return [
    value.dev,
    value.ino,
    value.uid,
    value.gid,
    value.mode.toString(8).padStart(4, "0"),
    value.nlink,
    value.size,
    value.generation,
    value.mtimeSeconds,
    value.mtimeNanoseconds,
    value.ctimeSeconds,
    value.ctimeNanoseconds,
  ].join("|");
}

function removeFixture(fixture) {
  for (const field of ["mutationFd", "manifestMutationFd"]) {
    if (fixture[field] != null) {
      try { fs.closeSync(fixture[field]); } catch {}
      fixture[field] = null;
    }
  }
  for (const relative of ["bin", "config", "lib", "native"]) {
    try { fs.chmodSync(path.join(fixture.root, relative), 0o700); } catch {}
  }
  try { fs.chmodSync(fixture.root, 0o700); } catch {}
  fs.rmSync(fixture.parent, { force: true, recursive: true });
}

function createFixture(options = {}) {
  const temporary = fs.mkdtempSync(path.join(fixtureWorkspace, "bundle-"));
  const parent = fs.realpathSync(temporary);
  const ancestrySlot = options.ancestorSlot === true ? path.join(parent, "slot") : parent;
  if (options.ancestorSlot === true) fs.mkdirSync(ancestrySlot, { mode: 0o700 });
  const root = path.join(ancestrySlot, "bundle");
  const manifestPath = path.join(root, MANIFEST_RELATIVE);
  fs.mkdirSync(root, { mode: 0o700 });
  for (const directory of ["bin", "config", "lib", "native"]) {
    fs.mkdirSync(path.join(root, directory), { mode: 0o700 });
  }
  fs.writeFileSync(path.join(root, "bin/node"), "fixture-node-runtime\n", { mode: 0o600 });
  fs.writeFileSync(path.join(root, "config/worker.json"), "{\"fixture\":true}\n", { mode: 0o600 });
  const workerBytes = options.workerBytes == null
    ? Buffer.from("module.exports = Object.freeze({ fixture: true });\n")
    : Buffer.alloc(options.workerBytes, 0x61);
  fs.writeFileSync(path.join(root, "lib/worker.js"), workerBytes, { mode: 0o600 });
  fs.writeFileSync(path.join(root, "native/driver.node"), "fixture-native-addon\n", { mode: 0o600 });
  fs.writeFileSync(manifestPath, "placeholder\n", { mode: 0o600 });

  let mutationFd = null;
  let manifestMutationFd = null;
  if (options.keepWorkerMutationFd === true) {
    mutationFd = fs.openSync(path.join(root, "lib/worker.js"), "r+");
  }
  if (options.keepManifestMutationFd === true) {
    manifestMutationFd = fs.openSync(manifestPath, "r+");
  }
  fs.chmodSync(path.join(root, "bin/node"), 0o500);
  for (const relative of ["config/worker.json", "lib/worker.js", "native/driver.node"]) {
    fs.chmodSync(path.join(root, relative), 0o400);
  }
  for (const relative of ["bin", "config", "lib", "native"]) {
    fs.chmodSync(path.join(root, relative), 0o500);
  }
  fs.chmodSync(root, 0o500);

  const rootIdentity = identity(root);
  const entries = ENTRY_SPECS.map((specification) => {
    const target = path.join(root, specification.relative);
    const entryIdentity = identity(target);
    const digest = specification.type === "f" ? sha256(fs.readFileSync(target)) : "-";
    const canonical = [
      specification.relative,
      specification.type,
      identityFields(entryIdentity),
      digest,
    ].join("|");
    return Object.freeze({ ...specification, identity: entryIdentity, digest, canonical });
  });
  const contractDigests = Object.freeze({
    launch_plan_digest: contractDigest("launch-plan"),
    worker_bundle_projection_digest: contractDigest("worker-bundle-projection"),
    native_evidence_digest: contractDigest("native-evidence"),
    path_plan_digest: contractDigest("path-plan"),
    argv_digest: contractDigest("argv"),
    environment_digest: contractDigest("environment"),
    fd_set_digest: contractDigest("fd-set"),
    credential_plan_digest: contractDigest("credential-plan"),
  });
  const manifestLines = [
    "version=1",
    "role=active_device_worker",
    `root_path=${root}`,
    `executable_path=${root}/bin/node`,
    `entrypoint_path=${root}/lib/worker.js`,
    `config_manifest_path=${root}/config/worker.json`,
    ...Object.entries(contractDigests).map(([key, value]) => `${key}=${value}`),
    `root=${identityFields(rootIdentity)}`,
    `entry_count=${ENTRY_SPECS.length}`,
    ...entries.map((entry) => `entry=${entry.canonical}`),
  ];
  const manifest = `${manifestLines.join("\n")}\n`;
  fs.writeFileSync(manifestPath, manifest);
  fs.chmodSync(manifestPath, 0o400);

  const finalRootIdentity = identity(root);
  assert.deepEqual(finalRootIdentity, rootIdentity, "fixture root identity drifted during assembly");
  for (let index = 0; index < entries.length; index += 1) {
    assert.deepEqual(
      identity(path.join(root, entries[index].relative)),
      entries[index].identity,
      `fixture entry identity drifted: ${entries[index].relative}`,
    );
  }
  return {
    parent,
    ancestrySlot,
    root,
    manifest,
    manifestPath,
    manifestDigest: sha256(manifest),
    rootIdentity,
    entries,
    contractDigests,
    mutationFd,
    manifestMutationFd,
  };
}

function spawnFixture(fixture, options = {}) {
  const root = options.root == null ? fixture.root : options.root;
  const manifestDigest = options.manifestDigest == null
    ? fixture.manifestDigest
    : options.manifestDigest;
  const extraPath = path.join(fixture.parent, "inherited-extra-fd");
  fs.writeFileSync(extraPath, "must-close-in-child\n");
  const extraFd = fs.openSync(extraPath, "r");
  try {
    return childProcess.spawnSync(binary, [
      "--verify-fixture",
      "--root",
      root,
      "--manifest-sha256",
      manifestDigest,
      "--report-fd",
      "3",
    ], {
      encoding: "utf8",
      env: options.env == null ? {} : options.env,
      stdio: ["pipe", "pipe", "pipe", "pipe", extraFd],
      timeout: 10_000,
    });
  } finally {
    fs.closeSync(extraFd);
  }
}

async function runAtTestOnlyTerminalBarrier(fixture, testBinary, mutate) {
  const child = childProcess.spawn(testBinary, [
    "--verify-fixture",
    "--root",
    fixture.root,
    "--manifest-sha256",
    fixture.manifestDigest,
    "--report-fd",
    "3",
  ], {
    env: {},
    stdio: ["pipe", "pipe", "pipe", "pipe", "pipe", "pipe"],
  });
  let report = "";
  child.stdio[3].setEncoding("utf8");
  child.stdio[3].on("data", (chunk) => { report += chunk; });
  const marker = await new Promise((resolve, reject) => {
    let observed = "";
    const onError = (error) => reject(error);
    const onClose = (status) => reject(new Error(`test-only phase child exited early: ${status}`));
    child.once("error", onError);
    child.once("close", onClose);
    child.stdio[4].setEncoding("utf8");
    child.stdio[4].on("data", (chunk) => {
      observed += chunk;
      if (observed.includes("\n")) {
        child.off("error", onError);
        child.off("close", onClose);
        resolve(observed);
      }
    });
  });
  assert.equal(marker, "HB_TEST_ONLY_TERMINAL_SWEEP\n");
  let mutationError;
  try {
    mutate();
  } catch (error) {
    mutationError = error;
  }
  child.stdio[5].end("A");
  const outcome = await new Promise((resolve, reject) => {
    const timeout = setTimeout(() => child.kill("SIGKILL"), 10_000);
    child.once("error", reject);
    child.once("close", (status, signal) => {
      clearTimeout(timeout);
      resolve({ status, signal });
    });
  });
  if (mutationError != null) throw mutationError;
  return { ...outcome, report };
}

function reportText(result) {
  return result.output[3] == null ? "" : result.output[3];
}

function assertRejected(result, status = 65) {
  assert.equal(result.status, status);
  assert.equal(result.signal, null);
  assert.equal(
    reportText(result),
    "{\"version\":2,\"kind\":\"darwin_native_launcher_fixture_rejection\","
      + "\"code\":\"fixture_rejected\"}\n",
  );
}

test("native fixture verifies a closed tree and emits an unprovenanced contract record", (t) => {
  const fixture = createFixture();
  t.after(() => removeFixture(fixture));
  const result = spawnFixture(fixture);
  assert.equal(result.status, 0);
  assert.equal(result.signal, null);
  assert.equal(result.stdout, "");
  assert.equal(result.stderr, "");
  const rawRecord = JSON.parse(reportText(result));
  const record = normalizeDarwinNativeFixtureContractRecord(rawRecord);
  assert.equal(Object.isFrozen(record), true);
  assert.equal(record.version, DARWIN_NATIVE_FIXTURE_CONTRACT_RECORD_VERSION);
  assert.equal(record.record_domain, DARWIN_NATIVE_FIXTURE_CONTRACT_RECORD_DOMAIN);
  assert.equal(record.bundle_entry_count, DARWIN_NATIVE_FIXTURE_ENTRY_COUNT);
  assert.equal(record.fixture_manifest_digest, fixture.manifestDigest);
  assert.equal(
    record.native_launcher_on_disk_path_object_sha256,
    sha256(fs.readFileSync(binary)),
  );
  for (const [field, value] of Object.entries(fixture.contractDigests)) {
    assert.equal(record[`declared_${field}`], value);
  }
  const rootTranscript = `${ROOT_DOMAIN}\nroot|${identityFields(fixture.rootIdentity)}\n`;
  assert.equal(record.fixture_root_identity_digest, sha256(rootTranscript));
  const walkTranscript = `${WALK_DOMAIN}\n${fixture.entries.map((entry) => entry.canonical).join("\n")}\n`;
  assert.equal(record.openat_fstatat_walk_digest, sha256(walkTranscript));
  const fdTranscript = `${FD_DOMAIN}\n0=dev-null\n1=dev-null\n2=dev-null\n3=report-one-shot\n`;
  assert.equal(record.fd_enumeration_digest, sha256(fdTranscript));
  assert.deepEqual(
    record.production_blockers,
    DARWIN_NATIVE_FIXTURE_CONTRACT_PRODUCTION_BLOCKERS,
  );
  assert.equal(record.retained_bundle_fds_verified, true);
  assert.equal(record.double_hash_identity_pass_complete, true);
  assert.equal(record.terminal_ancestry_rewalk_complete, true);
  assert.equal(record.final_retained_fd_identity_sweep_complete, true);
  assert.equal(record.native_launcher_mapped_process_image_identity_bound, false);
  assert.equal(record.native_fixture_record_provenance_attested, false);
  assert.equal(record.child_process_custody_attested, false);
  assert.equal(record.report_channel_authenticated, false);
  assert.equal(Object.hasOwn(record, "native_launcher_binary_digest"), false);
  assert.equal(
    record.production_blockers.includes(
      "native_launcher_mapped_process_image_identity_unbound"
    ),
    true,
  );
  assert.equal(record.credential_drop_executed, false);
  assert.equal(record.execve_executed, false);
  assert.equal(record.production_ready, false);
});

test("fixture CLI has no credential-changing or exec activation surface", () => {
  const result = childProcess.spawnSync(binary, [], {
    encoding: "utf8",
    env: {},
    stdio: ["pipe", "pipe", "pipe", "pipe"],
  });
  assertRejected(result, 64);
  const fixtureBytes = fs.readFileSync(linkedSource, "utf8");
  const executorBytes = fs.readFileSync(privilegedExecutorSource, "utf8");
  const buildBytes = fs.readFileSync(
    path.resolve(__dirname, "..", "scripts", "build-native-fixture.js"),
    "utf8",
  );
  const checkBytes = fs.readFileSync(
    path.resolve(__dirname, "..", "scripts", "check-native-fixture.js"),
    "utf8",
  );
  assert.doesNotMatch(
    fixtureBytes,
    /hb_audit_apply_credentials_and_exec|\bset(?:groups|gid|uid)\s*\(|\bexecve\s*\(/u,
  );
  assert.match(executorBytes, /HB_PRIVILEGED_LAUNCH_SOURCE_ONLY/u);
  assert.match(executorBytes, /static int hb_privileged_launch_execute/u);
  assert.match(executorBytes, /static int hb_install_descriptor_projection/u);
  assert.match(executorBytes, /char \*const empty_environment\[\] = \{NULL\}/u);
  assert.match(executorBytes, /execve\(path, argv, environment\)/u);
  assert.equal(fs.readFileSync(binary).includes(Buffer.from("HB_TEST_ONLY", "utf8")), false);
  assert.doesNotMatch(fixtureBytes, /native_launcher_binary_digest|hb_hash_self/u);
  assert.match(buildBytes, /-UHB_TEST_ONLY_PHASE_BARRIER/u);
  assert.doesNotMatch(buildBytes, /-DHB_TEST_ONLY_PHASE_BARRIER/u);
  assert.match(checkBytes, /assertExactDarwinNativeFixtureUndefinedSymbols/u);
  assert.match(checkBytes, /production native fixture contains a test-only phase hook/u);
});

test("native undefined-symbol contract rejects additions, omissions, reorderings, and getters", () => {
  const exact = [...DARWIN_NATIVE_FIXTURE_UNDEFINED_SYMBOL_ALLOWLIST];
  assert.deepEqual(assertExactDarwinNativeFixtureUndefinedSymbols(exact), exact);
  assert.throws(() => assertExactDarwinNativeFixtureUndefinedSymbols([...exact, "_getenv"]));
  assert.throws(() => assertExactDarwinNativeFixtureUndefinedSymbols(exact.slice(1)));
  const reordered = [...exact];
  [reordered[0], reordered[1]] = [reordered[1], reordered[0]];
  assert.throws(() => assertExactDarwinNativeFixtureUndefinedSymbols(reordered));
  assert.throws(() => assertExactDarwinNativeFixtureUndefinedSymbols(new Proxy(exact, {})));
  let getterCalls = 0;
  const accessor = [...exact];
  Object.defineProperty(accessor, "0", {
    enumerable: true,
    get() {
      getterCalls += 1;
      return exact[0];
    },
  });
  assert.throws(() => assertExactDarwinNativeFixtureUndefinedSymbols(accessor));
  assert.equal(getterCalls, 0);
});

test("native fixture rejects environmental, digest, path, tree, object, and content drift", async (t) => {
  const cases = [
    {
      name: "non-empty environment",
      mutate() {},
      options: { env: { LANG: "C" } },
    },
    {
      name: "wrong manifest digest",
      mutate() {},
      options: { manifestDigest: contractDigest("wrong-manifest") },
    },
    {
      name: "symlink root",
      mutate(fixture) {
        const alias = path.join(fixture.parent, "bundle-alias");
        fs.symlinkSync(fixture.root, alias, "dir");
        this.options.root = alias;
      },
      options: {},
    },
    {
      name: "extra tree entry",
      mutate(fixture) {
        fs.chmodSync(path.join(fixture.root, "native"), 0o700);
        fs.writeFileSync(path.join(fixture.root, "native/extra.node"), "unexpected\n");
        fs.chmodSync(path.join(fixture.root, "native"), 0o500);
      },
      options: {},
    },
    {
      name: "mode drift",
      mutate(fixture) {
        fs.chmodSync(path.join(fixture.root, "config/worker.json"), 0o600);
      },
      options: {},
    },
    {
      name: "content drift",
      mutate(fixture) {
        fs.chmodSync(path.join(fixture.root, "lib/worker.js"), 0o600);
        fs.writeFileSync(path.join(fixture.root, "lib/worker.js"), "drifted\n");
        fs.chmodSync(path.join(fixture.root, "lib/worker.js"), 0o400);
      },
      options: {},
    },
    {
      name: "object replacement",
      mutate(fixture) {
        const target = path.join(fixture.root, "bin/node");
        fs.chmodSync(path.join(fixture.root, "bin"), 0o700);
        fs.unlinkSync(target);
        fs.writeFileSync(target, "fixture-node-runtime\n", { mode: 0o500 });
        fs.chmodSync(path.join(fixture.root, "bin"), 0o500);
      },
      options: {},
    },
  ];
  for (const testCase of cases) {
    await t.test(testCase.name, () => {
      const fixture = createFixture();
      t.after(() => removeFixture(fixture));
      testCase.mutate.call(testCase, fixture);
      assertRejected(spawnFixture(fixture, testCase.options));
    });
  }
});

test("test-only phase barrier deterministically reproduces terminal mutation races", async (t) => {
  const phaseBinary = buildTestOnlyPhaseBinary();
  t.after(() => fs.rmSync(phaseBinary.directory, { force: true, recursive: true }));
  const expectedRejection =
    "{\"version\":2,\"kind\":\"darwin_native_launcher_fixture_rejection\","
      + "\"code\":\"fixture_rejected\"}\n";

  await t.test("retained entry changes after the second hash pass", async (subtest) => {
    const fixture = createFixture({ keepWorkerMutationFd: true });
    subtest.after(() => removeFixture(fixture));
    const outcome = await runAtTestOnlyTerminalBarrier(fixture, phaseBinary.output, () => {
      fs.writeSync(fixture.mutationFd, Buffer.from("z"), 0, 1, 0);
      fs.fsyncSync(fixture.mutationFd);
    });
    assert.deepEqual({ status: outcome.status, signal: outcome.signal }, {
      status: 65,
      signal: null,
    });
    assert.equal(outcome.report, expectedRejection);
  });

  await t.test("retained manifest changes before the final sweep", async (subtest) => {
    const fixture = createFixture({ keepManifestMutationFd: true });
    subtest.after(() => removeFixture(fixture));
    const outcome = await runAtTestOnlyTerminalBarrier(fixture, phaseBinary.output, () => {
      fs.writeSync(fixture.manifestMutationFd, Buffer.from("X"), 0, 1, 0);
      fs.fsyncSync(fixture.manifestMutationFd);
    });
    assert.deepEqual({ status: outcome.status, signal: outcome.signal }, {
      status: 65,
      signal: null,
    });
    assert.equal(outcome.report, expectedRejection);
  });

  await t.test("absolute ancestor swaps before the terminal rewalk", async (subtest) => {
    const fixture = createFixture({ ancestorSlot: true });
    subtest.after(() => removeFixture(fixture));
    const replacementSlot = path.join(fixture.parent, "slot-replacement");
    const retainedSlot = path.join(fixture.parent, "slot-retained");
    fs.mkdirSync(path.join(replacementSlot, "bundle"), { recursive: true, mode: 0o700 });
    let swapped = false;
    let outcome;
    try {
      outcome = await runAtTestOnlyTerminalBarrier(fixture, phaseBinary.output, () => {
        fs.renameSync(fixture.ancestrySlot, retainedSlot);
        fs.renameSync(replacementSlot, fixture.ancestrySlot);
        swapped = true;
      });
    } finally {
      if (swapped) {
        fs.rmSync(fixture.ancestrySlot, { force: true, recursive: true });
        fs.renameSync(retainedSlot, fixture.ancestrySlot);
      }
    }
    assert.deepEqual({ status: outcome.status, signal: outcome.signal }, {
      status: 65,
      signal: null,
    });
    assert.equal(outcome.report, expectedRejection);
  });
});

test("native contract-record parser rejects hostile shapes and survives intrinsic substitution", () => {
  const fixture = createFixture();
  try {
    const result = spawnFixture(fixture);
    assert.equal(result.status, 0);
    const raw = JSON.parse(reportText(result));
    assert.equal(Object.isFrozen(nativeRecordModule), true);
    let getterCalls = 0;
    const accessorRecord = { ...raw };
    Object.defineProperty(accessorRecord, "declared_launch_plan_digest", {
      enumerable: true,
      get() {
        getterCalls += 1;
        return raw.declared_launch_plan_digest;
      },
    });
    assert.throws(() => normalizeDarwinNativeFixtureContractRecord(accessorRecord));
    assert.equal(getterCalls, 0);
    assert.throws(() => normalizeDarwinNativeFixtureContractRecord(new Proxy(raw, {})));

    const hashPrototype = Object.getPrototypeOf(crypto.createHash("sha256"));
    const originals = [
      [crypto, "createHash", Object.getOwnPropertyDescriptor(crypto, "createHash")],
      [hashPrototype, "update", Object.getOwnPropertyDescriptor(hashPrototype, "update")],
      [hashPrototype, "digest", Object.getOwnPropertyDescriptor(hashPrototype, "digest")],
      [Object.prototype, "declared_launch_plan_digest",
        Object.getOwnPropertyDescriptor(Object.prototype, "declared_launch_plan_digest")],
    ];
    try {
      Object.defineProperty(crypto, "createHash", {
        ...originals[0][2],
        value() { throw new Error("late crypto substitution reached"); },
      });
      for (let index = 1; index <= 2; index += 1) {
        Object.defineProperty(originals[index][0], originals[index][1], {
          ...originals[index][2],
          value() { throw new Error("late hash prototype substitution reached"); },
        });
      }
      Object.defineProperty(Object.prototype, "declared_launch_plan_digest", {
        configurable: true,
        set() { throw new Error("prototype setter reached"); },
      });
      const normalized = normalizeDarwinNativeFixtureContractRecord(raw);
      assert.equal(
        normalized.contract_record_checksum,
        raw.contract_record_checksum,
      );
    } finally {
      for (let index = 0; index < originals.length; index += 1) {
        const [target, property, descriptor] = originals[index];
        if (descriptor == null) {
          delete target[property];
        } else {
          Object.defineProperty(target, property, descriptor);
        }
      }
    }
  } finally {
    removeFixture(fixture);
  }
});
