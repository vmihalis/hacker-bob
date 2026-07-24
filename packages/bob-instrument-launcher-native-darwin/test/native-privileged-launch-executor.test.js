"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const childProcess = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const packageRoot = path.resolve(__dirname, "..");
const source = path.join(
  packageRoot,
  "native",
  "darwin-privileged-launch-executor.source.c",
);

if (process.platform !== "darwin" || process.arch !== "arm64"
    || typeof process.getuid !== "function" || process.getuid() === 0) {
  throw new Error("privileged launch executor tests require non-root Darwin arm64");
}

function run(tool, args, options = {}) {
  const result = childProcess.spawnSync(tool, args, {
    encoding: "utf8",
    env: {},
    stdio: ["ignore", "pipe", "pipe"],
    ...options,
  });
  if (options.acceptStatus == null && result.status !== 0) {
    throw new Error(`native executor test command failed: ${path.basename(tool)}\n${result.stderr}`);
  }
  return result;
}

function resolveTool(name) {
  const result = run("/usr/bin/xcrun", ["--find", name]);
  const resolved = result.stdout.trim();
  if (!path.isAbsolute(resolved)) throw new Error(`Darwin tool is unavailable: ${name}`);
  return resolved;
}

function sdkPath() {
  const result = run("/usr/bin/xcrun", ["--sdk", "macosx", "--show-sdk-path"]);
  const sdk = result.stdout.trim();
  if (!path.isAbsolute(sdk)) throw new Error("macOS SDK path is unavailable");
  return sdk;
}

function compilerFlags(sdk) {
  return [
    "-std=c17",
    "-Wall",
    "-Wextra",
    "-Werror",
    "-Wpedantic",
    "-Wshadow",
    "-Wconversion",
    "-Wsign-conversion",
    "-Wno-deprecated-declarations",
    "-fstack-protector-strong",
    "-D_FORTIFY_SOURCE=2",
    "-mmacosx-version-min=13.0",
    "-isysroot",
    sdk,
  ];
}

test("source-only executor compiles separately and hostile native selftests pass", (t) => {
  const clang = resolveTool("clang");
  const sdk = sdkPath();
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "bob-launch-executor-test-"));
  const binary = path.join(directory, "darwin-privileged-launch-executor-selftest");
  t.after(() => fs.rmSync(directory, { force: true, recursive: true }));

  run(clang, [
    ...compilerFlags(sdk),
    "-DHB_PRIVILEGED_LAUNCH_SOURCE_ONLY=1",
    "-fsyntax-only",
    source,
  ]);
  run(clang, [
    ...compilerFlags(sdk),
    "-O2",
    "-fPIE",
    "-DHB_PRIVILEGED_LAUNCH_TEST_ONLY=1",
    "-Wl,-pie",
    "-Wl,-fatal_warnings",
    "-o",
    binary,
    source,
  ]);

  const result = run(binary, ["--test-only-selftest-v1"]);
  assert.equal(result.stderr, "");
  assert.deepEqual(JSON.parse(result.stdout), {
    version: 1,
    kind: "darwin_privileged_launch_executor_selftest",
    tests: 19,
    result_record_bytes: 196,
    production_ready: false,
  });
  const rejected = run(binary, ["--path", "/tmp/attacker"], { acceptStatus: 64 });
  assert.equal(rejected.status, 64);
  assert.equal(rejected.stdout, "");
  assert.equal(rejected.stderr, "");
});

test("executor source exposes only the fixed source-gated child contract", () => {
  const bytes = fs.readFileSync(source, "utf8");
  for (const required of [
    "HB_PRIVILEGED_LAUNCH_SOURCE_ONLY",
    "HB_PRIVILEGED_LAUNCH_TEST_ONLY",
    "#define HB_CONTEXT_SOURCE_FD 7",
    "#define HB_DEVICE_SOURCE_FD 8",
    "#define HB_DISPATCH_SOURCE_FD 9",
    "#define HB_RESULT_SOURCE_FD 10",
    "#define HB_VAULT_SINK_SOURCE_FD 11",
    "#define HB_CONTEXT_CHILD_FD 3",
    "#define HB_DEVICE_CHILD_FD 4",
    "#define HB_DISPATCH_CHILD_FD 5",
    "#define HB_RESULT_CHILD_FD 6",
    "#define HB_VAULT_SINK_CHILD_FD 7",
    "#define HB_RESULT_RECORD_BYTES 196",
    "identity->status_flags == (O_RDWR | O_NONBLOCK)",
    "identity->status_flags == O_RDWR",
    "identity->status_flags == (O_WRONLY | O_APPEND)",
    "identity->nlink == 1",
    "identity->size == 0",
    "shutdown(bindings[0].source_fd, SHUT_WR)",
    "shutdown(bindings[2].source_fd, SHUT_WR)",
    "shutdown(bindings[3].source_fd, SHUT_RD)",
    "F_DUPFD_CLOEXEC",
    "setgroups(count, groups)",
    "setgid(gid)",
    "setuid(uid)",
    "PROC_PIDTBSDINFO",
    "information.pbi_svuid != plan->target_uid",
    "information.pbi_svgid != plan->target_gid",
    "char *const empty_environment[] = {NULL}",
    "char *const child_argv[] = {(char *)HB_CHILD_IMAGE, (char *)HB_CHILD_GATE, NULL}",
    "execve(path, argv, environment)",
  ]) {
    assert.equal(bytes.includes(required), true, `executor source omits ${required}`);
  }
  assert.doesNotMatch(bytes, /\bgetenv\s*\(|\benviron\b/u);
  assert.doesNotMatch(bytes, /--(?:path|fd|uid|gid|env|argv)\b/u);
  assert.match(bytes, /production_attested\s*=\s*0/u);
  assert.match(bytes, /production_ready\s*=\s*0/u);
  assert.match(bytes, /hardware_authorized\s*=\s*0/u);
  assert.match(bytes, /mapped_process_image_identity_bound\s*=\s*0/u);
  assert.match(bytes, /provenance_persisted_by_parent\s*=\s*0/u);
});
