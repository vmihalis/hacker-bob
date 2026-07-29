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
  "darwin-post-exec-capability-release.source.c",
);
const legacySource = path.join(
  packageRoot,
  "native",
  "darwin-privileged-launch-executor.source.c",
);

if (process.platform !== "darwin" || process.arch !== "arm64"
    || typeof process.getuid !== "function" || process.getuid() === 0) {
  throw new Error("post-exec capability-release tests require non-root Darwin arm64");
}

function run(tool, args, options = {}) {
  const result = childProcess.spawnSync(tool, args, {
    encoding: "utf8",
    env: {},
    stdio: ["ignore", "pipe", "pipe"],
    ...options,
  });
  if (options.acceptStatus == null && result.status !== 0) {
    throw new Error(
      `post-exec native test command failed: ${path.basename(tool)}\n${result.stderr}`,
    );
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

test("post-exec release source compiles separately and 23 native protocol cases pass", (t) => {
  const clang = resolveTool("clang");
  const sdk = sdkPath();
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "bob-post-exec-release-test-"));
  const binary = path.join(directory, "darwin-post-exec-release-selftest");
  t.after(() => fs.rmSync(directory, { force: true, recursive: true }));

  run(clang, [
    ...compilerFlags(sdk),
    "-DHB_POST_EXEC_RELEASE_SOURCE_ONLY=1",
    "-fsyntax-only",
    source,
  ]);
  run(clang, [
    ...compilerFlags(sdk),
    "-O2",
    "-fPIE",
    "-DHB_POST_EXEC_RELEASE_TEST_ONLY=1",
    "-Wl,-pie",
    "-Wl,-fatal_warnings",
    "-lbsm",
    "-o",
    binary,
    source,
  ]);

  const result = run(binary, ["--test-only-post-exec-selftest-v1"]);
  assert.equal(result.stderr, "");
  assert.deepEqual(JSON.parse(result.stdout), {
    version: 1,
    kind: "darwin_post_exec_capability_release_selftest",
    tests: 23,
    path_exec_powerless: true,
    fresh_unix_peer_bound: true,
    wrong_peer_preaccepted_before_direct_child: true,
    scm_rights_closed_set_once: true,
    ready_no_effect_then_commit_go: true,
    terminal_peer_identity_refreshed: true,
    security_framework_attested: false,
    mapped_image_bound: false,
    durable_state_authenticated: false,
    production_attested: false,
    production_ready: false,
    hardware_access_authorized: false,
  });
  const rejected = run(binary, ["--listener", "/tmp/attacker"], { acceptStatus: 64 });
  assert.equal(rejected.status, 64);
  assert.equal(rejected.stdout, "");
  assert.equal(rejected.stderr, "");
});

test("post-exec release is a distinct production-false contract, not a legacy fixture rewrite", () => {
  const bytes = fs.readFileSync(source, "utf8");
  const legacyBytes = fs.readFileSync(legacySource, "utf8");
  for (const required of [
    "HB_POST_EXEC_RELEASE_SOURCE_ONLY",
    "HB_POST_EXEC_RELEASE_TEST_ONLY",
    "LOCAL_PEERTOKEN",
    "LOCAL_PEERPID",
    "getpeereid",
    "proc_pidpath_audittoken",
    "audit_token_to_pidversion",
    "identity->parent_pid != getpid()",
    "hb_wrong_peer_rejection_exact",
    "process_start_seconds",
    "listener_generation",
    "SCM_RIGHTS",
    "control_record_count != 1",
    "control_end - header_start < sizeof(*header)",
    "(size_t)header->cmsg_len > available",
    "MSG_CTRUNC",
    "F_DUPFD_CLOEXEC",
    "FD_CLOEXEC",
    "O_ACCMODE",
    "capability_abi_digest",
    "HB_READY_NO_EFFECT",
    "HB_COMMIT_GO",
    "HB_TERMINAL_IDENTITY_ACCEPTED",
    "go.sequence <= grant.sequence",
    "SecCodeCopyGuestWithAttributes",
    "kSecGuestAttributeAudit",
    "SecCodeCheckValidity",
    "MH_EXECUTE",
    "hb_security_framework_live_guest_attestation_fail_closed",
    "hb_retained_fd_live_mh_execute_measurement_fail_closed",
    "hb_authenticated_durable_grant_go_outbox_fail_closed",
    "execve(fixture->executable_path, child_argv, empty_environment)",
  ]) {
    assert.equal(bytes.includes(required), true, `post-exec source omits ${required}`);
  }
  for (const hostileCase of [
    "HB_CASE_INHERITED_CONNECTED_SOCKET",
    "HB_CASE_WRONG_PEER",
    "HB_CASE_WRONG_NONCE",
    "HB_CASE_WRONG_GENERATION",
    "HB_CASE_EXTRA_DESCRIPTORS",
    "HB_CASE_ANCILLARY_TRUNCATION",
    "HB_CASE_DESCRIPTOR_ALIAS",
    "HB_CASE_DESCRIPTOR_ORDER",
    "HB_CASE_MISSING_CLOEXEC",
    "HB_CASE_UNEXPECTED_DESCRIPTOR",
    "HB_CASE_REPLAYED_GRANT",
    "HB_CASE_REPLAYED_GO",
    "HB_CASE_PRE_GO_EFFECT",
    "HB_CASE_CRASH_AFTER_HELLO",
    "HB_CASE_CRASH_AFTER_GRANT",
    "HB_CASE_CRASH_AFTER_READY",
    "HB_CASE_CRASH_AFTER_GO",
    "HB_CASE_CRASH_AFTER_EFFECT",
    "HB_CASE_SPLIT_ANCILLARY_RECORDS",
    "HB_CASE_MALFORMED_ANCILLARY_BOUNDS",
    "HB_CASE_CRASH_AFTER_RESULT",
  ]) {
    assert.equal(bytes.includes(hostileCase), true, `hostile case is absent: ${hostileCase}`);
  }
  assert.equal(
    bytes.includes("return -1;\n}\n\n#ifdef HB_POST_EXEC_RELEASE_TEST_ONLY"),
    true,
  );
  assert.doesNotMatch(bytes, /production_(?:attested|ready)\s*[:=]\s*true/u);
  assert.doesNotMatch(bytes, /hardware_access_authorized\s*[:=]\s*true/u);
  assert.equal(legacyBytes.includes("HB_PRIVILEGED_LAUNCH_SOURCE_ONLY"), true);
  assert.equal(legacyBytes.includes("#define HB_CONTEXT_SOURCE_FD 7"), true);
});
