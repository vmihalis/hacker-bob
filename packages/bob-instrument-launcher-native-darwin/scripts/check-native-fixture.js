"use strict";

const childProcess = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");
const {
  assertExactDarwinNativeFixtureUndefinedSymbols,
} = require("../lib/native-binary-symbol-contract.js");

const packageRoot = path.resolve(__dirname, "..");
const binary = path.join(packageRoot, "dist", "bob-darwin-launcher-fixture");
const fixtureSource = path.join(packageRoot, "native", "darwin-launcher-fixture.c");
const privilegedExecutorSource = path.join(
  packageRoot,
  "native",
  "darwin-privileged-launch-executor.source.c",
);
const postExecReleaseSource = path.join(
  packageRoot,
  "native",
  "darwin-post-exec-capability-release.source.c",
);

function run(tool, args, allowStderr = false) {
  const result = childProcess.spawnSync(tool, args, {
    encoding: "utf8",
    env: {},
    stdio: ["ignore", "pipe", "pipe"],
  });
  if (result.status !== 0) {
    throw new Error(`${path.basename(tool)} rejected native fixture binary`);
  }
  return `${result.stdout || ""}${allowStderr ? result.stderr || "" : ""}`;
}

if (process.platform !== "darwin" || process.arch !== "arm64") {
  throw new Error("native fixture checks require Darwin arm64");
}
const status = fs.lstatSync(binary);
if (!status.isFile() || status.isSymbolicLink() || status.nlink !== 1
    || (status.mode & 0o7777) !== 0o755) {
  throw new Error("native fixture binary mode is not exact");
}

const fileDescription = run("/usr/bin/file", [binary]);
if (!/Mach-O 64-bit executable arm64/u.test(fileDescription)) {
  throw new Error("native fixture binary is not a Darwin arm64 Mach-O executable");
}

const linkage = run("/usr/bin/otool", ["-L", binary]);
const linkedLibraries = linkage.split("\n").slice(1).map((line) => line.trim()).filter(Boolean);
if (linkedLibraries.length !== 1 || !linkedLibraries[0].startsWith("/usr/lib/libSystem.B.dylib ")) {
  throw new Error("native fixture binary linkage is not closed to libSystem");
}
const loadCommands = run("/usr/bin/otool", ["-l", binary]);
if (!loadCommands.includes("LC_CODE_SIGNATURE") || loadCommands.includes("LC_RPATH")) {
  throw new Error("native fixture binary signature or runtime-path commands are invalid");
}
const header = run("/usr/bin/otool", ["-hv", binary]);
if (!header.includes("PIE")) throw new Error("native fixture binary is not PIE");

const symbols = run("/usr/bin/nm", ["-u", binary]);
const undefinedSymbols = symbols.split("\n").map((line) => line.trim()).filter(Boolean);
assertExactDarwinNativeFixtureUndefinedSymbols(undefinedSymbols);
const globalSymbols = run("/usr/bin/nm", ["-gU", binary])
  .split("\n")
  .map((line) => line.trim().split(/\s+/u).at(-1))
  .filter(Boolean);
if (globalSymbols.length !== 2
    || globalSymbols[0] !== "__mh_execute_header"
    || globalSymbols[1] !== "_main") {
  throw new Error("native fixture binary exports an unexpected activation symbol");
}

const linkedFixtureSource = fs.readFileSync(fixtureSource, "utf8");
const executorSource = fs.readFileSync(privilegedExecutorSource, "utf8");
const postExecSource = fs.readFileSync(postExecReleaseSource, "utf8");
const buildSource = fs.readFileSync(path.join(packageRoot, "scripts", "build-native-fixture.js"), "utf8");
const binaryBytes = fs.readFileSync(binary);
const allSymbols = run("/usr/bin/nm", [binary]);
if (binaryBytes.includes(Buffer.from("HB_TEST_ONLY", "utf8"))
    || binaryBytes.includes(Buffer.from("post-exec capability-release", "utf8"))
    || allSymbols.includes("test_only")
    || globalSymbols.some((symbol) => symbol.includes("test_only"))
    || /-DHB_TEST_ONLY_PHASE_BARRIER/u.test(buildSource)) {
  throw new Error("production native fixture contains a test-only phase hook");
}
for (const required of [
  "HB_POST_EXEC_RELEASE_SOURCE_ONLY",
  "HB_POST_EXEC_RELEASE_TEST_ONLY",
  "LOCAL_PEERTOKEN",
  "LOCAL_PEERPID",
  "SCM_RIGHTS",
  "control_record_count != 1",
  "(size_t)header->cmsg_len > available",
  "hb_test_split_control_records_rejected",
  "hb_test_oversized_control_record_rejected",
  "HB_READY_NO_EFFECT",
  "HB_COMMIT_GO",
  "HB_TERMINAL_IDENTITY_ACCEPTED",
  "HB_CASE_CRASH_AFTER_RESULT",
  "hb_security_framework_live_guest_attestation_fail_closed",
  "hb_retained_fd_live_mh_execute_measurement_fail_closed",
  "hb_authenticated_durable_grant_go_outbox_fail_closed",
]) {
  if (!postExecSource.includes(required)) {
    throw new Error(`source-only post-exec release fixture omits ${required}`);
  }
}
if (/-DHB_POST_EXEC_RELEASE_TEST_ONLY/u.test(buildSource)) {
  throw new Error("production native fixture build enables the post-exec test gate");
}
if (/hb_audit_apply_credentials_and_exec|\bset(?:groups|gid|uid)\s*\(|\bexecve\s*\(/u
  .test(linkedFixtureSource)) {
  throw new Error("linked fixture source contains a credential or exec activation seam");
}
for (const required of [
  "HB_PRIVILEGED_LAUNCH_SOURCE_ONLY",
  "static int hb_privileged_launch_execute",
  "#define HB_CONTEXT_SOURCE_FD 7",
  "#define HB_DEVICE_SOURCE_FD 8",
  "#define HB_DISPATCH_SOURCE_FD 9",
  "#define HB_RESULT_SOURCE_FD 10",
  "#define HB_CONTEXT_CHILD_FD 3",
  "#define HB_DEVICE_CHILD_FD 4",
  "#define HB_DISPATCH_CHILD_FD 5",
  "#define HB_RESULT_CHILD_FD 6",
  "F_DUPFD_CLOEXEC",
  "hb_fail_closed_cleanup",
  "setgroups(count, groups)",
  "setgid(gid)",
  "setuid(uid)",
  "PROC_PIDTBSDINFO",
  "information.pbi_svuid != plan->target_uid",
  "information.pbi_svgid != plan->target_gid",
  "char *const empty_environment[] = {NULL}",
  "execve(path, argv, environment)",
]) {
  if (!executorSource.includes(required)) {
    throw new Error(`source-only privileged executor omits ${required}`);
  }
}

run("/usr/bin/codesign", ["--verify", "--strict", "--verbose=4", binary], true);
const signature = run("/usr/bin/codesign", ["--display", "--verbose=4", binary], true);
if (!signature.includes("Signature=adhoc") || !signature.includes("TeamIdentifier=not set")) {
  throw new Error("native fixture binary must carry only an explicit ad-hoc test signature");
}

process.stdout.write("native Darwin fixture binary checks passed\n");
