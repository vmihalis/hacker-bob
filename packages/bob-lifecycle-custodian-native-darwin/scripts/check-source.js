"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const ROOT = path.resolve(__dirname, "..");
const SOURCE = path.join(ROOT, "native", "lifecycle_custodian.c");
const sourceText = fs.readFileSync(SOURCE, "utf8");

for (const forbidden of [
  { label: "/dev/fd", pattern: /\/dev\/fd/u },
  { label: "realpath", pattern: /(^|[^A-Za-z0-9_])realpath\s*\(/mu },
  { label: "remove", pattern: /(^|[^A-Za-z0-9_])remove\s*\(/mu },
  { label: "rename", pattern: /(^|[^A-Za-z0-9_])rename\s*\(/mu },
  { label: "mkdir", pattern: /(^|[^A-Za-z0-9_])mkdir\s*\(/mu },
  { label: "rmdir", pattern: /(^|[^A-Za-z0-9_])rmdir\s*\(/mu },
]) {
  if (forbidden.pattern.test(sourceText)) {
    throw new Error(`forbidden pathname mutation or descriptor bridge: ${forbidden.label}`);
  }
}
for (const required of [
  "openat(",
  "fstatat(",
  "AT_SYMLINK_NOFOLLOW",
  "mkdirat(",
  "renameat(",
  "unlinkat(",
  "HB_TARGET_ROOT_FD 3",
  "HB_SOURCE_ROOT_FD 4",
]) {
  if (!sourceText.includes(required)) throw new Error(`required native invariant missing: ${required}`);
}

if (process.platform !== "darwin" || process.arch !== "arm64") {
  throw new Error("Darwin arm64 is required for strict lifecycle custodian source checks");
}
const capture = (args) => {
  const result = spawnSync("/usr/bin/xcrun", args, { encoding: "utf8" });
  if (result.status !== 0) throw new Error(result.stderr || result.stdout || "xcrun failed");
  return result.stdout.trim();
};
const sdk = capture(["--sdk", "macosx", "--show-sdk-path"]);
const clang = capture(["--find", "clang"]);
const result = spawnSync(clang, [
  "-std=c17",
  "-Wall",
  "-Wextra",
  "-Werror",
  "-Wpedantic",
  "-Wshadow",
  "-Wconversion",
  "-Wsign-conversion",
  "-Wno-deprecated-declarations",
  "-D_FORTIFY_SOURCE=2",
  "-mmacosx-version-min=13.0",
  "-isysroot",
  sdk,
  "-DHB_LIFECYCLE_CUSTODIAN_SOURCE_ONLY=1",
  "-fsyntax-only",
  SOURCE,
], { encoding: "utf8" });
if (result.status !== 0) {
  process.stderr.write(result.stderr || result.stdout || "strict source check failed\n");
  process.exit(result.status || 1);
}
