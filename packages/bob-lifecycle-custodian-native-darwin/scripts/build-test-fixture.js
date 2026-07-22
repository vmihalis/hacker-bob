"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const ROOT = path.resolve(__dirname, "..");
const SOURCE = path.join(ROOT, "native", "lifecycle_custodian.c");
const DIST = path.join(ROOT, "dist");
const OUTPUT = path.join(DIST, "lifecycle-custodian-test");

function capture(command, args) {
  const result = spawnSync(command, args, { encoding: "utf8" });
  if (result.status !== 0) {
    process.stderr.write(result.stderr || result.stdout || `${command} failed\n`);
    process.exit(result.status || 1);
  }
  return result.stdout.trim();
}

if (process.platform !== "darwin" || process.arch !== "arm64") {
  process.stderr.write("Darwin arm64 is required for the lifecycle custodian test fixture\n");
  process.exit(1);
}

const sdk = capture("/usr/bin/xcrun", ["--sdk", "macosx", "--show-sdk-path"]);
const clang = capture("/usr/bin/xcrun", ["--find", "clang"]);
fs.mkdirSync(DIST, { recursive: true });
const args = [
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
  "-O2",
  "-fPIE",
  "-DHB_LIFECYCLE_CUSTODIAN_TEST_ONLY=1",
  "-Wl,-pie",
  "-Wl,-fatal_warnings",
  SOURCE,
  "-o",
  OUTPUT,
];
const result = spawnSync(clang, args, { encoding: "utf8" });
if (result.status !== 0) {
  process.stderr.write(result.stderr || result.stdout || "strict native build failed\n");
  process.exit(result.status || 1);
}
fs.chmodSync(OUTPUT, 0o755);
process.stdout.write(`${OUTPUT}\n`);
