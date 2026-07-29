"use strict";

const childProcess = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");

const packageRoot = path.resolve(__dirname, "..");
const source = path.join(packageRoot, "native", "darwin-launcher-fixture.c");
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
const outputDirectory = path.join(packageRoot, "dist");
const output = path.join(outputDirectory, "bob-darwin-launcher-fixture");

function resolveTool(name) {
  if (name === "codesign") {
    const systemCodesign = "/usr/bin/codesign";
    const status = fs.lstatSync(systemCodesign);
    if (!status.isFile() || status.isSymbolicLink()) {
      throw new Error("required Darwin build tool is unavailable: codesign");
    }
    return systemCodesign;
  }
  const result = childProcess.spawnSync("/usr/bin/xcrun", ["--find", name], {
    encoding: "utf8",
    env: {},
    stdio: ["ignore", "pipe", "pipe"],
  });
  const resolved = result.status === 0 ? result.stdout.trim() : "";
  if (!path.isAbsolute(resolved) || !fs.existsSync(resolved)) {
    throw new Error(`required Darwin build tool is unavailable: ${name}`);
  }
  return resolved;
}

function resolveSdk() {
  const result = childProcess.spawnSync("/usr/bin/xcrun", ["--sdk", "macosx", "--show-sdk-path"], {
    encoding: "utf8",
    env: {},
    stdio: ["ignore", "pipe", "pipe"],
  });
  const sdk = result.status === 0 ? result.stdout.trim() : "";
  if (!path.isAbsolute(sdk) || !fs.statSync(sdk).isDirectory()) {
    throw new Error("required macOS SDK is unavailable");
  }
  return sdk;
}

function run(tool, args) {
  const result = childProcess.spawnSync(tool, args, {
    encoding: "utf8",
    env: {},
    stdio: ["ignore", "pipe", "pipe"],
  });
  if (result.status !== 0) {
    const detail = `${result.stdout || ""}${result.stderr || ""}`.trim();
    throw new Error(`native fixture build command failed: ${path.basename(tool)}\n${detail}`);
  }
  return `${result.stdout || ""}${result.stderr || ""}`;
}

if (process.platform !== "darwin" || process.arch !== "arm64") {
  throw new Error("native fixture build requires Darwin arm64");
}

for (const sourcePath of [source, privilegedExecutorSource, postExecReleaseSource]) {
  const status = fs.lstatSync(sourcePath);
  if (!status.isFile() || status.isSymbolicLink() || status.nlink !== 1) {
    throw new Error("native fixture source identity is not a single regular file");
  }
}
fs.mkdirSync(outputDirectory, { recursive: true, mode: 0o755 });
const outputDirectoryStatus = fs.lstatSync(outputDirectory);
if (!outputDirectoryStatus.isDirectory() || outputDirectoryStatus.isSymbolicLink()) {
  throw new Error("native fixture output directory identity is invalid");
}
const temporaryDirectory = fs.mkdtempSync(path.join(outputDirectory, ".native-build-"));
const temporary = path.join(temporaryDirectory, "bob-darwin-launcher-fixture");
try {
  const clang = resolveTool("clang");
  const codesign = resolveTool("codesign");
  const nm = resolveTool("nm");
  const sdk = resolveSdk();
  const compilerFlags = [
    "-std=c17",
    "-Wall",
    "-Wextra",
    "-Werror",
    "-Wpedantic",
    "-Wno-deprecated-declarations",
    "-fstack-protector-strong",
    "-D_FORTIFY_SOURCE=2",
    "-fPIE",
    "-mmacosx-version-min=13.0",
    "-isysroot",
    sdk,
  ];
  run(clang, [
    ...compilerFlags,
    "-Wshadow",
    "-Wconversion",
    "-Wsign-conversion",
    "-DHB_PRIVILEGED_LAUNCH_SOURCE_ONLY=1",
    "-fsyntax-only",
    privilegedExecutorSource,
  ]);
  run(clang, [
    ...compilerFlags,
    "-Wshadow",
    "-Wconversion",
    "-Wsign-conversion",
    "-DHB_POST_EXEC_RELEASE_SOURCE_ONLY=1",
    "-fsyntax-only",
    postExecReleaseSource,
  ]);
  run(clang, [
    ...compilerFlags,
    "-O2",
    "-Wl,-pie",
    "-Wl,-fatal_warnings",
    "-UHB_TEST_ONLY_PHASE_BARRIER",
    "-o",
    temporary,
    source,
  ]);
  const productionSymbols = run(nm, [temporary]);
  if (fs.readFileSync(temporary).includes(Buffer.from("HB_TEST_ONLY", "utf8"))
      || productionSymbols.includes("test_only")) {
    throw new Error("production native fixture build retained a test-only phase hook");
  }
  run(codesign, ["--force", "--sign", "-", "--timestamp=none", temporary]);
  fs.chmodSync(temporary, 0o755);
  fs.renameSync(temporary, output);
} finally {
  fs.rmSync(temporaryDirectory, { force: true, recursive: true });
}

process.stdout.write(`${output}\n`);
