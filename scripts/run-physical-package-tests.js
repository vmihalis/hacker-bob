#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const {
  DARWIN_ARM64_PHYSICAL_PACKAGE_ROOTS,
  PORTABLE_PHYSICAL_PACKAGE_ROOTS,
  darwinArm64Applicability,
  portablePackageApplicability,
} = require("./lib/physical-package-test-matrix.js");

const ROOT = path.resolve(__dirname, "..");
const args = process.argv.slice(2);
const mode = args.length === 1 ? args[0] : null;

function fail(message) {
  process.stderr.write(`${message}\n`);
  process.exit(1);
}

if (mode !== "--portable" && mode !== "--native-darwin"
    && mode !== "--native-darwin-required") {
  fail(
    "Usage: node scripts/run-physical-package-tests.js "
    + "--portable|--native-darwin|--native-darwin-required",
  );
}

let packageRoots;
if (mode === "--native-darwin" || mode === "--native-darwin-required") {
  const applicability = darwinArm64Applicability();
  if (!applicability.applicable) {
    if (mode === "--native-darwin-required") {
      fail(
        "Physical native package qualification requires Darwin arm64; observed "
        + `${applicability.platform}/${applicability.architecture}`,
      );
    }
    process.stdout.write(
      `SKIP physical native package tests (${applicability.reason_code}: `
      + `${applicability.platform}/${applicability.architecture})\n`,
    );
    process.exit(0);
  }
  if (!applicability.supported) {
    fail(`Physical native package tests require Node.js 20; observed major ${applicability.node_major}`);
  }
  packageRoots = DARWIN_ARM64_PHYSICAL_PACKAGE_ROOTS;
} else {
  const applicability = portablePackageApplicability();
  if (!applicability.applicable) {
    process.stdout.write(
      `SKIP portable physical package tests (${applicability.reason_code}: `
      + `Node.js ${applicability.node_major})\n`,
    );
    process.exit(0);
  }
  packageRoots = PORTABLE_PHYSICAL_PACKAGE_ROOTS;
}

const npmExecPath = process.env.npm_execpath;
for (const relativeRoot of packageRoots) {
  const packageRoot = path.join(ROOT, ...relativeRoot.split("/"));
  const packagePath = path.join(packageRoot, "package.json");
  if (!fs.existsSync(packagePath)) fail(`Physical package is missing: ${relativeRoot}`);
  let manifest;
  try {
    manifest = JSON.parse(fs.readFileSync(packagePath, "utf8"));
  } catch {
    fail(`Physical package manifest is invalid: ${relativeRoot}`);
  }
  if (!manifest.scripts || typeof manifest.scripts.test !== "string"
      || manifest.scripts.test.trim().length === 0) {
    fail(`Physical package has no test script: ${relativeRoot}`);
  }
  process.stdout.write(`\n=== ${relativeRoot} ===\n`);
  // A package that declares a build is built before it is tested. The native
  // Darwin packages compile a node-gyp addon into a gitignored build/, so a
  // fresh checkout — which is every CI run — carries no addon at all and every
  // test that needs one fails with "custody was rejected". This stayed hidden
  // locally because a developer's build/ survives from an earlier build.
  const declaresBuild = typeof manifest.scripts.build === "string"
    && manifest.scripts.build.trim().length > 0;
  for (const step of declaresBuild ? [["run", "build"], ["test"]] : [["test"]]) {
    const result = npmExecPath
      ? spawnSync(process.execPath, [npmExecPath, ...step, "--prefix", packageRoot], {
        cwd: ROOT,
        env: process.env,
        stdio: "inherit",
      })
      : spawnSync("npm", [...step, "--prefix", packageRoot], {
        cwd: ROOT,
        env: process.env,
        stdio: "inherit",
      });
    const label = step[0] === "run" ? step[1] : step[0];
    if (result.error) fail(`Physical package ${label} could not start: ${relativeRoot}`);
    if (result.status !== 0) process.exit(result.status || 1);
  }
}
