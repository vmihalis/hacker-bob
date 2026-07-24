"use strict";

const PORTABLE_PHYSICAL_PACKAGE_ROOTS = Object.freeze([
  "packages/bob-artifact-vault",
  "packages/bob-instrument-broker",
  "packages/bob-instrument-contracts",
  "packages/bob-instrument-chameleon",
  "packages/bob-instrument-chameleon-worker",
  "packages/bob-instrument-chameleon-worker-runtime",
  "packages/bob-instrument-deterministic",
  "packages/bob-instrument-native-prebuild-trust",
  "packages/bob-instrument-principal-acl-darwin",
]);

const DARWIN_ARM64_PHYSICAL_PACKAGE_ROOTS = Object.freeze([
  "packages/bob-instrument-chameleon-native-darwin",
  "packages/bob-instrument-native-darwin",
  "packages/bob-instrument-trusted-clock-native-darwin",
  "packages/bob-instrument-launcher-native-darwin",
  "packages/bob-instrument-safety-native-darwin",
]);

function nodeMajor(version = process.versions.node) {
  const match = /^(\d+)\./u.exec(String(version || ""));
  return match ? Number.parseInt(match[1], 10) : 0;
}

function portablePackageApplicability(host = {}) {
  const major = nodeMajor(host.node_version || process.versions.node);
  if (major !== 20) {
    return Object.freeze({
      applicable: false,
      reason_code: "node_major_not_20",
      node_major: major,
    });
  }
  return Object.freeze({
    applicable: true,
    supported: true,
    reason_code: "node20",
    node_major: major,
  });
}

function darwinArm64Applicability(host = {}) {
  const platform = host.platform || process.platform;
  const architecture = host.architecture || process.arch;
  const major = nodeMajor(host.node_version || process.versions.node);
  if (platform !== "darwin" || architecture !== "arm64") {
    return Object.freeze({
      applicable: false,
      reason_code: "host_not_darwin_arm64",
      platform,
      architecture,
      node_major: major,
    });
  }
  if (major !== 20) {
    return Object.freeze({
      applicable: true,
      supported: false,
      reason_code: "node_major_not_20",
      platform,
      architecture,
      node_major: major,
    });
  }
  return Object.freeze({
    applicable: true,
    supported: true,
    reason_code: "darwin_arm64_node20",
    platform,
    architecture,
    node_major: major,
  });
}

module.exports = {
  DARWIN_ARM64_PHYSICAL_PACKAGE_ROOTS,
  PORTABLE_PHYSICAL_PACKAGE_ROOTS,
  darwinArm64Applicability,
  nodeMajor,
  portablePackageApplicability,
};
