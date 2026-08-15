"use strict";

// Narrow dependency-inversion ports for generic core consumers of physical
// runtime authority. Concrete plane modules register their implementations
// after their private brands and stores are initialized; the composition root
// loads all three modules before dispatch begins.

const fs = require("node:fs");
const {
  physicalCampaignDir,
  physicalSessionBootstrapPath,
} = require("./io/paths.js");

const implementations = Object.create(null);

function pathEntryPresent(filePath) {
  try {
    fs.lstatSync(filePath);
    return true;
  } catch (error) {
    if (error && error.code === "ENOENT") return false;
    throw error;
  }
}

function configurePhysicalDomainRuntimePorts(ports) {
  const supported = [
    "assertVerifiedPhysicalClaimProjection",
    "normalizePhysicalFindingRecord",
    "physicalCampaignClosureReadiness",
  ];
  if (ports == null || typeof ports !== "object") {
    throw new Error("physical domain runtime ports are incomplete");
  }
  const names = Object.keys(ports);
  if (names.length === 0 || names.some((name) => !supported.includes(name)
      || typeof ports[name] !== "function")) {
    throw new Error("physical domain runtime ports are incomplete");
  }
  for (const name of names) {
    if (implementations[name] && implementations[name] !== ports[name]) {
      throw new Error(`physical domain runtime port ${name} is already configured`);
    }
    implementations[name] = ports[name];
  }
}

function invoke(name, args) {
  if (typeof implementations[name] !== "function") {
    throw new Error(`physical domain runtime port ${name} is not configured`);
  }
  return implementations[name](...args);
}

function assertVerifiedPhysicalClaimProjection(value) {
  return invoke("assertVerifiedPhysicalClaimProjection", [value]);
}

function normalizePhysicalFindingRecord(record, options) {
  return invoke("normalizePhysicalFindingRecord", [record, options]);
}

function physicalCampaignClosureReadiness(targetDomain) {
  if (typeof implementations.physicalCampaignClosureReadiness !== "function"
      && !pathEntryPresent(physicalCampaignDir(targetDomain))
      && !pathEntryPresent(physicalSessionBootstrapPath(targetDomain))) {
    return Object.freeze({ active: false, satisfied: true });
  }
  return invoke("physicalCampaignClosureReadiness", [targetDomain]);
}

module.exports = Object.freeze({
  assertVerifiedPhysicalClaimProjection,
  configurePhysicalDomainRuntimePorts,
  normalizePhysicalFindingRecord,
  physicalCampaignClosureReadiness,
});
