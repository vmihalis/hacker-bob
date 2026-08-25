"use strict";

const {
  normalizeOpaqueRef,
} = require("../../../packages/bob-instrument-contracts/lib/physical-quantities.js");
const {
  hashCanonicalJson,
} = require("../verification/verification-contracts.js");

const CONTRACT_TARGET_DOMAIN_PATTERN =
  /^(?:sc-(?:evm|svm|aptos|sui|substrate|cosmwasm)-[a-z0-9._-]+-[a-z0-9]{1,8}|contracts-[0-9a-f]{8})$/;
const PHYSICAL_SESSION_IDENTITY_VERSION = 1;
const PHYSICAL_SESSION_IDENTITY_DOMAIN = "hacker-bob/physical-session-identity/v1";
const PHYSICAL_SESSION_TARGET_DOMAIN_PATTERN = /^physical-[a-f0-9]{24}$/;

function isContractTargetDomain(value) {
  return typeof value === "string" && CONTRACT_TARGET_DOMAIN_PATTERN.test(value);
}

function normalizePhysicalScopeImportRef(value) {
  return normalizeOpaqueRef(
    value,
    "physical_scope_import_ref",
    { prefix: "physical-scope-import" },
  );
}

function physicalScopeImportRefDigest(value) {
  const ref = normalizePhysicalScopeImportRef(value);
  return hashCanonicalJson({
    domain: PHYSICAL_SESSION_IDENTITY_DOMAIN,
    version: PHYSICAL_SESSION_IDENTITY_VERSION,
    physical_scope_import_ref: ref,
  });
}

function derivePhysicalSessionIdentity(value) {
  const physicalScopeImportRef = normalizePhysicalScopeImportRef(value);
  const physicalScopeImportRefDigestValue = physicalScopeImportRefDigest(physicalScopeImportRef);
  const targetDomain = `physical-${physicalScopeImportRefDigestValue.slice(0, 24)}`;
  return Object.freeze({
    version: PHYSICAL_SESSION_IDENTITY_VERSION,
    target_domain: targetDomain,
    session_id: targetDomain,
    physical_scope_import_ref: physicalScopeImportRef,
    physical_scope_import_ref_digest: physicalScopeImportRefDigestValue,
  });
}

function isPhysicalSessionTargetDomain(value) {
  return typeof value === "string" && PHYSICAL_SESSION_TARGET_DOMAIN_PATTERN.test(value);
}

module.exports = {
  CONTRACT_TARGET_DOMAIN_PATTERN,
  PHYSICAL_SESSION_IDENTITY_DOMAIN,
  PHYSICAL_SESSION_IDENTITY_VERSION,
  PHYSICAL_SESSION_TARGET_DOMAIN_PATTERN,
  derivePhysicalSessionIdentity,
  isContractTargetDomain,
  isPhysicalSessionTargetDomain,
  normalizePhysicalScopeImportRef,
  physicalScopeImportRefDigest,
};
