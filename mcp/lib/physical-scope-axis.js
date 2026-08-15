"use strict";

// Leaf contract for the compact physical-scope axis carried by state.json and
// session-nucleus.json. This module deliberately has no dependency on either
// state or governance contracts, so both can normalize the same axis without
// introducing a require cycle.

const {
  assertInteger,
  assertNonEmptyString,
} = require("../core/io/validation.js");
const {
  withDocumentHash,
} = require("../core/verification/document-hash.js");
const {
  validateNoSensitiveMaterial,
  validateNoPhysicalSensitiveMaterial,
} = require("../core/redaction/sensitive-material.js");

const PHYSICAL_SCOPE_NUCLEUS_AXIS_VERSION = 1;
const PHYSICAL_SCOPE_POLICY_VERSION = 1;
const PHYSICAL_SCOPE_PROJECTION_VERSION = 1;
const SHA256_PATTERN = /^[a-f0-9]{64}$/;

function assertDigest(value, fieldName) {
  if (typeof value !== "string" || !SHA256_PATTERN.test(value)) {
    throw new Error(`${fieldName} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function closedDataObjectValues(input, label, allowedFields) {
  if (input == null || typeof input !== "object" || Array.isArray(input)) {
    throw new Error(`${label} must be an object`);
  }
  const prototype = Object.getPrototypeOf(input);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new Error(`${label} must be a plain data object`);
  }
  const ownKeys = Reflect.ownKeys(input);
  if (ownKeys.some((key) => typeof key !== "string")) {
    throw new Error(`${label} must not carry symbol fields`);
  }
  const unknown = ownKeys.filter((field) => !allowedFields.has(field)).sort();
  if (unknown.length > 0) {
    throw new Error(`${label} has unknown fields: ${unknown.join(", ")}`);
  }
  const descriptors = Object.getOwnPropertyDescriptors(input);
  const values = Object.create(null);
  for (const field of ownKeys) {
    const descriptor = descriptors[field];
    if (!descriptor || descriptor.enumerable !== true
        || !Object.prototype.hasOwnProperty.call(descriptor, "value")) {
      throw new Error(`${label}.${field} must be an enumerable data property`);
    }
    values[field] = descriptor.value;
  }
  return values;
}

function normalizePhysicalScopeNucleusAxis(input) {
  const required = [
    "version",
    "physical_enabled",
    "policy_version",
    "policy_id",
    "policy_digest",
    "projection_version",
    "projection_digest",
    "provenance_digest",
    "compatibility_digest",
    "transition_receipt_registry_digest",
    "authority_epoch",
    "revocation_generation",
  ];
  const allowed = new Set([...required, "axis_digest"]);
  const values = closedDataObjectValues(input, "physical_scope", allowed);
  const missing = required.filter((field) => !Object.prototype.hasOwnProperty.call(values, field));
  if (missing.length > 0) {
    throw new Error(`physical_scope is missing fields: ${missing.join(", ")}`);
  }
  if (values.version !== PHYSICAL_SCOPE_NUCLEUS_AXIS_VERSION) {
    throw new Error(`physical_scope.version must be ${PHYSICAL_SCOPE_NUCLEUS_AXIS_VERSION}`);
  }
  if (values.physical_enabled !== true) {
    throw new Error("physical_scope.physical_enabled must be true; omit the axis to disable physical authority");
  }
  if (values.policy_version !== PHYSICAL_SCOPE_POLICY_VERSION) {
    throw new Error(`physical_scope.policy_version must be ${PHYSICAL_SCOPE_POLICY_VERSION}`);
  }
  if (values.projection_version !== PHYSICAL_SCOPE_PROJECTION_VERSION) {
    throw new Error(`physical_scope.projection_version must be ${PHYSICAL_SCOPE_PROJECTION_VERSION}`);
  }
  const policyId = assertNonEmptyString(values.policy_id, "physical_scope.policy_id");
  if (!/^[a-z][a-z0-9._-]{0,127}$/.test(policyId)) {
    throw new Error("physical_scope.policy_id must be a lowercase identifier");
  }
  const axis = {
    version: PHYSICAL_SCOPE_NUCLEUS_AXIS_VERSION,
    physical_enabled: true,
    policy_version: PHYSICAL_SCOPE_POLICY_VERSION,
    policy_id: policyId,
    policy_digest: assertDigest(values.policy_digest, "physical_scope.policy_digest"),
    projection_version: PHYSICAL_SCOPE_PROJECTION_VERSION,
    projection_digest: assertDigest(values.projection_digest, "physical_scope.projection_digest"),
    provenance_digest: assertDigest(values.provenance_digest, "physical_scope.provenance_digest"),
    compatibility_digest: assertDigest(values.compatibility_digest, "physical_scope.compatibility_digest"),
    transition_receipt_registry_digest: assertDigest(
      values.transition_receipt_registry_digest,
      "physical_scope.transition_receipt_registry_digest",
    ),
    authority_epoch: assertInteger(values.authority_epoch, "physical_scope.authority_epoch", { min: 1 }),
    revocation_generation: assertInteger(
      values.revocation_generation,
      "physical_scope.revocation_generation",
      { min: 0 },
    ),
  };
  validateNoSensitiveMaterial(axis, "physical_scope");
  validateNoPhysicalSensitiveMaterial(axis, "physical_scope");
  const normalized = withDocumentHash(axis, "axis_digest");
  if (values.axis_digest != null
      && assertDigest(values.axis_digest, "physical_scope.axis_digest") !== normalized.axis_digest) {
    throw new Error("physical_scope.axis_digest does not match the canonical physical scope axis");
  }
  return normalized;
}

module.exports = {
  PHYSICAL_SCOPE_NUCLEUS_AXIS_VERSION,
  PHYSICAL_SCOPE_POLICY_VERSION,
  PHYSICAL_SCOPE_PROJECTION_VERSION,
  normalizePhysicalScopeNucleusAxis,
};
