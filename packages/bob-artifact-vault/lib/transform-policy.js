"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const {
  ARTIFACT_VAULT_SCHEMA_VERSION,
  assertClosedObject,
  assertIdentifier,
} = require("./contracts.js");

const SHA256_RE = /^[a-f0-9]{64}$/;
const POLICY_STATUS_VALUES = Object.freeze(["trusted", "revoked"]);
const OPERATOR_TRANSFORM_POLICY_AUTHORITIES = new WeakSet();
const OPERATOR_TRANSFORM_POLICY_AUTHORITY_STATE = new WeakMap();
const OPERATOR_TRANSFORM_POLICIES = new WeakSet();
const OPERATOR_TRANSFORM_POLICY_STATE = new WeakMap();

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value != null && typeof value === "object") {
    const output = Object.create(null);
    for (const key of Object.keys(value).sort()) output[key] = canonicalize(value[key]);
    return output;
  }
  return value;
}

function canonicalJson(value) {
  return JSON.stringify(canonicalize(value));
}

function digest(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function realpathNative(filePath) {
  return fs.realpathSync.native ? fs.realpathSync.native(filePath) : fs.realpathSync(filePath);
}

function inspectImplementationRoot(root, label) {
  if (typeof root !== "string" || !path.isAbsolute(root)) {
    throw new Error(`${label} must be an absolute directory path`);
  }
  let lexicalStats;
  let realPath;
  let realStats;
  try {
    lexicalStats = fs.lstatSync(root);
    if (!lexicalStats.isDirectory() || lexicalStats.isSymbolicLink()) {
      throw new Error("not a real directory");
    }
    realPath = realpathNative(root);
    realStats = fs.statSync(realPath);
    if (!realStats.isDirectory()) throw new Error("not a directory");
  } catch (error) {
    throw new Error(`${label} must resolve to a real directory`, { cause: error });
  }
  if (typeof process.geteuid === "function" && realStats.uid !== process.geteuid()) {
    throw new Error(`${label} must be owned by the effective operator user`);
  }
  return Object.freeze({
    configured_path: root,
    real_path: realPath,
    dev: realStats.dev.toString(),
    ino: realStats.ino.toString(),
    uid: realStats.uid,
    mode: realStats.mode & 0o777,
  });
}

function normalizeTrustedDigests(input, label) {
  if (!Array.isArray(input) || input.length < 1 || input.length > 1024
    || input.some((value) => typeof value !== "string" || !SHA256_RE.test(value))) {
    throw new Error(`${label} must be a non-empty bounded SHA-256 allowlist`);
  }
  const normalized = [...input].sort();
  if (new Set(normalized).size !== normalized.length) {
    throw new Error(`${label} must not contain duplicates`);
  }
  return Object.freeze(normalized);
}

function assertAuthorityCapability(input) {
  const state = input == null ? null : OPERATOR_TRANSFORM_POLICY_AUTHORITY_STATE.get(input);
  if (!input || !OPERATOR_TRANSFORM_POLICY_AUTHORITIES.has(input) || !state) {
    throw new Error("transform policy authority must be a private branded operator capability");
  }
  if (!Object.isFrozen(input)
    || input.version !== ARTIFACT_VAULT_SCHEMA_VERSION
    || input.authority_id !== state.authority_id
    || input.authority_digest !== state.authority_digest
    || Reflect.ownKeys(input).length !== 3) {
    throw new Error("operator transform policy authority capability drifted");
  }
  return state;
}

function createOperatorTransformPolicyAuthority(input) {
  assertClosedObject(input, "operator_transform_policy_authority", [
    "version",
    "authority_id",
    "resolve_current_policy",
  ]);
  if (input.version !== ARTIFACT_VAULT_SCHEMA_VERSION) {
    throw new Error(
      `operator_transform_policy_authority.version must be ${ARTIFACT_VAULT_SCHEMA_VERSION}`,
    );
  }
  if (typeof input.resolve_current_policy !== "function") {
    throw new Error("operator_transform_policy_authority.resolve_current_policy must be a synchronous function");
  }
  const authorityId = assertIdentifier(
    input.authority_id,
    "operator_transform_policy_authority.authority_id",
  );
  const authorityDigest = digest(canonicalJson({
    domain: "hacker-bob/operator-transform-policy-authority/v1",
    version: ARTIFACT_VAULT_SCHEMA_VERSION,
    authority_id: authorityId,
    authority_instance_nonce: crypto.randomBytes(32).toString("base64url"),
  }));
  const authority = Object.freeze({
    version: ARTIFACT_VAULT_SCHEMA_VERSION,
    authority_id: authorityId,
    authority_digest: authorityDigest,
  });
  OPERATOR_TRANSFORM_POLICY_AUTHORITIES.add(authority);
  OPERATOR_TRANSFORM_POLICY_AUTHORITY_STATE.set(authority, Object.freeze({
    authority_id: authorityId,
    authority_digest: authorityDigest,
    resolve_current_policy: input.resolve_current_policy,
  }));
  return authority;
}

function normalizeResolvedPolicyEnvelope(input, label) {
  if (input && typeof input.then === "function") {
    throw new Error(`${label} must return synchronously, not a Promise or thenable`);
  }
  assertClosedObject(input, label, [
    "version",
    "policy_id",
    "policy_epoch",
    "status",
    "trusted_implementation_root",
    "trusted_implementation_digests",
  ]);
  if (input.version !== ARTIFACT_VAULT_SCHEMA_VERSION) {
    throw new Error(`${label}.version must be ${ARTIFACT_VAULT_SCHEMA_VERSION}`);
  }
  const policyId = assertIdentifier(input.policy_id, `${label}.policy_id`);
  if (!Number.isSafeInteger(input.policy_epoch) || input.policy_epoch < 1) {
    throw new Error(`${label}.policy_epoch must be a positive safe integer`);
  }
  if (!POLICY_STATUS_VALUES.includes(input.status)) {
    throw new Error(`${label}.status must be one of ${POLICY_STATUS_VALUES.join(", ")}`);
  }
  if (typeof input.trusted_implementation_root !== "string"
    || !path.isAbsolute(input.trusted_implementation_root)) {
    throw new Error(`${label}.trusted_implementation_root must be an absolute directory path`);
  }
  return Object.freeze({
    version: ARTIFACT_VAULT_SCHEMA_VERSION,
    policy_id: policyId,
    policy_epoch: input.policy_epoch,
    status: input.status,
    trusted_implementation_root: input.trusted_implementation_root,
    trusted_implementation_digests: normalizeTrustedDigests(
      input.trusted_implementation_digests,
      `${label}.trusted_implementation_digests`,
    ),
  });
}

function buildCurrentPolicyState(resolved, authorityState, label) {
  const rootIdentity = inspectImplementationRoot(
    resolved.trusted_implementation_root,
    `${label}.trusted_implementation_root`,
  );
  const rootBindingDigest = digest(canonicalJson(rootIdentity));
  const allowlistDigest = digest(canonicalJson(resolved.trusted_implementation_digests));
  const publicBasis = Object.freeze({
    domain: "hacker-bob/operator-transform-policy/v1",
    version: ARTIFACT_VAULT_SCHEMA_VERSION,
    policy_authority_id: authorityState.authority_id,
    policy_authority_digest: authorityState.authority_digest,
    policy_id: resolved.policy_id,
    policy_epoch: resolved.policy_epoch,
    root_binding_digest: rootBindingDigest,
    implementation_allowlist_digest: allowlistDigest,
  });
  return Object.freeze({
    status: resolved.status,
    policy_digest: digest(canonicalJson(publicBasis)),
    public_basis: publicBasis,
    root_identity: rootIdentity,
    trusted_implementation_digests: resolved.trusted_implementation_digests,
  });
}

function resolveAuthorityPolicy(authority, policyId, label) {
  const authorityState = assertAuthorityCapability(authority);
  const query = Object.freeze({
    version: ARTIFACT_VAULT_SCHEMA_VERSION,
    authority_id: authorityState.authority_id,
    authority_digest: authorityState.authority_digest,
    policy_id: policyId,
  });
  let output;
  try {
    output = authorityState.resolve_current_policy(query);
  } catch (error) {
    throw new Error(`${label} current-policy resolver is unavailable`, { cause: error });
  }
  let resolved;
  try {
    resolved = normalizeResolvedPolicyEnvelope(output, `${label} resolver output`);
  } catch (error) {
    throw new Error(`${label} current-policy resolver returned malformed state: ${error.message}`, {
      cause: error,
    });
  }
  if (resolved.policy_id !== policyId) {
    throw new Error(`${label} current-policy resolver substituted a different policy identity`);
  }
  return buildCurrentPolicyState(resolved, authorityState, label);
}

function enrollOperatorTransformPolicy(input, authority) {
  assertClosedObject(input, "operator_transform_policy_enrollment", [
    "version",
    "policy_authority_id",
    "policy_authority_digest",
    "policy_id",
  ]);
  if (input.version !== ARTIFACT_VAULT_SCHEMA_VERSION) {
    throw new Error(`operator_transform_policy_enrollment.version must be ${ARTIFACT_VAULT_SCHEMA_VERSION}`);
  }
  const policyId = assertIdentifier(input.policy_id, "operator_transform_policy_enrollment.policy_id");
  const authorityState = assertAuthorityCapability(authority);
  if (input.policy_authority_id !== authorityState.authority_id
    || typeof input.policy_authority_digest !== "string"
    || !SHA256_RE.test(input.policy_authority_digest)
    || input.policy_authority_digest !== authorityState.authority_digest) {
    throw new Error("operator transform policy enrollment does not match its pinned authority");
  }
  const current = resolveAuthorityPolicy(authority, policyId, "operator transform policy enrollment");
  if (current.status !== "trusted") {
    throw new Error("operator transform policy enrollment refuses a revoked policy");
  }
  const policy = Object.freeze({
    version: ARTIFACT_VAULT_SCHEMA_VERSION,
    policy_authority_id: authorityState.authority_id,
    policy_authority_digest: authorityState.authority_digest,
    policy_id: policyId,
    policy_epoch: current.public_basis.policy_epoch,
    policy_digest: current.policy_digest,
  });
  OPERATOR_TRANSFORM_POLICIES.add(policy);
  OPERATOR_TRANSFORM_POLICY_STATE.set(policy, Object.freeze({
    authority,
    policy_digest: current.policy_digest,
    public_basis: current.public_basis,
  }));
  return policy;
}

function resolveOperatorTransformPolicy(input) {
  const state = input == null ? null : OPERATOR_TRANSFORM_POLICY_STATE.get(input);
  if (!input || !OPERATOR_TRANSFORM_POLICIES.has(input) || !state) {
    throw new Error("transform policy must be a private branded operator-enrolled capability");
  }
  if (!Object.isFrozen(input)
    || input.version !== ARTIFACT_VAULT_SCHEMA_VERSION
    || input.policy_authority_id !== state.public_basis.policy_authority_id
    || input.policy_authority_digest !== state.public_basis.policy_authority_digest
    || input.policy_id !== state.public_basis.policy_id
    || input.policy_epoch !== state.public_basis.policy_epoch
    || input.policy_digest !== state.policy_digest
    || Reflect.ownKeys(input).length !== 6) {
    throw new Error("operator-enrolled transform policy capability drifted");
  }
  const current = resolveAuthorityPolicy(
    state.authority,
    state.public_basis.policy_id,
    "operator-enrolled transform policy",
  );
  if (current.status === "revoked") {
    throw new Error("operator-enrolled transform policy is revoked");
  }
  if (current.public_basis.policy_epoch !== state.public_basis.policy_epoch) {
    throw new Error("operator-enrolled transform policy is stale relative to the current policy epoch");
  }
  for (const field of [
    "policy_authority_id",
    "policy_authority_digest",
    "policy_id",
    "root_binding_digest",
    "implementation_allowlist_digest",
  ]) {
    if (current.public_basis[field] !== state.public_basis[field]) {
      throw new Error(`operator-enrolled transform policy current ${field} binding drifted`);
    }
  }
  if (current.policy_digest !== state.policy_digest) {
    throw new Error("operator-enrolled transform policy digest drifted");
  }
  return current;
}

module.exports = {
  createOperatorTransformPolicyAuthority,
  enrollOperatorTransformPolicy,
  resolveOperatorTransformPolicy,
};
