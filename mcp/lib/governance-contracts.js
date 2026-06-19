"use strict";

const fs = require("fs");
const path = require("path");
const {
  AUTH_STATUS_VALUES,
} = require("./constants.js");
const {
  assertBoolean,
  assertEnumValue,
  assertInteger,
  assertNonEmptyString,
  normalizeOptionalText,
} = require("./validation.js");
const {
  assertSafeDomain,
} = require("./paths.js");
const {
  blockInternalHostsPolicyFields,
} = require("./session-state-contracts.js");
const {
  hashDocumentExcluding,
  normalizeOptionalObject,
  withDocumentHash,
} = require("./fabric-common.js");
const {
  validateNoSensitiveMaterial,
} = require("./sensitive-material.js");

const GOVERNANCE_VERSION = 1;
const LIFECYCLE_STATE_VALUES = Object.freeze([
  "SETUP",
  "OPEN_FRONTIER",
  "CLAIM_FREEZE",
  "VERIFY",
  "GRADE",
  "REPORT",
]);

function normalizeLifecycleState(value, fieldName = "lifecycle_state") {
  return assertEnumValue(value == null ? "SETUP" : value, LIFECYCLE_STATE_VALUES, fieldName);
}

// Cycle O.1: assertRepoRootPath enforces O-P1 (local-repo first). The path
// MUST exist locally as a directory before a repo session can be bound.
// Returned value is the canonical absolute path so downstream derivations
// (target_domain hashing, docker bind-mount) see a stable string.
function assertRepoRootPath(value, fieldName = "target_repo.root_path") {
  const raw = assertNonEmptyString(value, fieldName);
  validateNoSensitiveMaterial(raw, fieldName, { maxTextChars: 4096 });
  if (!path.isAbsolute(raw)) {
    throw new Error(`${fieldName} must be an absolute path (got ${raw})`);
  }
  let resolved;
  try {
    resolved = fs.realpathSync.native
      ? fs.realpathSync.native(raw)
      : fs.realpathSync(raw);
  } catch (error) {
    if (error && error.code === "ENOENT") {
      const err = new Error(`${fieldName} does not exist: ${raw}`);
      err.code = "repo_path_not_found";
      throw err;
    }
    throw error;
  }
  let stats;
  try {
    stats = fs.statSync(resolved);
  } catch (error) {
    if (error && error.code === "ENOENT") {
      const err = new Error(`${fieldName} does not exist: ${raw}`);
      err.code = "repo_path_not_found";
      throw err;
    }
    throw error;
  }
  if (!stats.isDirectory()) {
    const err = new Error(`${fieldName} is not a directory: ${raw}`);
    err.code = "repo_path_not_directory";
    throw err;
  }
  return resolved;
}

function normalizeTargetRepo(input, fieldName = "target_repo") {
  if (input == null || typeof input !== "object" || Array.isArray(input)) {
    throw new Error(`${fieldName} must be an object`);
  }
  const rootPath = assertRepoRootPath(input.root_path, `${fieldName}.root_path`);
  const sourceUrl = input.source_url == null
    ? null
    : assertNonEmptyString(input.source_url, `${fieldName}.source_url`);
  if (sourceUrl != null) {
    validateNoSensitiveMaterial(sourceUrl, `${fieldName}.source_url`, { maxTextChars: 2048 });
  }
  const branch = input.branch == null
    ? null
    : assertNonEmptyString(input.branch, `${fieldName}.branch`);
  if (branch != null) {
    validateNoSensitiveMaterial(branch, `${fieldName}.branch`, { maxTextChars: 256 });
  }
  const commit = input.commit == null
    ? null
    : assertNonEmptyString(input.commit, `${fieldName}.commit`);
  if (commit != null) {
    if (!/^[0-9a-f]{7,64}$/i.test(commit)) {
      throw new Error(`${fieldName}.commit must be a 7-64 character hex commit id`);
    }
  }
  const repo = { root_path: rootPath };
  if (sourceUrl) repo.source_url = sourceUrl;
  if (branch) repo.branch = branch;
  if (commit) repo.commit = commit.toLowerCase();
  return repo;
}

function normalizeScopePolicy(input) {
  if (input == null || typeof input !== "object" || Array.isArray(input)) {
    throw new Error("scope_policy must be an object");
  }
  const targetDomain = assertSafeDomain(input.target_domain);
  const hasUrl = input.target_url != null && (typeof input.target_url !== "string" || input.target_url.trim().length > 0);
  const hasRepo = input.target_repo != null;
  if (!hasUrl && !hasRepo) {
    throw new Error("scope_policy requires exactly one of target_url or target_repo");
  }
  if (hasUrl && hasRepo) {
    throw new Error("scope_policy must carry exactly one of target_url or target_repo, not both");
  }
  const internalHostPolicy = blockInternalHostsPolicyFields(input);
  if (hasRepo) {
    const targetRepo = normalizeTargetRepo(input.target_repo);
    return {
      target_domain: targetDomain,
      target_repo: targetRepo,
      checkpoint_mode: internalHostPolicy.checkpoint_mode,
      block_internal_hosts: internalHostPolicy.block_internal_hosts,
      block_internal_hosts_source: internalHostPolicy.block_internal_hosts_source,
    };
  }
  const targetUrl = assertNonEmptyString(input.target_url, "target_url");
  validateNoSensitiveMaterial(targetUrl, "target_url", { maxTextChars: 2048 });
  return {
    target_domain: targetDomain,
    target_url: targetUrl,
    checkpoint_mode: internalHostPolicy.checkpoint_mode,
    block_internal_hosts: internalHostPolicy.block_internal_hosts,
    block_internal_hosts_source: internalHostPolicy.block_internal_hosts_source,
  };
}

function normalizeEgressIdentity(input = {}) {
  if (input == null || typeof input !== "object" || Array.isArray(input)) {
    throw new Error("egress_identity must be an object");
  }
  const profile = assertNonEmptyString(input.egress_profile || input.name || "default", "egress_profile");
  const identity = {
    egress_profile: profile,
    egress_region: normalizeOptionalText(input.egress_region || input.region, "egress_region"),
    proxy_configured: input.proxy_configured == null
      ? false
      : assertBoolean(input.proxy_configured, "proxy_configured"),
    egress_profile_identity_hash: normalizeOptionalText(
      input.egress_profile_identity_hash,
      "egress_profile_identity_hash",
    ),
    egress_profile_identity_version: input.egress_profile_identity_version == null
      ? null
      : assertInteger(input.egress_profile_identity_version, "egress_profile_identity_version", { min: 1 }),
    egress_profile_identity_source: normalizeOptionalObject(
      input.egress_profile_identity_source,
      "egress_profile_identity_source",
    ),
  };
  validateNoSensitiveMaterial(identity, "egress_identity");
  return identity;
}

function normalizeAuthContext(input = {}) {
  if (input == null || typeof input !== "object" || Array.isArray(input)) {
    throw new Error("auth_context must be an object");
  }
  const context = {
    auth_status: assertEnumValue(input.auth_status || input.status || "pending", AUTH_STATUS_VALUES, "auth_status"),
  };
  const handleCount = input.auth_handle_count == null
    ? null
    : assertInteger(input.auth_handle_count, "auth_handle_count", { min: 0 });
  if (handleCount != null) context.auth_handle_count = handleCount;
  return context;
}

function normalizeOperatorConstraint(input = {}) {
  if (input == null || typeof input !== "object" || Array.isArray(input)) {
    throw new Error("operator_constraint must be an object");
  }
  const note = normalizeOptionalText(input.operator_note, "operator_note");
  if (note != null) {
    validateNoSensitiveMaterial(note, "operator_note", { maxTextChars: 1000 });
  }
  const constraint = {
    handoff_provenance_required: input.handoff_provenance_required == null
      ? true
      : assertBoolean(input.handoff_provenance_required, "handoff_provenance_required"),
  };
  if (note != null) constraint.operator_note = note;
  return constraint;
}

function buildSessionNucleus(input) {
  if (input == null || typeof input !== "object" || Array.isArray(input)) {
    throw new Error("session nucleus input must be an object");
  }
  const scopePolicyInput = input.scope_policy || {};
  const mergedScopePolicy = {
    ...scopePolicyInput,
    target_domain: input.target_domain || scopePolicyInput.target_domain,
  };
  // target_url and target_repo are mutually exclusive in normalizeScopePolicy.
  // Honor top-level overrides if present, but do not auto-merge both fields.
  if (input.target_url != null) {
    mergedScopePolicy.target_url = input.target_url;
  } else if (scopePolicyInput.target_url != null) {
    mergedScopePolicy.target_url = scopePolicyInput.target_url;
  }
  if (input.target_repo != null) {
    mergedScopePolicy.target_repo = input.target_repo;
  } else if (scopePolicyInput.target_repo != null) {
    mergedScopePolicy.target_repo = scopePolicyInput.target_repo;
  }
  const scopePolicy = normalizeScopePolicy(mergedScopePolicy);
  const nucleus = {
    version: GOVERNANCE_VERSION,
    target_domain: scopePolicy.target_domain,
    lifecycle_state: normalizeLifecycleState(input.lifecycle_state),
    scope_policy: scopePolicy,
    egress_identity: normalizeEgressIdentity(input.egress_identity),
    auth_context: normalizeAuthContext(input.auth_context),
    operator_constraint: normalizeOperatorConstraint(input.operator_constraint),
  };
  // Cycle O.1: repo sessions persist the session-init repo_hash so the
  // docker image tag derivation stays stable across the session lifetime
  // (Plane O O-D6 cache-bust contract). repo_hash is supplied by the
  // caller (initRepoSession) — never recomputed here.
  if (input.repo_hash != null) {
    if (!/^[0-9a-f]{8,64}$/i.test(String(input.repo_hash))) {
      throw new Error("repo_hash must be 8-64 hex characters");
    }
    nucleus.repo_hash = String(input.repo_hash).toLowerCase();
  }
  return withDocumentHash(nucleus, "nucleus_hash");
}

function sessionNucleusFromState(state) {
  if (state == null || typeof state !== "object" || Array.isArray(state)) {
    throw new Error("state must be an object");
  }
  const scopePolicy = {
    target_domain: state.target,
    checkpoint_mode: state.checkpoint_mode,
    block_internal_hosts: state.block_internal_hosts,
    block_internal_hosts_source: state.block_internal_hosts_source,
  };
  if (state.target_repo != null) {
    scopePolicy.target_repo = state.target_repo;
  } else if (state.target_url != null) {
    scopePolicy.target_url = state.target_url;
  }
  const args = {
    target_domain: state.target,
    scope_policy: scopePolicy,
    egress_identity: {
      egress_profile: state.egress_profile,
      egress_region: state.egress_region,
      proxy_configured: state.proxy_configured,
      egress_profile_identity_hash: state.egress_profile_identity_hash,
      egress_profile_identity_version: state.egress_profile_identity_version,
      egress_profile_identity_source: state.egress_profile_identity_source,
    },
    auth_context: {
      auth_status: state.auth_status,
    },
    operator_constraint: {
      operator_note: state.operator_note,
      handoff_provenance_required: state.handoff_provenance_required,
    },
    lifecycle_state: state.lifecycle_state,
  };
  if (state.target_url != null) {
    args.target_url = state.target_url;
  }
  if (state.target_repo != null) {
    args.target_repo = state.target_repo;
  }
  if (state.repo_hash != null) {
    args.repo_hash = state.repo_hash;
  }
  return buildSessionNucleus(args);
}

function sessionNucleusHash(nucleus) {
  return hashDocumentExcluding(nucleus, ["nucleus_hash"]);
}

module.exports = {
  GOVERNANCE_VERSION,
  LIFECYCLE_STATE_VALUES,
  assertRepoRootPath,
  buildSessionNucleus,
  normalizeAuthContext,
  normalizeEgressIdentity,
  normalizeLifecycleState,
  normalizeOperatorConstraint,
  normalizeScopePolicy,
  normalizeTargetRepo,
  sessionNucleusFromState,
  sessionNucleusHash,
};
