"use strict";

// The single deep-frozen, per-call authority context every session-bound
// tool call is driven from. It is built ONCE per call from a verified
// SessionNucleus read (readVerifiedSessionNucleus) -- never from raw
// state.json field shape, never from target_domain slug pattern-matching.
// dispatch.js scopes the handler invocation inside an AsyncLocalStorage
// store carrying this context (or null for a non-session-bound / legacy /
// shadow call) so concurrent tool calls never observe each other's
// authority. Direct/offline callers (tests, CLI harnesses, or any code
// running outside a dispatched tool call) fall back to a fresh verified
// read via getOrVerifySessionAuthorityContext.

const { AsyncLocalStorage } = require("async_hooks");
const fs = require("fs");
const {
  sessionNucleusPath,
} = require("../io/paths.js");
const {
  readVerifiedSessionNucleus,
} = require("../governance/index.js");
const {
  blockInternalHostsPolicyFields,
} = require("./session-state-contracts.js");

const sessionAuthorityContextStorage = new AsyncLocalStorage();

// The exact state-only legacy carveout: a session that has state.json but no
// session-nucleus.json yet admits ONLY these reads (tagged A6L projection
// reads) plus bob_advance_session (tagged legacy_migration_only, whose own
// handler already fails closed without a verified nucleus). Every other
// session-bound tool is blocked pre-handler by session-authority.js.
const LEGACY_PROJECTION_READ_TOOLS = Object.freeze([
  "bob_read_session_state",
  "bob_read_session_nucleus",
]);
const LEGACY_MIGRATION_ONLY_TOOL = "bob_advance_session";

function deepFreeze(value) {
  if (value === null || typeof value !== "object" || Object.isFrozen(value)) {
    return value;
  }
  if (Array.isArray(value)) {
    for (const item of value) deepFreeze(item);
  } else {
    for (const key of Object.keys(value)) deepFreeze(value[key]);
  }
  return Object.freeze(value);
}

// Axes are derived EXCLUSIVELY from the verified nucleus's scope_policy /
// physical_scope fields -- never from raw state.json shape and never from
// target_domain slug shape (a custom operator-supplied repo/contracts slug
// still resolves correctly here because it is the nucleus content, not the
// slug string, that drives the axis list).
function deriveAxesFromNucleus(nucleus) {
  const axes = [];
  const scopePolicy = nucleus && nucleus.scope_policy;
  if (scopePolicy && scopePolicy.target_url != null) axes.push("url");
  if (scopePolicy && scopePolicy.target_repo != null) axes.push("repo");
  if (scopePolicy && Array.isArray(scopePolicy.target_contracts) && scopePolicy.target_contracts.length > 0) {
    axes.push("contracts");
  }
  if (nucleus && nucleus.physical_scope != null) axes.push("physical");
  return axes;
}

function deriveChainTuplesFromNucleus(nucleus) {
  const scopePolicy = nucleus && nucleus.scope_policy;
  if (!scopePolicy || !Array.isArray(scopePolicy.target_contracts)) return [];
  return scopePolicy.target_contracts.map((tuple) => ({
    chain_family: tuple.chain_family,
    chain_id: tuple.chain_id,
    address: tuple.address,
  }));
}

// Builds the one private authority context for a call from a verified
// nucleus. Deep-frozen so no consumer (handler, telemetry, envelope) can
// mutate or leak a writable reference to it.
function buildSessionAuthorityContext(nucleus) {
  if (!nucleus || typeof nucleus !== "object") {
    throw new Error("buildSessionAuthorityContext requires a verified SessionNucleus");
  }
  const scopePolicy = nucleus.scope_policy || null;
  const context = {
    target_domain: nucleus.target_domain,
    nucleus_hash: nucleus.nucleus_hash,
    lifecycle_state: nucleus.lifecycle_state || null,
    axes: deriveAxesFromNucleus(nucleus),
    chain_tuples: deriveChainTuplesFromNucleus(nucleus),
    chain_authority_hash: (scopePolicy && scopePolicy.chain_authority_hash) || null,
    repo: scopePolicy && scopePolicy.target_repo ? { ...scopePolicy.target_repo } : null,
    repo_hash: nucleus.repo_hash || null,
    url: (scopePolicy && scopePolicy.target_url) || null,
    // The session's block_internal_hosts FLOOR, captured once here from the same
    // verified nucleus read this context is built from (scope_policy already carries
    // the normalized checkpoint_mode/block_internal_hosts/block_internal_hosts_source
    // triple -- see governance-contracts.js's normalizeScopePolicyInternal). Reused
    // verbatim via the existing helper rather than re-derived; a per-request
    // block_internal_hosts:true override still composes on top of this floor at the
    // consuming call site (session-state-store.js's composeBlockInternalHostsPolicy),
    // it only ever tightens, never loosens, this captured value.
    block_internal_hosts_policy: scopePolicy ? blockInternalHostsPolicyFields(scopePolicy) : null,
    physical_scope: nucleus.physical_scope ? { ...nucleus.physical_scope } : null,
    egress_identity: nucleus.egress_identity ? { ...nucleus.egress_identity } : null,
  };
  return deepFreeze(context);
}

// Defensive parity check for HTTP/WS effect call sites: a context resolved via
// getOrVerifySessionAuthorityContext(targetDomain) can never actually disagree with
// the targetDomain it was requested for (the ALS-cached branch only reuses the active
// context when its target_domain already matches; every other path fresh-verifies for
// exactly that domain) -- this predicate exists so callers assert that invariant
// explicitly at the point of use rather than trusting it silently, and so the
// assertion is independently unit-testable without a live dispatch/transport.
function authorityContextTargetDomainMismatch(context, targetDomain) {
  return !!(context && context.target_domain !== targetDomain);
}

// Throws "no active context" when called outside runWithSessionAuthorityContext
// so a caller can never silently fall back to an unscoped read. A legitimately
// context-free call (non-session-bound tool, legacy carveout, shadow) scopes
// with an explicit `null` store, which this returns as-is (not an error).
function currentSessionAuthorityContext() {
  const store = sessionAuthorityContextStorage.getStore();
  if (store === undefined) {
    throw new Error("no active session authority context; call inside runWithSessionAuthorityContext");
  }
  return store;
}

function hasActiveSessionAuthorityContext() {
  return sessionAuthorityContextStorage.getStore() !== undefined;
}

// Node 20 AsyncLocalStorage scope. Each dispatched tool call gets its own
// `als.run` invocation, so concurrent calls never observe or mutate each
// other's context (standard per-async-chain ALS isolation).
function runWithSessionAuthorityContext(context, fn) {
  return sessionAuthorityContextStorage.run(context === undefined ? null : context, fn);
}

// Verified-reads a nucleus for `targetDomain` and builds its frozen context.
// No fallback: any verification failure (missing, tampered, symlinked,
// oversized, hash mismatch) propagates as a throw.
function verifySessionAuthorityContext(targetDomain) {
  const nucleus = readVerifiedSessionNucleus(targetDomain);
  return buildSessionAuthorityContext(nucleus);
}

// The shared dispatch-vs-direct-call resolver: reuse the ALS-scoped context
// when the current call is already inside a matching dispatch scope for the
// same target_domain, otherwise perform a fresh verified read. This is what
// lets repo-target.js / repo-env.js / verification-round-store.js consume
// "the current context when dispatched, fresh-verify when called directly"
// without threading a context parameter through every call site.
function getOrVerifySessionAuthorityContext(targetDomain) {
  const active = sessionAuthorityContextStorage.getStore();
  if (active && active.target_domain === targetDomain) {
    return active;
  }
  return verifySessionAuthorityContext(targetDomain);
}

function nucleusFileExists(targetDomain) {
  try {
    fs.lstatSync(sessionNucleusPath(targetDomain));
    return true;
  } catch (error) {
    if (error && error.code === "ENOENT") return false;
    // A present-but-unstattable path (e.g. permission error) is not
    // "absent" -- let the verified read below report the precise failure
    // instead of silently treating it as a legacy state-only session.
    return true;
  }
}

module.exports = {
  LEGACY_MIGRATION_ONLY_TOOL,
  LEGACY_PROJECTION_READ_TOOLS,
  authorityContextTargetDomainMismatch,
  buildSessionAuthorityContext,
  currentSessionAuthorityContext,
  deriveAxesFromNucleus,
  deriveChainTuplesFromNucleus,
  getOrVerifySessionAuthorityContext,
  hasActiveSessionAuthorityContext,
  nucleusFileExists,
  runWithSessionAuthorityContext,
  verifySessionAuthorityContext,
};
