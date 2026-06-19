"use strict";

const {
  hashCanonicalJson,
} = require("./verification-contracts.js");
const {
  sessionNucleusFromState,
} = require("./governance-contracts.js");

// governance-context.js threads the canonical governance triple
// {nucleus_hash, lifecycle_state, egress_identity_hash} into every pipeline
// event append. Cycle G.4 of the realization hypergraph wires this through so
// pipeline-events no longer re-reads state.json on every append. Callers
// derive the context inline from whatever they already have in scope --
// either a `state` document (most legacy code) or a `nucleus` document (new
// governance writers).

function isPlainObject(value) {
  return value != null && typeof value === "object" && !Array.isArray(value);
}

function pickLifecycleState(stateOrNucleus) {
  if (!isPlainObject(stateOrNucleus)) return null;
  if (typeof stateOrNucleus.lifecycle_state === "string" && stateOrNucleus.lifecycle_state) {
    return stateOrNucleus.lifecycle_state;
  }
  return null;
}

function pickEgressIdentityHash(state) {
  if (!isPlainObject(state)) return null;
  if (typeof state.egress_profile_identity_hash === "string" && state.egress_profile_identity_hash) {
    return state.egress_profile_identity_hash;
  }
  return null;
}

// buildGovernanceContext derives the governance triple from a session-state
// document (the legacy `state.json` shape). Most call sites have `state` in
// scope already because they just opened the session lock; the helper avoids
// re-deriving the nucleus on the hot path while keeping the contract uniform.
function buildGovernanceContext(state) {
  if (!isPlainObject(state)) {
    throw new Error("governance_context source must be an object");
  }
  let nucleus;
  try {
    nucleus = sessionNucleusFromState(state);
  } catch (error) {
    throw new Error(`failed to derive session nucleus for governance_context: ${error.message || String(error)}`);
  }
  const lifecycleState = pickLifecycleState(state) || pickLifecycleState(nucleus);
  const egressIdentityHash = pickEgressIdentityHash(state)
    || hashCanonicalJson(nucleus.egress_identity);
  return Object.freeze({
    nucleus_hash: nucleus.nucleus_hash,
    lifecycle_state: lifecycleState,
    egress_identity_hash: egressIdentityHash,
  });
}

// buildGovernanceContextFromNucleus is the parallel helper for writers that
// already hold a canonical SessionNucleus document (governance-plane writers
// after Cycle G.1 / G.2). Hashing the egress_identity sub-document is cheap
// (already canonicalized inside the nucleus contract).
function buildGovernanceContextFromNucleus(nucleus) {
  if (!isPlainObject(nucleus)) {
    throw new Error("governance_context source nucleus must be an object");
  }
  if (typeof nucleus.nucleus_hash !== "string" || !nucleus.nucleus_hash) {
    throw new Error("governance_context source nucleus is missing nucleus_hash");
  }
  return Object.freeze({
    nucleus_hash: nucleus.nucleus_hash,
    lifecycle_state: pickLifecycleState(nucleus),
    egress_identity_hash: hashCanonicalJson(nucleus.egress_identity),
  });
}

// safeGovernanceContextForDomain is a defensive wrapper for callers that
// emit *best-effort* analytics events outside the orchestration hot path.
// When the session lock is held for an event append but the underlying
// session-state has not been seeded yet (test fixtures, evidence-mode
// post-report markers, replay-policy lease events emitted before init), the
// derived context falls back to null so the matching safe* writers silently
// drop the event instead of failing the hot-path operation. Authoritative
// writers (initSession, advanceSession, applyOperatorConstraintUpdate, etc.)
// must use buildGovernanceContext directly so a missing context surfaces.
function safeGovernanceContextForDomain(domain) {
  if (!domain) return null;
  try {
    const { readSessionStateStrict } = require("./session-state-store.js");
    const { state } = readSessionStateStrict(domain);
    return buildGovernanceContext(state);
  } catch {
    return null;
  }
}

module.exports = {
  buildGovernanceContext,
  buildGovernanceContextFromNucleus,
  safeGovernanceContextForDomain,
};
