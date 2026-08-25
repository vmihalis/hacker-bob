"use strict";

const {
  getOrVerifySessionAuthorityContext,
  nucleusFileExists,
} = require("../../core/session/session-authority-context.js");

// Verified-nucleus-first accessor for the pre-handler chain-authority gate
// (session-authority.js's authorizeChainScope). No mutation, no fallback to
// raw state.json shape.
//
// A state-only legacy session (no session-nucleus.json yet) returns an empty
// contracts context -- the gate's "!target_contracts.length -> return null"
// branch then falls through to authorizeSessionBound's exact legacy carveout
// instead of independently granting from raw state.
//
// A present nucleus is resolved through getOrVerifySessionAuthorityContext
// (descriptor-pinned, tamper-evident, verified-nucleus-first) with NO
// fallback: an unverifiable (missing, tampered, symlinked, corrupt) nucleus
// propagates as a throw, which the caller must hard-fail on, never swallow
// into a silent grant. This is the ONLY call path onto the nucleus-derived
// chain tuple set -- deriveChainTuplesFromNucleus itself is invoked exactly
// once, inside session-authority-context.js's buildSessionAuthorityContext,
// so the context's chain_tuples field (deep-frozen there) is reused verbatim
// here rather than re-derived a second time.
function sessionChainContext(targetDomain) {
  if (!nucleusFileExists(targetDomain)) {
    return Object.freeze({
      target_domain: targetDomain,
      target_contracts: [],
      chain_authority_hash: null,
    });
  }

  const context = getOrVerifySessionAuthorityContext(targetDomain);

  return Object.freeze({
    target_domain: context.target_domain,
    target_contracts: context.chain_tuples,
    chain_authority_hash: context.chain_authority_hash,
  });
}

module.exports = { sessionChainContext };
