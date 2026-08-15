"use strict";

const { readSessionStateStrict } = require("../../core/session/session-state-store.js");

// Thin, pure-read accessor for a future pre-handler chain-authority gate.
// Loads the strict session state (fail-closed on missing/malformed) and
// surfaces the canonical chain-identity context. No mutation, no disk writes.
//
// target_contracts and chain_authority_hash are read state-first, raw-second:
// normalizeSessionStateDocument is an allowlist that currently drops these
// unknown fields, so reading raw keeps them visible while the state-first
// check stays correct if the normalizer later adopts them.
function sessionChainContext(targetDomain) {
  const { raw, state } = readSessionStateStrict(targetDomain);

  const target_domain = state.target;

  let target_contracts;
  if (Array.isArray(state.target_contracts)) {
    target_contracts = state.target_contracts.slice();
  } else if (raw && Array.isArray(raw.target_contracts)) {
    target_contracts = raw.target_contracts.slice();
  } else {
    target_contracts = [];
  }

  let chain_authority_hash;
  if (typeof state.chain_authority_hash === "string") {
    chain_authority_hash = state.chain_authority_hash;
  } else if (raw && typeof raw.chain_authority_hash === "string") {
    chain_authority_hash = raw.chain_authority_hash;
  } else {
    chain_authority_hash = null;
  }

  return Object.freeze({
    target_domain,
    target_contracts,
    chain_authority_hash,
  });
}

module.exports = { sessionChainContext };
