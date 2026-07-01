"use strict";

// Pure chain-authority module — no fs/network/clock/process-env/child_process
// I/O, no session-state-store or chain-tool-identity require, no top-level side
// effects. Mirrors the dependency-light posture of target-intake.js and
// frontier-events.js: data in, data out, importing it has no observable effect.
//
// It answers one question for the (later) pre-handler gate: given a session's
// bound in-scope contracts, is a chain tuple (chain_family, chain_id, address)
// inside the authority? Membership is strict exact-tuple by default; a same-chain
// relaxation (OD3) is reachable only when the caller explicitly passes a
// provenance flag. Provenance DETECTION is intentionally not wired here — it
// lands with a later node. This module is not wired into any tool handler; the
// pre-handler gate is a separate node.

// hashCanonicalJson (verification-contracts.js) is the single canonical hashing
// primitive — no parallel hash implementation is introduced here.
const { hashCanonicalJson } = require("./verification-contracts.js");
// classifyTargetToken (target-intake.js) is the single canonical string-token
// parser; it is already load-time-asserted against CHAIN_FAMILY_VALUES, so this
// module never redefines or hardcodes the chain-family vocabulary.
const { classifyTargetToken } = require("./target-intake.js");

// Mirror of the chain-family token normalizer (lowercase, trim, collapse runs of
// whitespace/dashes to a single underscore). The canonical-but-unexported source
// is normalizeChainToken in mcp/lib/frontier-events.js; importing it would
// require touching that module, which is out of this node's scope, so the rule is
// reproduced here verbatim and applied to chain_family only.
function normalizeChainToken(value) {
  if (value == null) return null;
  const normalized = String(value).trim().toLowerCase().replace(/[\s-]+/g, "_");
  return normalized || null;
}

// Normalize one contracts entry into a canonical {chain_family, chain_id,
// address} tuple, or null when the entry is not a valid contract tuple.
//
//   - String entries are parsed with classifyTargetToken and accepted ONLY when
//     axis === "contract" (web_url / refuse results are dropped defensively).
//   - Plain-object entries carrying chain_family/chain_id/address are used
//     directly.
//
// address is trimmed and lowercased (case-folded so 0xABC and 0xabc collide);
// chain_id is trimmed but case-PRESERVED (do not conflate distinct references);
// chain_family is run through the normalizeChainToken rule.
function normalizeOneTuple(entry) {
  let chainFamily;
  let chainId;
  let address;

  if (typeof entry === "string") {
    // Drop blank/empty tokens as garbage rather than letting classifyTargetToken
    // throw on length 0 — a throw inside the authority predicate is a fail-mode
    // hazard, not a clean deny (the isChainTupleInAuthority tuple arg is unnormalized).
    if (entry.trim() === "") return null;
    const classified = classifyTargetToken(entry);
    if (!classified || classified.axis !== "contract") return null;
    chainFamily = classified.chain_family;
    chainId = classified.chain_id;
    address = classified.address;
  } else if (entry && typeof entry === "object") {
    chainFamily = entry.chain_family;
    chainId = entry.chain_id;
    address = entry.address;
  } else {
    return null;
  }

  const normalizedFamily = normalizeChainToken(chainFamily);
  if (
    normalizedFamily == null
    || chainId == null
    || address == null
  ) {
    return null;
  }

  const normalizedChainId = String(chainId).trim();
  const normalizedAddress = String(address).trim().toLowerCase();
  if (normalizedChainId === "" || normalizedAddress === "") return null;

  return {
    chain_family: normalizedFamily,
    chain_id: normalizedChainId,
    address: normalizedAddress,
  };
}

// Resolve a contracts array from EITHER a raw array OR a state-shaped object that
// carries .target_contracts, then normalize each entry, dropping anything that is
// not a valid contract tuple (rank, do not bound — invalid entries fall away, the
// valid ones all survive).
function extractChainTuples(stateOrContracts) {
  const contracts = Array.isArray(stateOrContracts)
    ? stateOrContracts
    : stateOrContracts
        && Array.isArray(stateOrContracts.target_contracts)
      ? stateOrContracts.target_contracts
      : [];

  const tuples = [];
  for (const entry of contracts) {
    const tuple = normalizeOneTuple(entry);
    if (tuple) tuples.push(tuple);
  }
  return tuples;
}

// Deterministic, order-independent authority hash. Projects each normalized tuple
// to an ordered [chain_family, chain_id, address] triple, sorts the projected
// triples with a stable comparator, and delegates to the single canonical
// hashCanonicalJson. Empty/duplicate-reordered input yields a stable hash; the
// same normalized contract set always hashes equal regardless of input order.
function chainAuthorityHash(contracts) {
  const projected = extractChainTuples(contracts).map((t) => [
    t.chain_family,
    t.chain_id,
    t.address,
  ]);
  projected.sort((a, b) => {
    if (a[0] !== b[0]) return a[0] < b[0] ? -1 : 1;
    if (a[1] !== b[1]) return a[1] < b[1] ? -1 : 1;
    if (a[2] !== b[2]) return a[2] < b[2] ? -1 : 1;
    return 0;
  });
  return hashCanonicalJson(projected);
}

// Membership predicate. Default is strict exact-tuple membership (chain_family
// AND chain_id AND address all match a bound contract). The OD3 same-chain
// relaxation — chain_family + chain_id match, address may differ — is reachable
// ONLY when the caller explicitly passes { provenanced: true }. This implements
// the relaxed-membership switch only; provenance DETECTION is not wired here and
// lands with a later node.
function isChainTupleInAuthority(tuple, boundContracts, options = {}) {
  const { provenanced = false } = options;
  const t = normalizeOneTuple(tuple);
  if (!t) return false;

  const authority = extractChainTuples(boundContracts);

  const exact = authority.some(
    (a) =>
      a.chain_family === t.chain_family
      && a.chain_id === t.chain_id
      && a.address === t.address,
  );
  if (exact) return true;

  if (provenanced) {
    return authority.some(
      (a) => a.chain_family === t.chain_family && a.chain_id === t.chain_id,
    );
  }

  return false;
}

module.exports = {
  extractChainTuples,
  chainAuthorityHash,
  isChainTupleInAuthority,
  // Exported so a later pre-handler gate can reuse the exact normalization the
  // hashing and membership paths share, instead of re-deriving it.
  normalizeOneTuple,
};
