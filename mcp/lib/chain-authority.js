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
const { hashCanonicalJson } = require("../core/verification/verification-contracts.js");
// classifyTargetToken (target-intake.js) is the single canonical string-token
// parser; it is already load-time-asserted against CHAIN_FAMILY_VALUES, so this
// module never redefines or hardcodes the chain-family vocabulary.
const { classifyTargetToken } = require("../core/target-intake.js");
// CHAIN_FAMILY_VALUES (shared-vocabulary.js) is the single known-chain-family authority,
// the same set the Y-D21 append funnel checks; ToolError/ERROR_CODES (envelope.js)
// are the canonical fail-closed error carriers. Both are pure, I/O-free modules,
// so the strict bind-time normalizer keeps this module's dependency-light posture.
const { CHAIN_FAMILY_VALUES } = require("../core/constants/shared-vocabulary.js");
const { ERROR_CODES, ToolError } = require("../core/io/envelope.js");

// Chain families whose address encoding is case-INSENSITIVE hex, so folding to
// lowercase is safe and lets 0xABC and 0xabc collide. base58 (svm), SS58
// (substrate), and bech32 (cosmwasm) are case-SENSITIVE / already-normalized —
// lowercasing them corrupts identity, colliding two distinct addresses onto one
// authority entry (membership fail-open) and desyncing the authority hash — so
// their addresses are trimmed but case-PRESERVED. Single-sourced here (imported
// by the producer floor) so address case-folding keys on families identically.
const CASE_FOLD_SAFE_CHAIN_FAMILIES = Object.freeze(new Set(["evm", "aptos", "sui"]));

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

// THE single canonical contract-address normalizer every identity / dedup / hash
// / CAIP-10 site must call, so address casing can never disagree across modules
// (the whack-a-mole that produced repeated base58/SS58 scope fail-opens). Trims,
// then case-folds ONLY for case-insensitive hex families (evm/aptos/sui); base58
// (svm), SS58 (substrate), and bech32 (cosmwasm) are case-PRESERVED. Accepts a
// raw or already-normalized chain_family (normalizeChainToken is idempotent).
function normalizeContractAddress(chainFamily, address) {
  const trimmed = String(address == null ? "" : address).trim();
  const family = normalizeChainToken(chainFamily);
  return family != null && CASE_FOLD_SAFE_CHAIN_FAMILIES.has(family)
    ? trimmed.toLowerCase()
    : trimmed;
}

// THE single canonical CAIP-10 contract-identity string builder. Every site that
// derives a '<family>:<chainId>:<address>' identity / dedup / surface key MUST call
// this (caip10Endpoint, lead-promotion.smartContractSurfaceKey, finalize-node's
// producer surface emission) so family + address casing can never disagree across
// modules — the class of base58/SS58 scope fail-opens that recurred once per site
// when each built the string by hand. Family folded via normalizeChainToken,
// address via normalizeContractAddress (hex fold; base58/SS58/bech32 preserved).
function contractIdentityKey({ chain_family, chain_id, address }) {
  const family = normalizeChainToken(chain_family);
  const id = String(chain_id == null ? "" : chain_id).trim();
  return `${family}:${id}:${normalizeContractAddress(family, address)}`;
}

// Strict, fail-closed canonical normalization of ONE raw {chain_family, chain_id,
// address} binding into a canonical tuple. This is the SINGLE bind-time normal
// form shared by every axis that persists an in-scope contract set: the
// contracts-axis init path (init-contract-session.normalizeContracts) and the
// url/repo companion path (contract-target.normalizeContractBinding). Both derive
// chain_authority_hash from the tuples this returns, so the SAME contract set
// hashes to the SAME chain_authority_hash on every path, and an uppercase-family
// or colon-in-chain_id binding is folded/rejected identically instead of silently
// dropping to the empty-set hash through the case-sensitive CAIP-10 string parser.
//
// Unlike normalizeOneTuple (lenient — returns null so the query-time membership
// path can rank garbage away), this THROWS: a bind-time malformation is an
// operator scope error, not a tuple to drop. chain_family is folded through the
// same normalizeChainToken rule and checked against CHAIN_FAMILY_VALUES (Y-D21);
// chain_id is trimmed, required non-empty, and colon-guarded because it round-
// trips through the CAIP-10 '<family>:<chainId>:<address>' projection; address is
// trimmed (case PRESERVED — SS58/base58 addresses are case-sensitive) and
// required. When `index` is an integer the errors carry it for per-entry context.
function normalizeContractTupleStrict(raw, index) {
  const where = Number.isInteger(index) ? ` at index ${index}` : "";
  const at = Number.isInteger(index) ? { index } : {};
  if (raw == null || typeof raw !== "object" || Array.isArray(raw)) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      `contract binding${where} must be a plain object`,
      at,
    );
  }
  const chainFamily = normalizeChainToken(raw.chain_family);
  if (!chainFamily || !CHAIN_FAMILY_VALUES.includes(chainFamily)) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      `contract binding${where} must carry a chain_family in ${CHAIN_FAMILY_VALUES.join(", ")} `
        + `(Y-D21 fail-closed); got ${JSON.stringify(raw.chain_family)}`,
      { ...at, chain_family: raw.chain_family == null ? null : raw.chain_family },
    );
  }
  const chainId = raw.chain_id == null ? "" : String(raw.chain_id).trim();
  if (!chainId) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      `contract binding${where} must carry a non-empty chain_id`,
      at,
    );
  }
  // chain_id round-trips through the CAIP-10 '<family>:<chainId>:<address>'
  // projection AND is interpolated into the sc-recon-expander scratch path
  // contracts/<chain_id>/<address>/, so reject the CAIP separator ':' and any
  // path-traversal / separator characters ('/', '\', '..'): an operator typo or a
  // hostile chain_id must fail closed at bind time, never escape the scratch dir.
  if (/[:/\\]/.test(chainId) || chainId.includes("..")) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      `contract binding${where} chain_id must not contain ':', '/', '\\', or '..' (CAIP-10 separator / path-traversal)`,
      at,
    );
  }
  const address = typeof raw.address === "string" ? raw.address.trim() : "";
  if (!address) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      `contract binding${where} must carry a non-empty address`,
      at,
    );
  }
  // address is likewise interpolated into the scratch path — same traversal guard.
  if (/[/\\]/.test(address) || address.includes("..")) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      `contract binding${where} address must not contain '/', '\\', or '..' (path-traversal)`,
      at,
    );
  }
  return { chain_family: chainFamily, chain_id: chainId, address };
}

// Normalize one contracts entry into a canonical {chain_family, chain_id,
// address} tuple, or null when the entry is not a valid contract tuple.
//
//   - String entries are parsed with classifyTargetToken and accepted ONLY when
//     axis === "contract" (web_url / refuse results are dropped defensively).
//   - Plain-object entries carrying chain_family/chain_id/address are used
//     directly.
//
// address is trimmed and, for case-insensitive hex families (evm/aptos/sui),
// lowercased so 0xABC and 0xabc collide; base58/SS58/bech32 addresses
// (svm/substrate/cosmwasm) are case-PRESERVED (folding them corrupts identity);
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
  // Bind-vs-query consistency: the bind path (normalizeContractTupleStrict) rejects
  // any chain_family outside CHAIN_FAMILY_VALUES. This query-time normalizer must
  // apply the SAME membership check (fail-closed) so a family that could never be
  // bound is never normalized-and-compared into a match — a tuple with an unknown
  // family drops to null (no membership, no hash entry), never a lenient pass.
  if (!CHAIN_FAMILY_VALUES.includes(normalizedFamily)) return null;

  const normalizedChainId = String(chainId).trim();
  // Single-sourced canonical address normalization (fold hex families, preserve
  // base58/SS58/bech32) so membership + hash never disagree with the other sites.
  const normalizedAddress = normalizeContractAddress(normalizedFamily, address);
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

// Membership predicate. ALWAYS strict exact-tuple membership (chain_family AND
// chain_id AND address all match a bound contract). The OD3 same-chain relaxation
// is INTENTIONALLY INERT: a bare same-(chain_family, chain_id) match would be a
// chain-wide fail-open (one bound contract authorizing every address on the chain),
// so it must require a PROVEN edge (impl slot / role table / constructor arg) from
// the bound set — and that provenance-edge detection is not yet wired. The
// { provenanced } option is reserved for that future edge-checked path; today it
// changes NOTHING (never a bare same-chain shortcut).
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

  // OD3 same-chain relaxation is INTENTIONALLY inert. A bare same-(chain_family,
  // chain_id) match is a chain-WIDE fail-open — one bound contract would authorize
  // EVERY address on that chain. A real relaxation must require a PROVEN edge
  // (EIP-1967 impl slot / role table / constructor arg) from the bound set to the
  // candidate address; that provenance-edge detection is not yet wired, and until it
  // is, membership stays STRICT exact-tuple regardless of the flag. `provenanced` is
  // reserved for the future edge-checked path — it is NEVER a bare same-chain
  // shortcut (which would be a primed fail-open in the authority kernel).
  void provenanced;
  return false;
}

module.exports = {
  extractChainTuples,
  chainAuthorityHash,
  isChainTupleInAuthority,
  // Exported so a later pre-handler gate can reuse the exact normalization the
  // hashing and membership paths share, instead of re-deriving it.
  normalizeOneTuple,
  // The single fail-closed bind-time normalizer both the contracts-axis init path
  // and the url/repo companion path call, so one contract set yields one hash.
  normalizeContractTupleStrict,
  // Single-sourced case-fold-safe (hex) family set; imported by the producer floor
  // so address case-folding keys on chain_family identically everywhere.
  CASE_FOLD_SAFE_CHAIN_FAMILIES,
  // The single canonical address / family normalizers every contract identity,
  // dedup key, and CAIP-10 endpoint routes through so casing never diverges.
  normalizeContractAddress,
  normalizeChainToken,
  // THE single CAIP-10 identity-string builder — every family:chainId:address
  // key is built here so no site can hand-roll a divergent casing again.
  contractIdentityKey,
};
