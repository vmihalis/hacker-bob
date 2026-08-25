"use strict";

// the smart-contract target axis. Sibling of repo-target.js's OSS
// axis and the URL axis: given a session state and a list of in-scope contracts
// ({chain_family, chain_id, address}), it seeds ONE surface.observed per bound
// contract so the materializer folds a smart_contract surface keyed on the
// on-chain identity. Mixed initializers bind target_contracts and
// chain_authority_hash through their canonical create UOW before calling this
// module's verified, retryable companion seeder.
//
// Reuse, not re-implementation: every surface.observed flows through the single
// Y-D21 append funnel (frontier-events.js appendFrontierEvent /
// assertSmartContractChainFamily). A dropped or unknown chain_family fails CLOSED
// there — this module performs NO chain-family membership check of its own and
// never defaults or web-fallbacks chain_family, so the funnel stays the sole
// authority for the gate.

const {
  appendFrontierEvent,
  readFrontierEvents,
} = require("../../core/frontier/frontier-events.js");
const { scheduleMaterialization } = require("../../core/frontier/frontier-materialize-debounce.js");
const { validateNoSensitiveMaterial } = require("../../core/redaction/index.js");
const { ToolError, ERROR_CODES } = require("../../core/io/envelope.js");
const { withSessionLock } = require("../../core/io/storage.js");
const {
  readVerifiedSessionNucleus,
  sessionNucleusFromState,
} = require("../../core/governance/index.js");
const { readSessionStateStrict } = require("../../core/session/session-state-store.js");
const { hashCanonicalJson } = require("../../core/verification/verification-contracts.js");
const {
  chainAuthorityHash,
  extractChainTuples,
  normalizeContractTupleStrict,
  normalizeContractAddress,
  contractIdentityKey,
  deriveContractSession,
  deriveContractTargetDomain,
  normalizeContracts,
} = require("../../core/chain-authority-contracts.js");

// Normalize ONE raw {chain_family, chain_id, address} binding into the internal
// camelCase shape the seeding + CAIP-10 helpers consume. Delegates to the single
// shared bind-time normalizer (chain-authority.normalizeContractTupleStrict) so
// this companion path enforces the SAME normal form as the contracts-axis init
// path: chain_family folded to lowercase + CHAIN_FAMILY_VALUES-checked (Y-D21),
// chain_id colon-guarded, address trimmed. This shared normal form is why a
// companion contract set hashes to the same chain_authority_hash as the
// contracts-axis init path (no case-sensitive drift, no colon re-parse desync).
function normalizeContractBinding(raw, index) {
  const { chain_family: chainFamily, chain_id: chainId, address } =
    normalizeContractTupleStrict(raw, index);
  return { chainFamily, chainId, address };
}

// Deterministic on-chain surface identity. Colon-free, '-'-separated so it stays
// index/path-safe (cf. safeSurfaceId, repo-target.js:1265); address normalized via
// the shared normalizeContractAddress (hex families case-fold; base58/SS58 preserve)
// so one contract => one id and distinct contracts => distinct id on every chain.
function contractSurfaceId({ chainFamily, chainId, address }) {
  return `sc-${chainFamily}-${chainId}-${normalizeContractAddress(chainFamily, address)}`;
}

// Canonical CAIP-10 '<family>:<chainId>:<normalizeContractAddress(...)>'. Parse-
// compatible with lead-promotion.smartContractSurfaceKey, which routes through the
// SAME shared family+address normalizers, so a seeded surface and any promoted lead
// for one contract share one on-chain identity key (hex fold; base58/SS58 preserve).
function caip10Endpoint({ chainFamily, chainId, address }) {
  return contractIdentityKey({ chain_family: chainFamily, chain_id: chainId, address });
}

// Seed one surface.observed per bound contract through the Y-D21 funnel. READ-ONLY
// on `state` (reads target / target_domain only) and WRITE-only on the frontier
// ledger; it never writes state.json / target_contracts (that is a later node's init
// path). Any Y-D21 ToolError from the funnel PROPAGATES (fail-closed) — no partial
// surface is seeded for a contract with a dropped/unknown chain_family.
function bindAndSeedContracts(state, contracts) {
  const targetDomain = state && (state.target || state.target_domain);
  if (typeof targetDomain !== "string" || !targetDomain.trim()) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      "bindAndSeedContracts requires a session state carrying target / target_domain",
    );
  }
  if (!Array.isArray(contracts) || contracts.length === 0) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      "bindAndSeedContracts requires a non-empty contracts array",
    );
  }
  const domain = targetDomain.trim();
  const seeded = [];
  for (let i = 0; i < contracts.length; i += 1) {
    const { chainFamily, chainId, address } = normalizeContractBinding(contracts[i], i);
    const surfaceId = contractSurfaceId({ chainFamily, chainId, address });
    const endpoint = caip10Endpoint({ chainFamily, chainId, address });
    const payload = {
      surface_type: "smart_contract",
      chain_family: chainFamily,
      chain_id: String(chainId),
      contract_address: address,
      endpoints: [endpoint],
    };
    // Pre-flight mirrors emitSurfaceObserved (repo-target.js:1286): appendFrontierEvent
    // re-runs validateNoSensitiveMaterial internally, but the redundant pre-flight
    // gives a stable error path if a producer regression slips through.
    validateNoSensitiveMaterial(payload, "contract_target.surface_observed");
    // The single Y-D21 funnel. assertSmartContractChainFamily fires here for a
    // dropped/unknown chain_family and throws ToolError(INVALID_ARGUMENTS); we do
    // NOT swallow it (unlike lead-promotion.js:243-250's best-effort IO swallow),
    // so a malformed binding writes no partial surface.
    const event = appendFrontierEvent({
      target_domain: domain,
      kind: "surface.observed",
      surface_id: surfaceId,
      payload,
      source: { artifact: "state.json", tool: "bob_init_contract_session" },
    });
    seeded.push({
      surface_id: surfaceId,
      chain_family: chainFamily,
      chain_id: String(chainId),
      address,
      endpoint,
      event_id: event.event_id,
    });
  }
  scheduleMaterialization(domain);
  return { seeded, count: seeded.length };
}

function contractSeed(state, rawContract, index) {
  const targetDomain = state && (state.target || state.target_domain);
  const { chainFamily, chainId, address } = normalizeContractBinding(rawContract, index);
  const surfaceId = contractSurfaceId({ chainFamily, chainId, address });
  return {
    input: {
      target_domain: targetDomain,
      kind: "surface.observed",
      surface_id: surfaceId,
      payload: {
        surface_type: "smart_contract",
        chain_family: chainFamily,
        chain_id: String(chainId),
        contract_address: address,
        endpoints: [caip10Endpoint({ chainFamily, chainId, address })],
      },
      source: { artifact: "session-nucleus.json", tool: "bob_init_contract_companion" },
    },
    result: {
      surface_id: surfaceId,
      chain_family: chainFamily,
      chain_id: String(chainId),
      address,
      endpoint: caip10Endpoint({ chainFamily, chainId, address }),
    },
  };
}

function canonicalContractKeys(contracts) {
  return extractChainTuples(contracts)
    .map((tuple) => contractIdentityKey(tuple))
    .sort();
}

function sameStrings(left, right) {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function exactSeedEvent(event, input) {
  return event.kind === input.kind
    && event.surface_id === input.surface_id
    && hashCanonicalJson(event.payload) === hashCanonicalJson(input.payload)
    && hashCanonicalJson(event.source) === hashCanonicalJson(input.source);
}

// Mixed-axis companion effects run only after the create UOW has durably bound
// the exact contract set in both state and SessionNucleus. The ledger append is
// resumable: an exact prior seed is reused, a missing seed is appended, and any
// conflicting same-surface row fails closed rather than being claimed as ours.
function seedVerifiedContractCompanion(targetDomain, companion) {
  if (!companion || !Array.isArray(companion.contracts) || companion.contracts.length === 0) {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "contract companion is required");
  }
  return withSessionLock(targetDomain, () => {
    const { state } = readSessionStateStrict(targetDomain);
    const verified = readVerifiedSessionNucleus(targetDomain);
    const projected = sessionNucleusFromState(state);
    const stateContracts = Array.isArray(state.target_contracts) ? state.target_contracts : [];
    const nucleusContracts = Array.isArray(verified.scope_policy.target_contracts)
      ? verified.scope_policy.target_contracts
      : [];
    const expectedKeys = canonicalContractKeys(companion.contracts);
    const stateKeys = canonicalContractKeys(stateContracts);
    const nucleusKeys = canonicalContractKeys(nucleusContracts);
    const expectedHash = chainAuthorityHash(companion.contracts);
    if (expectedKeys.length === 0
        || stateContracts.length !== stateKeys.length
        || nucleusContracts.length !== nucleusKeys.length
        || !sameStrings(expectedKeys, stateKeys)
        || !sameStrings(expectedKeys, nucleusKeys)
        || companion.chain_authority_hash !== expectedHash
        || state.chain_authority_hash !== expectedHash
        || verified.scope_policy.chain_authority_hash !== expectedHash
        || projected.nucleus_hash !== verified.nucleus_hash) {
      throw new ToolError(
        ERROR_CODES.STATE_CONFLICT,
        `contracts companion does not match the verified authority for ${targetDomain}`,
      );
    }

    const desired = [];
    const seenSurfaceIds = new Set();
    for (let index = 0; index < companion.contracts.length; index += 1) {
      const seed = contractSeed(state, companion.contracts[index], index);
      if (!seenSurfaceIds.has(seed.result.surface_id)) {
        desired.push(seed);
        seenSurfaceIds.add(seed.result.surface_id);
      }
    }

    const events = readFrontierEvents(targetDomain);
    const seeded = [];
    for (const seed of desired) {
      validateNoSensitiveMaterial(seed.input.payload, "contract_target.surface_observed");
      const existing = events.filter((event) => (
        event.kind === "surface.observed" && event.surface_id === seed.input.surface_id
      ));
      if (existing.length > 1 || (existing.length === 1 && !exactSeedEvent(existing[0], seed.input))) {
        throw new ToolError(
          ERROR_CODES.STATE_CONFLICT,
          `frontier seed conflicts with contract companion surface ${seed.result.surface_id}`,
        );
      }
      const event = existing[0] || appendFrontierEvent(seed.input);
      if (!existing[0]) events.push(event);
      seeded.push({ ...seed.result, event_id: event.event_id });
    }
    scheduleMaterialization(targetDomain);
    return {
      seeded,
      count: seeded.length,
      target_contracts: [...stateContracts],
      chain_authority_hash: state.chain_authority_hash,
    };
  });
}

// Companion-axis prep for an O-P6 MIXED program (a url|repo PRIMARY axis with an
// OPTIONAL contracts companion). Normalizes the raw {chain_family, chain_id,
// address} bindings ONCE through the single shared strict normalizer, then
// derives BOTH the CAIP-10 projection (the only shape target_contracts round-
// trips through normalizeStringArray) AND the order-independent
// chain_authority_hash from those SAME normalized tuple OBJECTS. The hash is
// never computed from CAIP-10 strings routed through the case-sensitive
// classifyTargetToken, so an uppercase family folds to the SAME hash the
// contracts-axis init path derives instead of dropping to the empty-set hash
// (which chain_scope_blocked every in-scope companion contract). The returned
// `contracts` is the canonical tuple array handed to either seeding path, so the
// seeded surfaces and persisted target_contracts share one on-chain identity.
// Fails CLOSED (ToolError) on an
// empty array or a malformed binding (unknown/uppercase-invalid family, colon
// chain_id, empty field), BEFORE any session state is written.
function prepareContractCompanion(rawContracts) {
  // Use the contracts-axis bind-time funnel itself. Besides strict tuple
  // normalization, this validates each family-specific address shape and
  // deduplicates by the canonical contract identity. Canonicalize the returned
  // address once more for retry-stable seed payloads: normalizeContracts uses
  // the normalized address as its dedup key but intentionally preserves the
  // first spelling in its returned tuple for the pure contracts initializer.
  const normalized = normalizeContracts(rawContracts).map((tuple) => ({
    ...tuple,
    address: normalizeContractAddress(tuple.chain_family, tuple.address),
  }));
  const targetContracts = normalized.map((tuple) => caip10Endpoint({
    chainFamily: tuple.chain_family,
    chainId: tuple.chain_id,
    address: tuple.address,
  }));
  return {
    contracts: normalized,
    target_contracts: targetContracts,
    chain_authority_hash: chainAuthorityHash(normalized),
  };
}

module.exports = Object.freeze({
  bindAndSeedContracts,
  contractSurfaceId,
  caip10Endpoint,
  deriveContractSession,
  deriveContractTargetDomain,
  normalizeContractBinding,
  normalizeContracts,
  prepareContractCompanion,
  seedVerifiedContractCompanion,
});
