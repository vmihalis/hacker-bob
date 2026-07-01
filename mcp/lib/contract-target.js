"use strict";

// the smart-contract target axis. Sibling of repo-target.js's OSS
// axis and the URL axis: given a session state and a list of in-scope contracts
// ({chain_family, chain_id, address}), it seeds ONE surface.observed per bound
// contract so the materializer folds a smart_contract surface keyed on the
// on-chain identity. It is the seeding companion to the target_contracts session
// axis (session-state-contracts.js:401-407,674-689); the init path that persists
// target_contracts / chain_authority_hash into state.json is a later node's
// bob_init_contract_session and is intentionally NOT in this module.
//
// Reuse, not re-implementation: every surface.observed flows through the single
// Y-D21 append funnel (frontier-events.js appendFrontierEvent /
// assertSmartContractChainFamily). A dropped or unknown chain_family fails CLOSED
// there — this module performs NO chain-family membership check of its own and
// never defaults or web-fallbacks chain_family, so the funnel stays the sole
// authority for the gate.

const { appendFrontierEvent } = require("./frontier-events.js");
const { scheduleMaterialization } = require("./frontier-materialize-debounce.js");
const { validateNoSensitiveMaterial } = require("./sensitive-material.js");
const { ToolError, ERROR_CODES } = require("./envelope.js");
const { chainAuthorityHash } = require("./chain-authority.js");

// Pure, trim/stringify discipline mirrors lead-promotion.smartContractSurfaceKey
// (lead-promotion.js:164-186): trim chain_family, stringify+trim chain_id, trim
// address. chain_family is NOT lowercased/normalized here — membership
// enforcement is left to the Y-D21 funnel so this module never re-validates it.
function normalizeContractBinding(raw, index) {
  if (raw == null || typeof raw !== "object" || Array.isArray(raw)) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      `contract binding at index ${index} must be a plain object`,
      { index },
    );
  }
  const chainFamily = typeof raw.chain_family === "string" ? raw.chain_family.trim() : "";
  if (!chainFamily) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      `contract binding at index ${index} must carry a non-empty chain_family`,
      { index },
    );
  }
  const chainId = raw.chain_id == null ? "" : String(raw.chain_id).trim();
  if (!chainId) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      `contract binding at index ${index} must carry a non-empty chain_id`,
      { index },
    );
  }
  const address = typeof raw.address === "string" ? raw.address.trim() : "";
  if (!address) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      `contract binding at index ${index} must carry a non-empty address`,
      { index },
    );
  }
  return { chainFamily, chainId, address };
}

// Deterministic on-chain surface identity. Colon-free, '-'-separated so it stays
// index/path-safe (cf. safeSurfaceId, repo-target.js:1265); address lowercased so
// two casings of one EVM address fold to a single surface. Same contract => same
// id (idempotent fold); distinct contracts => distinct id.
function contractSurfaceId({ chainFamily, chainId, address }) {
  return `sc-${chainFamily}-${chainId}-${address.toLowerCase()}`;
}

// Canonical CAIP-10 '<family>:<chainId>:<addr.toLowerCase()>'. Parse-compatible
// with lead-promotion.smartContractSurfaceKey (lead-promotion.js:171-184) so a
// seeded surface and any promoted lead for the same contract share one on-chain
// identity key.
function caip10Endpoint({ chainFamily, chainId, address }) {
  return `${chainFamily}:${chainId}:${address.toLowerCase()}`;
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

// Companion-axis prep for an O-P6 MIXED program (a url|repo PRIMARY axis with an
// OPTIONAL contracts companion). Normalizes the raw {chain_family, chain_id,
// address} bindings through the same trim/stringify discipline as the seeding
// path, projects each to its CAIP-10 endpoint (the only shape target_contracts
// round-trips through normalizeStringArray), and derives the order-independent
// chain_authority_hash from those endpoints. The returned `contracts` is the
// caller's raw array, handed straight to bindAndSeedContracts so the Y-D21
// funnel stays the SOLE chain-family authority (this helper performs no
// chain-family membership check of its own). Fails CLOSED (ToolError) on an
// empty array or a malformed binding, BEFORE any session state is written.
function prepareContractCompanion(rawContracts) {
  if (!Array.isArray(rawContracts) || rawContracts.length === 0) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      "contracts companion must be a non-empty array of {chain_family, chain_id, address} bindings",
    );
  }
  const targetContracts = rawContracts.map((raw, index) => caip10Endpoint(normalizeContractBinding(raw, index)));
  return {
    contracts: rawContracts,
    target_contracts: targetContracts,
    chain_authority_hash: chainAuthorityHash(targetContracts),
  };
}

module.exports = Object.freeze({
  bindAndSeedContracts,
  contractSurfaceId,
  caip10Endpoint,
  normalizeContractBinding,
  prepareContractCompanion,
});
