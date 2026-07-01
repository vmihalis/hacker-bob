"use strict";

// the smart-contract session init path. Sibling of init-session.js
// (URL axis) and init-repo-session.js (OSS repo axis): given a list of in-scope
// contracts ({chain_family, chain_id, address}), it derives a deterministic
// on-chain target_domain slug and persists the contracts axis
// (target_contracts[] + chain_authority_hash) into state.json instead of
// target_url. No nucleus/scope_policy is written — normalizeScopePolicy only
// recognises the url/repo axes, so the governance nucleus for contracts is a
// later node; a later node is bounded to the state.json + frontier seeding the
// contract-target.js header documents.
//
// Reuse, not re-implementation: chain-family membership + per-contract surface
// seeding flow through the single Y-D21 funnel (bindAndSeedContracts ->
// appendFrontierEvent/assertSmartContractChainFamily), the authority hash through
// chainAuthorityHash, the state document through buildInitialSessionState, and
// the per-family address shape through the canonical client/finding-contract
// validators. A dropped or unknown chain_family fails CLOSED here (explicit
// CHAIN_FAMILY_VALUES membership check) AND again at the append funnel.

const fs = require("fs");
const { ERROR_CODES, ToolError } = require("../envelope.js");
const { CHAIN_FAMILY_VALUES } = require("../constants.js");
const {
  assertBoolean,
  assertEnumValue,
  assertInteger,
  assertNonEmptyString,
} = require("../validation.js");
const { sessionDir, statePath } = require("../paths.js");
const { isSessionDirEffectivelyEmpty, withSessionLock } = require("../storage.js");
const { resolveEgressProfile } = require("../egress-profiles.js");
const { buildInitialSessionState, publicSessionState } = require("../session-state-contracts.js");
const { writeSessionStateDocument } = require("../session-state-store.js");
const { appendFrontierEvent } = require("../frontier-events.js");
const { scheduleMaterialization } = require("../frontier-materialize-debounce.js");
const { ensureHandoffSigningKey, ensureHandoffKeypair } = require("../handoff-signing-key.js");
const { bindAndSeedContracts, caip10Endpoint } = require("../contract-target.js");
const { chainAuthorityHash } = require("../chain-authority.js");
const { writeQueuePolicy } = require("../queue-policy.js");

// Per-family address shape validators — reuse the canonical sources rather than
// re-copying any regex. EVM 0x+40hex (evm-client), Solana base58 pubkey
// (svm-client.isPubkey), Move 0x+1..64hex for aptos/sui (sui-client), SS58 for
// substrate and bech32 for cosmwasm (finding-contracts normalizers, which
// return null on a shape/checksum miss).
const { ADDRESS_RE: EVM_ADDRESS_RE } = require("../evm-client.js");
const { isPubkey: isSvmPubkey } = require("../svm-client.js");
const { MOVE_ADDRESS_RE } = require("../sui-client.js");
const { normalizeSs58Address, normalizeBech32Address } = require("../finding-contracts.js");

const CHECKPOINT_MODE_VALUES = ["normal", "paranoid", "yolo"];
// OD4 default depth for the linked-contract closure walk recorded on the seed.
const DEFAULT_LINKED_CONTRACT_DEPTH = 3;

function isValidContractAddressShape(chainFamily, address) {
  switch (chainFamily) {
    case "evm":
      return EVM_ADDRESS_RE.test(address);
    case "svm":
      return isSvmPubkey(address);
    case "aptos":
    case "sui":
      return MOVE_ADDRESS_RE.test(address);
    case "substrate":
      return normalizeSs58Address(address) != null;
    case "cosmwasm":
      return normalizeBech32Address(address) != null;
    default:
      return false;
  }
}

// Lowercase, collapse anything outside the safe-domain alphabet to '-', and trim
// stray separators so the derived slug passes assertSafeDomain (no '/' '\' '..').
function safeSlug(value) {
  return String(value)
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    || "contracts";
}

function addressSlug(address) {
  const lowered = String(address).toLowerCase();
  const body = lowered.startsWith("0x") ? lowered.slice(2) : lowered;
  const safe = body.replace(/[^a-z0-9]/g, "");
  return (safe || "addr").slice(0, 8);
}

// One contract => the on-chain identity slug; several => a stable digest of the
// whole authority set (order-independent via chainAuthorityHash).
function deriveContractTargetDomain(normalizedContracts, authorityHash) {
  if (normalizedContracts.length === 1) {
    const { chain_family: chainFamily, chain_id: chainId, address } = normalizedContracts[0];
    return safeSlug(`sc-${chainFamily}-${chainId}-${addressSlug(address)}`);
  }
  return safeSlug(`contracts-${String(authorityHash).slice(0, 8)}`);
}

// Single shared derivation funnel: the ONE place the contracts axis turns raw
// contract bindings into (normalizedContracts, authorityHash, domain). The
// handler consumes it to persist state.json, and the pre-dispatch bootstrap gate
// (session-authority.js authorizeBootstrap) lazy-requires it so the gate's
// authorityTargetDomain is byte-equal to the persisted slug — the slug rule is
// defined once, never duplicated in the authority kernel. Throws fail-closed
// (ToolError) on any malformed contract via normalizeContracts.
function deriveContractSession(rawContracts) {
  const normalizedContracts = normalizeContracts(rawContracts);
  const authorityHash = chainAuthorityHash(normalizedContracts);
  const domain = deriveContractTargetDomain(normalizedContracts, authorityHash);
  return { normalizedContracts, authorityHash, domain };
}

function normalizeContracts(rawContracts) {
  if (!Array.isArray(rawContracts) || rawContracts.length === 0) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      "contracts must be a non-empty array of {chain_family, chain_id, address} bindings",
    );
  }
  const seen = new Set();
  const normalized = [];
  for (let i = 0; i < rawContracts.length; i += 1) {
    const raw = rawContracts[i];
    if (raw == null || typeof raw !== "object" || Array.isArray(raw)) {
      throw new ToolError(
        ERROR_CODES.INVALID_ARGUMENTS,
        `contract binding at index ${i} must be a plain object`,
        { index: i },
      );
    }
    // Y-D21 fail-closed: a dropped/unknown chain_family is rejected here (and
    // again at the append funnel). Trim+lowercase mirrors the funnel's
    // normalizeChainToken so casing is accepted consistently with the gate.
    const chainFamily = typeof raw.chain_family === "string" ? raw.chain_family.trim().toLowerCase() : "";
    if (!CHAIN_FAMILY_VALUES.includes(chainFamily)) {
      throw new ToolError(
        ERROR_CODES.INVALID_ARGUMENTS,
        `contract binding at index ${i} must carry a chain_family in ${CHAIN_FAMILY_VALUES.join(", ")} `
          + `(Y-D21 fail-closed); got ${JSON.stringify(raw.chain_family)}`,
        { index: i },
      );
    }
    const chainId = raw.chain_id == null ? "" : String(raw.chain_id).trim();
    if (!chainId) {
      throw new ToolError(
        ERROR_CODES.INVALID_ARGUMENTS,
        `contract binding at index ${i} must carry a non-empty chain_id`,
        { index: i },
      );
    }
    const address = typeof raw.address === "string" ? raw.address.trim() : "";
    if (!address) {
      throw new ToolError(
        ERROR_CODES.INVALID_ARGUMENTS,
        `contract binding at index ${i} must carry a non-empty address`,
        { index: i },
      );
    }
    if (!isValidContractAddressShape(chainFamily, address)) {
      throw new ToolError(
        ERROR_CODES.INVALID_ARGUMENTS,
        `contract binding at index ${i} carries an address that is not a valid ${chainFamily} address shape`,
        { index: i, chain_family: chainFamily },
      );
    }
    const endpoint = caip10Endpoint({ chainFamily, chainId, address });
    if (seen.has(endpoint)) continue;
    seen.add(endpoint);
    normalized.push({ chain_family: chainFamily, chain_id: chainId, address });
  }
  return normalized;
}

function handler(args = {}) {
  // Single funnel shared with the bootstrap gate: order/result unchanged from the
  // prior inline normalizeContracts -> chainAuthorityHash -> deriveContractTargetDomain.
  const { normalizedContracts, authorityHash, domain } = deriveContractSession(args.contracts);

  const linkedContractDepth = args.linked_contract_depth == null
    ? DEFAULT_LINKED_CONTRACT_DEPTH
    : assertInteger(args.linked_contract_depth, "linked_contract_depth", { min: 0, max: 32 });
  const deepMode = args.deep_mode == null ? false : assertBoolean(args.deep_mode, "deep_mode");
  const checkpointMode = args.checkpoint_mode == null
    ? "normal"
    : assertEnumValue(args.checkpoint_mode, CHECKPOINT_MODE_VALUES, "checkpoint_mode");
  const profileName = args.egress_profile == null
    ? "default"
    : assertNonEmptyString(args.egress_profile, "egress_profile");

  // CAIP-10 string projection ('<family>:<chainId>:<addr>') — the only shape that
  // round-trips through normalizeSessionStateDocument's normalizeStringArray on
  // target_contracts and re-parses to an axis:contract tuple.
  const targetContracts = normalizedContracts.map((c) => caip10Endpoint({
    chainFamily: c.chain_family,
    chainId: c.chain_id,
    address: c.address,
  }));

  return withSessionLock(domain, () => {
    const dir = sessionDir(domain);
    const filePath = statePath(domain);

    if (fs.existsSync(filePath)) {
      throw new ToolError(ERROR_CODES.STATE_CONFLICT, `Session already initialized: ${filePath}`);
    }
    if (!isSessionDirEffectivelyEmpty(dir)) {
      throw new ToolError(ERROR_CODES.STATE_CONFLICT, `Session directory is not empty: ${dir}`);
    }

    const egressProfile = resolveEgressProfile(profileName);
    // NO target_url — the contracts axis is the single primary axis
    // (normalizeSessionStateDocument enforces exactly-one-axis).
    const state = buildInitialSessionState(domain, null, {
      deepMode,
      egressProfile,
      checkpointMode,
      targetContracts,
      chainAuthorityHash: authorityHash,
    });
    writeSessionStateDocument(domain, {}, state);
    // Provision handoff keys at creation so every later path finds them
    // (idempotent; same posture as init-session.js / init-repo-session.js).
    ensureHandoffSigningKey(domain);
    ensureHandoffKeypair(domain);

    // The front-door linked_contract_depth is the ENFORCED OD4 governor, so it is
    // persisted into the QueuePolicy that materialize-producer-floor's depthCap
    // reads via loadQueuePolicy -> linked_contract_depth. Without this write
    // loadQueuePolicy falls back to DEFAULT_QUEUE_POLICY.linked_contract_depth and
    // the operator value only reaches the seed event / response (the recursion
    // walks the default depth regardless of intent). An omitted param resolves to
    // DEFAULT_LINKED_CONTRACT_DEPTH above, which equals the queue-policy default,
    // so the persisted cap matches the value recorded on the seed event below.
    writeQueuePolicy(domain, { linked_contract_depth: linkedContractDepth });

    // Frontier ledger: session.seeded opens the contract field before the
    // per-contract surface.observed events fold the smart_contract surfaces.
    try {
      appendFrontierEvent({
        target_domain: domain,
        kind: "session.seeded",
        payload: {
          seed_surface_map: {
            target_domain: domain,
            target_contracts: targetContracts,
            chain_authority_hash: authorityHash,
            in_scope: normalizedContracts.map((c) => ({
              chain_family: c.chain_family,
              chain_id: c.chain_id,
              address: c.address,
            })),
            out_of_scope: [],
            notes: {
              deep_mode: state.deep_mode,
              checkpoint_mode: state.checkpoint_mode,
              linked_contract_depth: linkedContractDepth,
            },
          },
          chain_authority_hash: authorityHash,
        },
        source: { artifact: "state.json", tool: "bob_init_contract_session" },
      });
      scheduleMaterialization(domain);
    } catch {
      // Frontier ledger session.seeded is best-effort; the per-contract
      // surface.observed funnel below is the authoritative seeding path.
    }

    // Seed one surface.observed per bound contract through the single Y-D21
    // funnel. A dropped/unknown chain_family throws here (fail-closed) before
    // any partial surface is recorded.
    const seedResult = bindAndSeedContracts({ target: domain }, normalizedContracts);

    return JSON.stringify({
      version: 1,
      created: true,
      session_dir: dir,
      target_domain: domain,
      target_contracts: targetContracts,
      chain_authority_hash: authorityHash,
      linked_contract_depth: linkedContractDepth,
      seeded_surfaces: seedResult.seeded.map((s) => s.surface_id),
      state: publicSessionState(state),
    });
  });
}

const toolDescriptor = {
  name: "bob_init_contract_session",
  description:
    "Initialize a new session bound to a set of in-scope smart contracts (the contracts axis). "
    + "target_domain is derived from the on-chain identity; the session writes target_contracts + "
    + "chain_authority_hash into state.json instead of target_url and seeds one smart_contract surface "
    + "per bound contract through the Y-D21 chain-family funnel.",
  inputSchema: {
    "type": "object",
    "properties": {
      "contracts": {
        "type": "array",
        "minItems": 1,
        "description": "In-scope smart contracts. Each entry binds one on-chain identity; a single entry derives an sc-<family>-<chainId>-<addr8> target_domain, several derive contracts-<hash8>.",
        "items": {
          "type": "object",
          "properties": {
            "chain_family": {
              "type": "string",
              "enum": ["evm", "svm", "aptos", "sui", "substrate", "cosmwasm"],
              "description": "Chain family. Validated against CHAIN_FAMILY_VALUES (Y-D21 fail-closed); a dropped/unknown family is rejected."
            },
            "chain_id": {
              "type": ["string", "integer"],
              "description": "Chain reference (e.g. EVM numeric chain id, or a named network/cluster for non-EVM families)."
            },
            "address": {
              "type": "string",
              "description": "Contract address. Validated against the per-family address shape (EVM 0x+40hex, Solana base58 pubkey, Move 0x hex, SS58, or bech32)."
            }
          },
          "required": ["chain_family", "chain_id", "address"]
        }
      },
      "linked_contract_depth": {
        "type": "integer",
        "minimum": 0,
        "maximum": 32,
        "description": "OD4 linked-contract closure depth recorded on the session.seeded event. Defaults to 3."
      },
      "deep_mode": {
        "type": "boolean"
      },
      "checkpoint_mode": {
        "type": "string",
        "enum": ["normal", "paranoid", "yolo"],
        "description": "Selected checkpoint mode. Defaults to normal."
      },
      "egress_profile": {
        "type": "string",
        "pattern": "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$",
        "description": "Egress profile to bind to this session. Defaults to default."
      }
    },
    "required": [
      "contracts"
    ]
  },
  handler,
  role_bundles: ["orchestrator"],
  mutating: true,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: ["state.json", "queue-policy.json"],
};

// Expose the shared derivation funnel to the pre-dispatch bootstrap gate WITHOUT
// polluting the tool-registry descriptor shape: a non-enumerable property is
// invisible to defineTool's `{...entry}` spread and every Object.keys/JSON path,
// so the registry entry and mcp-server.test.js key assertions are unaffected,
// while session-authority's require(...).deriveContractSession still resolves.
Object.defineProperty(toolDescriptor, "deriveContractSession", {
  value: deriveContractSession,
  enumerable: false,
});

module.exports = Object.freeze(toolDescriptor);
