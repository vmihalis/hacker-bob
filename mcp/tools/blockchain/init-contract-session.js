"use strict";

// the smart-contract session init path. Sibling of init-session.js
// (URL axis) and init-repo-session.js (OSS repo axis): given a list of in-scope
// contracts ({chain_family, chain_id, address}), it derives a deterministic
// on-chain target_domain slug and persists the contracts axis
// (target_contracts[] + chain_authority_hash) into state.json instead of
// target_url. The contracts-only SessionNucleus, state projection, and canonical
// initialization event are published together before any derived side effect.
//
// Reuse, not re-implementation: chain-family membership + per-contract surface
// seeding flow through the single Y-D21 funnel (bindAndSeedContracts ->
// appendFrontierEvent/assertSmartContractChainFamily), the authority hash through
// chainAuthorityHash, the state document through buildInitialSessionState, and
// the per-family address shape through the canonical client/finding-contract
// validators. A dropped or unknown chain_family fails CLOSED here (explicit
// CHAIN_FAMILY_VALUES membership check) AND again at the append funnel.

const fs = require("fs");
const { ERROR_CODES, ToolError } = require("../../core/io/envelope.js");
const {
  assertBoolean,
  assertEnumValue,
  assertInteger,
  assertNonEmptyString,
} = require("../../core/io/validation.js");
const { sessionDir, statePath } = require("../../core/io/paths.js");
const { isSessionDirEffectivelyEmpty, withSessionLock } = require("../../core/io/storage.js");
const { resolveEgressProfile } = require("../../core/egress-profiles.js");
const { buildInitialSessionState, publicSessionState } = require("../../core/session/session-state-contracts.js");
const {
  readVerifiedSessionNucleus,
  sessionNucleusFromState,
} = require("../../core/governance/index.js");
const {
  commitSessionAuthority,
} = require("../../core/session/session-authority-unit-of-work.js");
const {
  hashCanonicalJson,
} = require("../../core/verification/verification-contracts.js");
const { appendFrontierEvent } = require("../../core/frontier/frontier-events.js");
const { scheduleMaterialization } = require("../../core/frontier/frontier-materialize-debounce.js");
const { ensureHandoffSigningKey, ensureHandoffKeypair } = require("../../core/ledger-integrity/index.js");
const {
  bindAndSeedContracts,
  caip10Endpoint,
} = require("../../domains/blockchain/contract-target.js");
const {
  deriveContractSession,
  deriveContractTargetDomain,
} = require("../../core/chain-authority-contracts.js");
const { writeQueuePolicy } = require("../../core/io/queue-policy.js");

const CHECKPOINT_MODE_VALUES = ["normal", "paranoid", "yolo"];
// OD4 default depth for the linked-contract closure walk recorded on the seed.
const DEFAULT_LINKED_CONTRACT_DEPTH = 3;

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
    const nucleus = sessionNucleusFromState(state);
    commitSessionAuthority({
      targetDomain: domain,
      nextNucleus: nucleus,
      stateProjection: {
        rawDocument: {},
        nextState: state,
      },
      event: {
        target_domain: domain,
        kind: "governance.session.initialized",
        nucleus_hash: nucleus.nucleus_hash,
        payload: {
          nucleus_hash: nucleus.nucleus_hash,
          scope_policy_hash: hashCanonicalJson(nucleus.scope_policy),
          egress_identity_hash: hashCanonicalJson(nucleus.egress_identity),
          auth_context_hash: hashCanonicalJson(nucleus.auth_context),
          operator_constraint_hash: hashCanonicalJson(nucleus.operator_constraint),
          chain_authority_hash: authorityHash,
        },
        source: { artifact: "state.json", tool: "bob_init_contract_session" },
      },
      expectedNucleusHash: null,
    });
    const verifiedNucleus = readVerifiedSessionNucleus(domain);
    if (verifiedNucleus.nucleus_hash !== nucleus.nucleus_hash) {
      throw new ToolError(
        ERROR_CODES.STATE_CONFLICT,
        "Committed contract session nucleus does not match its state projection",
      );
    }
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
    + "target_domain is derived from the on-chain identity; the session atomically publishes a contracts-only "
    + "SessionNucleus, its state.json projection, and one initialization event before it seeds one smart_contract "
    + "surface per bound contract through the Y-D21 chain-family funnel.",
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
  session_artifacts_written: [
    "state.json",
    "session-nucleus.json",
    "session-events.jsonl",
    ".handoff-signing-key.json",
    ".handoff-signing-key-ed25519.json",
    "handoff-signing-pubkey.json",
    "queue-policy.json",
    "frontier-events.jsonl",
    "surface-index.json",
    "task-queue.json",
    "task-graph.json",
  ],
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

// The identity minter itself, exposed the SAME non-enumerable way so the
// blockchain plane (mcp/domains/blockchain/plane.js) can bind identityMinter BY
// REFERENCE to the ONE definition site here, while the registry descriptor
// shape and every Object.keys/JSON path stay unchanged.
Object.defineProperty(toolDescriptor, "deriveContractTargetDomain", {
  value: deriveContractTargetDomain,
  enumerable: false,
});

module.exports = Object.freeze(toolDescriptor);
