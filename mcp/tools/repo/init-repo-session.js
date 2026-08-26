"use strict";

const { initRepoSession } = require("../../domains/repo/repo-target.js");
const {
  prepareContractCompanion,
  seedVerifiedContractCompanion,
} = require("../../domains/blockchain/contract-target.js");

// O-P6 MIXED program: the repo axis is PRIMARY; an OPTIONAL contracts companion
// binds the chain authority (chain_authority_hash) + seeds one smart_contract
// surface per contract ALONGSIDE the repo session, unioned into the same
// frontier. Scope stays independent — the pre-handler chain scope gate reads the
// persisted target_contracts, so the repo axis never authorizes a chain tuple
// outside this set. The companion is authority-bound in the original create UOW;
// postcommit seeding is verified and retryable for only that exact binding.

function handler(args) {
  // Validate the contracts companion shape BEFORE creating the repo session so a
  // malformed companion fails closed with no partial session.
  const companion = (args && args.contracts != null)
    ? prepareContractCompanion(args.contracts)
    : null;
  const result = initRepoSession({
    repo_path: args.repo_path,
    target_domain: args.target_domain,
    source_url: args.source_url,
    branch: args.branch,
    commit: args.commit,
    deep_mode: args.deep_mode,
    egress_profile: args.egress_profile,
    contract_companion: companion,
  });
  if (!companion) {
    return JSON.stringify({
      version: 1,
      ...result,
    });
  }
  const seedResult = seedVerifiedContractCompanion(result.target_domain, companion);
  return JSON.stringify({
    version: 1,
    ...result,
    target_contracts: seedResult.target_contracts,
    chain_authority_hash: seedResult.chain_authority_hash,
    seeded_surfaces: seedResult.seeded.map((s) => s.surface_id),
  });
}

module.exports = Object.freeze({
  name: "bob_init_repo_session",
  description:
    "Initialize a new session bound to a locally-checked-out repo (Plane O OSS axis). target_domain is derived from the absolute repo path; the session writes target_repo + repo_hash into state.json instead of target_url.",
  inputSchema: {
    "type": "object",
    "properties": {
      "repo_path": {
        "type": "string",
        "description": "Absolute path to a locally-checked-out repository. Plane O O-P1 forbids remote clones; the path must already exist as a directory."
      },
      "target_domain": {
        "type": "string",
        "description": "Optional custom safe-slug override for the derived repo target_domain (supports --target-id stability across path changes). When omitted, the slug is derived from the canonical repo path."
      },
      "source_url": {
        "type": "string",
        "description": "Optional upstream URL (e.g. https://github.com/org/repo). Stored for provenance; never used to clone."
      },
      "branch": {
        "type": "string",
        "description": "Optional branch name for provenance."
      },
      "commit": {
        "type": "string",
        "description": "Optional 7-64 character hex commit id. When present, pinned as repo_hash so the docker image tag stays stable across the session lifetime."
      },
      "deep_mode": {
        "type": "boolean"
      },
      "egress_profile": {
        "type": "string",
        "pattern": "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$",
        "description": "Egress profile to bind to this session. Defaults to default."
      },
      "contracts": {
        "type": "array",
        "minItems": 1,
        "description": "OPTIONAL companion smart contracts for an O-P6 MIXED program. The repo axis stays PRIMARY; each {chain_family, chain_id, address} binds an in-scope on-chain identity ALONGSIDE it — the chain authority (chain_authority_hash) is bound and one smart_contract surface is seeded per contract, unioned into the same frontier. Scope stays independent: the repo axis never authorizes a chain tuple outside this set. Bound at session creation only.",
        "items": {
          "type": "object",
          "properties": {
            "chain_family": {
              "type": "string",
              "enum": ["evm", "svm", "aptos", "sui", "substrate", "cosmwasm"],
              "description": "Chain family. Validated against the chain-family vocabulary (Y-D21 fail-closed)."
            },
            "chain_id": {
              "type": ["string", "integer"],
              "description": "Chain reference (e.g. EVM numeric chain id, or a named network/cluster for non-EVM families)."
            },
            "address": {
              "type": "string",
              "description": "Contract address."
            }
          },
          "required": ["chain_family", "chain_id", "address"]
        }
      }
    },
    "required": [
      "repo_path"
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
  session_artifacts_written: ["state.json", "session-nucleus.json"],
});
