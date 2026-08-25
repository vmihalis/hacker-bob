"use strict";

const { initSession } = require("../core/session/session-state.js");
const { ERROR_CODES, ToolError } = require("../core/io/envelope.js");
const {
  prepareContractCompanion,
  seedVerifiedContractCompanion,
} = require("../domains/blockchain/contract-target.js");

// O-P6 MIXED program: the url axis is PRIMARY; an OPTIONAL contracts companion
// binds the chain authority (chain_authority_hash) + seeds one smart_contract
// surface per contract ALONGSIDE the web session, unioned into the same
// frontier. Scope stays independent — these contracts never widen the HTTP/PSL
// scope, and the web axis never authorizes a chain tuple outside this set (the
// pre-handler chain scope gate reads the persisted target_contracts). The
// Companion effects seed only after the canonical state+nucleus+event UOW has
// bound the chain authority. Exact-binding retries reuse existing seed events
// and append only those missing from an interrupted first call.

// Cycle O.1: web-mode init_session refuses target_repo with a structured
// pointer to bob_init_repo_session. Cross-mode sessions are opt-in via a
// separate companion-binding tool (out of scope for O.1).
function handler(args) {
  if (args && args.target_repo != null) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      "bob_init_session is the web-mode entrypoint; call bob_init_repo_session to bind a repo target",
      { redirect_to_tool: "bob_init_repo_session" },
    );
  }
  // Validate the contracts companion shape BEFORE creating the web session so a
  // malformed companion fails closed with no partial session.
  const companion = (args && args.contracts != null)
    ? prepareContractCompanion(args.contracts)
    : null;
  const initResultJson = initSession(args, { contractCompanion: companion });
  if (!companion) return initResultJson;
  const initResult = JSON.parse(initResultJson);
  const domain = initResult.state.target;
  const seedResult = seedVerifiedContractCompanion(domain, companion);
  return JSON.stringify({
    ...initResult,
    target_contracts: seedResult.target_contracts,
    chain_authority_hash: seedResult.chain_authority_hash,
    seeded_surfaces: seedResult.seeded.map((seed) => seed.surface_id),
  });
}

module.exports = Object.freeze({
  name: "bob_init_session",
  description:
    "Initialize a new session state.json for a target domain.",
  inputSchema: {
    "type": "object",
    "properties": {
      "target_domain": {
        "type": "string"
      },
      "target_url": {
        "type": "string"
      },
      "deep_mode": {
        "type": "boolean"
      },
      "checkpoint_mode": {
        "type": "string",
        "enum": ["normal", "paranoid", "yolo"],
        "description": "Selected checkpoint mode. normal/yolo keep internal-host blocking opt-in; paranoid defaults block_internal_hosts to true on direct/default egress."
      },
      "block_internal_hosts": {
        "type": "boolean",
        "description": "Force strict direct-egress DNS/private/internal-host blocking for this session."
      },
      "allow_internal_hosts": {
        "type": "boolean",
        "description": "Disable paranoid's default internal-host blocking for explicitly authorized internal/lab programs. Cannot be combined with block_internal_hosts."
      },
      "egress_profile": {
        "type": "string",
        "pattern": "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$",
        "description": "Egress profile to bind to this session. Defaults to default."
      },
      "contracts": {
        "type": "array",
        "minItems": 1,
        "description": "OPTIONAL companion smart contracts for an O-P6 MIXED program. The url axis stays PRIMARY; each {chain_family, chain_id, address} binds an in-scope on-chain identity ALONGSIDE it — the chain authority (chain_authority_hash) is bound and one smart_contract surface is seeded per contract, unioned into the same frontier. Scope stays independent: these contracts never widen the HTTP/PSL scope, and the web axis never authorizes a chain tuple outside this set.",
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
      },
      "lab_authorization": {
        "type": "object",
        "description": "OFF BY DEFAULT. Declares intent to scope this session to a private host (IPv4 loopback 127.0.0.0/8 or RFC1918: 10/8, 172.16/12, 192.168/16) that the OPERATOR owns and is authorized to test. This declaration ALONE does NOT grant the escape: the operator must ALSO set, on the MCP server (operator-only controls the agent cannot supply), BOTH the BOB_LAB_TARGET_ACK environment variable (consent) AND BOB_LAB_TARGET to the exact host (e.g. 192.168.1.53; comma-separated for several). Without all of these, the public-DNS gate rejects non-public targets, and the grant is bound to the named host(s) only. Cloud-metadata, link-local, IPv6, and .internal/.local hosts are never eligible. Recorded as an audit-graded artifact and implies allow_internal_hosts for this session; cannot be combined with block_internal_hosts.",
        "properties": {
          "private_targets": {
            "type": "boolean",
            "description": "Must be true to declare a private-target session. Authorization is granted out-of-band by the operator via the BOB_LAB_TARGET_ACK server environment variable, not by any value in this call."
          }
        },
        "required": ["private_targets"],
        "additionalProperties": false
      }
    },
    "required": [
      "target_domain",
      "target_url"
    ],
    "additionalProperties": false
  },
  handler,
  role_bundles: ["orchestrator"],
  mutating: true,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: ["state.json", "lab-authorization.json"],
});
