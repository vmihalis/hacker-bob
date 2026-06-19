"use strict";

const { ethCall, isAddress } = require("../evm-client.js");

const HAS_ROLE_SELECTOR = "0x91d14854";    // hasRole(bytes32,address)
const WARDS_SELECTOR = "0xbf353dbb";       // wards(address)
const ROLES_SELECTOR = "0xfe9fbb80";       // isAuthorized(bytes32,address) — DSAuth-style

const ROLE_HASH_RE = /^0x[0-9a-fA-F]{64}$/;

function pad32(hex) {
  const stripped = hex.startsWith("0x") ? hex.slice(2) : hex;
  return "0x" + stripped.padStart(64, "0");
}

function encodeAddress(address) {
  return pad32(address.toLowerCase().slice(2));
}

function buildHasRoleData(roleHash, account) {
  if (!ROLE_HASH_RE.test(roleHash)) {
    throw new Error(`role_hash must be a 32-byte hex string, received: ${roleHash}`);
  }
  if (!isAddress(account)) {
    throw new Error(`account must be a 20-byte hex address, received: ${account}`);
  }
  return HAS_ROLE_SELECTOR + roleHash.slice(2).toLowerCase() + encodeAddress(account).slice(2);
}

function buildWardsData(account) {
  if (!isAddress(account)) {
    throw new Error(`account must be a 20-byte hex address, received: ${account}`);
  }
  return WARDS_SELECTOR + encodeAddress(account).slice(2);
}

function decodeBool(returnData) {
  if (typeof returnData !== "string" || !returnData.startsWith("0x")) return false;
  const hex = returnData.slice(2);
  if (hex.length === 0) return false;
  // hasRole returns bytes32: nonzero => true. Same for wards (uint256).
  return /[1-9a-fA-F]/.test(hex);
}

async function evaluateAccessControl({ chainId, contract, roleHashes, accounts, block, endpoints }) {
  const matrix = [];
  for (const role of roleHashes) {
    const row = { role_hash: role, accounts: [] };
    for (const account of accounts) {
      try {
        const { result, endpoint } = await ethCall({
          chainId,
          to: contract,
          data: buildHasRoleData(role, account),
          block,
          endpoints,
        });
        row.accounts.push({ account, has_role: decodeBool(result), endpoint_used: endpoint });
      } catch (error) {
        row.accounts.push({ account, error: error.message || String(error) });
      }
    }
    matrix.push(row);
  }
  return matrix;
}

async function evaluateWards({ chainId, contract, accounts, block, endpoints }) {
  const rows = [];
  for (const account of accounts) {
    try {
      const { result, endpoint } = await ethCall({
        chainId,
        to: contract,
        data: buildWardsData(account),
        block,
        endpoints,
      });
      rows.push({ account, ward: decodeBool(result), endpoint_used: endpoint });
    } catch (error) {
      rows.push({ account, error: error.message || String(error) });
    }
  }
  return rows;
}

async function handler(args) {
  const chainId = Number(args.chain_id);
  const contract = args.contract;
  const accounts = Array.isArray(args.accounts) ? args.accounts : [];
  const roleHashes = Array.isArray(args.role_hashes) ? args.role_hashes : [];
  const includeWards = args.include_wards === true;

  if (!isAddress(contract)) {
    throw new Error(`contract must be a 20-byte hex address, received: ${contract}`);
  }
  if (accounts.length === 0) {
    throw new Error("accounts must contain at least one address");
  }
  if (accounts.length > 25) {
    throw new Error("accounts must contain at most 25 addresses to bound RPC fan-out");
  }
  if (roleHashes.length > 25) {
    throw new Error("role_hashes must contain at most 25 entries");
  }

  const block = args.block || "latest";
  const endpoints = Array.isArray(args.endpoints) ? args.endpoints : null;
  const result = {
    chain_id: chainId,
    contract,
    block,
    role_hashes: roleHashes,
    accounts,
    access_control: roleHashes.length > 0 ? await evaluateAccessControl({ chainId, contract, roleHashes, accounts, block, endpoints }) : [],
    wards: includeWards ? await evaluateWards({ chainId, contract, accounts, block, endpoints }) : null,
  };
  return JSON.stringify(result);
}

module.exports = Object.freeze({
  name: "bob_evm_role_table",
  aliases: ["bounty_evm_role_table"],
  description: "Bulk role-membership check for an EVM contract through the DNS-pinned direct public HTTPS RPC policy. Calls hasRole(bytes32,address) for each (role_hash, account) pair and optionally wards(address) for Maker/Sky-style auth. DNS-private/private endpoints and egress_profile proxy routing are unsupported by default. Bounded fan-out (≤25 accounts × ≤25 role_hashes) to keep RPC budget predictable. Used to map the trust boundary before declaring a role-gated function out of scope.",
  inputSchema: {
    "type": "object",
    "properties": {
      "chain_id": { "type": "integer", "minimum": 1 },
      "contract": { "type": "string", "pattern": "^0x[0-9a-fA-F]{40}$" },
      "accounts": { "type": "array", "items": { "type": "string", "pattern": "^0x[0-9a-fA-F]{40}$" }, "minItems": 1, "maxItems": 25 },
      "role_hashes": { "type": "array", "items": { "type": "string", "pattern": "^0x[0-9a-fA-F]{64}$" }, "maxItems": 25 },
      "include_wards": { "type": "boolean" },
      "block": {
        "oneOf": [
          { "type": "integer", "minimum": 0 },
          { "type": "string" }
        ]
      },
      "endpoints": { "type": "array", "items": { "type": "string", "format": "uri" }, "maxItems": 8 }
    },
    "required": ["chain_id", "contract", "accounts"]
  },
  handler,
  role_bundles: ["evaluator-evm", "verifier", "evidence"],
  mutating: false,
  global_preapproval: true,
  network_access: true,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: [],
});
