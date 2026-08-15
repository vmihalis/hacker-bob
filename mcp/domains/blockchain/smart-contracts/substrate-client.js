"use strict";

// Substrate JSON-RPC client. Substrate nodes implement JSON-RPC over both
// WebSocket (preferred for subscriptions) and HTTP (sufficient for read-only
// queries). Bob's substrate read tools talk HTTP because subprocess lifetime
// doesn't share a WS session.
//
// Method dispatch: state_*, chain_*, system_*, contracts_call_*. The methods
// we care about for SC verification are:
//   - state_getStorage(key, blockHash?) → raw storage at key
//   - state_call(method, callData, blockHash?) → execute a runtime API call
//   - chain_getBlockHash(number?) → resolve block number to hash for pinning
//   - chain_getHeader(blockHash?) → latest header for height/parent lookups
//   - system_chain() → chain spec_name (sanity check that endpoint matches network)
//
// The pallet_contracts ContractInfoOf storage layout uses a Twox64Concat hasher
// over the AccountId, so we expose getContractInfo as a convenience that
// builds the storage key from the SS58 address. Evaluators and verifiers who
// need lower-level access can call rpcRequest directly with a raw key.

const { resolveSubstrateRpcEndpoints } = require("./substrate-rpc-pool.js");
const { makeJsonRpcClient } = require("./json-rpc-transport.js");

const DEFAULT_MAX_RESULT_BYTES = 64 * 1024;

const SS58_BASE58_RE = /^[1-9A-HJ-NP-Za-km-z]+$/;

function isSs58Address(value) {
  if (typeof value !== "string") return false;
  if (value.length < 45 || value.length > 52) return false;
  return SS58_BASE58_RE.test(value);
}

const { rpcRequest } = makeJsonRpcClient({
  resolveEndpoints: resolveSubstrateRpcEndpoints,
  selectorKey: "network",
  selectorLabel: "network",
  envHint: (network) => `BOB_SUBSTRATE_RPCS_${String(network).toUpperCase()}`,
});

async function getStorage({ network, storageKey, blockHash, endpoints }) {
  if (typeof storageKey !== "string" || !storageKey.startsWith("0x")) {
    throw new Error("storageKey must be a 0x-prefixed hex string");
  }
  const params = blockHash != null ? [storageKey, blockHash] : [storageKey];
  return rpcRequest({
    network,
    method: "state_getStorage",
    params,
    endpoints,
    maxResponseBytes: 1024 * 1024,
  });
}

async function getRuntimeVersion({ network, blockHash, endpoints }) {
  // state_getRuntimeVersion returns spec_name, spec_version, transaction_version,
  // and the auth/runtime API list. Verifiers use spec_version to confirm the
  // chain hasn't been upgraded since the evaluator recorded the bug.
  const params = blockHash != null ? [blockHash] : [];
  return rpcRequest({
    network,
    method: "state_getRuntimeVersion",
    params,
    endpoints,
    maxResponseBytes: 64 * 1024,
  });
}

async function getBlockHash({ network, blockNumber, endpoints }) {
  // chain_getBlockHash(number) returns the hash for that block. With no
  // argument it returns the head block hash.
  const params = blockNumber != null ? [blockNumber] : [];
  return rpcRequest({
    network,
    method: "chain_getBlockHash",
    params,
    endpoints,
    maxResponseBytes: 4096,
  });
}

async function getHeader({ network, blockHash, endpoints }) {
  // chain_getHeader returns the parent_hash, number, state_root, extrinsics_root,
  // and digest for the latest (or specified) block. Useful as a chain liveness
  // probe and for resolving fork height at verification time.
  const params = blockHash != null ? [blockHash] : [];
  return rpcRequest({
    network,
    method: "chain_getHeader",
    params,
    endpoints,
    maxResponseBytes: 16 * 1024,
  });
}

async function getSystemChain({ network, endpoints }) {
  // system_chain returns the chain's spec_name (e.g., "Polkadot", "Kusama").
  // Verifier prompts use this as a cross-check that a substrate RPC endpoint
  // actually serves the network the evaluator claimed in chain_id.
  return rpcRequest({
    network,
    method: "system_chain",
    params: [],
    endpoints,
    maxResponseBytes: 4096,
  });
}

module.exports = {
  DEFAULT_MAX_RESULT_BYTES,
  SS58_BASE58_RE,
  getBlockHash,
  getHeader,
  getRuntimeVersion,
  getStorage,
  getSystemChain,
  isSs58Address,
  rpcRequest,
};
