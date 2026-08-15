"use strict";

const { resolveEvmRpcEndpoints } = require("./evm-rpc-pool.js");
const { filterResolvedPublicRpcEndpoints } = require("./sc-egress-policy.js");
const { makeJsonRpcClient } = require("./json-rpc-transport.js");

const DEFAULT_MAX_RESULT_BYTES = 64 * 1024;     // 64 KiB returned to caller

const HEX_BYTES_RE = /^0x([0-9a-fA-F]*)$/;
const ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;
const STORAGE_SLOT_RE = /^0x[0-9a-fA-F]{1,64}$/;

function isAddress(value) {
  return typeof value === "string" && ADDRESS_RE.test(value);
}

function isHexBytes(value) {
  return typeof value === "string" && HEX_BYTES_RE.test(value);
}

function isStorageSlot(value) {
  return typeof value === "string" && STORAGE_SLOT_RE.test(value);
}

function normalizeBlockTag(value) {
  if (value == null || value === "" || value === "latest" || value === "earliest" || value === "pending" || value === "safe" || value === "finalized") {
    return value || "latest";
  }
  if (typeof value === "number" && Number.isInteger(value) && value >= 0) {
    return `0x${value.toString(16)}`;
  }
  if (typeof value === "string" && /^0x[0-9a-fA-F]+$/.test(value)) {
    return value.toLowerCase();
  }
  if (typeof value === "string" && /^[0-9]+$/.test(value)) {
    return `0x${BigInt(value).toString(16)}`;
  }
  throw new Error(`block must be 'latest|earliest|pending|safe|finalized', a non-negative integer, or a hex string; received: ${value}`);
}

const { rpcRequest, rpcRequestOnce } = makeJsonRpcClient({
  resolveEndpoints: resolveEvmRpcEndpoints,
  selectorKey: "chainId",
  selectorLabel: "chain",
  availabilitySelectorLabel: "chain_id",
  envHint: (chainId) => `BOB_EVM_RPCS_${chainId}`,
});

async function ethCall({ chainId, to, data, block = "latest", from = null, endpoints }) {
  if (!isAddress(to)) throw new Error(`to must be a 20-byte hex address, received: ${to}`);
  if (!isHexBytes(data)) throw new Error(`data must be a hex string, received: ${data}`);
  if (from != null && !isAddress(from)) throw new Error(`from must be a 20-byte hex address, received: ${from}`);
  const txObject = { to, data };
  if (from) txObject.from = from;
  return rpcRequest({
    chainId,
    method: "eth_call",
    params: [txObject, normalizeBlockTag(block)],
    endpoints,
    maxResponseBytes: DEFAULT_MAX_RESULT_BYTES * 4,
  });
}

async function ethGetStorageAt({ chainId, address, slot, block = "latest", endpoints }) {
  if (!isAddress(address)) throw new Error(`address must be a 20-byte hex address, received: ${address}`);
  if (!isStorageSlot(slot)) throw new Error(`slot must be a hex string with up to 32 bytes, received: ${slot}`);
  return rpcRequest({
    chainId,
    method: "eth_getStorageAt",
    params: [address, slot, normalizeBlockTag(block)],
    endpoints,
    maxResponseBytes: 4096,
  });
}

async function ethGetCode({ chainId, address, block = "latest", endpoints }) {
  if (!isAddress(address)) throw new Error(`address must be a 20-byte hex address, received: ${address}`);
  return rpcRequest({
    chainId,
    method: "eth_getCode",
    params: [address, normalizeBlockTag(block)],
    endpoints,
    maxResponseBytes: 1024 * 1024, // up to 1 MiB for runtime bytecode
  });
}

// Security-grade runtime-bytecode lookup for the cross-stack target binding. Unlike
// rpcRequest's first-endpoint-wins, this probes MULTIPLE endpoints and only trusts a code
// value the real-code responders AGREE on, so a single non-archival endpoint that returns
// "0x" for a historical fork_block (or a stale/compromised endpoint) cannot produce a wrong
// hash that would FALSELY refuse a genuine target. An empty "0x" response is treated as a
// NON-answer (a real audited contract has code at fork_block; "0x" means that endpoint could
// not serve the historical state), so a mixed archival/non-archival ladder still resolves
// from the archival nodes. Transient failures are retried.
//
// Returns { status: "resolved", code, corroboration } when >=1 endpoint returned non-empty
// code and all such responders agree; { status: "unavailable", reason } when no endpoint
// returned code (all failed/timed-out/"0x") or the real-code responders DISAGREE. NEVER
// throws for an availability failure — the caller records the run as target-unverified
// (re-runnable) instead of a permanent forgery refusal. This NEVER returns a value an agent
// can steer: the agent controls neither the trusted endpoint ladder nor the real chain state.
// Default corroboration quorum for the security-critical on-chain bytecode cross-check: the
// number of INDEPENDENT trusted endpoints that must agree before a value is trusted. >= 2 so a
// LONE responder (quorum-of-one) — whether the only one that answered, or a single compromised
// trusted endpoint — can never decide the hash. Operator-overridable via env for a deployment
// with a single highly-trusted archival provider (an informed choice, never the silent default).
const DEFAULT_BYTECODE_MIN_CORROBORATION = 2;
function resolvedBytecodeMinCorroboration(explicit) {
  if (Number.isInteger(explicit) && explicit >= 1) return explicit;
  const fromEnv = Number(process.env.BOB_EVM_BYTECODE_MIN_CORROBORATION);
  if (Number.isInteger(fromEnv) && fromEnv >= 1) return fromEnv;
  return DEFAULT_BYTECODE_MIN_CORROBORATION;
}

// Pure quorum decision over a round of per-endpoint eth_getCode results (each a raw result
// string, or a non-string for an endpoint that failed). Normalizes to lowercased 0x-stripped
// hex, DROPS empty "0x" (a non-archival "no code at block" miss is not a trustworthy answer),
// and decides: resolved (>= minCorroboration real-code responders that ALL agree),
// endpoint_disagreement (real-code responders disagree — trust no single value),
// insufficient_corroboration (fewer than minCorroboration agreeing responders — a lone value is
// not a quorum), or no_code_responses (none returned code). insufficient_corroboration and
// no_code_responses are retryable; endpoint_disagreement is definitive. Extracted pure so the
// quorum logic is unit-testable without network. The agent steers none of these inputs (the
// caller resolves the TRUSTED ladder, not agent fork_urls; the chain state is real).
function decideAgreedBytecode(results, { minCorroboration = DEFAULT_BYTECODE_MIN_CORROBORATION } = {}) {
  const quorum = Math.max(1, minCorroboration);
  const codes = [];
  for (const r of Array.isArray(results) ? results : []) {
    if (typeof r !== "string") continue;
    const normalized = r.toLowerCase().replace(/^0x/, "");
    if (normalized.length > 0) codes.push(normalized);
  }
  if (codes.length === 0) return { status: "unavailable", reason: "no_code_responses" };
  if (new Set(codes).size > 1) return { status: "unavailable", reason: "endpoint_disagreement" };
  if (codes.length < quorum) {
    return { status: "unavailable", reason: "insufficient_corroboration", corroboration: codes.length, required: quorum };
  }
  return { status: "resolved", code: codes[0], corroboration: codes.length };
}

async function ethGetCodeAgreed({ chainId, address, block = "latest", endpoints, maxEndpoints = 3, attempts = 2, minCorroboration } = {}) {
  if (!isAddress(address)) throw new Error(`address must be a 20-byte hex address, received: ${address}`);
  const quorum = resolvedBytecodeMinCorroboration(minCorroboration);
  const rawEndpointList = Array.isArray(endpoints) && endpoints.length > 0
    ? endpoints
    : resolveEvmRpcEndpoints(chainId);
  let endpointList = [];
  try {
    ({ endpoints: endpointList } = await filterResolvedPublicRpcEndpoints(rawEndpointList));
  } catch {
    return { status: "unavailable", reason: "endpoint_resolution_failed" };
  }
  // Probe at least `quorum` endpoints so corroboration is achievable when the ladder is large
  // enough; a ladder smaller than the quorum can never resolve (fail-closed by design).
  const probe = endpointList.slice(0, Math.max(quorum, maxEndpoints));
  if (probe.length === 0) return { status: "unavailable", reason: "no_public_endpoints" };
  const blockTag = normalizeBlockTag(block);
  let lastDecided = { status: "unavailable", reason: "all_endpoints_failed" };
  for (let attempt = 0; attempt < Math.max(1, attempts); attempt += 1) {
    const results = [];
    for (const endpoint of probe) {
      try {
        results.push(await rpcRequestOnce(endpoint, "eth_getCode", [address, blockTag], {
          maxResponseBytes: 1024 * 1024,
        }));
      } catch {
        results.push(null); // a transient endpoint miss does not decide the lookup
      }
    }
    const decided = decideAgreedBytecode(results, { minCorroboration: quorum });
    // resolved or a definitive ladder DISAGREEMENT both return now; an all-failed/empty round
    // (no_code_responses) OR a sub-quorum round (insufficient_corroboration) retries, covering a
    // transient endpoint blip that may recover the missing corroborator.
    if (decided.status === "resolved" || decided.reason === "endpoint_disagreement") return decided;
    lastDecided = decided;
  }
  return lastDecided;
}

async function ethBlockNumber({ chainId, endpoints }) {
  const { result } = await rpcRequest({
    chainId,
    method: "eth_blockNumber",
    params: [],
    endpoints,
    maxResponseBytes: 1024,
  });
  return result;
}

module.exports = {
  ADDRESS_RE,
  HEX_BYTES_RE,
  STORAGE_SLOT_RE,
  DEFAULT_MAX_RESULT_BYTES,
  decideAgreedBytecode,
  ethBlockNumber,
  ethCall,
  ethGetCode,
  ethGetCodeAgreed,
  ethGetStorageAt,
  isAddress,
  isHexBytes,
  isStorageSlot,
  normalizeBlockTag,
  rpcRequest,
};
