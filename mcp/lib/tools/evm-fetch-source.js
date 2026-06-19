"use strict";

const path = require("path");
const { fetchVerifiedSource } = require("../evm-source.js");

async function handler(args) {
  const result = await fetchVerifiedSource({
    domain: args.target_domain,
    chainId: args.chain_id,
    address: args.address,
    force: args.force === true,
  });
  // Trim file content out of the returned envelope; sources are cached on
  // disk and the response carries names + sizes only to keep token usage low.
  const filesSummary = (result.files || []).map((file) => ({
    name: file.name,
    total_bytes: typeof file.total_bytes === "number" ? file.total_bytes : (file.content ? Buffer.byteLength(file.content, "utf8") : 0),
    truncated: file.truncated === true,
    omitted: file.omitted === true,
  }));
  return JSON.stringify({
    ok: result.ok !== false,
    chain_id: result.chain_id,
    address: result.address,
    source: result.source || null,
    contract_name: result.contract_name || null,
    proxy: result.proxy === undefined ? null : result.proxy,
    implementation: result.implementation || null,
    files: filesSummary,
    total_bytes: result.total_bytes || 0,
    cache_dir: result.chain_id && result.address
      ? path.join("contracts", String(result.chain_id), result.address.toLowerCase())
      : null,
    cached: result.cached === true,
    attempts: Array.isArray(result.attempts) ? result.attempts : [],
    reason: result.reason || null,
  });
}

module.exports = Object.freeze({
  name: "bob_evm_fetch_source",
  aliases: ["bounty_evm_fetch_source"],
  description: "Fetch verified source code for an EVM contract through DNS-pinned direct public HTTPS source endpoints. Tries Sourcify (no API key) first, then Etherscan V2 multi-chain when BOB_ETHERSCAN_API_KEY is set; DNS-private/private endpoints and egress_profile proxy routing are unsupported by default. Caches under [SESSION]/contracts/<chain_id>/<address>/sources/. Returns a file-summary envelope (names, sizes, truncation flags) so callers can request specific files via Read after the cache is populated.",
  inputSchema: {
    "type": "object",
    "properties": {
      "target_domain": { "type": "string" },
      "chain_id": { "type": "integer", "minimum": 1 },
      "address": { "type": "string", "pattern": "^0x[0-9a-fA-F]{40}$" },
      "force": { "type": "boolean" }
    },
    "required": ["target_domain", "chain_id", "address"]
  },
  handler,
  role_bundles: ["evaluator-evm", "verifier", "evidence"],
  mutating: true,
  global_preapproval: true,
  network_access: true,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: ["contracts/<chain_id>/<address>/source-manifest.json", "contracts/<chain_id>/<address>/sources/"],
});
