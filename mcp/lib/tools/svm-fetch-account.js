"use strict";

const { getAccountInfo, getSlot } = require("../svm-client.js");

async function handler(args) {
  const result = await getAccountInfo({
    cluster: args.cluster,
    pubkey: args.pubkey,
    encoding: args.encoding || "base64",
    endpoints: args.endpoints,
  });
  // Resolve a slot reference for the verifier's "verified at slot N" claim.
  // Best-effort: an RPC slot follow-up failure does not invalidate a
  // successful getAccountInfo. The final-verifier prompt accepts slot_used=null
  // and reasons "no stable slot reference."
  let slotUsed = null;
  try {
    const slotResult = await getSlot({ cluster: args.cluster, endpoints: args.endpoints });
    if (typeof slotResult.result === "number" && Number.isFinite(slotResult.result)) {
      slotUsed = slotResult.result;
    }
  } catch {
    // ignore — slot is opportunistic
  }

  // SVM getAccountInfo returns { context: { slot, apiVersion }, value: { lamports, owner, data: [base64, encoding], executable, rentEpoch, space } }
  // We surface the raw envelope and the helpful slot from context.
  const value = result.result && result.result.value;
  const contextSlot = result.result && result.result.context && typeof result.result.context.slot === "number"
    ? result.result.context.slot
    : null;
  const dataLength = value && Array.isArray(value.data) && typeof value.data[0] === "string"
    ? Buffer.from(value.data[0], "base64").length
    : 0;

  return JSON.stringify({
    cluster: args.cluster,
    pubkey: args.pubkey,
    block_used: contextSlot != null ? contextSlot : slotUsed,
    endpoint_used: result.endpoint,
    account: value
      ? {
          lamports: typeof value.lamports === "number" ? value.lamports : null,
          owner: typeof value.owner === "string" ? value.owner : null,
          executable: value.executable === true,
          rent_epoch: typeof value.rentEpoch === "number" ? value.rentEpoch : null,
          data_length: dataLength,
          // The raw base64 data is included so the verifier can re-decode it
          // for assertions; capped at the JSON-RPC client's response cap.
          data_base64: value && Array.isArray(value.data) && typeof value.data[0] === "string"
            ? value.data[0]
            : null,
        }
      : null,
  });
}

module.exports = Object.freeze({
  name: "bob_svm_fetch_account",
  aliases: ["bounty_svm_fetch_account"],
  description: "Read-only Solana getAccountInfo against a pubkey through the DNS-pinned direct public HTTPS RPC fallback ladder. DNS-private/private endpoints and egress_profile proxy routing are unsupported by default; endpoint_used is redacted. Returns lamports, owner program, executable flag, rent_epoch, and base64-encoded account data plus the slot the read was anchored at. Used by SVM evaluators to read program state, multisig members, and account-data layouts before constructing impact hypotheses.",
  inputSchema: {
    "type": "object",
    "properties": {
      "target_domain": { "type": "string" },
      "cluster": { "type": "string", "enum": ["mainnet-beta", "devnet", "testnet"] },
      "pubkey": { "type": "string", "pattern": "^[1-9A-HJ-NP-Za-km-z]{32,44}$" },
      "encoding": { "type": "string", "enum": ["base64", "base58", "jsonParsed"] },
      "endpoints": { "type": "array", "items": { "type": "string", "format": "uri" }, "maxItems": 8 }
    },
    "required": ["target_domain", "cluster", "pubkey"]
  },
  handler,
  role_bundles: ["evaluator-svm", "verifier", "evidence"],
  mutating: false,
  global_preapproval: true,
  network_access: true,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: [],
});
