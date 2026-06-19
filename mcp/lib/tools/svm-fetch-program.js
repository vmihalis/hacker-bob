"use strict";

const { getAccountInfo, getSlot } = require("../svm-client.js");

const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// Solana uses Bitcoin-style base58 (no 0/O/I/l). Encode is bytes → string;
// kept inline so we don't pull a dependency. Pubkeys are 32 bytes → 43-44
// base58 chars. The implementation handles leading zero bytes (each becomes
// a leading '1' character).
function base58Encode(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length === 0) return "";
  let zeros = 0;
  while (zeros < buffer.length && buffer[zeros] === 0) zeros += 1;
  let big = 0n;
  for (const byte of buffer) {
    big = (big << 8n) + BigInt(byte);
  }
  let output = "";
  while (big > 0n) {
    const rem = big % 58n;
    big = big / 58n;
    output = BASE58_ALPHABET[Number(rem)] + output;
  }
  return "1".repeat(zeros) + output;
}

// BPFLoaderUpgradeable account discriminator layout (Anchor-style enum tag,
// little-endian u32):
//   0 = Uninitialized
//   1 = Buffer
//   2 = Program (data: programdata_address: Pubkey)
//   3 = ProgramData (data: slot: u64, upgrade_authority: Option<Pubkey>, ...)
function parseProgramAccount(dataBuffer) {
  if (!Buffer.isBuffer(dataBuffer) || dataBuffer.length < 36) {
    return { kind: "unknown", reason: "data_too_short" };
  }
  const tag = dataBuffer.readUInt32LE(0);
  if (tag === 2) {
    const programdataAddressBytes = dataBuffer.subarray(4, 36);
    return {
      kind: "program",
      programdata_address: base58Encode(programdataAddressBytes),
    };
  }
  if (tag === 1) return { kind: "buffer" };
  if (tag === 3) return { kind: "programdata" };
  if (tag === 0) return { kind: "uninitialized" };
  return { kind: "unknown", tag };
}

function parseProgramDataAccount(dataBuffer) {
  if (!Buffer.isBuffer(dataBuffer) || dataBuffer.length < 13) {
    return { kind: "unknown", reason: "data_too_short" };
  }
  // [discriminator (4) | slot (8) | upgrade_authority option (1 + optional 32) | bytecode...]
  const tag = dataBuffer.readUInt32LE(0);
  if (tag !== 3) return { kind: "unknown", tag };
  const slotBigInt = dataBuffer.readBigUInt64LE(4);
  const optionByte = dataBuffer.readUInt8(12);
  if (optionByte === 0) {
    return { kind: "programdata", deployed_slot: Number(slotBigInt), upgrade_authority: null };
  }
  if (optionByte === 1 && dataBuffer.length >= 45) {
    const authorityBytes = dataBuffer.subarray(13, 45);
    return {
      kind: "programdata",
      deployed_slot: Number(slotBigInt),
      upgrade_authority: base58Encode(authorityBytes),
    };
  }
  return { kind: "programdata", reason: "unparseable_authority_option", deployed_slot: Number(slotBigInt) };
}

async function handler(args) {
  const programResult = await getAccountInfo({
    cluster: args.cluster,
    pubkey: args.program_id,
    encoding: "base64",
    endpoints: args.endpoints,
  });

  const programValue = programResult.result && programResult.result.value;
  const programContextSlot = programResult.result && programResult.result.context && typeof programResult.result.context.slot === "number"
    ? programResult.result.context.slot
    : null;

  if (!programValue) {
    return JSON.stringify({
      cluster: args.cluster,
      program_id: args.program_id,
      block_used: programContextSlot,
      endpoint_used: programResult.endpoint,
      program: null,
      reason: "program_not_found",
    });
  }

  const programOwner = typeof programValue.owner === "string" ? programValue.owner : null;
  const programDataB64 = Array.isArray(programValue.data) && typeof programValue.data[0] === "string"
    ? programValue.data[0]
    : null;
  const programDataBuffer = programDataB64 ? Buffer.from(programDataB64, "base64") : null;
  const programParsed = programDataBuffer ? parseProgramAccount(programDataBuffer) : { kind: "unknown" };

  let programData = null;
  if (programParsed.kind === "program" && programParsed.programdata_address) {
    try {
      const pdResult = await getAccountInfo({
        cluster: args.cluster,
        pubkey: programParsed.programdata_address,
        encoding: "base64",
        endpoints: args.endpoints,
      });
      const pdValue = pdResult.result && pdResult.result.value;
      const pdDataB64 = pdValue && Array.isArray(pdValue.data) && typeof pdValue.data[0] === "string"
        ? pdValue.data[0]
        : null;
      const pdDataBuffer = pdDataB64 ? Buffer.from(pdDataB64, "base64") : null;
      const pdParsed = pdDataBuffer ? parseProgramDataAccount(pdDataBuffer) : { kind: "unknown" };
      programData = {
        address: programParsed.programdata_address,
        deployed_slot: pdParsed.deployed_slot != null ? pdParsed.deployed_slot : null,
        upgrade_authority: pdParsed.upgrade_authority || null,
        // null distinguishes "no programdata fetched" from "frozen (no authority)"
        // — when option byte is 0x00 the program is permanently frozen.
        frozen: pdParsed.upgrade_authority === null && pdParsed.kind === "programdata",
      };
    } catch (error) {
      programData = {
        address: programParsed.programdata_address,
        deployed_slot: null,
        upgrade_authority: null,
        frozen: null,
        error: error.message || String(error),
      };
    }
  }

  let slotUsed = null;
  try {
    const slotResult = await getSlot({ cluster: args.cluster, endpoints: args.endpoints });
    if (typeof slotResult.result === "number" && Number.isFinite(slotResult.result)) {
      slotUsed = slotResult.result;
    }
  } catch {
    // best-effort
  }

  return JSON.stringify({
    cluster: args.cluster,
    program_id: args.program_id,
    block_used: programContextSlot != null ? programContextSlot : slotUsed,
    endpoint_used: programResult.endpoint,
    program: {
      executable: programValue.executable === true,
      owner: programOwner,
      lamports: typeof programValue.lamports === "number" ? programValue.lamports : null,
      account_kind: programParsed.kind,
    },
    program_data: programData,
  });
}

module.exports = Object.freeze({
  name: "bob_svm_fetch_program",
  aliases: ["bounty_svm_fetch_program"],
  description: "Fetch a Solana upgradeable program's metadata through the DNS-pinned direct public HTTPS RPC fallback ladder. DNS-private/private endpoints and egress_profile proxy routing are unsupported by default; endpoint_used is redacted. Returns deployed slot, upgrade authority (or frozen), and the BPFLoaderUpgradeable account_kind. Useful to confirm program upgrade authority and immutability before constructing impact hypotheses involving program upgrades, frozen invariants, or governance-controlled deploys.",
  inputSchema: {
    "type": "object",
    "properties": {
      "target_domain": { "type": "string" },
      "cluster": { "type": "string", "enum": ["mainnet-beta", "devnet", "testnet"] },
      "program_id": { "type": "string", "pattern": "^[1-9A-HJ-NP-Za-km-z]{32,44}$" },
      "endpoints": { "type": "array", "items": { "type": "string", "format": "uri" }, "maxItems": 8 }
    },
    "required": ["target_domain", "cluster", "program_id"]
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
  // Exposed for tests
  _internals: { base58Encode, parseProgramAccount, parseProgramDataAccount },
});
