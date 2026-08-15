"use strict";

// Pure bind-time address-shape predicates. Keeping these beside the contract
// target seam avoids loading transport clients (or the finding pipeline) just
// to validate the contracts axis.

const EVM_ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;
const SVM_PUBKEY_RE = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;
const MOVE_ADDRESS_RE = /^0x[a-fA-F0-9]{1,64}$/;
const SS58_BASE58_RE = /^[1-9A-HJ-NP-Za-km-z]+$/;
const SS58_LENGTH_RANGE = Object.freeze({ min: 45, max: 52 });
const SS58_BYTE_LENGTH_RANGE = Object.freeze({ min: 33, max: 38 });
const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const BECH32_ALPHABET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32_GENERATORS = Object.freeze([
  0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3,
]);

function base58Decode(input) {
  if (typeof input !== "string" || input.length === 0) return null;
  let zeros = 0;
  while (zeros < input.length && input[zeros] === "1") zeros += 1;
  let big = 0n;
  for (let i = zeros; i < input.length; i += 1) {
    const idx = BASE58_ALPHABET.indexOf(input[i]);
    if (idx < 0) return null;
    big = big * 58n + BigInt(idx);
  }
  const tail = [];
  while (big > 0n) {
    tail.unshift(Number(big & 0xFFn));
    big >>= 8n;
  }
  return Buffer.from([...new Array(zeros).fill(0), ...tail]);
}

function normalizeSs58Address(input) {
  if (typeof input !== "string") return null;
  const trimmed = input.trim();
  if (trimmed.length < SS58_LENGTH_RANGE.min || trimmed.length > SS58_LENGTH_RANGE.max) return null;
  if (!SS58_BASE58_RE.test(trimmed)) return null;
  const decoded = base58Decode(trimmed);
  if (!decoded) return null;
  if (decoded.length < SS58_BYTE_LENGTH_RANGE.min || decoded.length > SS58_BYTE_LENGTH_RANGE.max) return null;
  return trimmed;
}

function bech32Polymod(values) {
  let chk = 1;
  for (const value of values) {
    const top = chk >>> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ value;
    for (let i = 0; i < 5; i += 1) {
      if ((top >> i) & 1) chk ^= BECH32_GENERATORS[i];
    }
  }
  return chk >>> 0;
}

function bech32HrpExpand(hrp) {
  const out = [];
  for (let i = 0; i < hrp.length; i += 1) out.push(hrp.charCodeAt(i) >> 5);
  out.push(0);
  for (let i = 0; i < hrp.length; i += 1) out.push(hrp.charCodeAt(i) & 31);
  return out;
}

function bech32Decode(input) {
  if (typeof input !== "string") return null;
  if (input.length < 8 || input.length > 90) return null;
  let hasUpper = false;
  let hasLower = false;
  for (let i = 0; i < input.length; i += 1) {
    const code = input.charCodeAt(i);
    if (code < 33 || code > 126) return null;
    if (code >= 97 && code <= 122) hasLower = true;
    if (code >= 65 && code <= 90) hasUpper = true;
  }
  if (hasUpper && hasLower) return null;
  const lower = input.toLowerCase();
  const separator = lower.lastIndexOf("1");
  if (separator < 1 || separator + 7 > lower.length) return null;
  const hrp = lower.slice(0, separator);
  for (let i = 0; i < hrp.length; i += 1) {
    const code = hrp.charCodeAt(i);
    if (code < 33 || code > 126) return null;
  }
  const data = [];
  for (let i = separator + 1; i < lower.length; i += 1) {
    const value = BECH32_ALPHABET.indexOf(lower[i]);
    if (value < 0) return null;
    data.push(value);
  }
  if (bech32Polymod([...bech32HrpExpand(hrp), ...data]) !== 1) return null;
  return { hrp, data: data.slice(0, data.length - 6) };
}

function normalizeBech32Address(input) {
  if (typeof input !== "string") return null;
  const trimmed = input.trim();
  if (!bech32Decode(trimmed)) return null;
  return trimmed.toLowerCase();
}

function isValidContractAddressShape(chainFamily, address) {
  switch (chainFamily) {
    case "evm": return EVM_ADDRESS_RE.test(address);
    case "svm": return SVM_PUBKEY_RE.test(address);
    case "aptos":
    case "sui": return MOVE_ADDRESS_RE.test(address);
    case "substrate": return normalizeSs58Address(address) != null;
    case "cosmwasm": return normalizeBech32Address(address) != null;
    default: return false;
  }
}

module.exports = Object.freeze({
  isValidContractAddressShape,
  normalizeBech32Address,
  normalizeSs58Address,
});
