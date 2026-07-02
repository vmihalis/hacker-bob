"use strict";

// Guard against the recurring base58/SS58 scope fail-open class. The
// '<family>:<chainId>:<address>' contract identity AND the contract-address
// case-fold are single-sourced in chain-authority.js (contractIdentityKey /
// normalizeContractAddress). Every other site MUST route through them — never
// hand-roll the CAIP-10 string or lowercase an address inline. That defect
// recurred once per hand-rolled site (chain-authority.normalizeOneTuple,
// contract-target caip10Endpoint/contractSurfaceId, lead-promotion
// smartContractSurfaceKey, finalize-node producer emission); this scan fails fast
// if a new hand-rolled site appears.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");

const ROOT = path.join(__dirname, "..");
const read = (p) => fs.readFileSync(path.join(ROOT, p), "utf8");

test("no inline contract-address lowercase in the SC-identity modules", () => {
  // contract-target.js and lead-promotion.js are smart-contract identity code:
  // an address is never lowercased inline — it routes through the shared normalizer.
  for (const f of ["mcp/lib/contract-target.js", "mcp/lib/lead-promotion.js"]) {
    assert.ok(
      !/\baddress\.toLowerCase\(\)/.test(read(f)),
      `${f}: address lowercased inline — use chain-authority.normalizeContractAddress / contractIdentityKey`,
    );
  }
});

test("no hand-rolled CAIP-10 identity with inline lowercase in the SC path", () => {
  // A '`${...}:${...}:${<addr>.toLowerCase()}`' literal is the exact recurring
  // anti-pattern — the CAIP-10 identity must be built by contractIdentityKey.
  const CAIP_INLINE = /`[^`]*\$\{[^}]+\}:\$\{[^}]+\}:\$\{[^}]*\.toLowerCase\(\)\}/;
  for (const f of [
    "mcp/lib/tools/finalize-node.js",
    "mcp/lib/contract-target.js",
    "mcp/lib/lead-promotion.js",
    "mcp/lib/tools/materialize-producer-floor.js",
  ]) {
    assert.ok(
      !CAIP_INLINE.test(read(f)),
      `${f}: hand-rolled CAIP-10 identity with inline lowercase — route through chain-authority.contractIdentityKey`,
    );
  }
});

test("every contract-identity producer agrees and preserves base58/SS58 case", () => {
  const { contractIdentityKey, normalizeOneTuple } = require("../mcp/lib/chain-authority.js");
  const { caip10Endpoint } = require("../mcp/lib/contract-target.js");
  // base58 (svm) is case-SENSITIVE: the shared key preserves case, and the CAIP-10
  // endpoint + the membership normalizer agree with it (no divergent hand-rolled form).
  const svm = { chain_family: "svm", chain_id: "mainnet", address: "AbCdEf1234" };
  const key = contractIdentityKey(svm);
  assert.equal(key, "svm:mainnet:AbCdEf1234", "canonical identity preserves base58 case");
  assert.equal(
    caip10Endpoint({ chainFamily: "svm", chainId: "mainnet", address: "AbCdEf1234" }),
    key,
    "caip10Endpoint agrees with contractIdentityKey",
  );
  assert.equal(normalizeOneTuple(svm).address, "AbCdEf1234", "normalizeOneTuple preserves base58 case");
  // evm (hex) folds both family and address.
  assert.equal(
    contractIdentityKey({ chain_family: "EVM", chain_id: "1", address: "0xABCDEF" }),
    "evm:1:0xabcdef",
    "evm family + address case-folded",
  );
});
