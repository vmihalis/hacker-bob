"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");

const { classifySurfaceCapability } = require("../mcp/lib/capability-packs.js");
const { normalizeSurfaceLead } = require("../mcp/lib/lead-intake.js");

const BASE_CONTRACT = "0x1111111111111111111111111111111111111111";
const UNKNOWN_CONTRACT = "0x2222222222222222222222222222222222222222";

test("smart_contract lead with Base evidence resolves evm chain context", () => {
  const normalized = normalizeSurfaceLead({
    title: "Base pool contract",
    surface_type: "smart_contract",
    contract_address: BASE_CONTRACT,
    evidence: ["observed via base-mainnet RPC"],
  });

  assert.equal(normalized.chain_family, "evm");
  assert.equal(normalized.chain_id, 8453);
});

test("resolved smart_contract lead routes after intake", () => {
  const normalized = normalizeSurfaceLead({
    title: "Base pool contract",
    surface_type: "smart_contract",
    contract_address: BASE_CONTRACT,
    evidence: ["observed via base-mainnet RPC"],
  });
  const routed = classifySurfaceCapability(normalized);

  assert.equal(routed.routable, true);
});

test("unresolvable smart_contract lead carries a visible blocked prerequisite", () => {
  const normalized = normalizeSurfaceLead({
    title: "Ambiguous contract",
    surface_type: "smart_contract",
    contract_address: UNKNOWN_CONTRACT,
  });

  assert.equal(normalized.chain_family, null);
  assert.ok(Array.isArray(normalized.blocked_prereqs));
  assert.ok(normalized.blocked_prereqs.length > 0);
  assert.equal(typeof normalized.blocked_prereqs[0].reason, "string");
  assert.ok(normalized.blocked_prereqs[0].reason.length > 0);
});

test("smart_contract lead with chain_family is unchanged by resolver", () => {
  const normalized = normalizeSurfaceLead({
    title: "Known EVM contract",
    surface_type: "smart_contract",
    chain_family: "evm",
    contract_address: UNKNOWN_CONTRACT,
  });

  assert.equal(normalized.chain_family, "evm");
  assert.equal(normalized.blocked_prereqs, undefined);
});

test("web lead is untouched by chain resolver", () => {
  const normalized = normalizeSurfaceLead({
    title: "Web endpoint",
    surface_type: "web",
    contract_address: UNKNOWN_CONTRACT,
  });

  assert.equal(normalized.chain_family, null);
  assert.equal(normalized.blocked_prereqs, undefined);
});
