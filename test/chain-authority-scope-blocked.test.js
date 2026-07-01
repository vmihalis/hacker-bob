"use strict";

// The pre-handler chain scope gate runs through the REAL runtime dispatch path
// (dispatch.executeTool -> enforceToolPolicy -> authorizeToolCall ->
// authorizeChainScope). When a session binds a non-empty target_contracts[], a
// bob_* chain tool whose (chain_family, chain_id, address) is outside the bound
// authority is SCOPE_BLOCKED before the handler runs; an in-authority tuple is
// admitted; and a web session (empty target_contracts[]) is untouched by the
// gate. These tests assert each arm end-to-end via executeTool.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const { executeTool } = require("../mcp/lib/dispatch.js");

async function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-chain-scope-gate-"));
  process.env.HOME = home;
  try {
    return await fn(home);
  } finally {
    process.env.HOME = previousHome;
    try { fs.rmSync(home, { recursive: true, force: true }); } catch {}
  }
}

test("an in-authority chain tuple is admitted past the gate", async () => {
  await withTempHome(async () => {
    const boot = await executeTool("bob_init_contract_session", {
      contracts: [{
        chain_family: "evm",
        chain_id: "1",
        address: "0x0000000000000000000000000000000000000001",
      }],
    });
    assert.equal(boot.ok, true, `expected ok:true, got ${JSON.stringify(boot)}`);
    const domain = boot.data.target_domain;
    assert.ok(domain.startsWith("sc-evm-1-"), `expected sc-evm-1-<addr8> slug, got ${domain}`);

    // The bound (evm, 1, 0x..01) tuple is exactly in authority. The downstream
    // verified-source fetch is network-dependent and may fail in the sandbox,
    // but the chain scope gate is the ONLY producer of SCOPE_BLOCKED on this
    // path, so "admitted past the gate" == the outcome is not SCOPE_BLOCKED.
    const env = await executeTool("bob_evm_fetch_source", {
      target_domain: domain,
      chain_id: 1,
      address: "0x0000000000000000000000000000000000000001",
    });
    assert.ok(
      env.ok === true || (env.error && env.error.code !== "SCOPE_BLOCKED"),
      `expected admit past the gate, got ${JSON.stringify(env)}`,
    );
  });
});

test("an out-of-set chain tuple is SCOPE_BLOCKED pre-handler", async () => {
  await withTempHome(async () => {
    const boot = await executeTool("bob_init_contract_session", {
      contracts: [{
        chain_family: "evm",
        chain_id: "1",
        address: "0x0000000000000000000000000000000000000001",
      }],
    });
    assert.equal(boot.ok, true, `expected ok:true, got ${JSON.stringify(boot)}`);
    const domain = boot.data.target_domain;

    // Same chain_id (1), DIFFERENT address: strict exact-tuple membership blocks
    // it. The OD3 same-chain relaxation that would admit an address-only
    // difference is gated behind provenance detection, which is not wired, so the
    // gate is fail-closed and this surfaces as a reported scope gap.
    const env = await executeTool("bob_evm_fetch_source", {
      target_domain: domain,
      chain_id: 1,
      address: "0x0000000000000000000000000000000000000002",
    });
    assert.equal(env.ok, false, `expected ok:false, got ${JSON.stringify(env)}`);
    assert.equal(env.error.code, "SCOPE_BLOCKED", `expected SCOPE_BLOCKED, got ${JSON.stringify(env.error)}`);
    assert.equal(
      env.error.details.authority.authority_block_reason,
      "chain_scope_blocked",
      `expected chain_scope_blocked, got ${JSON.stringify(env.error.details)}`,
    );
  });
});

test("a web session (empty target_contracts) is untouched by the gate", async () => {
  await withTempHome(async () => {
    const boot = await executeTool("bob_init_session", {
      target_domain: "example.com",
      target_url: "https://example.com",
    });
    assert.equal(boot.ok, true, `expected ok:true, got ${JSON.stringify(boot)}`);

    // Deterministic proof the web read path is byte-unchanged by the gate.
    const read = await executeTool("bob_read_session_state", { target_domain: "example.com" });
    assert.equal(read.ok, true, `expected ok:true, got ${JSON.stringify(read)}`);

    // A chain tool on a web session resolves an empty target_contracts[], so the
    // gate is a no-op: the base path handles it and never chain-scope-blocks.
    const env = await executeTool("bob_evm_fetch_source", {
      target_domain: "example.com",
      chain_id: 1,
      address: "0x0000000000000000000000000000000000000001",
    });
    assert.notEqual(
      env.error && env.error.details && env.error.details.authority
        && env.error.details.authority.authority_block_reason,
      "chain_scope_blocked",
      `web session must not be chain-scope-blocked, got ${JSON.stringify(env)}`,
    );
  });
});
