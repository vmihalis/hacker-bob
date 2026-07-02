"use strict";

// A contracts-axis session (state.target_contracts non-empty, synthetic on-chain
// slug like sc-<family>-<chainId>-<addr8> or contracts-<hash8>) must be able to run
// non-chain orchestration mutation tools (the producer/cell floor, seed/graph
// schedulers, ...). The session-bound authority gate previously rejected the
// synthetic slug because assertHttpScopeDomain treats it as a bare public suffix; a
// contract session now authorizes via a SESSION-KEY MATCH (the arg target_domain
// equals the stored slug whose state.json carries target_contracts +
// chain_authority_hash), mirroring how a repo session skips the public-suffix check.
// These tests drive the REAL dispatch entrypoint end-to-end.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const { executeTool } = require("../mcp/lib/dispatch.js");

async function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-contract-session-orchestration-"));
  process.env.HOME = home;
  try {
    return await fn(home);
  } finally {
    process.env.HOME = previousHome;
    try { fs.rmSync(home, { recursive: true, force: true }); } catch {}
  }
}

test("contract session runs bob_materialize_producer_floor through the authority gate", async () => {
  await withTempHome(async () => {
    const session = await executeTool("bob_init_contract_session", {
      contracts: [{
        chain_family: "evm",
        chain_id: "1",
        address: "0x0000000000000000000000000000000000000001",
      }],
    });
    assert.equal(session.ok, true, `expected init ok:true, got ${JSON.stringify(session)}`);

    const domain = session.data.target_domain;
    assert.equal(typeof domain, "string");
    assert.ok(domain.startsWith("sc-evm-1-"), `expected sc-evm-1-<addr8> slug, got ${domain}`);

    // The blocker: this used to fail at the authority gate with a public-suffix
    // rejection of the synthetic slug. It now authorizes via session-key match.
    const floor = await executeTool("bob_materialize_producer_floor", { target_domain: domain });
    assert.equal(floor.ok, true, `expected floor ok:true, got ${JSON.stringify(floor)}`);
    assert.equal(typeof floor.data.tier1_producers_emitted, "number");
  });
});

test("web session still rejects an off-scope public-suffix target_domain on the same tool", async () => {
  await withTempHome(async () => {
    const session = await executeTool("bob_init_session", {
      target_domain: "example.com",
      target_url: "https://example.com",
    });
    assert.equal(session.ok, true, `expected init ok:true, got ${JSON.stringify(session)}`);

    // 'com' is a bare public suffix; assertHttpScopeDomain rejects it on the
    // web/default path. The contract branch must not loosen this.
    const floor = await executeTool("bob_materialize_producer_floor", { target_domain: "com" });
    assert.equal(floor.ok, false, `expected floor ok:false for bare public suffix, got ${JSON.stringify(floor)}`);
  });
});

test("a contract-shaped target_domain with no session does not authorize", async () => {
  await withTempHome(async () => {
    // Pattern-match alone is not authorization: the contract branch still requires
    // a real session-key-matched state.json, so an unknown slug is no_session.
    const floor = await executeTool("bob_materialize_producer_floor", { target_domain: "sc-evm-1-deadbeef" });
    assert.equal(floor.ok, false, `expected floor ok:false with no session, got ${JSON.stringify(floor)}`);
  });
});
