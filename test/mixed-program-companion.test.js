"use strict";

// O-P6 MIXED program (a url PRIMARY axis + an OPTIONAL contracts companion),
// driven end-to-end through the REAL runtime dispatch path (executeTool ->
// enforceToolPolicy -> authorizeToolCall). A mixed bob_init_session binds the
// web target AND seeds one smart_contract surface per companion contract into
// the same frontier; the two axis scope gates stay INDEPENDENT — an
// out-of-authority chain tuple is SCOPE_BLOCKED while the web axis is untouched,
// and a control web-only init is byte-unchanged.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const { executeTool } = require("../mcp/lib/dispatch.js");
const { statePath } = require("../mcp/lib/paths.js");
const { readJsonFile } = require("../mcp/lib/storage.js");

const ADDR_IN = "0x0000000000000000000000000000000000000001";
const ADDR_OUT = "0x0000000000000000000000000000000000000002";
const CAIP_IN = `evm:1:${ADDR_IN}`;

async function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-mixed-companion-"));
  process.env.HOME = home;
  try {
    return await fn(home);
  } finally {
    process.env.HOME = previousHome;
    try { fs.rmSync(home, { recursive: true, force: true }); } catch {}
  }
}

test("mixed init binds the web target AND seeds a smart_contract surface", async () => {
  await withTempHome(async () => {
    const env = await executeTool("bob_init_session", {
      target_domain: "example.com",
      target_url: "https://example.com",
      contracts: [{ chain_family: "evm", chain_id: "1", address: ADDR_IN }],
    });

    assert.equal(env.ok, true, `expected ok:true, got ${JSON.stringify(env)}`);

    // Web axis bound.
    assert.equal(env.data.state.target, "example.com");
    assert.equal(env.data.state.target_url, "https://example.com");

    // Contracts companion bound + seeded, unioned into the same session.
    assert.deepEqual(env.data.target_contracts, [CAIP_IN]);
    assert.equal(typeof env.data.chain_authority_hash, "string");
    assert.ok(Array.isArray(env.data.seeded_surfaces) && env.data.seeded_surfaces.length >= 1,
      `expected >=1 seeded surface, got ${JSON.stringify(env.data.seeded_surfaces)}`);
    assert.ok(env.data.seeded_surfaces.includes(`sc-evm-1-${ADDR_IN}`));

    // state.json projects BOTH the web axis and the contracts companion.
    const persisted = readJsonFile(statePath("example.com"), { label: "state.json" });
    assert.equal(persisted.target_url, "https://example.com");
    assert.deepEqual(persisted.target_contracts, [CAIP_IN]);
    assert.equal(typeof persisted.chain_authority_hash, "string");
  });
});

test("an out-of-authority chain tuple on the mixed session is SCOPE_BLOCKED (independent axis gate)", async () => {
  await withTempHome(async () => {
    const boot = await executeTool("bob_init_session", {
      target_domain: "example.com",
      target_url: "https://example.com",
      contracts: [{ chain_family: "evm", chain_id: "1", address: ADDR_IN }],
    });
    assert.equal(boot.ok, true, `expected ok:true, got ${JSON.stringify(boot)}`);

    // Wrong chain_id + address: outside the bound chain authority. The chain
    // scope gate is the only producer of SCOPE_BLOCKED on this path.
    const env = await executeTool("bob_evm_fetch_source", {
      target_domain: "example.com",
      chain_id: 8453,
      address: ADDR_OUT,
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

test("an in-authority chain tuple on the mixed session is admitted past the gate", async () => {
  await withTempHome(async () => {
    const boot = await executeTool("bob_init_session", {
      target_domain: "example.com",
      target_url: "https://example.com",
      contracts: [{ chain_family: "evm", chain_id: "1", address: ADDR_IN }],
    });
    assert.equal(boot.ok, true, `expected ok:true, got ${JSON.stringify(boot)}`);

    // The bound (evm, 1, 0x..01) tuple is exactly in authority. The downstream
    // verified-source fetch is network-dependent and may fail in the sandbox,
    // but the chain scope gate is the ONLY producer of SCOPE_BLOCKED here, so
    // "admitted past the gate" == the outcome is not SCOPE_BLOCKED.
    const env = await executeTool("bob_evm_fetch_source", {
      target_domain: "example.com",
      chain_id: 1,
      address: ADDR_IN,
    });
    assert.ok(
      env.ok === true || (env.error && env.error.code !== "SCOPE_BLOCKED"),
      `expected admit past the gate, got ${JSON.stringify(env)}`,
    );
  });
});

test("a control web-only init (no contracts) is unchanged", async () => {
  await withTempHome(async () => {
    const env = await executeTool("bob_init_session", {
      target_domain: "example.com",
      target_url: "https://example.com",
    });
    assert.equal(env.ok, true, `expected ok:true, got ${JSON.stringify(env)}`);
    // No contracts companion: the historical web-session shape is preserved.
    assert.equal(env.data.target_contracts, undefined);
    assert.equal(env.data.seeded_surfaces, undefined);

    // The public projection OMITS an empty target_contracts / null
    // chain_authority_hash, keeping the historical web-session shape byte-stable
    // (the normalizer still defaults them to [] / null on read).
    const persisted = readJsonFile(statePath("example.com"), { label: "state.json" });
    assert.equal(persisted.target_contracts, undefined);
    assert.equal(persisted.chain_authority_hash, undefined);

    // A chain tool on a web-only session resolves an empty target_contracts[],
    // so the chain scope gate is a no-op: never chain-scope-blocked.
    const chain = await executeTool("bob_evm_fetch_source", {
      target_domain: "example.com",
      chain_id: 1,
      address: ADDR_IN,
    });
    assert.notEqual(
      chain.error && chain.error.details && chain.error.details.authority
        && chain.error.details.authority.authority_block_reason,
      "chain_scope_blocked",
      `web-only session must not be chain-scope-blocked, got ${JSON.stringify(chain)}`,
    );
  });
});
