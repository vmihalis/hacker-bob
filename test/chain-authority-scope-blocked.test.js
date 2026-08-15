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

const { executeTool } = require("../mcp/core/dispatch/dispatch.js");
const { authorizeToolCall } = require("../mcp/core/session/session-authority.js");
const { getRegisteredTool, TOOL_REGISTRY } = require("../mcp/core/dispatch/tool-registry.js");
const { validateToolArguments } = require("../mcp/core/dispatch/tool-validation.js");

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

test("a web session cannot lend URL-axis authority to a contracts-axis tool", async () => {
  await withTempHome(async () => {
    const boot = await executeTool("bob_init_session", {
      target_domain: "example.com",
      target_url: "https://example.com",
    });
    assert.equal(boot.ok, true, `expected ok:true, got ${JSON.stringify(boot)}`);

    // Deterministic proof the web read path is byte-unchanged by the gate.
    const read = await executeTool("bob_read_session_state", { target_domain: "example.com" });
    assert.equal(read.ok, true, `expected ok:true, got ${JSON.stringify(read)}`);

    // The tuple gate is a no-op for an empty target_contracts[] set, then the
    // base authority path rejects the missing contracts axis before dispatch.
    const env = await executeTool("bob_evm_fetch_source", {
      target_domain: "example.com",
      chain_id: 1,
      address: "0x0000000000000000000000000000000000000001",
    });
    assert.equal(env.ok, false, `expected ok:false, got ${JSON.stringify(env)}`);
    assert.equal(env.error.code, "SCOPE_BLOCKED", `expected SCOPE_BLOCKED, got ${JSON.stringify(env.error)}`);
    assert.equal(env.error.details.authority.authority_error_code, "session_axis_mismatch");
  });
});

const CONTRACT_EXECUTION_TOOLS = Object.freeze([
  "bob_run_invariant_for_finding",
  "bob_foundry_run",
  "bob_anchor_run",
  "bob_aptos_run",
  "bob_sui_run",
  "bob_substrate_run",
  "bob_cosmwasm_run",
]);

test("URL-only sessions cannot authorize any chain execution tool", async () => {
  await withTempHome(async () => {
    const boot = await executeTool("bob_init_session", {
      target_domain: "example.com",
      target_url: "https://example.com",
    });
    assert.equal(boot.ok, true, JSON.stringify(boot));

    for (const name of CONTRACT_EXECUTION_TOOLS) {
      assert.throws(
        () => authorizeToolCall(getRegisteredTool(name), { target_domain: "example.com" }),
        (error) => error && error.code === "SCOPE_BLOCKED"
          && error.authority.authority_error_code === "session_axis_mismatch",
        `${name} must require a contracts axis`,
      );
    }
  });
});

test("a mixed URL plus contracts session can authorize chain execution tools", async () => {
  await withTempHome(async () => {
    const boot = await executeTool("bob_init_session", {
      target_domain: "example.com",
      target_url: "https://example.com",
      contracts: [{
        chain_family: "evm",
        chain_id: "1",
        address: "0x0000000000000000000000000000000000000001",
      }],
    });
    assert.equal(boot.ok, true, JSON.stringify(boot));

    for (const name of CONTRACT_EXECUTION_TOOLS) {
      const decision = authorizeToolCall(getRegisteredTool(name), { target_domain: "example.com" });
      assert.equal(decision.authority_result, "allowed", `${name}: ${JSON.stringify(decision)}`);
      assert.equal(decision.authority_class, "smart_contract_contextual");
    }
  });
});

test("contracts-only sessions cannot authorize any URL-axis network or browser tool", async () => {
  await withTempHome(async () => {
    const boot = await executeTool("bob_init_contract_session", {
      contracts: [{
        chain_family: "evm",
        chain_id: "1",
        address: "0x0000000000000000000000000000000000000001",
      }],
    });
    assert.equal(boot.ok, true, JSON.stringify(boot));
    const urlAxisExternalTools = TOOL_REGISTRY.filter((tool) => (
      (tool.network_access || tool.browser_access)
      && tool.required_session_axes.includes("url")
    ));
    assert.ok(urlAxisExternalTools.length > 0);

    for (const tool of urlAxisExternalTools) {
      assert.throws(
        () => authorizeToolCall(tool, { target_domain: boot.data.target_domain }),
        (error) => error && error.code === "SCOPE_BLOCKED"
          && error.authority.authority_error_code === "session_axis_mismatch",
        `${tool.name} must require a URL axis`,
      );
    }
  });
});

// ── Closed residual gap: EVM read/call tools are exact-tuple session-bound ────

const SESSION_BOUND_EVM_TOOLS = [
  {
    name: "bob_evm_call",
    bound_args: {
      chain_id: 1,
      to: "0x0000000000000000000000000000000000000001",
      data: "0x",
    },
    outside_args: { to: "0x0000000000000000000000000000000000000002" },
  },
  {
    name: "bob_evm_storage_read",
    bound_args: {
      chain_id: 1,
      address: "0x0000000000000000000000000000000000000001",
      slot: "0x0",
    },
    outside_args: { address: "0x0000000000000000000000000000000000000002" },
  },
  {
    name: "bob_evm_role_table",
    bound_args: {
      chain_id: 1,
      contract: "0x0000000000000000000000000000000000000001",
      accounts: ["0x0000000000000000000000000000000000000003"],
    },
    outside_args: { contract: "0x0000000000000000000000000000000000000002" },
  },
];

for (const { name, bound_args: boundArgs, outside_args: outsideArgs } of SESSION_BOUND_EVM_TOOLS) {
  test(`${name} schema requires the session handle and registry requires contracts authority`, () => {
    assert.throws(
      () => validateToolArguments(name, boundArgs),
      /target_domain is required/,
      `${name} must require target_domain`,
    );
    assert.doesNotThrow(() => validateToolArguments(name, {
      target_domain: "sc-evm-1-00000000",
      ...boundArgs,
    }));
    const tool = getRegisteredTool(name);
    assert.equal(tool.global_preapproval, false);
    assert.deepEqual(tool.required_session_axes, ["contracts"]);
  });

  test(`${name} admits only an exact tuple in the bound contract session`, async () => {
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

      const tool = getRegisteredTool(name);
      assert.ok(tool, `tool ${name} must be registered`);
      const boundDecision = authorizeToolCall(tool, {
        target_domain: domain,
        ...boundArgs,
      });
      assert.equal(boundDecision.authority_result, "allowed", `expected allowed, got ${JSON.stringify(boundDecision)}`);
      assert.equal(boundDecision.authority_class, "smart_contract_contextual");

      assert.throws(
        () => authorizeToolCall(tool, {
          target_domain: domain,
          ...boundArgs,
          ...outsideArgs,
        }),
        (error) => error && error.code === "SCOPE_BLOCKED"
          && error.authority.authority_error_code === "chain_scope_blocked",
        `${name} must reject a same-chain address outside the exact bound tuple`,
      );
    });
  });
}

test("a bound contract fetch tuple is still enforced at the authority layer (control)", async () => {
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

    const fetchSource = getRegisteredTool("bob_evm_fetch_source");
    assert.ok(fetchSource, "bob_evm_fetch_source must be registered");

    // Bound address is admitted past the gate.
    const boundDecision = authorizeToolCall(fetchSource, {
      target_domain: domain,
      chain_id: 1,
      address: "0x0000000000000000000000000000000000000001",
    });
    assert.equal(boundDecision.authority_result, "allowed", `bound tuple should be allowed, got ${JSON.stringify(boundDecision)}`);

    // Non-bound same-chain address is SCOPE_BLOCKED by the chain-scope gate.
    assert.throws(
      () => authorizeToolCall(fetchSource, {
        target_domain: domain,
        chain_id: 1,
        address: "0x0000000000000000000000000000000000000002",
      }),
      (error) => error && error.authority && error.authority.authority_block_reason === "chain_scope_blocked",
      "non-bound tuple should be chain_scope_blocked",
    );
  });
});

test("normalizeOneTuple case-folds hex families but PRESERVES base58/SS58 identity (no scope fail-open)", () => {
  const { normalizeOneTuple, isChainTupleInAuthority } = require("../mcp/lib/chain-authority.js");
  // base58 (svm) is case-SENSITIVE: two addresses differing only in case are
  // DISTINCT and must not collide; membership must stay fail-closed. The pre-fix
  // unconditional lowercase collided them (a scope-membership fail-open).
  const svmA = { chain_family: "svm", chain_id: "mainnet", address: "AbCdEf1234" };
  const svmB = { chain_family: "svm", chain_id: "mainnet", address: "abcdef1234" };
  assert.equal(normalizeOneTuple(svmA).address, "AbCdEf1234", "svm address case preserved");
  assert.notEqual(
    normalizeOneTuple(svmA).address,
    normalizeOneTuple(svmB).address,
    "distinct svm addresses must not collide under case-folding",
  );
  assert.equal(isChainTupleInAuthority(svmB, [svmA]), false, "svm membership fail-closed (no case collision)");
  assert.equal(isChainTupleInAuthority(svmA, [svmA]), true, "svm exact tuple admitted");
  // SS58 (substrate) is likewise case-sensitive.
  assert.equal(
    normalizeOneTuple({ chain_family: "substrate", chain_id: "polkadot", address: "5GrwvaEF" }).address,
    "5GrwvaEF",
    "substrate SS58 address case preserved",
  );
  // evm hex stays case-INSENSITIVE: checksummed and lowercased forms are one authority.
  assert.equal(
    isChainTupleInAuthority(
      { chain_family: "evm", chain_id: "1", address: "0xABCDEF" },
      [{ chain_family: "evm", chain_id: "1", address: "0xabcdef" }],
    ),
    true,
    "evm case-insensitive membership preserved",
  );
});

test("chain-authority hardening: traversal-guarded chain_id/address, fail-closed query family, inert provenanced", () => {
  const {
    normalizeContractTupleStrict, normalizeOneTuple, isChainTupleInAuthority,
  } = require("../mcp/lib/chain-authority.js");
  // (1) chain_id / address are interpolated into contracts/<chain_id>/<address>/ —
  // path-traversal / separator chars must fail closed at bind time.
  for (const bad of ["../../x", "a/b", "a\\b", "1:2"]) {
    assert.throws(
      () => normalizeContractTupleStrict({ chain_family: "evm", chain_id: bad, address: "0xabc" }),
      /must not contain/,
      `chain_id '${bad}' must be rejected`,
    );
  }
  assert.throws(
    () => normalizeContractTupleStrict({ chain_family: "evm", chain_id: "1", address: "../evil" }),
    /path-traversal/,
    "address with '..' must be rejected",
  );
  // legit still passes
  assert.equal(
    normalizeContractTupleStrict({ chain_family: "evm", chain_id: "1", address: "0xABC" }).chain_id,
    "1",
  );
  // (2) query-time normalizer applies the SAME CHAIN_FAMILY_VALUES check as bind-time.
  assert.equal(
    normalizeOneTuple({ chain_family: "boguschain", chain_id: "1", address: "0xabc" }),
    null,
    "unknown chain_family drops to null at query time (fail-closed, matches bind path)",
  );
  // (3) OD3 same-chain relaxation is inert: provenanced:true must NOT admit a
  // same-(family,chain_id) DIFFERENT address (that was a primed chain-wide fail-open).
  const bound = [{ chain_family: "evm", chain_id: "1", address: "0xaaa" }];
  assert.equal(
    isChainTupleInAuthority({ chain_family: "evm", chain_id: "1", address: "0xbbb" }, bound, { provenanced: true }),
    false,
    "provenanced:true does NOT authorize a different same-chain address (no bare same-chain fail-open)",
  );
  assert.equal(
    isChainTupleInAuthority({ chain_family: "evm", chain_id: "1", address: "0xaaa" }, bound, { provenanced: true }),
    true,
    "exact tuple still admitted regardless of the flag",
  );
});
