"use strict";

// bob_init_contract_session must be reachable through the REAL
// runtime dispatch path (dispatch.executeTool -> enforceToolPolicy ->
// authorizeToolCall). It is a bootstrap_session sibling of bob_init_session /
// bob_init_repo_session: the contracts axis CREATES the session, so it must NOT
// route through authorizeSessionBound (which would deadlock demanding a
// target_domain argument the schema lacks AND a pre-existing state.json the tool
// is about to write). These tests drive the dispatch entrypoint end-to-end:
//   * positive: a single EVM contract bootstraps a session, persists
//     target_contracts (no target_url), and seeds >=1 smart_contract surface;
//   * fail-closed: an unknown chain_family (schema enum) and a valid family with
//     a malformed address (the new bootstrap branch's Y-D21/shape catch) both
//     return ok:false and create no session.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const { executeTool } = require("../mcp/core/dispatch/dispatch.js");
const {
  handoffSigningKeyPath,
  handoffSigningPrivateKeyPath,
  handoffSigningPublicKeyPath,
  queuePolicyPath,
  sessionEventsJsonlPath,
  sessionNucleusPath,
  statePath,
} = require("../mcp/core/io/paths.js");
const { readJsonFile } = require("../mcp/core/io/storage.js");
const { loadQueuePolicy, writeQueuePolicy } = require("../mcp/core/io/queue-policy.js");
const {
  readVerifiedSessionNucleus,
  sessionNucleusFromState,
} = require("../mcp/core/governance/index.js");
const { readSessionEvents } = require("../mcp/core/session/session-events.js");
const { deriveContractSession } = require("../mcp/core/chain-authority-contracts.js");
const setQueuePolicy = require("../mcp/tools/set-queue-policy.js");

async function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-init-contract-dispatch-"));
  process.env.HOME = home;
  try {
    return await fn(home);
  } finally {
    process.env.HOME = previousHome;
    try { fs.rmSync(home, { recursive: true, force: true }); } catch {}
  }
}

function sessionRootEntries(home) {
  const root = path.join(home, "hacker-bob-sessions");
  try {
    return fs.readdirSync(root);
  } catch {
    return [];
  }
}

function assertNoSessionRootEntries(home) {
  const entries = sessionRootEntries(home);
  assert.equal(entries.length, 0, `expected no session created, found ${JSON.stringify(entries)}`);
}

function assertContractAuthorityCommitted(domain, state) {
  assert.equal(fs.existsSync(statePath(domain)), true, "state.json must be written");
  assert.equal(fs.existsSync(sessionNucleusPath(domain)), true, "session-nucleus.json must be written");
  assert.equal(fs.existsSync(sessionEventsJsonlPath(domain)), true, "session-events.jsonl must be written");
  const rehydrated = sessionNucleusFromState(state);
  const verified = readVerifiedSessionNucleus(domain);
  assert.equal(verified.lifecycle_state, "SETUP");
  assert.equal(rehydrated.nucleus_hash, verified.nucleus_hash);
  const initEvents = readSessionEvents(domain).filter(
    (event) => event.kind === "governance.session.initialized",
  );
  assert.equal(initEvents.length, 1, "exactly one initialization event is canonical");
  assert.equal(initEvents[0].target_domain, domain);
  assert.equal(initEvents[0].nucleus_hash, verified.nucleus_hash);
  assert.equal(initEvents[0].payload.nucleus_hash, verified.nucleus_hash);
  return verified;
}

test("bob_init_contract_session bootstraps a contracts-axis session through dispatch", async () => {
  await withTempHome(async () => {
    const expected = deriveContractSession([{
      chain_family: "evm",
      chain_id: "1",
      address: "0x0000000000000000000000000000000000000001",
    }]);
    const env = await executeTool("bob_init_contract_session", {
      contracts: [{
        chain_family: "evm",
        chain_id: "1",
        address: "0x0000000000000000000000000000000000000001",
      }],
    });

    assert.equal(env.ok, true, `expected ok:true, got ${JSON.stringify(env)}`);

    const domain = env.data.target_domain;
    assert.equal(typeof domain, "string");
    assert.equal(domain, expected.domain);
    assert.equal(env.data.chain_authority_hash, expected.authorityHash);
    assert.ok(
      domain.startsWith("sc-evm-1-"),
      `expected sc-evm-1-<addr8> slug, got ${domain}`,
    );

    // The session is created on disk: state.json persists the contracts axis as
    // the SOLE primary axis (target_contracts present, target_url null).
    const state = readJsonFile(statePath(domain), { label: "state.json" });
    assert.deepEqual(
      state.target_contracts,
      ["evm:1:0x0000000000000000000000000000000000000001"],
    );
    assert.deepEqual(env.data.target_contracts, state.target_contracts);
    assert.equal(state.chain_authority_hash, expected.authorityHash);
    assert.equal(state.target_url, null, "contracts-axis sessions carry no target_url");
    const nucleus = assertContractAuthorityCommitted(domain, state);
    assert.equal(nucleus.scope_policy.target_url, undefined);
    assert.equal(nucleus.scope_policy.target_repo, undefined);
    assert.deepEqual(nucleus.scope_policy.target_contracts, [{
      chain_family: "evm",
      chain_id: "1",
      address: "0x0000000000000000000000000000000000000001",
    }]);
    assert.equal(nucleus.scope_policy.chain_authority_hash, expected.authorityHash);
    assert.equal(loadQueuePolicy(domain).linked_contract_depth, 3);
    assert.equal(fs.existsSync(queuePolicyPath(domain)), true);
    assert.equal(fs.existsSync(handoffSigningKeyPath(domain)), true);
    assert.equal(fs.existsSync(handoffSigningPrivateKeyPath(domain)), true);
    assert.equal(fs.existsSync(handoffSigningPublicKeyPath(domain)), true);

    // At least one smart_contract surface is seeded via the Y-D21 funnel.
    assert.ok(Array.isArray(env.data.seeded_surfaces));
    assert.ok(
      env.data.seeded_surfaces.length >= 1,
      `expected >=1 seeded surface, got ${JSON.stringify(env.data.seeded_surfaces)}`,
    );
  });
});

test("bob_init_contract_session persists the front-door linked_contract_depth into the enforced queue policy", async () => {
  await withTempHome(async () => {
    // The front-door linked_contract_depth is the ENFORCED OD4 governor: it must
    // reach loadQueuePolicy (the source materialize-producer-floor's depthCap
    // reads), not only the seed event / response. An explicit 1 must enforce 1,
    // never the DEFAULT_QUEUE_POLICY fallback of 3.
    const env = await executeTool("bob_init_contract_session", {
      contracts: [{
        chain_family: "evm",
        chain_id: "1",
        address: "0x0000000000000000000000000000000000000001",
      }],
      linked_contract_depth: 1,
    });
    assert.equal(env.ok, true, `expected ok:true, got ${JSON.stringify(env)}`);
    assert.equal(env.data.linked_contract_depth, 1);

    const domain = env.data.target_domain;
    const policy = loadQueuePolicy(domain);
    assert.equal(
      policy.linked_contract_depth,
      1,
      `enforced depthCap must reflect the front-door value, got ${policy.linked_contract_depth}`,
    );
  });
});

test("bob_init_contract_session enforces the default linked_contract_depth of 3 when omitted", async () => {
  await withTempHome(async () => {
    const env = await executeTool("bob_init_contract_session", {
      contracts: [{
        chain_family: "evm",
        chain_id: "1",
        address: "0x0000000000000000000000000000000000000002",
      }],
    });
    assert.equal(env.ok, true, `expected ok:true, got ${JSON.stringify(env)}`);
    assert.equal(env.data.linked_contract_depth, 3);

    const domain = env.data.target_domain;
    const policy = loadQueuePolicy(domain);
    assert.equal(policy.linked_contract_depth, 3);
  });
});

test("a partial bob_set_queue_policy preserves the init-persisted linked_contract_depth (OD4 durability)", async () => {
  await withTempHome(async () => {
    // Front door persists the operator OD4 depth override (1, not the default 3).
    const env = await executeTool("bob_init_contract_session", {
      contracts: [{
        chain_family: "evm",
        chain_id: "1",
        address: "0x0000000000000000000000000000000000000003",
      }],
      linked_contract_depth: 1,
    });
    assert.equal(env.ok, true, `expected ok:true, got ${JSON.stringify(env)}`);
    const domain = env.data.target_domain;
    assert.equal(loadQueuePolicy(domain).linked_contract_depth, 1);

    // The orchestrator's partial-surface-ack flow issues a PARTIAL set_queue_policy
    // that does NOT carry linked_contract_depth. Before the read-modify-write fix,
    // normalizeQueuePolicy reset the omitted governor to DEFAULT_QUEUE_POLICY (3).
    const out = JSON.parse(setQueuePolicy.handler({
      target_domain: domain,
      policy: {
        partial_surface_advance_acknowledgements: [
          { surface_id: "sc-surface-1", attestation_token: "ack-token-abc" },
        ],
      },
    }));
    // The enforced depthCap returned AND persisted stays the operator value, not 3.
    assert.equal(
      out.queue_policy.linked_contract_depth,
      1,
      `partial set_queue_policy must preserve the OD4 depth, got ${out.queue_policy.linked_contract_depth}`,
    );
    assert.equal(
      loadQueuePolicy(domain).linked_contract_depth,
      1,
      "enforced depthCap (loadQueuePolicy) must remain the operator value after the partial update",
    );
    // The partial update itself still applied — preservation is scoped to the
    // init-owned governors and does not block other fields.
    assert.equal(out.queue_policy.partial_surface_advance_acknowledgements.length, 1);
  });
});

test("a partial bob_set_queue_policy preserves init-persisted OD1 seed-producer caps", async () => {
  await withTempHome(async () => {
    const env = await executeTool("bob_init_contract_session", {
      contracts: [{
        chain_family: "evm",
        chain_id: "1",
        address: "0x0000000000000000000000000000000000000004",
      }],
    });
    assert.equal(env.ok, true, `expected ok:true, got ${JSON.stringify(env)}`);
    const domain = env.data.target_domain;

    // Plant non-default seed governors the way a front door persists them.
    writeQueuePolicy(domain, {
      linked_contract_depth: 2,
      seed_producer_per_pass_cap: 7,
      per_expander_linked_address_cap: 5,
      max_total_seed_producers: 200,
    });

    // A partial update on an UNRELATED field must not reset the seed governors.
    const out = JSON.parse(setQueuePolicy.handler({
      target_domain: domain,
      policy: { close_blocked_on_freeze: true },
    }));
    assert.equal(out.queue_policy.linked_contract_depth, 2);
    assert.equal(out.queue_policy.seed_producer_per_pass_cap, 7);
    assert.equal(out.queue_policy.per_expander_linked_address_cap, 5);
    assert.equal(out.queue_policy.max_total_seed_producers, 200);
    // The partial field still applied.
    assert.equal(out.queue_policy.close_blocked_on_freeze, true);

    // An EXPLICIT governor in the input still wins over the persisted value.
    const updated = JSON.parse(setQueuePolicy.handler({
      target_domain: domain,
      policy: { seed_producer_per_pass_cap: 9 },
    }));
    assert.equal(updated.queue_policy.seed_producer_per_pass_cap, 9);
    // ...while the other governors omitted from THIS call still survive.
    assert.equal(updated.queue_policy.linked_contract_depth, 2);
    assert.equal(updated.queue_policy.per_expander_linked_address_cap, 5);
  });
});

test("bob_init_contract_session fails closed on a chain_id containing a colon", async () => {
  await withTempHome(async (home) => {
    // target_contracts round-trip through the CAIP-10 string
    // '<family>:<chainId>:<address>' and re-parse by splitting on ':'
    // (chain_id = parts[1], address = parts.slice(2).join(':')). A chain_id that
    // itself carries ':' would shift the re-parse (chain_id -> '1',
    // address -> '2:0x..'), desyncing the runtime tuple from authority.
    // normalizeContracts rejects it fail-closed BEFORE any session is written.
    const env = await executeTool("bob_init_contract_session", {
      contracts: [{
        chain_family: "evm",
        chain_id: "1:2",
        address: "0x0000000000000000000000000000000000000001",
      }],
    });
    assert.equal(env.ok, false, `expected ok:false, got ${JSON.stringify(env)}`);

    assertNoSessionRootEntries(home);
  });
});

test("two contracts sharing an 8-hex address prefix derive DISTINCT target_domains", async () => {
  await withTempHome(async () => {
    // addressSlug truncates the address to 8 hex nibbles (32 bits). Two addresses
    // sharing their first 8 nibbles on the same family+chain_id must still derive
    // distinct target_domains via the full-authority digest suffix — otherwise
    // the second init throws STATE_CONFLICT or a chain tool reads
    // chain_scope_blocked on the wrong-but-same-slug contract.
    const a = await executeTool("bob_init_contract_session", {
      contracts: [{
        chain_family: "evm",
        chain_id: "1",
        address: "0x1234567800000000000000000000000000000001",
      }],
    });
    const b = await executeTool("bob_init_contract_session", {
      contracts: [{
        chain_family: "evm",
        chain_id: "1",
        address: "0x1234567800000000000000000000000000000002",
      }],
    });
    assert.equal(a.ok, true, `expected ok:true, got ${JSON.stringify(a)}`);
    assert.equal(b.ok, true, `expected ok:true, got ${JSON.stringify(b)}`);

    // Both keep the human-readable on-chain identity prefix...
    assert.ok(a.data.target_domain.startsWith("sc-evm-1-"), a.data.target_domain);
    assert.ok(b.data.target_domain.startsWith("sc-evm-1-"), b.data.target_domain);
    // ...but the digest suffix disambiguates the shared addr8 prefix.
    assert.notEqual(
      a.data.target_domain,
      b.data.target_domain,
      `distinct contracts sharing an 8-hex prefix must derive distinct target_domains, both got ${a.data.target_domain}`,
    );

    // Both sessions materialize independently on disk (no STATE_CONFLICT collapse).
    assert.ok(fs.existsSync(statePath(a.data.target_domain)));
    assert.ok(fs.existsSync(statePath(b.data.target_domain)));
  });
});

test("the companion path and the contracts-axis init path derive the SAME chain_authority_hash (uppercase family folds identically)", () => {
  const { prepareContractCompanion } = require("../mcp/domains/blockchain/contract-target.js");
  const { chainAuthorityHash } = require("../mcp/core/chain-authority-contracts.js");
  const initTool = require("../mcp/tools/blockchain/init-contract-session.js");

  const contract = {
    chain_family: "evm",
    chain_id: "1",
    address: "0x0000000000000000000000000000000000000001",
  };
  // deriveContractSession is the contracts-axis normal form the persisted
  // chain_authority_hash is written from.
  const initHash = initTool.deriveContractSession([contract]).authorityHash;
  assert.notEqual(initHash, chainAuthorityHash([]), "sanity: non-empty set != empty-set hash");

  // The companion path with an UPPERCASE family must fold to the identical hash,
  // not the empty-set hash the old CAIP-string-through-classifyTargetToken path
  // produced (which chain_scope_blocked every in-scope companion contract).
  const companion = prepareContractCompanion([{ ...contract, chain_family: "EVM" }]);
  assert.equal(companion.chain_authority_hash, initHash);
  assert.notEqual(companion.chain_authority_hash, chainAuthorityHash([]));
  // The CAIP-10 projection lowercases the family so the runtime tuple matches.
  assert.deepEqual(
    companion.target_contracts,
    ["evm:1:0x0000000000000000000000000000000000000001"],
  );
});

test("the companion path rejects a chain_id containing a colon (fail-closed, same as init)", () => {
  const { prepareContractCompanion } = require("../mcp/domains/blockchain/contract-target.js");
  assert.throws(
    () => prepareContractCompanion([{
      chain_family: "evm",
      chain_id: "1:2",
      address: "0x0000000000000000000000000000000000000001",
    }]),
    /chain_id must not contain ':'/,
    "companion path must colon-guard chain_id like the init path",
  );
});

test("bob_init_contract_session fails closed on an unknown chain_family", async () => {
  await withTempHome(async (home) => {
    const env = await executeTool("bob_init_contract_session", {
      contracts: [{
        chain_family: "notachain",
        chain_id: "1",
        address: "0x0000000000000000000000000000000000000001",
      }],
    });
    assert.equal(env.ok, false, `expected ok:false, got ${JSON.stringify(env)}`);
    assertNoSessionRootEntries(home);
  });
});

test("bob_init_contract_session fails closed at the bootstrap gate on a malformed address", async () => {
  await withTempHome(async (home) => {
    // chain_family passes the schema enum, so this exercises the NEW bootstrap
    // branch's deriveContractSession -> normalizeContracts shape catch (not just
    // schema validation): a malformed EVM address rewraps as normalization_failed
    // BEFORE the handler runs, so no session is written.
    const env = await executeTool("bob_init_contract_session", {
      contracts: [{
        chain_family: "evm",
        chain_id: "1",
        address: "0xZZZ",
      }],
    });
    assert.equal(env.ok, false, `expected ok:false, got ${JSON.stringify(env)}`);

    // The gate blocks pre-handler: no session directory is materialized.
    // sessionsRoot() resolves under os.homedir(), which honors process.env.HOME
    // on POSIX (the same isolation the withTempHome helper relies on).
    assertNoSessionRootEntries(home);
  });
});
