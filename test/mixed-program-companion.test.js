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

const { executeTool } = require("../mcp/core/dispatch/dispatch.js");
const { statePath } = require("../mcp/core/io/paths.js");
const { readJsonFile } = require("../mcp/core/io/storage.js");
const { chainAuthorityHash } = require("../mcp/lib/chain-authority.js");

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

test("an UPPERCASE-family companion binding folds to the SAME chain_authority_hash as the lowercased init tuple (not the empty-set hash)", () => {
  const { prepareContractCompanion } = require("../mcp/domains/blockchain/contract-target.js");
  // The contracts-axis normal form (tuple objects, family lowercased) is the
  // authoritative target hash for this single contract.
  const initHash = chainAuthorityHash([{ chain_family: "evm", chain_id: "1", address: ADDR_IN }]);
  const emptyHash = chainAuthorityHash([]);
  assert.notEqual(initHash, emptyHash, "sanity: a non-empty set must not hash to the empty-set hash");

  // Same contract on the COMPANION path but with an uppercase chain_family
  // (the schema enum guards the dispatch surface, so this exercises the shared
  // normalizer at its module boundary). Before the shared normalizer, the
  // companion hashed CAIP-10 strings through the case-sensitive
  // classifyTargetToken, so 'EVM:1:0x..' dropped and the hash collapsed to the
  // empty-set hash -> every in-scope contract was chain_scope_blocked. It must
  // now fold to the identical init-path hash and lowercase the CAIP projection.
  const companion = prepareContractCompanion([{ chain_family: "EVM", chain_id: "1", address: ADDR_IN }]);
  assert.equal(companion.chain_authority_hash, initHash,
    `companion hash must equal the init-path hash, got ${companion.chain_authority_hash}`);
  assert.notEqual(companion.chain_authority_hash, emptyHash,
    "companion hash must not be the empty-set hash");
  assert.deepEqual(companion.target_contracts, [CAIP_IN]);
});

test("the companion chain_authority_hash matches the contracts-axis init hash and binds a usable in-scope tuple", async () => {
  await withTempHome(async () => {
    // The dispatch-reachable proof: a companion contract must derive the SAME
    // chain_authority_hash the contracts-axis init path derives for that set...
    const initHash = chainAuthorityHash([{ chain_family: "evm", chain_id: "1", address: ADDR_IN }]);
    const env = await executeTool("bob_init_session", {
      target_domain: "example.com",
      target_url: "https://example.com",
      contracts: [{ chain_family: "evm", chain_id: "1", address: ADDR_IN }],
    });
    assert.equal(env.ok, true, `expected ok:true, got ${JSON.stringify(env)}`);
    assert.equal(env.data.chain_authority_hash, initHash,
      `companion hash must equal the init-path hash, got ${env.data.chain_authority_hash}`);
    const persisted = readJsonFile(statePath("example.com"), { label: "state.json" });
    assert.equal(persisted.chain_authority_hash, initHash);

    // ...so the in-scope bound tuple is ADMITTED past the chain-scope gate while
    // an out-of-set tuple is still SCOPE_BLOCKED.
    const bound = await executeTool("bob_evm_fetch_source", {
      target_domain: "example.com",
      chain_id: 1,
      address: ADDR_IN,
    });
    assert.ok(
      bound.ok === true || (bound.error && bound.error.code !== "SCOPE_BLOCKED"),
      `bound in-scope contract must be admitted past the gate, got ${JSON.stringify(bound)}`,
    );
    const outOfSet = await executeTool("bob_evm_fetch_source", {
      target_domain: "example.com",
      chain_id: 1,
      address: ADDR_OUT,
    });
    assert.equal(outOfSet.ok, false, `expected ok:false, got ${JSON.stringify(outOfSet)}`);
    assert.equal(outOfSet.error.details.authority.authority_block_reason, "chain_scope_blocked");
  });
});

test("a companion contract whose chain_id contains a colon is rejected fail-closed (no session)", async () => {
  await withTempHome(async (home) => {
    // The companion is validated BEFORE the primary web session is created, so a
    // colon chain_id (which would desync the CAIP-10 re-parse) fails closed with
    // NO session at all — same guard the contracts-axis init path enforces.
    const env = await executeTool("bob_init_session", {
      target_domain: "example.com",
      target_url: "https://example.com",
      contracts: [{ chain_family: "evm", chain_id: "1:2", address: ADDR_IN }],
    });
    assert.equal(env.ok, false, `expected ok:false, got ${JSON.stringify(env)}`);

    const sessionsRoot = path.join(home, "hacker-bob-sessions");
    let entries = [];
    try {
      entries = fs.readdirSync(sessionsRoot);
    } catch {
      entries = [];
    }
    assert.equal(entries.length, 0, `expected no session created, found ${JSON.stringify(entries)}`);
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
    // so the tuple gate is a no-op and the contracts-axis gate rejects it.
    const chain = await executeTool("bob_evm_fetch_source", {
      target_domain: "example.com",
      chain_id: 1,
      address: ADDR_IN,
    });
    assert.equal(chain.ok, false, JSON.stringify(chain));
    assert.equal(chain.error.code, "SCOPE_BLOCKED");
    assert.equal(chain.error.details.authority.authority_error_code, "session_axis_mismatch");
  });
});

test("a resume (re-init of the same domain with a DIFFERENT companion) does NOT overwrite the bound target_contracts", async () => {
  await withTempHome(async () => {
    // First init binds contract ADDR_IN.
    const first = await executeTool("bob_init_session", {
      target_domain: "example.com",
      target_url: "https://example.com",
      contracts: [{ chain_family: "evm", chain_id: "1", address: ADDR_IN }],
    });
    assert.equal(first.ok, true, `expected ok:true, got ${JSON.stringify(first)}`);
    assert.deepEqual(first.data.target_contracts, [CAIP_IN]);

    // Re-init the SAME domain with a DIFFERENT companion contract. The resume
    // must not overwrite the already-bound chain authority. (The web-axis init
    // refuses to re-create an existing session, so this returns an error rather
    // than silently re-binding.)
    const resume = await executeTool("bob_init_session", {
      target_domain: "example.com",
      target_url: "https://example.com",
      contracts: [{ chain_family: "evm", chain_id: "1", address: ADDR_OUT }],
    });
    assert.equal(resume.ok, false, `expected the resume to be refused, got ${JSON.stringify(resume)}`);

    // The originally-bound scope survives untouched: ADDR_IN, never ADDR_OUT.
    const persisted = readJsonFile(statePath("example.com"), { label: "state.json" });
    assert.deepEqual(persisted.target_contracts, [CAIP_IN],
      `resume must not clobber target_contracts, got ${JSON.stringify(persisted.target_contracts)}`);
  });
});

test("the handler guard skips the companion re-bind when initSession reports created !== true (fail-closed resume)", async () => {
  await withTempHome(async () => {
    // Establish a real session bound to ADDR_IN so a clobber would be observable
    // on disk as target_contracts flipping to ADDR_OUT.
    const first = await executeTool("bob_init_session", {
      target_domain: "example.com",
      target_url: "https://example.com",
      contracts: [{ chain_family: "evm", chain_id: "1", address: ADDR_IN }],
    });
    assert.equal(first.ok, true, `expected ok:true, got ${JSON.stringify(first)}`);
    assert.deepEqual(first.data.target_contracts, [CAIP_IN]);

    // Directly exercise the guard: patch initSession to RETURN created:false
    // (a resume that yields the existing binding instead of throwing), then load
    // a fresh copy of the tool that destructures the patched function. Without
    // the guard this would drive bindContractCompanion (a read-modify-write) and
    // overwrite target_contracts with the ADDR_OUT companion.
    const sessionStateModule = require("../mcp/core/session/session-state.js");
    const original = sessionStateModule.initSession;
    const toolPath = require.resolve("../mcp/tools/init-session.js");
    sessionStateModule.initSession = () => JSON.stringify({
      version: 1,
      created: false,
      session_dir: "example.com",
      state: { target: "example.com" },
    });
    delete require.cache[toolPath];
    try {
      const tool = require("../mcp/tools/init-session.js");
      const out = tool.handler({
        target_domain: "example.com",
        target_url: "https://example.com",
        contracts: [{ chain_family: "evm", chain_id: "1", address: ADDR_OUT }],
      });
      const parsed = JSON.parse(out);
      // The init result is returned UNTOUCHED: no companion projection is added.
      assert.equal(parsed.created, false);
      assert.equal(parsed.target_contracts, undefined,
        `resume must not project a companion binding, got ${JSON.stringify(parsed.target_contracts)}`);
      assert.equal(parsed.seeded_surfaces, undefined);
    } finally {
      sessionStateModule.initSession = original;
      delete require.cache[toolPath];
    }

    // The read-modify-write never ran: the bound scope is still ADDR_IN.
    const persisted = readJsonFile(statePath("example.com"), { label: "state.json" });
    assert.deepEqual(persisted.target_contracts, [CAIP_IN],
      `guard must leave target_contracts bound to ADDR_IN, got ${JSON.stringify(persisted.target_contracts)}`);
  });
});

test("contract identity keys preserve base58/SS58 case and stay consistent across mint + membership", () => {
  const { caip10Endpoint, contractSurfaceId } = require("../mcp/domains/blockchain/contract-target.js");
  const { normalizeOneTuple, isChainTupleInAuthority } = require("../mcp/lib/chain-authority.js");
  // svm (base58, case-SENSITIVE): the minted CAIP-10 endpoint + surface id must
  // PRESERVE case (the pre-fix unconditional lowercase corrupted Solana identity
  // and desynced the persisted target_contracts[] from the membership tuple).
  const svm = { chainFamily: "svm", chainId: "mainnet", address: "AbCdEf1234" };
  assert.equal(caip10Endpoint(svm), "svm:mainnet:AbCdEf1234", "svm caip10 endpoint case-preserved");
  assert.ok(contractSurfaceId(svm).endsWith("AbCdEf1234"), "svm surface id case-preserved");
  // Round-trip: the persisted CAIP-10 string re-parses (normalizeOneTuple) to a tuple
  // that IS in its own authority, and a case-variant svm address is NOT (fail-closed).
  const persisted = caip10Endpoint(svm);
  assert.equal(isChainTupleInAuthority(persisted, [persisted]), true, "persisted svm endpoint self-admits");
  assert.equal(
    isChainTupleInAuthority("svm:mainnet:abcdef1234", [persisted]),
    false,
    "case-variant svm address is NOT admitted (no fail-open collision)",
  );
  // evm (hex, case-INSENSITIVE): still folds, so checksummed and lowercased are one key.
  assert.equal(
    caip10Endpoint({ chainFamily: "evm", chainId: "1", address: "0xABCDEF" }),
    "evm:1:0xabcdef",
    "evm caip10 endpoint case-folded",
  );
});
