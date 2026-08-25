"use strict";

// A8: axes/effect context bound to a VERIFIED SessionNucleus, never raw
// state.json shape or target_domain slug pattern-matching; dispatch.js scopes
// each call inside a Node20 AsyncLocalStorage store; a state-only legacy
// session (state.json present, no session-nucleus.json yet) admits ONLY the
// exact carveout (bob_read_session_state / bob_read_session_nucleus as A6L
// projection reads, bob_advance_session as legacy_migration_only) with no
// axes attached, and every other session-bound tool is blocked pre-handler.
//
// Offline only. No network/Docker.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

require("../mcp/tools/tool-registry.js"); // composition root: installs the tool registry as a side effect

const { executeTool } = require("../mcp/core/dispatch/dispatch.js");
const {
  authorizeToolCall,
} = require("../mcp/core/session/session-authority.js");
const {
  LEGACY_MIGRATION_ONLY_TOOL,
  LEGACY_PROJECTION_READ_TOOLS,
  buildSessionAuthorityContext,
  currentSessionAuthorityContext,
  deriveAxesFromNucleus,
  deriveChainTuplesFromNucleus,
  getOrVerifySessionAuthorityContext,
  hasActiveSessionAuthorityContext,
  runWithSessionAuthorityContext,
  verifySessionAuthorityContext,
} = require("../mcp/core/session/session-authority-context.js");
const {
  readVerifiedSessionNucleus,
} = require("../mcp/core/governance/index.js");
const {
  sessionNucleusPath,
  statePath,
} = require("../mcp/core/io/paths.js");
const { initSession } = require("../mcp/core/session/session-state.js");
const { initRepoSession, readRepoSession } = require("../mcp/domains/repo/repo-target.js");
const setOperatorNoteTool = require("../mcp/tools/set-operator-note.js");
const readSessionStateTool = require("../mcp/tools/read-session-state.js");
const readSessionNucleusTool = require("../mcp/tools/read-session-nucleus.js");
const advanceSessionTool = require("../mcp/tools/advance-session.js");
const httpScanTool = require("../mcp/tools/web/http-scan.js");
const evmCallTool = require("../mcp/tools/blockchain/evm-call.js");
const svmFetchAccountTool = require("../mcp/tools/blockchain/svm-fetch-account.js");
const { sessionChainContext } = require("../mcp/domains/blockchain/chain-tool-identity.js");

async function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-a8-nucleus-binding-"));
  process.env.HOME = home;
  try {
    return await fn(home);
  } finally {
    if (previousHome === undefined) delete process.env.HOME;
    else process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function makeTempRepoDir(prefix = "bob-a8-repo-fixture-") {
  const raw = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  return fs.realpathSync.native ? fs.realpathSync.native(raw) : fs.realpathSync(raw);
}

function initWebDomain(domain) {
  JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}/` }));
}

// ---------------------------------------------------------------------------
// Axis / chain-tuple derivation is nucleus-only
// ---------------------------------------------------------------------------

test("buildSessionAuthorityContext derives the url axis solely from the verified nucleus", async () => {
  await withTempHome(() => {
    const domain = "axis-url.example.com";
    initWebDomain(domain);
    const context = verifySessionAuthorityContext(domain);
    assert.deepEqual(context.axes, ["url"]);
    assert.equal(context.url, `https://${domain}/`);
    assert.equal(context.repo, null);
    assert.equal(context.physical_scope, null);
    assert.deepEqual(context.chain_tuples, []);
  });
});

test("buildSessionAuthorityContext derives the repo axis for a custom operator-supplied slug", async () => {
  await withTempHome(() => {
    const repoPath = makeTempRepoDir();
    const customSlug = "repo-a8-custom-slug";
    const created = initRepoSession({ repo_path: repoPath, target_domain: customSlug });
    assert.equal(created.target_domain, customSlug);
    const context = verifySessionAuthorityContext(customSlug);
    assert.deepEqual(context.axes, ["repo"]);
    assert.equal(context.repo.root_path, repoPath);
    assert.equal(context.repo_hash, created.repo_hash);
    assert.equal(context.url, null);
    // Axis derivation is content-driven, not slug-shape-driven: a session
    // domain that does NOT match the repo-<name>-<sha8> synthetic pattern
    // still resolves the repo axis correctly from the nucleus content.
    const { REPO_TARGET_DOMAIN_PATTERN } = require("../mcp/core/session/session-authority.js");
    assert.equal(REPO_TARGET_DOMAIN_PATTERN.test(customSlug), false);
  });
});

test("buildSessionAuthorityContext derives the contracts axis with exact chain-tuple membership", async () => {
  await withTempHome(async () => {
    const env = await executeTool("bob_init_contract_session", {
      contracts: [{
        chain_family: "evm",
        chain_id: "1",
        address: "0x0000000000000000000000000000000000000002",
      }],
    });
    assert.equal(env.ok, true, JSON.stringify(env));
    const domain = env.data.target_domain;
    const context = verifySessionAuthorityContext(domain);
    assert.deepEqual(context.axes, ["contracts"]);
    assert.deepEqual(context.chain_tuples, [{
      chain_family: "evm",
      chain_id: "1",
      address: "0x0000000000000000000000000000000000000002",
    }]);
    // A tuple NOT bound to the session is absent from context.chain_tuples --
    // exact membership, not a superset/wildcard.
    assert.equal(
      context.chain_tuples.some((t) => t.address === "0x0000000000000000000000000000000000000003"),
      false,
    );
    const nucleus = readVerifiedSessionNucleus(domain);
    assert.deepEqual(deriveChainTuplesFromNucleus(nucleus), context.chain_tuples);
    assert.deepEqual(deriveAxesFromNucleus(nucleus), context.axes);
    // buildSessionAuthorityContext is the pure builder verifySessionAuthorityContext
    // wraps around a verified read -- confirm it reproduces the identical context
    // from that same nucleus object directly.
    assert.deepEqual(buildSessionAuthorityContext(nucleus), context);
  });
});

test("buildSessionAuthorityContext deep-freezes the context (no mutation survives)", async () => {
  await withTempHome(() => {
    const domain = "axis-freeze.example.com";
    initWebDomain(domain);
    const context = verifySessionAuthorityContext(domain);
    assert.equal(Object.isFrozen(context), true);
    assert.equal(Object.isFrozen(context.axes), true);
    assert.throws(() => { context.axes.push("repo"); }, TypeError);
    assert.throws(() => { context.url = "https://forged.example.com/"; }, TypeError);
    assert.equal(context.url, `https://${domain}/`);
  });
});

test("a present-but-tampered nucleus hard-fails and never falls back to raw state", async () => {
  await withTempHome(() => {
    const domain = "axis-tampered.example.com";
    initWebDomain(domain);
    const nucleus = JSON.parse(fs.readFileSync(sessionNucleusPath(domain), "utf8"));
    nucleus.lifecycle_state = "GRADE"; // mutate without recomputing nucleus_hash
    fs.writeFileSync(sessionNucleusPath(domain), `${JSON.stringify(nucleus, null, 2)}\n`, "utf8");
    assert.throws(() => verifySessionAuthorityContext(domain), /nucleus_hash does not match/);
    assert.throws(
      () => authorizeToolCall(httpScanTool, { target_domain: domain, method: "GET", url: `https://${domain}/` }),
      (error) => error.authority && error.authority.authority_error_code === "nucleus_unverifiable",
    );
  });
});

// ---------------------------------------------------------------------------
// AsyncLocalStorage scope: throws outside, null is a legitimate scope,
// concurrent calls never cross
// ---------------------------------------------------------------------------

test("currentSessionAuthorityContext throws outside any active scope", () => {
  assert.equal(hasActiveSessionAuthorityContext(), false);
  assert.throws(() => currentSessionAuthorityContext(), /no active session authority context/);
});

test("runWithSessionAuthorityContext(null, fn) is a legitimate context-free scope, not an error", async () => {
  const observed = await runWithSessionAuthorityContext(null, async () => {
    assert.equal(hasActiveSessionAuthorityContext(), true);
    return currentSessionAuthorityContext();
  });
  assert.equal(observed, null);
  assert.equal(hasActiveSessionAuthorityContext(), false);
});

test("concurrent scoped calls on different domains never observe each other's context", async () => {
  await withTempHome(async () => {
    const domainA = "concurrent-a.example.com";
    const domainB = "concurrent-b.example.com";
    initWebDomain(domainA);
    initWebDomain(domainB);
    const contextA = verifySessionAuthorityContext(domainA);
    const contextB = verifySessionAuthorityContext(domainB);

    const observedA = [];
    const observedB = [];
    const runA = runWithSessionAuthorityContext(contextA, async () => {
      observedA.push(currentSessionAuthorityContext().target_domain);
      await new Promise((resolve) => setImmediate(resolve));
      observedA.push(currentSessionAuthorityContext().target_domain);
    });
    const runB = runWithSessionAuthorityContext(contextB, async () => {
      observedB.push(currentSessionAuthorityContext().target_domain);
      await new Promise((resolve) => setImmediate(resolve));
      observedB.push(currentSessionAuthorityContext().target_domain);
    });
    await Promise.all([runA, runB]);
    assert.deepEqual(observedA, [domainA, domainA]);
    assert.deepEqual(observedB, [domainB, domainB]);
    assert.equal(hasActiveSessionAuthorityContext(), false);
  });
});

// ---------------------------------------------------------------------------
// Dispatch-vs-direct-call resolver: reuse the active scope, fresh-verify
// otherwise, never cross a mismatched domain
// ---------------------------------------------------------------------------

test("getOrVerifySessionAuthorityContext reuses the active ALS context for a matching domain", async () => {
  await withTempHome(async () => {
    const domain = "reuse-match.example.com";
    initWebDomain(domain);
    const scoped = verifySessionAuthorityContext(domain);
    await runWithSessionAuthorityContext(scoped, async () => {
      const resolved = getOrVerifySessionAuthorityContext(domain);
      assert.equal(resolved, scoped, "must return the SAME frozen object, not a fresh read");
    });
  });
});

test("getOrVerifySessionAuthorityContext fresh-verifies for a direct (non-dispatched) call with no active scope", async () => {
  await withTempHome(() => {
    const domain = "direct-call.example.com";
    initWebDomain(domain);
    assert.equal(hasActiveSessionAuthorityContext(), false);
    const resolved = getOrVerifySessionAuthorityContext(domain);
    assert.equal(resolved.target_domain, domain);
    assert.deepEqual(resolved.axes, ["url"]);
  });
});

test("getOrVerifySessionAuthorityContext fresh-verifies (never cross-reuses) when the active scope is for a different domain", async () => {
  await withTempHome(async () => {
    const domainA = "mismatch-a.example.com";
    const domainB = "mismatch-b.example.com";
    initWebDomain(domainA);
    initWebDomain(domainB);
    const scopedA = verifySessionAuthorityContext(domainA);
    await runWithSessionAuthorityContext(scopedA, async () => {
      const resolved = getOrVerifySessionAuthorityContext(domainB);
      assert.equal(resolved.target_domain, domainB);
      assert.notEqual(resolved, scopedA);
    });
  });
});

test("readRepoSession consumes the current dispatch-scoped context when available", async () => {
  await withTempHome(async () => {
    const repoPath = makeTempRepoDir();
    const created = initRepoSession({ repo_path: repoPath });
    const context = verifySessionAuthorityContext(created.target_domain);
    await runWithSessionAuthorityContext(context, async () => {
      const read = readRepoSession(created.target_domain);
      assert.equal(read.target_domain, created.target_domain);
      assert.equal(read.repo_hash, created.repo_hash);
    });
    // Direct (non-dispatched) call still fresh-verifies correctly.
    assert.equal(hasActiveSessionAuthorityContext(), false);
    const direct = readRepoSession(created.target_domain);
    assert.equal(direct.repo_hash, created.repo_hash);
  });
});

// ---------------------------------------------------------------------------
// State-only legacy carveout: EXACT, not per-tool special-casing
// ---------------------------------------------------------------------------

test("a state-only legacy session admits exactly the two A6L projection reads with no axes attached", async () => {
  await withTempHome(() => {
    const domain = "legacy-carveout-reads.example.com";
    initWebDomain(domain);
    fs.unlinkSync(sessionNucleusPath(domain));

    for (const toolName of LEGACY_PROJECTION_READ_TOOLS) {
      const tool = toolName === "bob_read_session_state" ? readSessionStateTool : readSessionNucleusTool;
      const decision = authorizeToolCall(tool, { target_domain: domain });
      assert.equal(decision.authority_result, "allowed", toolName);
      assert.equal(decision.authority_source, "legacy_state_projection", toolName);
    }
  });
});

test("a state-only legacy session admits bob_advance_session tagged legacy_migration_only (gate passes, handler still fails closed)", async () => {
  await withTempHome(async () => {
    const domain = "legacy-carveout-advance.example.com";
    initWebDomain(domain);
    fs.unlinkSync(sessionNucleusPath(domain));

    assert.equal(advanceSessionTool.name, LEGACY_MIGRATION_ONLY_TOOL);
    const decision = authorizeToolCall(advanceSessionTool, { target_domain: domain, to_state: "OPEN_FRONTIER" });
    assert.equal(decision.authority_result, "allowed");
    assert.equal(decision.authority_source, "legacy_migration_only");

    // The GATE passes it through with no axes; the HANDLER (owned outside this
    // node -- session-state.js's advanceSession) independently fails closed on
    // the missing verified nucleus. Both facts together prove the carveout is
    // gate-level-only, never a silent grant of migration authority.
    const env = await executeTool("bob_advance_session", { target_domain: domain, to_state: "OPEN_FRONTIER" });
    assert.equal(env.ok, false);
    assert.match(env.error.message, /nucleus missing or unverifiable/);
  });
});

test("every other registry-enumerated session-bound tool is blocked pre-handler for a state-only legacy session", async () => {
  await withTempHome(async () => {
    const domain = "legacy-carveout-blocked.example.com";
    initWebDomain(domain);
    fs.unlinkSync(sessionNucleusPath(domain));

    // A representative spread across authority classes: scoped_http_network,
    // initialized_session_mutation -- neither is the carveout, so both must be
    // blocked at the GATE (never reaching the handler) with the exact carveout
    // error code, before any axis/effect context is attached.
    for (const tool of [httpScanTool, setOperatorNoteTool]) {
      let caught = null;
      try {
        authorizeToolCall(tool, {
          target_domain: domain,
          method: "GET",
          url: `https://${domain}/`,
          operator_note: "x",
        });
      } catch (error) {
        caught = error;
      }
      assert.ok(caught, `${tool.name} must be blocked`);
      assert.equal(caught.authority.authority_result, "blocked", tool.name);
      assert.equal(caught.authority.authority_error_code, "legacy_session_axis_carveout", tool.name);
      assert.equal(caught.authority.authority_session_present, true, tool.name);
    }

    // Confirmed through the real dispatch entrypoint too, pre-handler (the
    // handler never runs -- no state.json/nucleus mutation results).
    const beforeState = fs.readFileSync(require("../mcp/core/io/paths.js").statePath(domain), "utf8");
    const env = await executeTool("bob_set_operator_note", { target_domain: domain, operator_note: "should not land" });
    assert.equal(env.ok, false);
    assert.equal(env.error.code, "SCOPE_BLOCKED");
    const afterState = fs.readFileSync(require("../mcp/core/io/paths.js").statePath(domain), "utf8");
    assert.equal(afterState, beforeState, "the legacy carveout blocks pre-handler: state.json is untouched");
  });
});

test("missing-both (no state, no nucleus) retains the existing acknowledged shadow behavior, unmodified by A8", async () => {
  await withTempHome(() => {
    const domain = "never-existed.example.com";
    assert.throws(
      () => authorizeToolCall(readSessionStateTool, { target_domain: domain }),
      (error) => error.authority && error.authority.authority_error_code === "no_session",
    );
  });
});

// ---------------------------------------------------------------------------
// Modern (nucleus-present) grants are unaffected by the legacy carveout
// ---------------------------------------------------------------------------

test("a modern nucleus-bound session still grants its axis normally through the real dispatch entrypoint", async () => {
  await withTempHome(async () => {
    const repoPath = makeTempRepoDir();
    const created = initRepoSession({ repo_path: repoPath });
    const env = await executeTool("bob_repo_check", {
      target_domain: created.target_domain,
      check_type: "file_exists",
      file_path: "does-not-exist.txt",
    });
    assert.equal(env.ok, true, JSON.stringify(env));
  });
});

// ---------------------------------------------------------------------------
// Chain-scope gate (authorizeChainScope / CHAIN_SCOPE_TUPLE_BY_TOOL): the
// contracts-axis membership check for bob_evm_call/bob_svm_fetch_account/etc.
// must resolve exclusively from the verified nucleus, with the SAME
// nucleus-absent-legacy-carveout and nucleus-present-hard-fail posture as the
// url/repo/contracts axes above -- never an independent grant sourced from
// raw state.json's target_contracts[].
// ---------------------------------------------------------------------------

const EVM_BOUND_ADDRESS = "0x0000000000000000000000000000000000000002";
const EVM_UNBOUND_ADDRESS = "0x0000000000000000000000000000000000000099";
const SVM_BOUND_ADDRESS = "1".repeat(32);

test("a state-only legacy contracts session never independently grants bob_evm_call/bob_svm_fetch_account from raw state; falls through to the exact legacy carveout", async () => {
  await withTempHome(async () => {
    const env = await executeTool("bob_init_contract_session", {
      contracts: [
        { chain_family: "evm", chain_id: "1", address: EVM_BOUND_ADDRESS },
        { chain_family: "svm", chain_id: "mainnet-beta", address: SVM_BOUND_ADDRESS },
      ],
    });
    assert.equal(env.ok, true, JSON.stringify(env));
    const domain = env.data.target_domain;

    // Confirm raw state.json really does carry the matching target_contracts --
    // this is the exact bypass surface: a raw reader would see this and grant,
    // which is precisely what must NOT happen once the nucleus is gone.
    const rawState = JSON.parse(fs.readFileSync(statePath(domain), "utf8"));
    assert.equal(rawState.target_contracts.length, 2);

    fs.unlinkSync(sessionNucleusPath(domain));

    const calls = [
      [evmCallTool, { target_domain: domain, chain_id: 1, to: EVM_BOUND_ADDRESS, data: "0x" }],
      [svmFetchAccountTool, { target_domain: domain, cluster: "mainnet-beta", pubkey: SVM_BOUND_ADDRESS }],
    ];
    for (const [tool, args] of calls) {
      let caught = null;
      try {
        authorizeToolCall(tool, args);
      } catch (error) {
        caught = error;
      }
      assert.ok(caught, `${tool.name} must be blocked`);
      assert.equal(caught.authority.authority_result, "blocked", tool.name);
      assert.equal(caught.authority.authority_error_code, "legacy_session_axis_carveout", tool.name);
      assert.equal(caught.authority.authority_session_present, true, tool.name);
    }

    // Confirmed through the real dispatch entrypoint too, pre-handler -- no RPC
    // call is attempted (offline).
    const dispatchEnv = await executeTool("bob_evm_call", {
      target_domain: domain,
      chain_id: 1,
      to: EVM_BOUND_ADDRESS,
      data: "0x",
    });
    assert.equal(dispatchEnv.ok, false);
    assert.equal(dispatchEnv.error.code, "SCOPE_BLOCKED");
  });
});

test("a present-but-tampered nucleus for a contracts-axis session hard-fails bob_evm_call; never falls back to raw state", async () => {
  await withTempHome(async () => {
    const env = await executeTool("bob_init_contract_session", {
      contracts: [{ chain_family: "evm", chain_id: "1", address: EVM_BOUND_ADDRESS }],
    });
    assert.equal(env.ok, true, JSON.stringify(env));
    const domain = env.data.target_domain;

    const nucleus = JSON.parse(fs.readFileSync(sessionNucleusPath(domain), "utf8"));
    nucleus.lifecycle_state = "GRADE"; // mutate without recomputing nucleus_hash
    fs.writeFileSync(sessionNucleusPath(domain), `${JSON.stringify(nucleus, null, 2)}\n`, "utf8");

    assert.throws(
      () => authorizeToolCall(evmCallTool, { target_domain: domain, chain_id: 1, to: EVM_BOUND_ADDRESS, data: "0x" }),
      (error) => error.authority && error.authority.authority_error_code === "nucleus_unverifiable",
    );
  });
});

test("a nucleus/state-diverged contracts session resolves chain-tuple membership from the verified nucleus, not raw state", async () => {
  await withTempHome(async () => {
    const env = await executeTool("bob_init_contract_session", {
      contracts: [{ chain_family: "evm", chain_id: "1", address: EVM_BOUND_ADDRESS }],
    });
    assert.equal(env.ok, true, JSON.stringify(env));
    const domain = env.data.target_domain;

    // Mutate raw state.json's target_contracts to a DIFFERENT address, leaving
    // the nucleus (still bound to EVM_BOUND_ADDRESS) untouched and verifiable.
    const rawState = JSON.parse(fs.readFileSync(statePath(domain), "utf8"));
    assert.deepEqual(rawState.target_contracts, [`evm:1:${EVM_BOUND_ADDRESS}`]);
    rawState.target_contracts = [`evm:1:${EVM_UNBOUND_ADDRESS}`];
    fs.writeFileSync(statePath(domain), `${JSON.stringify(rawState, null, 2)}\n`, "utf8");

    // The nucleus's bound address is still granted, even though raw state.json
    // no longer lists it.
    const grantedDecision = authorizeToolCall(evmCallTool, {
      target_domain: domain,
      chain_id: 1,
      to: EVM_BOUND_ADDRESS,
      data: "0x",
    });
    assert.equal(grantedDecision.authority_result, "allowed");
    assert.equal(grantedDecision.authority_source, "session_state");

    // The raw-state-only address is BLOCKED, even though raw state.json now
    // lists it -- membership must come from the verified nucleus, not raw state.
    assert.throws(
      () => authorizeToolCall(evmCallTool, {
        target_domain: domain,
        chain_id: 1,
        to: EVM_UNBOUND_ADDRESS,
        data: "0x",
      }),
      (error) => error.authority && error.authority.authority_error_code === "chain_scope_blocked",
    );
  });
});

test("a valid verified nucleus with bound target_contracts grants exact-tuple chain-tool reads with no regression of the integrated axis work", async () => {
  await withTempHome(async () => {
    const env = await executeTool("bob_init_contract_session", {
      contracts: [{ chain_family: "evm", chain_id: "1", address: EVM_BOUND_ADDRESS }],
    });
    assert.equal(env.ok, true, JSON.stringify(env));
    const domain = env.data.target_domain;

    const decision = authorizeToolCall(evmCallTool, {
      target_domain: domain,
      chain_id: 1,
      to: EVM_BOUND_ADDRESS,
      data: "0x",
    });
    assert.equal(decision.authority_result, "allowed");
    assert.equal(decision.authority_target_domain, domain);

    assert.throws(
      () => authorizeToolCall(evmCallTool, {
        target_domain: domain,
        chain_id: 1,
        to: EVM_UNBOUND_ADDRESS,
        data: "0x",
      }),
      (error) => error.authority && error.authority.authority_error_code === "chain_scope_blocked",
    );
  });
});

// A8C: sessionChainContext must be the SAME normalization path as
// buildSessionAuthorityContext -- not a second, independent
// deriveChainTuplesFromNucleus call site. Reference identity (not just
// deepEqual) is the only assertion that actually proves this: a duplicate
// derive over the same nucleus would still pass a deepEqual check.
test("sessionChainContext consumes the dispatch-scoped authority context's chain_tuples by reference, not a re-derived array", async () => {
  await withTempHome(async () => {
    const env = await executeTool("bob_init_contract_session", {
      contracts: [{ chain_family: "evm", chain_id: "1", address: EVM_BOUND_ADDRESS }],
    });
    assert.equal(env.ok, true, JSON.stringify(env));
    const domain = env.data.target_domain;

    const activeContext = verifySessionAuthorityContext(domain);
    await runWithSessionAuthorityContext(activeContext, async () => {
      const chainContext = sessionChainContext(domain);
      assert.equal(chainContext.target_contracts, activeContext.chain_tuples);
    });
  });
});
