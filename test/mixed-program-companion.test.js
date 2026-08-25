"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const { executeTool } = require("../mcp/core/dispatch/dispatch.js");
const {
  frontierEventsJsonlPath,
  sessionDir,
  sessionEventsJsonlPath,
  sessionNucleusPath,
  statePath,
} = require("../mcp/core/io/paths.js");
const { readSessionStateStrict } = require("../mcp/core/session/session-state-store.js");
const { readSessionEvents } = require("../mcp/core/session/session-events.js");
const {
  readVerifiedSessionNucleus,
  sessionNucleusFromState,
} = require("../mcp/core/governance/index.js");
const { readFrontierEvents } = require("../mcp/core/frontier/frontier-events.js");
const { deriveRepoTargetDomain } = require("../mcp/core/repo-identity-contracts.js");
const {
  chainAuthorityHash,
  deriveContractSession,
} = require("../mcp/core/chain-authority-contracts.js");
const {
  caip10Endpoint,
  contractSurfaceId,
  prepareContractCompanion,
} = require("../mcp/domains/blockchain/contract-target.js");

const ADDR_A = "0x0000000000000000000000000000000000000001";
const ADDR_B = "0x0000000000000000000000000000000000000002";
const CONTRACT_A = Object.freeze({ chain_family: "evm", chain_id: "1", address: ADDR_A });
const CONTRACT_B = Object.freeze({ chain_family: "evm", chain_id: "1", address: ADDR_B });
const CONTRACTS = Object.freeze([CONTRACT_A, CONTRACT_B]);
const DUPLICATE_ADDR_MIXED = `0x${"aBcD".repeat(10)}`;
const DUPLICATE_ADDR_CANONICAL = DUPLICATE_ADDR_MIXED.toLowerCase();
const DUPLICATE_CONTRACTS = Object.freeze([
  Object.freeze({ chain_family: "evm", chain_id: 1, address: DUPLICATE_ADDR_MIXED }),
  Object.freeze({ chain_family: "evm", chain_id: "1", address: DUPLICATE_ADDR_CANONICAL }),
  Object.freeze({ chain_family: "evm", chain_id: "1", address: DUPLICATE_ADDR_MIXED }),
]);
const DEDUPED_CONTRACT = Object.freeze({
  chain_family: "evm",
  chain_id: "1",
  address: DUPLICATE_ADDR_CANONICAL,
});

async function withTempHome(fn) {
  const prior = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-mixed-companion-"));
  process.env.HOME = home;
  try {
    return await fn(home);
  } finally {
    if (prior === undefined) delete process.env.HOME;
    else process.env.HOME = prior;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function primaryFixture(mode, home, label) {
  if (mode === "web") {
    const domain = `${label}.example.com`;
    return {
      mode,
      domain,
      tool: "bob_init_session",
      args: { target_domain: domain, target_url: `https://${domain}/program` },
    };
  }
  const repoPath = fs.realpathSync(fs.mkdtempSync(path.join(home, `${label}-repo-`)));
  const sentinelPath = path.join(repoPath, "OUTSIDER.txt");
  fs.writeFileSync(sentinelPath, `outside-${label}\n`, "utf8");
  const sentinel = fs.lstatSync(sentinelPath);
  return {
    mode,
    domain: deriveRepoTargetDomain(repoPath),
    tool: "bob_init_repo_session",
    args: { repo_path: repoPath },
    repoPath,
    sentinelPath,
    sentinel,
  };
}

function companionArgs(primary, contracts = CONTRACTS) {
  return { ...primary.args, contracts: contracts.map((entry) => ({ ...entry })) };
}

function rawAuthority(domain) {
  return {
    state: fs.readFileSync(statePath(domain), "utf8"),
    nucleus: fs.readFileSync(sessionNucleusPath(domain), "utf8"),
    events: fs.readFileSync(sessionEventsJsonlPath(domain), "utf8"),
  };
}

function assertRepoUnchanged(primary, expectedBytes) {
  if (primary.mode !== "repo") return;
  assert.deepEqual(fs.readdirSync(primary.repoPath), ["OUTSIDER.txt"]);
  const current = fs.lstatSync(primary.sentinelPath);
  assert.equal(current.dev, primary.sentinel.dev);
  assert.equal(current.ino, primary.sentinel.ino);
  assert.equal(fs.readFileSync(primary.sentinelPath, "utf8"), expectedBytes);
}

function assertNoSessionCreated(primary) {
  assert.equal(fs.existsSync(sessionDir(primary.domain)), false);
  for (const authorityPath of [
    statePath(primary.domain),
    sessionNucleusPath(primary.domain),
    sessionEventsJsonlPath(primary.domain),
    frontierEventsJsonlPath(primary.domain),
  ]) {
    assert.equal(fs.existsSync(authorityPath), false, authorityPath);
  }
}

function primeCachedEvmSource(domain, address) {
  const normalizedAddress = address.toLowerCase();
  const cacheDir = path.join(sessionDir(domain), "contracts", "1", normalizedAddress);
  fs.mkdirSync(cacheDir, { recursive: true });
  fs.writeFileSync(path.join(cacheDir, "source-manifest.json"), `${JSON.stringify({
    chain_id: 1,
    address: normalizedAddress,
    source: "mixed-companion-test-cache",
    files: [],
    total_bytes: 0,
  })}\n`, "utf8");
}

function companionSeedEvents(domain) {
  return readFrontierEvents(domain).filter((event) => (
    event.kind === "surface.observed"
      && event.source
      && event.source.tool === "bob_init_contract_companion"
  ));
}

function expectedSurfaceIds(contracts) {
  return contracts.map((contract) => contractSurfaceId({
    chainFamily: contract.chain_family,
    chainId: contract.chain_id,
    address: contract.address,
  })).sort();
}

function assertExactSeeds(domain, contracts) {
  const events = companionSeedEvents(domain);
  assert.deepEqual(events.map((event) => event.surface_id).sort(), expectedSurfaceIds(contracts));
  assert.equal(new Set(events.map((event) => event.surface_id)).size, contracts.length);
  for (const event of events) {
    assert.equal(event.source.artifact, "session-nucleus.json");
    assert.equal(event.payload.surface_type, "smart_contract");
  }
}

function assertCanonicalAuthority(primary, contracts) {
  const { state } = readSessionStateStrict(primary.domain);
  const verified = readVerifiedSessionNucleus(primary.domain);
  const projected = sessionNucleusFromState(state);
  const prepared = prepareContractCompanion(contracts);
  assert.equal(projected.nucleus_hash, verified.nucleus_hash);
  assert.deepEqual(state.target_contracts, prepared.target_contracts);
  assert.equal(state.chain_authority_hash, prepared.chain_authority_hash);
  assert.equal(verified.scope_policy.chain_authority_hash, prepared.chain_authority_hash);
  assert.equal(chainAuthorityHash(verified.scope_policy.target_contracts), prepared.chain_authority_hash);
  if (primary.mode === "web") {
    assert.equal(state.target_url, primary.args.target_url);
    assert.equal(verified.scope_policy.target_url, primary.args.target_url);
  } else {
    assert.equal(state.target_repo.root_path, primary.repoPath);
    assert.equal(verified.scope_policy.target_repo.root_path, primary.repoPath);
  }
  const initialized = readSessionEvents(primary.domain)
    .filter((event) => event.kind === "governance.session.initialized");
  assert.equal(initialized.length, 1);
  assert.equal(initialized[0].nucleus_hash, verified.nucleus_hash);
  assert.equal(initialized[0].payload.chain_authority_hash, prepared.chain_authority_hash);
  return { state, verified };
}

test("mixed web and repo primaries commit one canonical authority before idempotent companion seeds", async (t) => {
  for (const mode of ["web", "repo"]) {
    await t.test(mode, async () => withTempHome(async (home) => {
      const primary = primaryFixture(mode, home, `fresh-${mode}`);
      const response = await executeTool(primary.tool, companionArgs(primary));
      assert.equal(response.ok, true, JSON.stringify(response));
      assert.equal(response.data.created, true);
      assert.deepEqual(response.data.target_contracts, CONTRACTS.map((contract) => (
        caip10Endpoint({
          chainFamily: contract.chain_family,
          chainId: contract.chain_id,
          address: contract.address,
        })
      )));
      assertCanonicalAuthority(primary, CONTRACTS);
      assertExactSeeds(primary.domain, CONTRACTS);
      const before = rawAuthority(primary.domain);

      const resumed = await executeTool(primary.tool, companionArgs(primary));
      assert.equal(resumed.ok, true, JSON.stringify(resumed));
      assert.equal(resumed.data.created, false);
      assert.deepEqual(rawAuthority(primary.domain), before);
      assertExactSeeds(primary.domain, CONTRACTS);
      assertRepoUnchanged(primary, `outside-fresh-${mode}\n`);
    }));
  }
});

test("mixed web and repo dispatch admit the exact tuple and block an outsider tuple", async (t) => {
  for (const mode of ["web", "repo"]) {
    await t.test(mode, async () => withTempHome(async (home) => {
      const primary = primaryFixture(mode, home, `scope-${mode}`);
      const boot = await executeTool(primary.tool, companionArgs(primary, [CONTRACT_A]));
      assert.equal(boot.ok, true, JSON.stringify(boot));

      // Keep the admitted-handler half of this dispatch proof offline. The
      // authority gate still runs, then the real handler resolves this local
      // verified-source cache instead of contacting Sourcify/Etherscan.
      primeCachedEvmSource(primary.domain, ADDR_A);
      const admitted = await executeTool("bob_evm_fetch_source", {
        target_domain: primary.domain,
        chain_id: 1,
        address: ADDR_A,
      });
      assert.equal(admitted.ok, true, `exact bound tuple must pass the chain gate: ${JSON.stringify(admitted)}`);

      const blocked = await executeTool("bob_evm_fetch_source", {
        target_domain: primary.domain,
        chain_id: 1,
        address: ADDR_B,
      });
      assert.equal(blocked.ok, false, JSON.stringify(blocked));
      assert.equal(blocked.error.code, "SCOPE_BLOCKED");
      assert.equal(blocked.error.details.authority.authority_block_reason, "chain_scope_blocked");
      assertCanonicalAuthority(primary, [CONTRACT_A]);
      assertRepoUnchanged(primary, `outside-scope-${mode}\n`);
    }));
  }
});

test("mixed web and repo reject colon chain ids and malformed addresses before creating a session", async (t) => {
  const invalidCases = [
    {
      name: "colon-chain-id",
      contract: { chain_family: "evm", chain_id: "1:2", address: ADDR_A },
    },
    {
      name: "malformed-address",
      contract: { chain_family: "evm", chain_id: "1", address: "0x1234" },
    },
  ];
  for (const mode of ["web", "repo"]) {
    for (const invalid of invalidCases) {
      await t.test(`${mode}-${invalid.name}`, async () => withTempHome(async (home) => {
        const label = `invalid-${invalid.name}-${mode}`;
        const primary = primaryFixture(mode, home, label);
        const response = await executeTool(primary.tool, companionArgs(primary, [invalid.contract]));
        assert.equal(response.ok, false, JSON.stringify(response));
        assert.equal(response.error.code, "INVALID_ARGUMENTS");
        assertNoSessionCreated(primary);
        assertRepoUnchanged(primary, `outside-${label}\n`);
      }));
    }
  }
});

test("mixed web and repo canonicalize duplicate inputs with retry parity and one seed", async (t) => {
  const pureAuthority = deriveContractSession(DUPLICATE_CONTRACTS);
  const prepared = prepareContractCompanion(DUPLICATE_CONTRACTS);
  assert.equal(prepared.chain_authority_hash, pureAuthority.authorityHash);
  assert.equal(prepared.contracts.length, 1);
  assert.deepEqual(prepared.target_contracts, [`evm:1:${DUPLICATE_ADDR_CANONICAL}`]);

  for (const mode of ["web", "repo"]) {
    await t.test(mode, async () => withTempHome(async (home) => {
      const primary = primaryFixture(mode, home, `dedupe-${mode}`);
      const created = await executeTool(primary.tool, companionArgs(primary, DUPLICATE_CONTRACTS));
      assert.equal(created.ok, true, JSON.stringify(created));
      assert.equal(created.data.created, true);
      assert.deepEqual(created.data.target_contracts, prepared.target_contracts);
      assert.equal(created.data.chain_authority_hash, pureAuthority.authorityHash);
      assert.equal(created.data.seeded_surfaces.length, 1);
      assertCanonicalAuthority(primary, [DEDUPED_CONTRACT]);
      assertExactSeeds(primary.domain, [DEDUPED_CONTRACT]);
      const authorityBefore = rawAuthority(primary.domain);

      const reversed = [...DUPLICATE_CONTRACTS].reverse();
      const resumed = await executeTool(primary.tool, companionArgs(primary, reversed));
      assert.equal(resumed.ok, true, JSON.stringify(resumed));
      assert.equal(resumed.data.created, false);
      assert.deepEqual(resumed.data.target_contracts, prepared.target_contracts);
      assert.deepEqual(rawAuthority(primary.domain), authorityBefore);
      assertExactSeeds(primary.domain, [DEDUPED_CONTRACT]);
      assertRepoUnchanged(primary, `outside-dedupe-${mode}\n`);
    }));
  }
});

test("pure web conflict and pure repo resume remain companion-free", async () => {
  await withTempHome(async (home) => {
    const web = primaryFixture("web", home, "pure-web");
    const webCreated = await executeTool(web.tool, web.args);
    assert.equal(webCreated.ok, true, JSON.stringify(webCreated));
    assert.equal(webCreated.data.target_contracts, undefined);
    const webAgain = await executeTool(web.tool, web.args);
    assert.equal(webAgain.ok, false);
    assert.equal(webAgain.error.code, "STATE_CONFLICT");
    assert.equal(JSON.parse(fs.readFileSync(statePath(web.domain), "utf8")).target_contracts, undefined);

    const repo = primaryFixture("repo", home, "pure-repo");
    const repoCreated = await executeTool(repo.tool, repo.args);
    const repoResumed = await executeTool(repo.tool, repo.args);
    assert.equal(repoCreated.ok, true, JSON.stringify(repoCreated));
    assert.equal(repoCreated.data.created, true);
    assert.equal(repoResumed.ok, true, JSON.stringify(repoResumed));
    assert.equal(repoResumed.data.created, false);
    assert.equal(JSON.parse(fs.readFileSync(statePath(repo.domain), "utf8")).target_contracts, undefined);
    assert.equal(companionSeedEvents(repo.domain).length, 0);

    for (const primary of [web, repo]) {
      const before = rawAuthority(primary.domain);
      const rejectedUpgrade = await executeTool(primary.tool, companionArgs(primary, [CONTRACT_A]));
      assert.equal(rejectedUpgrade.ok, false, JSON.stringify(rejectedUpgrade));
      assert.equal(rejectedUpgrade.error.code, "STATE_CONFLICT");
      assert.deepEqual(rawAuthority(primary.domain), before);
      assert.equal(companionSeedEvents(primary.domain).length, 0);
    }
    assertRepoUnchanged(repo, "outside-pure-repo\n");
  });
});

test("state-only legacy repo resume stays read-only while mixed resume requires verified authority", async () => {
  await withTempHome(async (home) => {
    const primary = primaryFixture("repo", home, "legacy-repo");
    const created = await executeTool(primary.tool, primary.args);
    assert.equal(created.ok, true, JSON.stringify(created));
    const dir = sessionDir(primary.domain);
    const stateFile = statePath(primary.domain);
    for (const name of fs.readdirSync(dir)) {
      if (path.join(dir, name) === stateFile) continue;
      fs.rmSync(path.join(dir, name), { recursive: true, force: true });
    }
    const stateBytes = fs.readFileSync(stateFile);
    const stateIdentity = fs.lstatSync(stateFile);
    assert.deepEqual(fs.readdirSync(dir), [path.basename(stateFile)]);

    const resumed = await executeTool(primary.tool, primary.args);
    assert.equal(resumed.ok, true, JSON.stringify(resumed));
    assert.equal(resumed.data.created, false);
    assert.equal(resumed.data.nucleus_hash, null);
    assert.deepEqual(fs.readdirSync(dir), [path.basename(stateFile)]);
    assert.deepEqual(fs.readFileSync(stateFile), stateBytes);
    const afterResume = fs.lstatSync(stateFile);
    assert.equal(afterResume.dev, stateIdentity.dev);
    assert.equal(afterResume.ino, stateIdentity.ino);

    const rejectedMixed = await executeTool(primary.tool, companionArgs(primary, [CONTRACT_A]));
    assert.equal(rejectedMixed.ok, false, JSON.stringify(rejectedMixed));
    assert.equal(rejectedMixed.error.code, "STATE_CONFLICT");
    assert.match(rejectedMixed.error.message, /verified session nucleus/i);
    assert.deepEqual(fs.readdirSync(dir), [path.basename(stateFile)]);
    assert.deepEqual(fs.readFileSync(stateFile), stateBytes);
    assert.equal(companionSeedEvents(primary.domain).length, 0);
    assertRepoUnchanged(primary, "outside-legacy-repo\n");
  });
});

test("alternate companions conflict without rebinding authority or seeding a new surface", async (t) => {
  for (const mode of ["web", "repo"]) {
    await t.test(mode, async () => withTempHome(async (home) => {
      const primary = primaryFixture(mode, home, `conflict-${mode}`);
      const created = await executeTool(primary.tool, companionArgs(primary, [CONTRACT_A]));
      assert.equal(created.ok, true, JSON.stringify(created));
      const authorityBefore = rawAuthority(primary.domain);
      const frontierBefore = fs.readFileSync(frontierEventsJsonlPath(primary.domain), "utf8");

      const conflict = await executeTool(primary.tool, companionArgs(primary, [CONTRACT_B]));
      assert.equal(conflict.ok, false, JSON.stringify(conflict));
      assert.equal(conflict.error.code, "STATE_CONFLICT");
      assert.deepEqual(rawAuthority(primary.domain), authorityBefore);
      assert.equal(fs.readFileSync(frontierEventsJsonlPath(primary.domain), "utf8"), frontierBefore);
      assertCanonicalAuthority(primary, [CONTRACT_A]);
      assertExactSeeds(primary.domain, [CONTRACT_A]);
      assertRepoUnchanged(primary, `outside-conflict-${mode}\n`);
    }));
  }
});

async function authorityCollision(mode) {
  return withTempHome(async (home) => {
    const primary = primaryFixture(mode, home, `authority-${mode}`);
    const collisionPath = mode === "web"
      ? sessionEventsJsonlPath(primary.domain)
      : sessionNucleusPath(primary.domain);
    const winnerBytes = Buffer.from(`outsider-${mode}\n`);
    const originalLink = fs.linkSync;
    let fired = 0;
    let winner = null;
    fs.linkSync = (source, destination) => {
      if (destination === collisionPath && fired === 0) {
        fired += 1;
        const descriptor = fs.openSync(
          destination,
          fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY | (fs.constants.O_NOFOLLOW || 0),
          0o600,
        );
        try {
          fs.writeSync(descriptor, winnerBytes, 0, winnerBytes.length, 0);
        } finally {
          fs.closeSync(descriptor);
        }
        winner = fs.lstatSync(destination);
        const error = new Error(`outsider collision ${mode}`);
        error.code = "EEXIST";
        throw Object.freeze(error);
      }
      return originalLink(source, destination);
    };
    let response;
    try {
      response = await executeTool(primary.tool, companionArgs(primary));
    } finally {
      fs.linkSync = originalLink;
    }
    assert.equal(response.ok, false, JSON.stringify(response));
    assert.equal(fired, 1);
    const live = fs.lstatSync(collisionPath);
    assert.equal(live.dev, winner.dev);
    assert.equal(live.ino, winner.ino);
    assert.deepEqual(fs.readFileSync(collisionPath), winnerBytes);
    for (const authorityPath of [
      statePath(primary.domain),
      sessionNucleusPath(primary.domain),
      sessionEventsJsonlPath(primary.domain),
    ]) {
      assert.equal(fs.existsSync(authorityPath), authorityPath === collisionPath);
    }
    assert.equal(fs.existsSync(frontierEventsJsonlPath(primary.domain)), false);
    const temps = fs.readdirSync(sessionDir(primary.domain)).filter((name) => name.endsWith(".tmp"));
    assert.deepEqual(temps, []);
    assertRepoUnchanged(primary, `outside-authority-${mode}\n`);
  });
}

test("authority create collisions seed nothing and preserve outsider winners", async (t) => {
  for (const mode of ["web", "repo"]) {
    await t.test(mode, () => authorityCollision(mode));
  }
});

function frozenSeedError(mode, failAt) {
  const error = new Error(`companion seed fault ${mode}/${failAt}`);
  error.code = "EIO";
  return Object.freeze(error);
}

async function seedFailureRetry(mode, failAt) {
  return withTempHome(async (home) => {
    const primary = primaryFixture(mode, home, `seed-${mode}-${failAt}`);
    const frontierPath = frontierEventsJsonlPath(primary.domain);
    const fault = frozenSeedError(mode, failAt);
    const originalAppend = fs.appendFileSync;
    let seedAttempts = 0;
    fs.appendFileSync = (filePath, data, ...rest) => {
      if (filePath === frontierPath && String(data).includes('"tool":"bob_init_contract_companion"')) {
        const attempt = seedAttempts;
        seedAttempts += 1;
        if (attempt === failAt) throw fault;
      }
      return originalAppend(filePath, data, ...rest);
    };
    let failed;
    try {
      failed = await executeTool(primary.tool, companionArgs(primary));
    } finally {
      fs.appendFileSync = originalAppend;
    }
    assert.equal(failed.ok, false, JSON.stringify(failed));
    assert.equal(failed.error.code, "INTERNAL_ERROR");
    assert.equal(failed.error.message, fault.message);
    assert.equal(seedAttempts, failAt + 1);
    assertCanonicalAuthority(primary, CONTRACTS);
    assert.equal(companionSeedEvents(primary.domain).length, failAt);
    const authorityBeforeRetry = rawAuthority(primary.domain);

    const resumed = await executeTool(primary.tool, companionArgs(primary));
    assert.equal(resumed.ok, true, JSON.stringify(resumed));
    assert.equal(resumed.data.created, false);
    assert.deepEqual(rawAuthority(primary.domain), authorityBeforeRetry);
    assertExactSeeds(primary.domain, CONTRACTS);

    const replay = await executeTool(primary.tool, companionArgs(primary));
    assert.equal(replay.ok, true, JSON.stringify(replay));
    assert.equal(replay.data.created, false);
    assert.deepEqual(rawAuthority(primary.domain), authorityBeforeRetry);
    assertExactSeeds(primary.domain, CONTRACTS);
    assertRepoUnchanged(primary, `outside-seed-${mode}-${failAt}\n`);
  });
}

test("each failed companion seed append is completed exactly once by same-binding resume", async (t) => {
  for (const mode of ["web", "repo"]) {
    for (const failAt of [0, 1]) {
      await t.test(`${mode}-seed-${failAt}`, () => seedFailureRetry(mode, failAt));
    }
  }
});

test("companion normalization shares contract-axis authority and preserves case-sensitive identities", () => {
  const lowerHash = chainAuthorityHash([CONTRACT_A]);
  const upper = prepareContractCompanion([
    { chain_family: "EVM", chain_id: "1", address: ADDR_A.toUpperCase().replace("0X", "0x") },
  ]);
  assert.equal(upper.chain_authority_hash, lowerHash);
  assert.deepEqual(upper.target_contracts, [`evm:1:${ADDR_A}`]);

  const svm = { chainFamily: "svm", chainId: "mainnet", address: "AbCdEf1234" };
  assert.equal(caip10Endpoint(svm), "svm:mainnet:AbCdEf1234");
  assert.ok(contractSurfaceId(svm).endsWith("AbCdEf1234"));
});
