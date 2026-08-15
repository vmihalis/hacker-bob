"use strict";

// Pure smart-contract front-door milestone. A contracts-axis target
// (bob_init_contract_session, no URL/repo companion) bootstraps a session, seeds
// >=1 smart_contract surface through the chain funnel WITHOUT running any web
// recon, and drives the SETUP -> OPEN_FRONTIER advance through the REAL
// bob_advance_session dispatch. The governance kernel treats target_contracts as a
// third scope axis, so sessionNucleusFromState projects a contracts-only
// scope_policy (normalizeScopePolicy accepts the contracts axis standing alone),
// the seed gate (seed_surfaces_present) admits the advance purely on the seeded
// contract surfaces, and the nucleus reaches OPEN_FRONTIER. The complementary web
// cases drive the same gate end-to-end through the REAL wrapper across all three
// branches: satisfied (a seeded surface admits the advance), reported_gap (a
// transient/setup state is non-terminal and admits), and a genuine zero-route
// build (refused with seed_surfaces_absent while the nucleus stays SETUP).
//
// The unit cases below pin the kernel rule directly: target_contracts is an
// independent axis that may stand alone or accompany url/repo, url/repo stay
// mutually exclusive, and a supplied-but-invalid target_contracts fails closed.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const { executeTool } = require("../mcp/core/dispatch/dispatch.js");
const { appendFrontierEvent } = require("../mcp/core/frontier/frontier-events.js");
const { normalizeScopePolicy } = require("../mcp/core/governance/index.js");
const {
  attackSurfacePath,
  httpAuditJsonlPath,
} = require("../mcp/core/io/paths.js");

const EVM_CONTRACT = Object.freeze({
  chain_family: "evm",
  chain_id: "1",
  address: "0x0000000000000000000000000000000000000001",
});

// A consistent internal-host policy triple (normalizeScopePolicy validates these
// once a scope axis is present). The web/repo init paths supply these from state;
// the direct unit cases below pass them inline.
const HOST_POLICY = Object.freeze({
  checkpoint_mode: "normal",
  block_internal_hosts: false,
  block_internal_hosts_source: "mode_default",
});

async function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-pure-sc-front-door-"));
  process.env.HOME = home;
  try {
    return await fn(home);
  } finally {
    process.env.HOME = previousHome;
    try { fs.rmSync(home, { recursive: true, force: true }); } catch {}
  }
}

test("a pure contract target seeds a smart_contract surface and bob_advance_session admits SETUP -> OPEN_FRONTIER with no web recon", async () => {
  await withTempHome(async () => {
    const session = await executeTool("bob_init_contract_session", {
      contracts: [EVM_CONTRACT],
    });
    assert.equal(session.ok, true, `expected init ok:true, got ${JSON.stringify(session)}`);

    const domain = session.data.target_domain;
    assert.equal(typeof domain, "string");
    assert.ok(domain.startsWith("sc-evm-1-"), `expected sc-evm-1-<addr8> slug, got ${domain}`);
    assert.ok(Array.isArray(session.data.seeded_surfaces));
    assert.ok(
      session.data.seeded_surfaces.length >= 1,
      `expected >=1 seeded surface, got ${JSON.stringify(session.data.seeded_surfaces)}`,
    );

    // No web recon ran at init: the contract funnel never touches the HTTP audit
    // log or writes a seed-mapping attack_surface.json.
    assert.equal(fs.existsSync(httpAuditJsonlPath(domain)), false, "no http-audit.jsonl for a pure contract target");
    assert.equal(fs.existsSync(attackSurfacePath(domain)), false, "no attack_surface.json for a pure contract target");

    // The REAL dispatch advance: the contracts axis flows through the governance
    // kernel (sessionNucleusFromState -> normalizeScopePolicy accepts a
    // contracts-only scope_policy), the gate's forced materializeFrontier folds the
    // seeded contract surface in, seed_surfaces_present is satisfied, and the
    // advance commits ok:true.
    const advance = await executeTool("bob_advance_session", { target_domain: domain, to_state: "OPEN_FRONTIER" });
    assert.equal(advance.ok, true, `expected advance ok:true, got ${JSON.stringify(advance)}`);
    assert.equal(advance.data.advanced, true);
    assert.equal(advance.data.to_state, "OPEN_FRONTIER");

    // The persisted nucleus reached OPEN_FRONTIER and carries a contracts-only
    // scope_policy (no url/repo companion), read back through the real tool.
    const nucleus = await executeTool("bob_read_session_nucleus", { target_domain: domain });
    assert.equal(nucleus.ok, true, `expected read-nucleus ok:true, got ${JSON.stringify(nucleus)}`);
    assert.equal(nucleus.data.nucleus.lifecycle_state, "OPEN_FRONTIER");
    const scopePolicy = nucleus.data.nucleus.scope_policy;
    assert.equal(scopePolicy.target_url, undefined, "pure contract nucleus carries no target_url");
    assert.equal(scopePolicy.target_repo, undefined, "pure contract nucleus carries no target_repo");
    assert.ok(
      Array.isArray(scopePolicy.target_contracts) && scopePolicy.target_contracts.length >= 1,
      `expected a contracts-axis scope_policy, got ${JSON.stringify(scopePolicy.target_contracts)}`,
    );
    assert.equal(scopePolicy.target_contracts[0].chain_family, "evm");
    assert.equal(scopePolicy.target_contracts[0].chain_id, "1");

    // The materialized frontier routes >=1 smart_contract surface.
    const routed = await executeTool("bob_route_surfaces", { target_domain: domain });
    assert.equal(routed.ok, true, `expected route ok:true, got ${JSON.stringify(routed)}`);
    const routes = await executeTool("bob_read_surface_routes", { target_domain: domain });
    assert.equal(routes.ok, true, `expected read-routes ok:true, got ${JSON.stringify(routes)}`);
    assert.ok(routes.data.routes.length >= 1, `expected >=1 routed surface, got ${JSON.stringify(routes.data.routes)}`);
    assert.ok(
      routes.data.routes.some((r) => r.surface_type === "smart_contract"),
      `expected a routed smart_contract surface, got ${JSON.stringify(routes.data.routes.map((r) => r.surface_type))}`,
    );

    // Still no web recon artifacts after advance + materialize + route: the
    // smart_contract route came from the chain funnel, not from seed mapping.
    assert.equal(fs.existsSync(httpAuditJsonlPath(domain)), false, "no http-audit.jsonl after advance + routing");
    assert.equal(fs.existsSync(attackSurfacePath(domain)), false, "no attack_surface.json after advance + routing");
  });
});

test("normalizeScopePolicy accepts the contracts axis standing alone and rejects an all-garbage target_contracts", () => {
  // Contracts-only: a valid scope_policy with no url/repo, projected to the
  // canonical sorted tuple list (case-folded address, no CAIP-10 string form).
  const soloPolicy = normalizeScopePolicy({
    target_domain: "sc-evm-1-00000000",
    target_contracts: [EVM_CONTRACT],
    ...HOST_POLICY,
  });
  assert.equal(soloPolicy.target_url, undefined);
  assert.equal(soloPolicy.target_repo, undefined);
  assert.deepEqual(soloPolicy.target_contracts, [
    { chain_family: "evm", chain_id: "1", address: "0x0000000000000000000000000000000000000001" },
  ]);

  // The CAIP-10 string form (the shape state.json persists) projects to the same
  // canonical tuple — input shape does not change the result.
  const fromCaip = normalizeScopePolicy({
    target_domain: "sc-evm-1-00000000",
    target_contracts: ["evm:1:0x0000000000000000000000000000000000000001"],
    ...HOST_POLICY,
  });
  assert.deepEqual(fromCaip.target_contracts, soloPolicy.target_contracts);

  // A supplied-but-invalid target_contracts fails CLOSED — never a silent drop to
  // an empty scope.
  assert.throws(
    () => normalizeScopePolicy({ target_domain: "sc-evm-1-00000000", target_contracts: ["garbage"] }),
    /no valid \{chain_family, chain_id, address\} tuple/,
  );
});

test("normalizeScopePolicy treats target_contracts as a companion to url/repo and keeps url/repo mutually exclusive", () => {
  // url + contracts companion: both axes survive.
  const urlCompanion = normalizeScopePolicy({
    target_domain: "example.com",
    target_url: "https://example.com/",
    target_contracts: [EVM_CONTRACT],
    ...HOST_POLICY,
  });
  assert.equal(urlCompanion.target_url, "https://example.com/");
  assert.ok(Array.isArray(urlCompanion.target_contracts) && urlCompanion.target_contracts.length === 1);

  // repo + contracts companion: both axes survive.
  const repoDir = fs.mkdtempSync(path.join(os.tmpdir(), "bob-pure-sc-scope-repo-"));
  try {
    const repoCompanion = normalizeScopePolicy({
      target_domain: "repo-x-deadbeef",
      target_repo: { root_path: repoDir },
      target_contracts: [EVM_CONTRACT],
      ...HOST_POLICY,
    });
    assert.ok(repoCompanion.target_repo && typeof repoCompanion.target_repo.root_path === "string");
    assert.equal(repoCompanion.target_url, undefined);
    assert.ok(Array.isArray(repoCompanion.target_contracts) && repoCompanion.target_contracts.length === 1);

    // url + repo (with or without contracts) is still refused as the not-both case.
    assert.throws(
      () => normalizeScopePolicy({
        target_domain: "example.com",
        target_url: "https://example.com/",
        target_repo: { root_path: repoDir },
        target_contracts: [EVM_CONTRACT],
      }),
      /exactly one of target_url or target_repo, not both/,
    );
  } finally {
    fs.rmSync(repoDir, { recursive: true, force: true });
  }
});

test("SETUP -> OPEN_FRONTIER advances ok:true through the wrapper when a seed surface is routed (satisfied branch)", async () => {
  await withTempHome(async () => {
    const domain = "seeded-frontier.example.com";
    const session = await executeTool("bob_init_session", {
      target_domain: domain,
      target_url: "https://seeded-frontier.example.com/",
    });
    assert.equal(session.ok, true, `expected init ok:true, got ${JSON.stringify(session)}`);

    // A surface.observed frontier event gives the gate a routable seed surface
    // (the gate's forced materializeFrontier folds it into surface-index.json).
    appendFrontierEvent({
      target_domain: domain,
      kind: "surface.observed",
      ts: "2026-06-29T00:00:00.000Z",
      surface_id: "surface:billing",
      payload: {
        title: "Billing API",
        surface_type: "api",
        priority: "HIGH",
        hosts: ["billing.seeded-frontier.example.com"],
        endpoints: ["/api/billing/charge"],
      },
    });

    const advance = await executeTool("bob_advance_session", { target_domain: domain, to_state: "OPEN_FRONTIER" });
    assert.equal(advance.ok, true, `expected advance ok:true, got ${JSON.stringify(advance)}`);
    assert.equal(advance.data.advanced, true);
    assert.equal(advance.data.to_state, "OPEN_FRONTIER");
  });
});

test("SETUP -> OPEN_FRONTIER is blocked with seed_surfaces_absent when routing genuinely yields zero seed surfaces", async () => {
  await withTempHome(async () => {
    const domain = "empty-frontier.example.com";
    const session = await executeTool("bob_init_session", {
      target_domain: domain,
      target_url: "https://empty-frontier.example.com/",
    });
    assert.equal(session.ok, true, `expected init ok:true, got ${JSON.stringify(session)}`);

    // A present-but-empty attack_surface.json is the only shape that produces a
    // genuine zero-route build (route building succeeds and returns []). This is
    // a scratch, agent-writable artifact, so the test writes it directly.
    const surfacePath = attackSurfacePath(domain);
    fs.mkdirSync(path.dirname(surfacePath), { recursive: true });
    fs.writeFileSync(surfacePath, `${JSON.stringify({ surfaces: [] }, null, 2)}\n`, "utf8");

    const advance = await executeTool("bob_advance_session", { target_domain: domain, to_state: "OPEN_FRONTIER" });
    assert.equal(advance.ok, false, `expected advance ok:false, got ${JSON.stringify(advance)}`);
    assert.equal(advance.error.code, "STATE_CONFLICT");
    assert.equal(advance.error.details.code, "seed_surfaces_absent");
    assert.ok(Array.isArray(advance.error.details.blockers));
    assert.equal(advance.error.details.blockers[0].code, "seed_surfaces_absent");

    // The refused advance must not have moved the nucleus off SETUP.
    const nucleus = await executeTool("bob_read_session_nucleus", { target_domain: domain });
    assert.equal(nucleus.ok, true);
    assert.equal(nucleus.data.nucleus.lifecycle_state, "SETUP");
  });
});

test("SETUP -> OPEN_FRONTIER passes on a reported_gap (no surface input materialized yet) - RANK != BOUND", async () => {
  await withTempHome(async () => {
    const domain = "gap-frontier.example.com";
    const session = await executeTool("bob_init_session", {
      target_domain: domain,
      target_url: "https://gap-frontier.example.com/",
    });
    assert.equal(session.ok, true, `expected init ok:true, got ${JSON.stringify(session)}`);

    // No attack_surface.json and no materialized surface index: the precondition
    // maps the missing-surface-input THROW to a non-terminal reported_gap, which
    // the gate treats as PASS (a transient/setup state, never "no surfaces").
    assert.equal(fs.existsSync(attackSurfacePath(domain)), false);

    const advance = await executeTool("bob_advance_session", { target_domain: domain, to_state: "OPEN_FRONTIER" });
    assert.equal(advance.ok, true, `expected reported_gap advance ok:true, got ${JSON.stringify(advance)}`);
    assert.equal(advance.data.advanced, true);
    assert.equal(advance.data.to_state, "OPEN_FRONTIER");
  });
});
