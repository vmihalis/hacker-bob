"use strict";

// Regression suite for the cross-version surface-routes BRICK (harden/session-robustness):
// a route written by a prior framework version (the hunter_agent -> evaluator_agent v2.1 rename)
// must be QUARANTINED on read, not abort the whole read and brick every downstream consumer.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  readSurfaceRoutesStrict,
  routeSurfacesInternal,
  validateSurfaceRoute,
  SURFACE_ROUTES_VERSION,
  SURFACE_ROUTE_VERSION,
} = require("../mcp/lib/surface-router.js");
const { classifySurfaceCapability } = require("../mcp/lib/capability-packs.js");
const { surfaceRoutesPath } = require("../mcp/lib/paths.js");

function withTempHome(fn) {
  const prev = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-surface-router-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    if (prev === undefined) delete process.env.HOME;
    else process.env.HOME = prev;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

// A fully valid current-schema web route (derived, never hardcoded — survives pack edits).
function validWebRoute(surfaceId) {
  const c = classifySurfaceCapability({
    id: surfaceId, surface_type: "web", hosts: [`${surfaceId}.example.test`], endpoints: [`https://${surfaceId}.example.test/a`],
  });
  return {
    surface_id: surfaceId,
    surface_type: c.surface_type,
    capability_pack: c.capability_pack,
    capability_pack_version: c.capability_pack_version,
    evaluator_agent: c.evaluator_agent,
    brief_profile: c.brief_profile,
    context_budget: c.context_budget,
  };
}

// A route exactly as a PRE-rename framework version persisted it: hunter_agent, no evaluator_agent.
function staleHunterRoute(surfaceId) {
  const route = validWebRoute(surfaceId);
  delete route.evaluator_agent;
  route.hunter_agent = "hunter-agent";
  return route;
}

function writeRoutesFile(domain, routes, { version = SURFACE_ROUTES_VERSION, routeVersion = SURFACE_ROUTE_VERSION } = {}) {
  const p = surfaceRoutesPath(domain);
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, `${JSON.stringify({ version, route_version: routeVersion, routes }, null, 2)}\n`);
  return p;
}

test("reader QUARANTINES a stale-schema route (hunter_agent) instead of bricking the whole read", () => withTempHome(() => {
  const domain = "router-stale.example.test";
  writeRoutesFile(domain, [validWebRoute("s1"), staleHunterRoute("s2")]);
  const result = readSurfaceRoutesStrict(domain);
  assert.equal(result.document.routes.length, 1, "the valid route survives");
  assert.equal(result.document.routes[0].surface_id, "s1");
  assert.equal(result.malformed_routes.length, 1);
  assert.equal(result.malformed_routes[0].surface_id, "s2");
  assert.match(result.malformed_routes[0].reason, /evaluator_agent must be a non-empty string/);
  assert.match(result.repair_hint, /bob_route_surfaces/);
}));

test("reader survives an ALL-stale routes file (empty routes + repair hint, no throw = not bricked)", () => withTempHome(() => {
  const domain = "router-allstale.example.test";
  writeRoutesFile(domain, [staleHunterRoute("s1"), staleHunterRoute("s2")]);
  const result = readSurfaceRoutesStrict(domain);
  assert.equal(result.document.routes.length, 0);
  assert.equal(result.malformed_routes.length, 2);
  assert.match(result.repair_hint, /bob_route_surfaces/);
}));

test("reader quarantines a duplicate surface_id (keeps the first occurrence)", () => withTempHome(() => {
  const domain = "router-dupe.example.test";
  writeRoutesFile(domain, [validWebRoute("s1"), validWebRoute("s1")]);
  const result = readSurfaceRoutesStrict(domain);
  assert.equal(result.document.routes.length, 1);
  assert.equal(result.malformed_routes.length, 1);
  assert.match(result.malformed_routes[0].reason, /duplicate surface_id/);
}));

test("reader STILL fails hard on unrecoverable top-level shape (version mismatch)", () => withTempHome(() => {
  const domain = "router-badversion.example.test";
  writeRoutesFile(domain, [validWebRoute("s1")], { routeVersion: SURFACE_ROUTE_VERSION + 1 });
  assert.throws(() => readSurfaceRoutesStrict(domain), /expected versioned routes document/);
}));

test("validateSurfaceRoute rejects an empty evaluator_agent (the validate-on-write guard's mechanism)", () => {
  assert.throws(() => validateSurfaceRoute(staleHunterRoute("s1"), 0, "routes.json"), /evaluator_agent must be a non-empty string/);
});

test("happy path: routeSurfacesInternal writes valid routes that read back cleanly (validate-on-write passes)", () => withTempHome(() => {
  const domain = "router-roundtrip.example.test";
  fs.mkdirSync(path.dirname(surfaceRoutesPath(domain)), { recursive: true });
  const attackSurfaceInfo = { source: "test", document: { surfaces: [
    { id: "s1", surface_type: "web", hosts: ["s1.example.test"], endpoints: ["https://s1.example.test/a"] },
    { id: "s2", surface_type: "web", hosts: ["s2.example.test"], endpoints: ["https://s2.example.test/b"] },
  ] } };
  const written = routeSurfacesInternal(domain, { attackSurfaceInfo });
  assert.equal(written.document.routes.length, 2);
  const read = readSurfaceRoutesStrict(domain);
  assert.equal(read.document.routes.length, 2);
  assert.equal(read.malformed_routes, undefined, "a clean file carries no malformed_routes");
}));
