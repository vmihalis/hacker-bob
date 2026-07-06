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
  buildSurfaceRoutesDocument,
  readSurfaceRoutesStrict,
  routeSurfaces,
  routeSurfacesInternal,
  validateSurfaceRoute,
  isUnroutableRoute,
  countRoutesByCapabilityPack,
  deriveUnroutableSurfacesFromRoutes,
  SURFACE_ROUTES_VERSION,
  SURFACE_ROUTE_VERSION,
} = require("../mcp/lib/surface-router.js");
const { classifySurfaceCapability } = require("../mcp/lib/capability-packs.js");
const { appendFrontierEvent } = require("../mcp/lib/frontier-events.js");
const { findRoutedSurface } = require("../mcp/lib/offensive-http-common.js");
// S1 detector is injected into routing by the tool handler; tests inject it too.
const { surfaceExposesIdBearingCollection: idBearingDetector } = require("../mcp/lib/offensive-idor-producer.js");
const { surfaceRoutesPath, attackSurfacePath } = require("../mcp/lib/paths.js");

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

test("validateSurfaceRoute signals DATA failures with a PLAIN Error (premise of the quarantine-vs-rethrow guard)", () => {
  // readSurfaceRoutesStrict quarantines a plain Error (stale/malformed DATA) but RE-THROWS a JS error
  // subclass (TypeError/RangeError/…), which can only come from a validator CODE bug. That discriminator
  // is only safe while every data-validation failure is a plain Error — pin it here, so a future refactor
  // that threw e.g. a TypeError on bad data (which the guard would then wrongly re-throw and re-brick the
  // read) fails this test loudly instead.
  try {
    validateSurfaceRoute(staleHunterRoute("s1"), 0, "routes.json");
    assert.fail("expected validateSurfaceRoute to throw on a stale route");
  } catch (error) {
    assert.equal(error.constructor, Error, "a data-validation failure must be a plain Error (so it is quarantined, not re-thrown)");
  }
});

test("buildSurfaceRoutesDocument marks id-bearing routable surfaces when multiple auth profiles exist", () => {
  const domain = "router-auth-diff-id.example.test";
  const attackSurfaceInfo = { source: "test", document: { surfaces: [
    { id: "users:item", surface_type: "api", hosts: ["api.example.test"], endpoints: ["/api/users/1"] },
  ] } };
  const doc = buildSurfaceRoutesDocument(domain, { attackSurfaceInfo, authProfileCount: 2, idBearingDetector });
  assert.equal(doc.routes.length, 1);
  assert.equal(doc.routes[0].auth_differential_required, true);
});

test("buildSurfaceRoutesDocument accepts route-parameter item endpoints for auth-differential routing", () => {
  const domain = "router-auth-diff-param.example.test";
  const attackSurfaceInfo = { source: "test", document: { surfaces: [
    { id: "users:param", surface_type: "api", hosts: ["api.example.test"], endpoints: ["/api/users/{id}"] },
  ] } };
  const doc = buildSurfaceRoutesDocument(domain, { attackSurfaceInfo, authProfileCount: 2, idBearingDetector });
  assert.equal(doc.routes[0].auth_differential_required, true);
});

test("buildSurfaceRoutesDocument keeps id-bearing surfaces vacuous with one auth profile", () => {
  const domain = "router-auth-diff-one-profile.example.test";
  const attackSurfaceInfo = { source: "test", document: { surfaces: [
    { id: "users:item", surface_type: "api", hosts: ["api.example.test"], endpoints: ["/api/users/1"] },
  ] } };
  const doc = buildSurfaceRoutesDocument(domain, { attackSurfaceInfo, authProfileCount: 1, idBearingDetector });
  assert.equal(doc.routes[0].auth_differential_required, false);
});

test("buildSurfaceRoutesDocument keeps collection-only surfaces vacuous with multiple auth profiles", () => {
  const domain = "router-auth-diff-collection.example.test";
  const attackSurfaceInfo = { source: "test", document: { surfaces: [
    { id: "users:collection", surface_type: "api", hosts: ["api.example.test"], endpoints: ["/api/users"] },
  ] } };
  const doc = buildSurfaceRoutesDocument(domain, { attackSurfaceInfo, authProfileCount: 2, idBearingDetector });
  assert.equal(doc.routes[0].auth_differential_required, false);
});

test("buildSurfaceRoutesDocument defaults auth-differential routing to false on clean legacy-shaped input", () => {
  const domain = "router-auth-diff-default.example.test";
  const attackSurfaceInfo = { source: "test", document: { surfaces: [
    { id: "legacy:api", surface_type: "api", hosts: ["api.example.test"], endpoints: ["/api/users"] },
  ] } };
  const doc = buildSurfaceRoutesDocument(domain, { attackSurfaceInfo });
  assert.equal(doc.routes[0].auth_differential_required, false);
});

test("validateSurfaceRoute round-trips auth_differential_required and rejects non-boolean values", () => {
  const route = { ...validWebRoute("s1"), auth_differential_required: true };
  const normalized = validateSurfaceRoute(route, 0, "routes.json");
  assert.equal(normalized.auth_differential_required, true);

  assert.throws(
    () => validateSurfaceRoute({ ...route, auth_differential_required: "true" }, 0, "routes.json"),
    /auth_differential_required must be a boolean/,
  );
});

test("findRoutedSurface rejects a surface whose route was quarantined even if a valid duplicate exists (no split authority)", () => withTempHome(() => {
  const domain = "router-splitauth.example.test";
  // surface:api appears twice: a valid route + a stale (hunter_agent) duplicate. The reader keeps
  // the valid one and quarantines the stale one. findRoutedSurface must REJECT (mirroring
  // getContextBudget) — the file is corrupt, so an offensive probe must not proceed on it.
  writeRoutesFile(domain, [validWebRoute("surface:api"), staleHunterRoute("surface:api")]);
  assert.throws(() => findRoutedSurface(domain, "surface:api"), /malformed route/);
}));

test("findRoutedSurface rejection cannot be evaded by a whitespace-padded quarantined surface_id (trimmed on store)", () => withTempHome(() => {
  const domain = "router-wspad.example.test";
  // A valid route for "surface:api" plus a stale duplicate whose surface_id kept whitespace padding.
  // validateSurfaceRoute trims on the valid path, so the lookup id is "surface:api"; the quarantined
  // entry must ALSO be trimmed or its `=== surfaceId` match fails and the corruption-rejection is evaded.
  const padded = staleHunterRoute("surface:api");
  padded.surface_id = "  surface:api  ";
  writeRoutesFile(domain, [validWebRoute("surface:api"), padded]);
  const read = readSurfaceRoutesStrict(domain);
  assert.equal(read.malformed_routes.length, 1);
  assert.equal(read.malformed_routes[0].surface_id, "surface:api", "stored malformed surface_id is trimmed");
  assert.throws(() => findRoutedSurface(domain, "surface:api"), /malformed route/, "padded quarantined dupe must not evade rejection");
}));

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

test("persists chain_family + confidence for a resolved EVM smart-contract route", () => withTempHome(() => {
  const domain = "router-sc-evm.example.test";
  fs.mkdirSync(path.dirname(surfaceRoutesPath(domain)), { recursive: true });
  const surface = { id: "sc-evm", surface_type: "smart_contract", chain_family: "evm", address: "0xabc" };
  const expected = classifySurfaceCapability(surface);
  const attackSurfaceInfo = { source: "test", document: { surfaces: [surface] } };
  routeSurfacesInternal(domain, { attackSurfaceInfo });
  const read = readSurfaceRoutesStrict(domain);
  assert.equal(read.malformed_routes, undefined, "a resolved SC route reads back clean");
  const route = read.document.routes.find((r) => r.surface_id === "sc-evm");
  assert.ok(route, "the evm route reads back in document.routes");
  assert.equal(route.chain_family, expected.chain_family, "chain_family is persisted from the classifier (closes the always-null read)");
  assert.equal(route.chain_family, "evm");
  assert.ok(route.confidence, "confidence is truthy");
  assert.equal(route.confidence, expected.confidence);
}));

test("records an unroutable disposition for an unknown-chain_family smart-contract surface (never web-routed, no throw)", () => withTempHome(() => {
  const domain = "router-sc-unknown.example.test";
  fs.mkdirSync(path.dirname(surfaceRoutesPath(domain)), { recursive: true });
  const webPackId = classifySurfaceCapability({ id: "w", surface_type: "web" }).capability_pack;
  const cases = [
    { id: "sc-unknown", surface_type: "smart_contract", chain_family: "quantum" },
    { id: "sc-nofam", surface_type: "smart_contract" },
  ];
  for (const surface of cases) {
    const attackSurfaceInfo = { source: "test", document: { surfaces: [surface] } };
    assert.doesNotThrow(() => routeSurfacesInternal(domain, { attackSurfaceInfo }), "an unroutable SC surface never halts routing");
    const read = readSurfaceRoutesStrict(domain);
    assert.equal(read.malformed_routes, undefined, "an unroutable route reads back in document.routes, not malformed_routes");
    const route = read.document.routes.find((r) => r.surface_id === surface.id);
    assert.ok(route, "the unroutable route is present in document.routes");
    assert.equal(route.disposition, "unroutable");
    assert.equal(typeof route.reason, "string");
    assert.ok(route.reason.length > 0, "the unroutable route carries an evidenced reason");
    assert.equal(route.capability_pack, undefined, "an ambiguous smart_contract is never web-routed");
    assert.notEqual(route.capability_pack, webPackId);
  }
}));

test("a resolved SC route and an unroutable SC route read back cleanly together (no quarantine)", () => withTempHome(() => {
  const domain = "router-sc-mixed.example.test";
  fs.mkdirSync(path.dirname(surfaceRoutesPath(domain)), { recursive: true });
  const attackSurfaceInfo = { source: "test", document: { surfaces: [
    { id: "sc-evm", surface_type: "smart_contract", chain_family: "evm", address: "0xabc" },
    { id: "sc-unknown", surface_type: "smart_contract", chain_family: "quantum" },
    { id: "w1", surface_type: "web", hosts: ["w1.example.test"], endpoints: ["https://w1.example.test/a"] },
  ] } };
  routeSurfacesInternal(domain, { attackSurfaceInfo });
  const read = readSurfaceRoutesStrict(domain);
  assert.equal(read.malformed_routes, undefined, "the mixed file has no quarantined routes");
  assert.equal(read.document.routes.length, 3);
}));

// A capability_friction_observed frontier event scoped to one surface_id
// (mirrors the frictionEvent(...) shape in frontier-friction-predicate.test.js).
function frictionEvent(surfaceId, frictionKind, extra = {}) {
  return {
    kind: "observation.recorded",
    payload: {
      observation_kind: "capability_friction_observed",
      surface_id: surfaceId,
      friction_kind: frictionKind,
      ...extra,
    },
  };
}

// The confidence ordinal ladder, mirrored from capability-packs.js, so the
// caller-seam tests derive the demoted step from the classifier rather than
// hardcoding a level a pack edit could break.
const ROUTER_CONFIDENCE_LADDER = ["high", "medium", "low"];

test("buildSurfaceRoutesDocument: no frictionEvents keeps the classifier confidence (back-compat)", () => {
  const domain = "router-friction-none.example.test";
  // surface_type "api" is a known web type => classifier confidence "high".
  const surface = { id: "w1", surface_type: "api", hosts: ["w1.example.test"], endpoints: ["https://w1.example.test/a"] };
  const classification = classifySurfaceCapability(surface);
  assert.equal(classification.routable, true);
  const attackSurfaceInfo = { source: "test", document: { surfaces: [surface] } };
  const doc = buildSurfaceRoutesDocument(domain, { attackSurfaceInfo });
  assert.equal(doc.routes.length, 1);
  assert.equal(doc.routes[0].confidence, classification.confidence);
});

test("buildSurfaceRoutesDocument: >=3 tool_inadequate events for a surface demote its route confidence one step", () => {
  const domain = "router-friction-demote.example.test";
  const surface = { id: "w1", surface_type: "api", hosts: ["w1.example.test"], endpoints: ["https://w1.example.test/a"] };
  const classification = classifySurfaceCapability(surface);
  const baseIdx = ROUTER_CONFIDENCE_LADDER.indexOf(classification.confidence);
  assert.ok(baseIdx >= 0, "classifier confidence is on the ladder");
  assert.ok(baseIdx < ROUTER_CONFIDENCE_LADDER.length - 1, "base has room to demote one step (guards the assertion)");
  const attackSurfaceInfo = { source: "test", document: { surfaces: [surface] } };
  const frictionEvents = [
    frictionEvent("w1", "tool_inadequate"),
    frictionEvent("w1", "tool_inadequate"),
    frictionEvent("w1", "tool_inadequate"),
    // an unrelated surface's friction and a non-matching kind must not count
    frictionEvent("other", "tool_inadequate"),
    frictionEvent("w1", "tool_absent"),
  ];
  const doc = buildSurfaceRoutesDocument(domain, { attackSurfaceInfo, frictionEvents });
  assert.equal(doc.routes.length, 1);
  assert.equal(doc.routes[0].confidence, ROUTER_CONFIDENCE_LADDER[baseIdx + 1], "one full threshold demotes exactly one step");
});

test("buildSurfaceRoutesDocument: an unroutable smart_contract is byte-identical with and without friction", () => {
  const domain = "router-friction-unroutable.example.test";
  const surface = { id: "sc-none", surface_type: "smart_contract" };
  const attackSurfaceInfo = { source: "test", document: { surfaces: [surface] } };
  const frictionEvents = [
    frictionEvent("sc-none", "tool_inadequate"),
    frictionEvent("sc-none", "tool_inadequate"),
    frictionEvent("sc-none", "tool_inadequate"),
    frictionEvent("sc-none", "tool_inadequate"),
  ];
  const without = buildSurfaceRoutesDocument(domain, { attackSurfaceInfo });
  const withFriction = buildSurfaceRoutesDocument(domain, { attackSurfaceInfo, frictionEvents });
  assert.equal(without.routes[0].disposition, "unroutable");
  assert.equal(withFriction.routes[0].disposition, "unroutable");
  // demotion never touches routability: the unroutable route is identical.
  assert.deepEqual(withFriction.routes[0], without.routes[0]);
});

// Friction threaded through the routeSurfacesInternal / routeSurfaces caller
// seam so confidence demotion fires on the live bob_route_surfaces path.

// Write a legacy attack_surface.json under the current temp HOME so the live
// routeSurfaces path (which passes no attackSurfaceInfo and reads via
// currentSurfaces) has a surface source to route.
function writeAttackSurface(domain, surfaces) {
  const p = attackSurfacePath(domain);
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, `${JSON.stringify({ surfaces }, null, 2)}\n`);
  return p;
}

test("routeSurfacesInternal: frictionEvents param demotes the route one ladder step vs no friction", () => withTempHome(() => {
  const domain = "router-internal-friction.example.test";
  const surface = { id: "w1", surface_type: "api", hosts: ["w1.example.test"], endpoints: ["https://w1.example.test/a"] };
  const classification = classifySurfaceCapability(surface);
  const baseIdx = ROUTER_CONFIDENCE_LADDER.indexOf(classification.confidence);
  assert.ok(baseIdx >= 0, "classifier confidence is on the ladder");
  assert.ok(baseIdx < ROUTER_CONFIDENCE_LADDER.length - 1, "base has room to demote one step");
  const attackSurfaceInfo = { source: "test", document: { surfaces: [surface] } };

  // No frictionEvents => base confidence, byte-identical to today (fail-open default).
  const noFriction = routeSurfacesInternal(domain, { attackSurfaceInfo });
  assert.equal(noFriction.document.routes[0].confidence, classification.confidence);

  // >= threshold tool_inadequate events for the surface => demote exactly one step.
  const frictionEvents = [
    frictionEvent("w1", "tool_inadequate"),
    frictionEvent("w1", "tool_inadequate"),
    frictionEvent("w1", "tool_inadequate"),
  ];
  const demoted = routeSurfacesInternal(domain, { attackSurfaceInfo, frictionEvents });
  assert.equal(demoted.document.routes[0].confidence, ROUTER_CONFIDENCE_LADDER[baseIdx + 1], "one full threshold demotes exactly one step");
}));

test("routeSurfaces (live): heavy friction on frontier-events.jsonl demotes the persisted route confidence", () => withTempHome(() => {
  const domain = "router-live-friction.example.test";
  const surface = { id: "w1", surface_type: "api", hosts: ["w1.example.test"], endpoints: ["https://w1.example.test/a"] };
  const classification = classifySurfaceCapability(surface);
  const baseIdx = ROUTER_CONFIDENCE_LADDER.indexOf(classification.confidence);
  assert.ok(baseIdx < ROUTER_CONFIDENCE_LADDER.length - 1, "base has room to demote one step");
  writeAttackSurface(domain, [surface]);

  // >= HEAVY_FRICTION_DEMOTION_THRESHOLD (3) tool_inadequate observations for w1.
  for (let i = 0; i < 3; i += 1) {
    appendFrontierEvent({
      target_domain: domain,
      kind: "observation.recorded",
      payload: { observation_kind: "capability_friction_observed", surface_id: "w1", friction_kind: "tool_inadequate" },
    });
  }

  const raw = routeSurfaces({ target_domain: domain });
  const parsed = JSON.parse(raw);
  assert.equal(parsed.routed, true);
  // The persisted surface-routes.json carries the demoted confidence.
  const read = readSurfaceRoutesStrict(domain);
  assert.equal(read.document.routes.length, 1);
  assert.equal(read.document.routes[0].confidence, ROUTER_CONFIDENCE_LADDER[baseIdx + 1], "live route demoted one step by heavy friction");
}));

test("routeSurfaces (live): no frontier-events.jsonl fails open to base confidence and never throws", () => withTempHome(() => {
  const domain = "router-live-nofriction.example.test";
  const surface = { id: "w1", surface_type: "api", hosts: ["w1.example.test"], endpoints: ["https://w1.example.test/a"] };
  const classification = classifySurfaceCapability(surface);
  writeAttackSurface(domain, [surface]);
  // No frontier-events.jsonl written at all.
  assert.equal(fs.existsSync(surfaceRoutesPath(domain)), false);

  let raw;
  assert.doesNotThrow(() => { raw = routeSurfaces({ target_domain: domain }); }, "a missing friction ledger never breaks routing");
  const parsed = JSON.parse(raw);
  assert.equal(parsed.routed, true);
  const read = readSurfaceRoutesStrict(domain);
  assert.equal(read.document.routes.length, 1);
  // Fail-open: base classification confidence, byte-identical to today.
  assert.equal(read.document.routes[0].confidence, classification.confidence);
}));

// One canonical unroutable predicate (isUnroutableRoute) shared by the validator,
// the wave partition, the analytics derivation, and technique-pack selection.
// The write side pairs disposition:"unroutable" with a null pack, so on fresh data
// the two conditions agree; keying every consumer on their UNION closes the
// SC+null-pack wave-halt a cross-version route (one field without the other) opens.
test("isUnroutableRoute: disposition marker OR null pack — the two agree on fresh data, union catches drift", () => {
  // Fresh unroutable route (both conditions true).
  assert.equal(isUnroutableRoute({ surface_id: "s", disposition: "unroutable", reason: "x" }), true);
  // Cross-version drift: null pack WITHOUT the disposition marker — the narrow
  // `disposition === "unroutable"` check would have MISSED this and minted a
  // routable assignment for a pack-less route; the union catches it.
  assert.equal(isUnroutableRoute({ surface_id: "s", reason: "x" }), true);
  assert.equal(isUnroutableRoute({ surface_id: "s", capability_pack: null }), true);
  // Marker WITHOUT null pack (a stray pack survived) — still unroutable.
  assert.equal(isUnroutableRoute({ surface_id: "s", disposition: "unroutable", capability_pack: "web" }), true);
  // A routable web route is NOT unroutable.
  assert.equal(isUnroutableRoute({ surface_id: "s", capability_pack: "web", capability_pack_version: 1 }), false);
  // Defensive: null / non-object.
  assert.equal(isUnroutableRoute(null), false);
  assert.equal(isUnroutableRoute("nope"), false);
});

test("countRoutesByCapabilityPack uses the canonical predicate — a stray-pack unroutable (drift) route makes no bucket", () => {
  const counts = countRoutesByCapabilityPack([
    { surface_id: "a", capability_pack: "web" },
    { surface_id: "b", capability_pack: "web" },
    // A drift route: marked unroutable but a stray pack survived. The old inline
    // `capability_pack == null` check would have counted it into a "solana" bucket;
    // the canonical isUnroutableRoute skips it (unroutable contributes no bucket).
    { surface_id: "c", disposition: "unroutable", reason: "x", capability_pack: "solana" },
    // A normal pack-less unroutable route is skipped either way.
    { surface_id: "d", disposition: "unroutable", reason: "x" },
  ]);
  assert.deepEqual(counts, { web: 2 }, "only routable routes bucket; the drift route contributes nothing");
});

test("deriveUnroutableSurfacesFromRoutes classifies a drift row (null pack, no disposition marker) as unroutable", () => withTempHome(() => {
  const domain = "unroutable-drift-row.example.test";
  const routesPath = surfaceRoutesPath(domain);
  fs.mkdirSync(path.dirname(routesPath), { recursive: true });
  // A cross-version route: pack-less (capability_pack absent) with a reason but
  // NO disposition marker. Under the old narrow predicate this surface would be
  // treated as routable everywhere the wave path read it.
  fs.writeFileSync(routesPath, JSON.stringify({
    version: SURFACE_ROUTES_VERSION,
    route_version: SURFACE_ROUTE_VERSION,
    routes: [
      { surface_id: "drift:sc", surface_type: "smart_contract", reason: "unknown chain_family" },
      { surface_id: "ok:api", surface_type: "api", capability_pack: "web", capability_pack_version: 1, evaluator_agent: "evaluator-agent", brief_profile: "web" },
    ],
  }));

  const result = deriveUnroutableSurfacesFromRoutes(domain);
  assert.equal(result.error, null, "a well-formed drift row is not a corruption error");
  assert.deepEqual(Array.from(result.surfaceIds), ["drift:sc"], "the pack-less drift row is parked unroutable");
  assert.equal(result.surfaces[0].unroutable_reason, "unknown chain_family");
}));
