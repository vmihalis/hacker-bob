"use strict";

// One derivation of the "unroutable" set (deriveUnroutableSurfacesFromRoutes),
// used by planNextWave (fail-CLOSED on corruption) and bob_wave_status (additive
// diagnostic), plus the honest zero-executable signal on an all-unroutable wave
// start. These exercise the live scheduler/status path end-to-end (the pure
// planner-side corruption/missing/sanitize assertions live in wave-planner.test.js).

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const { attackSurfacePath, surfaceRoutesPath } = require("../mcp/core/io/paths.js");
const { writeFileAtomic } = require("../mcp/core/io/storage.js");
const { initSession, advanceSession } = require("../mcp/core/session/session-state.js");
const { startWave, waveStatus } = require("../mcp/core/waves/waves.js");
const {
  deriveUnroutableSurfacesFromRoutes,
} = require("../mcp/core/frontier/surface-router.js");
const {
  buildStartNextWaveResponse,
} = require("../mcp/core/waves/wave-promotion-detector.js");

function withClaudeHome(fn) {
  const prevHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-unroutable-ss-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    process.env.HOME = prevHome;
    try { fs.rmSync(home, { recursive: true, force: true }); } catch {}
  }
}

function seedSurfaces(domain, surfaces) {
  writeFileAtomic(attackSurfacePath(domain), `${JSON.stringify({ surfaces }, null, 2)}\n`);
}

function bootstrap(domain, surfaces) {
  JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}` }));
  seedSurfaces(domain, surfaces);
  JSON.parse(advanceSession({ target_domain: domain, to_state: "OPEN_FRONTIER" }));
}

test("zero-executable: an all-unroutable wave start is non-halting and carries the honest signal", () => {
  withClaudeHome(() => {
    const domain = "all-unroutable.example.com";
    // A smart_contract surface with NO chain_family classifies unroutable, so the
    // whole wave persists zero routable assignments.
    bootstrap(domain, [
      { id: "surface:sc", hosts: [`https://${domain}`], priority: "HIGH", surface_type: "smart_contract" },
    ]);

    let response;
    assert.doesNotThrow(() => {
      response = JSON.parse(startWave({
        target_domain: domain,
        wave_number: 1,
        assignments: [{ agent: "a1", surface_id: "surface:sc" }],
      }));
    }, "an all-unroutable wave must NOT throw (non-halting)");

    assert.equal(response.started, true, "the wave still starts (self-completing)");
    assert.deepEqual(response.assignments, [], "no routable assignments were minted");
    assert.equal(response.has_routable_assignments, false, "the honest zero-executable signal is present");
    assert.equal(response.zero_executable, true, "zero_executable flags the empty wave");
    assert.equal(response.unroutable_count, 1, "the parked surface is still reported");
  });
});

test("zero-executable: a routable wave start carries has_routable_assignments:true (additive, byte-identical shape)", () => {
  withClaudeHome(() => {
    const domain = "routable-wave.example.com";
    bootstrap(domain, [
      { id: "surface:api", hosts: [`https://${domain}`], priority: "HIGH", surface_type: "api" },
    ]);

    const response = JSON.parse(startWave({
      target_domain: domain,
      wave_number: 1,
      assignments: [{ agent: "a1", surface_id: "surface:api" }],
    }));

    assert.equal(response.started, true);
    assert.equal(response.assignments.length, 1);
    assert.equal(response.has_routable_assignments, true);
    assert.equal(response.zero_executable, false);
  });
});

test("zero-executable: the start next_action settles the wave — never spawn_evaluators against an empty assignment set", () => {
  // A zero-executable wave carries the honest signal AND a coherent next_action:
  // buildWaveReadiness self-settles an empty wave, so the orchestrator must be
  // told to settle (bob_apply_wave_merge), not to spawn evaluators against
  // `assignments: []`. Non-halting is preserved (settle advances the loop).
  const domain = "zero-exec-nextaction.example.com";
  const started = {
    wave_number: 3,
    assignments: [],
    unroutable_count: 1,
    unroutable_surfaces: [{ surface_id: "surface:sc", surface_type: "smart_contract" }],
    has_routable_assignments: false,
    zero_executable: true,
    assignments_path: "/session/assignments-wave-3.json",
    state: {},
  };
  const response = buildStartNextWaveResponse({
    domain,
    dryRun: false,
    state: {},
    plan: { decision: "start_wave", wave_number: 3 },
    promotion: { would_promote: 0, would_promote_lead_ids: [] },
    started,
  });

  assert.notEqual(response.next_action.kind, "spawn_evaluators", "must NOT direct spawning against an empty wave");
  assert.equal(response.next_action.kind, "call_tool");
  assert.equal(response.next_action.tool, "bob_apply_wave_merge");
  assert.equal(response.next_action.arguments.wave_number, 3, "settles the started wave");
  assert.equal(response.next_action.arguments.target_domain, domain);
  assert.equal(response.next_action.assignments_path, started.assignments_path);
  assert.equal(response.zero_executable, true, "the honest signal is still present");
  assert.equal(response.has_routable_assignments, false);
});

test("routable: the start next_action is byte-identical (spawn_evaluators) — zero-executable reconciliation does not touch it", () => {
  const domain = "routable-nextaction.example.com";
  const started = {
    wave_number: 1,
    assignments: [{ agent: "a1", surface_id: "surface:api", capability_pack: "web" }],
    unroutable_count: 0,
    unroutable_surfaces: [],
    has_routable_assignments: true,
    zero_executable: false,
    assignments_path: "/session/assignments-wave-1.json",
    state: {},
  };
  const response = buildStartNextWaveResponse({
    domain,
    dryRun: false,
    state: {},
    plan: { decision: "start_wave", wave_number: 1 },
    promotion: { would_promote: 0, would_promote_lead_ids: [] },
    started,
  });

  assert.equal(response.next_action.kind, "spawn_evaluators", "the routable path is unchanged");
  assert.equal(response.next_action.assignments_source, "top_level_assignments");
  assert.equal(response.next_action.assignments_path, started.assignments_path);
  assert.equal(response.zero_executable, false);
});

test("routes_unreadable: the start next_action instructs regenerating routes — not a misleading 'no candidates' stop", () => {
  // planNextWave fails CLOSED on a corrupt/version-mismatched routes file
  // (decision: routes_unreadable). The next_action must name the recovery
  // (bob_route_surfaces re-derives fresh routes, self-healing a version bump),
  // never fall through to the default "no assignable candidates" stop that
  // misdiagnoses a recoverable corruption as an empty frontier.
  const domain = "routes-unreadable-nextaction.example.com";
  const response = buildStartNextWaveResponse({
    domain,
    dryRun: false,
    state: {},
    plan: {
      decision: "routes_unreadable",
      reason: "Malformed surface routes JSON: surface-routes.json",
      routes_error: { code: "routes_unreadable", message: "Malformed surface routes JSON: surface-routes.json" },
    },
    promotion: { would_promote: 0, would_promote_lead_ids: [] },
  });

  assert.equal(response.decision, "routes_unreadable");
  assert.notEqual(response.next_action.kind, "stop", "a recoverable corruption must not read as a dead-end stop");
  assert.equal(response.next_action.kind, "call_tool");
  assert.equal(response.next_action.tool, "bob_route_surfaces");
  assert.equal(response.next_action.arguments.target_domain, domain);
  assert.match(response.next_action.reason, /regenerate|bob_route_surfaces/i);
});

test("spawn_budget_exhausted: the start next_action stops with an honest budget reason, not 'no candidates'", () => {
  const domain = "budget-exhausted-nextaction.example.com";
  const response = buildStartNextWaveResponse({
    domain,
    dryRun: false,
    state: {},
    plan: { decision: "spawn_budget_exhausted", reason: "spawn budget exhausted: 3 open surface(s) remain uncovered" },
    promotion: { would_promote: 0, would_promote_lead_ids: [] },
  });

  assert.equal(response.next_action.kind, "stop", "budget exhaustion is a genuine stop");
  assert.match(response.next_action.reason, /spawn budget exhausted/i);
  assert.doesNotMatch(response.next_action.reason, /no assignable candidates/i);
});

test("wave-status derives the unroutable set from the SAME shared helper as the planner", () => {
  withClaudeHome(() => {
    const domain = "status-single-source.example.com";
    bootstrap(domain, [
      { id: "surface:api", hosts: [`https://${domain}`], priority: "HIGH", surface_type: "api" },
      { id: "surface:sc", hosts: [`https://${domain}`], priority: "HIGH", surface_type: "smart_contract" },
    ]);
    // Materialize surface-routes.json via a real wave start.
    JSON.parse(startWave({
      target_domain: domain,
      wave_number: 1,
      assignments: [
        { agent: "a1", surface_id: "surface:api" },
        { agent: "a2", surface_id: "surface:sc" },
      ],
    }));

    const status = JSON.parse(waveStatus({ target_domain: domain }));
    const helper = deriveUnroutableSurfacesFromRoutes(domain);

    assert.deepEqual(
      status.unroutable_surfaces.map((s) => s.surface_id).sort(),
      Array.from(helper.surfaceIds).sort(),
      "wave-status and the helper agree on the parked surface set",
    );
    assert.deepEqual(status.unroutable_surfaces.map((s) => s.surface_id), ["surface:sc"]);
    assert.equal(status.unroutable_surfaces_error, undefined, "no error diagnostic on valid routes");
  });
});

test("wave-status corruption diagnostic basename-sanitizes (no absolute session path leaks)", () => {
  withClaudeHome(() => {
    const domain = "status-corrupt.example.com";
    bootstrap(domain, [
      { id: "surface:api", hosts: [`https://${domain}`], priority: "HIGH", surface_type: "api" },
    ]);
    const routesPath = surfaceRoutesPath(domain);
    // A version-mismatch (routes-not-an-array via a top-level shape break) is a
    // hard corruption the reader throws on — not a per-route quarantine.
    fs.mkdirSync(path.dirname(routesPath), { recursive: true });
    fs.writeFileSync(routesPath, JSON.stringify({ version: 999, route_version: 999, routes: "not-an-array" }));

    const status = JSON.parse(waveStatus({ target_domain: domain }));
    assert.ok(status.unroutable_surfaces_error, "corruption surfaces a distinct error diagnostic");
    assert.equal(status.unroutable_surfaces_error.code, "routes_unreadable");
    assert.match(status.unroutable_surfaces_error.message, /surface-routes\.json/);
    assert.ok(
      !status.unroutable_surfaces_error.message.includes(routesPath),
      "the absolute session path is basename-sanitized out of the diagnostic",
    );
    assert.ok(
      !status.unroutable_surfaces_error.message.includes(process.env.HOME),
      "no fragment of the session HOME path leaks",
    );
  });
});
