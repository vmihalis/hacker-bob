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

const { attackSurfacePath, surfaceRoutesPath } = require("../mcp/lib/paths.js");
const { writeFileAtomic } = require("../mcp/lib/storage.js");
const { initSession, advanceSession } = require("../mcp/lib/session-state.js");
const { startWave, waveStatus } = require("../mcp/lib/waves.js");
const {
  deriveUnroutableSurfacesFromRoutes,
} = require("../mcp/lib/surface-router.js");

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
