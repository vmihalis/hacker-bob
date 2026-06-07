"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  appendFrontierEvent,
} = require("../mcp/lib/frontier-events.js");
const {
  materializeFrontier,
} = require("../mcp/lib/frontier-materializer.js");
const {
  currentSurfaces,
} = require("../mcp/lib/frontier-projections.js");
const {
  rankAttackSurfaces,
} = require("../mcp/lib/ranking.js");
const {
  buildSurfaceRoutesDocument,
} = require("../mcp/lib/surface-router.js");
const {
  attackSurfacePath,
  sessionDir,
  surfaceIndexPath,
} = require("../mcp/lib/paths.js");
const {
  writeFileAtomic,
} = require("../mcp/lib/storage.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-surface-index-authoritative-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    if (previousHome === undefined) {
      delete process.env.HOME;
    } else {
      process.env.HOME = previousHome;
    }
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function ensureSessionDir(domain) {
  fs.mkdirSync(sessionDir(domain), { recursive: true });
}

function seedMaterializedSurface(domain, surfaceId, payload) {
  appendFrontierEvent({
    target_domain: domain,
    kind: "surface.observed",
    ts: "2026-05-27T00:00:00.000Z",
    surface_id: surfaceId,
    payload,
  });
  materializeFrontier(domain, { write: true });
}

test("currentSurfaces prefers surface-index.json over a corrupted attack_surface.json", () => {
  withTempHome(() => {
    const domain = "auth.example.com";
    ensureSessionDir(domain);
    // Materialize a surface-index.json carrying the canonical surface.
    seedMaterializedSurface(domain, "surface:billing", {
      title: "Billing API",
      surface_type: "api",
      priority: "HIGH",
      hosts: ["billing.example.com"],
      endpoints: ["/api/billing/charge"],
    });
    // Corrupt attack_surface.json on disk.
    writeFileAtomic(attackSurfacePath(domain), "{not-json}");

    const projection = currentSurfaces(domain);
    assert.equal(projection.source, "surface_index");
    assert.equal(projection.surfaces.length, 1);
    assert.equal(projection.surfaces[0].id, "surface:billing");
    assert.equal(projection.surfaces[0].priority, "HIGH");
    assert.equal(projection.warnings[0].code, "legacy_attack_surface_unreadable");
    assert.match(projection.warnings[0].message, /attack_surface\.json|JSON|Unexpected token/);
  });
});

test("phase-gates / ranking still operate when attack_surface.json is corrupted but surface-index.json is present", () => {
  withTempHome(() => {
    const domain = "ranking.example.com";
    ensureSessionDir(domain);
    seedMaterializedSurface(domain, "surface:api", {
      title: "Public API",
      surface_type: "api",
      priority: "HIGH",
      hosts: ["api.example.com"],
      endpoints: ["/api/users", "/api/admin/audit"],
      interesting_params: ["id"],
    });
    writeFileAtomic(attackSurfacePath(domain), "{this is not json");

    // rankAttackSurfaces reads through currentSurfaces (Cycle F.5).
    const ranked = rankAttackSurfaces(domain);
    assert.ok(ranked && Array.isArray(ranked.surfaces), "ranking falls through surface-index.json");
    assert.equal(ranked.surfaces.length, 1);
    assert.equal(ranked.surfaces[0].id, "surface:api");
    assert.equal(ranked.path, surfaceIndexPath(domain));

    // Route building reads through currentSurfaces too.
    const routes = buildSurfaceRoutesDocument(domain);
    assert.equal(routes.routes.length, 1);
    assert.equal(routes.routes[0].surface_id, "surface:api");
  });
});

test("currentSurfaces fails loud when surface-index.json is corrupted (no silent fallback in hot path)", () => {
  withTempHome(() => {
    const domain = "fail.example.com";
    ensureSessionDir(domain);
    // surface-index.json exists but is unparseable.
    writeFileAtomic(surfaceIndexPath(domain), "{not-json}");
    // attack_surface.json is well-formed and would have satisfied a legacy reader.
    writeFileAtomic(attackSurfacePath(domain), JSON.stringify({
      surfaces: [{ id: "surface:legacy", priority: "HIGH", hosts: ["legacy.example.com"] }],
    }, null, 2));

    assert.throws(
      () => currentSurfaces(domain),
      /surface-index\.json|JSON|Unexpected token/,
      "corrupted surface-index.json throws; the projection does not silently fall back to attack_surface.json",
    );
  });
});

test("currentSurfaces falls back to attack_surface.json when surface-index.json is absent (legacy session)", () => {
  withTempHome(() => {
    const domain = "legacy.example.com";
    ensureSessionDir(domain);
    // Legacy: no surface-index.json on disk.
    writeFileAtomic(attackSurfacePath(domain), JSON.stringify({
      surfaces: [
        { id: "surface:legacy-a", priority: "HIGH", hosts: ["a.example.com"] },
        { id: "surface:legacy-b", priority: "LOW", hosts: ["b.example.com"] },
      ],
    }, null, 2));
    assert.equal(fs.existsSync(surfaceIndexPath(domain)), false);

    const projection = currentSurfaces(domain);
    assert.equal(projection.source, "attack_surface_legacy");
    assert.equal(projection.surfaces.length, 2);
    assert.deepEqual(
      projection.surfaces.map((s) => s.id).sort(),
      ["surface:legacy-a", "surface:legacy-b"],
    );
    assert.equal(projection.path, attackSurfacePath(domain));
    assert.deepEqual(projection.warnings, []);
  });
});

test("currentSurfaces returns 'missing' when neither surface-index.json nor attack_surface.json exists", () => {
  withTempHome(() => {
    const domain = "empty.example.com";
    ensureSessionDir(domain);
    const projection = currentSurfaces(domain);
    assert.equal(projection.source, "missing");
    assert.deepEqual(projection.surfaces, []);
    assert.deepEqual(projection.warnings, []);
  });
});

test("currentSurfaces malformed attack_surface.json (legacy fallback path) raises a recognizable error", () => {
  withTempHome(() => {
    const domain = "bad-legacy.example.com";
    ensureSessionDir(domain);
    // No surface-index.json — fall through to attack_surface.json.
    writeFileAtomic(attackSurfacePath(domain), "{nope");
    assert.throws(
      () => currentSurfaces(domain),
      /Malformed attack surface JSON:/,
    );
  });
});

test("currentSurfaces with an empty surface-index.json falls back to attack_surface.json (transitional window)", () => {
  withTempHome(() => {
    const domain = "transitional.example.com";
    ensureSessionDir(domain);
    // surface-index.json present but with zero surfaces — possible when only
    // observation.recorded events without surface_id have been emitted.
    writeFileAtomic(surfaceIndexPath(domain), JSON.stringify({
      version: 1,
      target_domain: domain,
      surface_count: 0,
      surfaces: [],
    }, null, 2));
    writeFileAtomic(attackSurfacePath(domain), JSON.stringify({
      surfaces: [{ id: "surface:still-here", priority: "MEDIUM", hosts: ["legacy.example.com"] }],
    }, null, 2));

    const projection = currentSurfaces(domain);
    assert.equal(projection.source, "attack_surface_legacy");
    assert.equal(projection.surfaces.length, 1);
    assert.equal(projection.surfaces[0].id, "surface:still-here");
    assert.deepEqual(projection.warnings, []);
  });
});
