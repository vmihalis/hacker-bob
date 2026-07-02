"use strict";

// seed_surfaces_present precondition: stale-index re-materialization
// and the race_deadlock-2 reported-gap guard.
//
// seed_surfaces_present (mcp/lib/scheduler-preconditions.js) gates
// OPEN_FRONTIER -> CLAIM_FREEZE on at least one ROUTED seed surface. It FORCES a
// synchronous materializeFrontier(write:true) so a stale/absent surface-index.json
// is brought current from the frontier event log before routing, then derives the
// routed seeds via buildSurfaceRoutesDocument.
//
// race_deadlock-2: a materialize OR route THROW (a fresh session with neither a
// materialized surface-index.json nor an attack_surface.json) MUST surface as a
// NON-terminal reported gap ({satisfied:false, reported_gap:true, reason}), never
// a bare {satisfied:false} that a downstream gate misreads as "no surfaces exist".
// The only permitted bare satisfied:false is a successful route build whose routes
// array is genuinely empty. The gap reason redacts absolute paths to a basename so
// it never leaks the local session/home path.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  evaluateSchedulerPrecondition,
} = require("../mcp/lib/scheduler-preconditions.js");
const {
  evaluateLifecycleTransition,
} = require("../mcp/lib/lifecycle-gates.js");
const {
  appendFrontierEvent,
} = require("../mcp/lib/frontier-events.js");
const {
  attackSurfacePath,
  sessionDir,
  surfaceIndexPath,
} = require("../mcp/lib/paths.js");
const {
  readJsonFile,
  writeFileAtomic,
} = require("../mcp/lib/storage.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-seed-surfaces-stale-"));
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

// Append a surface.observed frontier event WITHOUT materializing — the surface
// lives in the event log but no fresh surface-index.json reflects it yet. The
// precondition's own materializeFrontier(write:true) is what must surface it.
function seedObservedSurface(domain, surfaceId) {
  appendFrontierEvent({
    target_domain: domain,
    kind: "surface.observed",
    ts: "2026-06-29T00:00:00.000Z",
    surface_id: surfaceId,
    payload: {
      title: "Billing API",
      surface_type: "api",
      priority: "HIGH",
      hosts: ["billing.example.com"],
      endpoints: ["/api/billing/charge"],
    },
  });
}

// Write a STALE materialized view: zero surfaces, predating the event log. A
// reader that trusts it blindly would conclude "no surfaces" even though the
// frontier event log already carries one.
function writeStaleEmptyIndex(domain) {
  writeFileAtomic(
    surfaceIndexPath(domain),
    `${JSON.stringify({ version: 1, target_domain: domain, surface_count: 0, surfaces: [] }, null, 2)}\n`,
  );
}

test("seed_surfaces_present re-materializes a stale empty surface index and reports satisfied with routed seeds", () => {
  withTempHome(() => {
    const domain = "stale-index.example.com";
    ensureSessionDir(domain);
    seedObservedSurface(domain, "surface:billing");
    writeStaleEmptyIndex(domain);
    // The stale view shows zero surfaces before the gate runs.
    assert.equal(readJsonFile(surfaceIndexPath(domain)).surface_count, 0);

    const result = evaluateSchedulerPrecondition("seed_surfaces_present", { target_domain: domain });

    assert.equal(result.satisfied, true);
    assert.ok(result.seed_surface_count >= 1, "at least one routed seed surface");
    assert.equal(result.reported_gap, undefined, "a real satisfied is never a reported gap");
    // The forced materializeFrontier(write:true) refreshed the index from the log.
    assert.ok(readJsonFile(surfaceIndexPath(domain)).surface_count >= 1, "stale index was re-materialized");
  });
});

test("seed_surfaces_present forces materializeFrontier(write:true), creating an absent surface index", () => {
  withTempHome(() => {
    const domain = "absent-index.example.com";
    ensureSessionDir(domain);
    seedObservedSurface(domain, "surface:billing");
    assert.equal(fs.existsSync(surfaceIndexPath(domain)), false, "no materialized view yet");

    const result = evaluateSchedulerPrecondition("seed_surfaces_present", { target_domain: domain });

    assert.equal(result.satisfied, true);
    assert.ok(result.seed_surface_count >= 1);
    assert.equal(result.reported_gap, undefined);
    assert.equal(fs.existsSync(surfaceIndexPath(domain)), true, "the forced materialize wrote the index");
  });
});

test("seed_surfaces_present maps a missing-surface-input THROW to a non-terminal reported gap (race_deadlock-2)", () => {
  withTempHome((home) => {
    const domain = "no-surface-input.example.com";
    ensureSessionDir(domain);
    // Neither a materialized surface-index.json nor an attack_surface.json, and an
    // empty frontier event log: materialize writes an empty index, then route
    // building throws "Missing attack surface JSON: <path>".
    assert.equal(fs.existsSync(surfaceIndexPath(domain)), false);
    assert.equal(fs.existsSync(attackSurfacePath(domain)), false);

    const result = evaluateSchedulerPrecondition("seed_surfaces_present", { target_domain: domain });

    // A NON-terminal reported gap — never a bare satisfied:false that a downstream
    // gate reads as "no surfaces exist" (race_deadlock-2).
    assert.equal(result.satisfied, false);
    assert.equal(result.reported_gap, true);
    assert.equal(typeof result.reason, "string");
    assert.match(result.reason, /Missing attack surface JSON/);
    // seed_surface_count is omitted on a gap — it is NOT a genuine zero-route count.
    assert.equal(result.seed_surface_count, undefined);
    // The reason redacts absolute paths to a basename: no local session/home leak.
    assert.ok(!result.reason.includes(home), "absolute session/home path must not leak");
    assert.ok(result.reason.includes("surface-index.json"), "redacted to the basename");
  });
});

test("seed_surfaces_present returns a bare satisfied=false ONLY when route building genuinely yields zero routes", () => {
  withTempHome(() => {
    const domain = "empty-surfaces.example.com";
    ensureSessionDir(domain);
    // A present-but-empty surface input: route building SUCCEEDS and returns []
    // (it does not throw). This is the only permitted bare satisfied:false, and it
    // must be distinguishable from the race_deadlock-2 reported gap above.
    writeFileAtomic(
      attackSurfacePath(domain),
      `${JSON.stringify({ surfaces: [] }, null, 2)}\n`,
    );

    const result = evaluateSchedulerPrecondition("seed_surfaces_present", { target_domain: domain });

    assert.equal(result.satisfied, false);
    assert.equal(result.seed_surface_count, 0);
    assert.equal(result.reported_gap, undefined, "a genuine zero-route build is not a reported gap");
  });
});

test("seed_surfaces_present maps a corrupt-surface-input THROW to a BLOCKING materialization error, not a reported gap", () => {
  withTempHome((home) => {
    const domain = "corrupt-surface-input.example.com";
    ensureSessionDir(domain);
    // No surface-index.json and an empty frontier event log: the forced
    // materializeFrontier(write:true) writes an empty index, then route building
    // falls through to the legacy attack_surface.json — which is CORRUPT — so
    // buildSurfaceRoutesDocument throws "Malformed attack surface JSON: <path>".
    // That is a materialization ERROR (the input exists but cannot be read), NOT a
    // not-yet-seeded frontier.
    assert.equal(fs.existsSync(surfaceIndexPath(domain)), false);
    writeFileAtomic(attackSurfacePath(domain), "{ this is not valid json");

    const result = evaluateSchedulerPrecondition("seed_surfaces_present", { target_domain: domain });

    // Distinct from the race_deadlock-2 reported gap: this must NOT read as a
    // non-terminal gap that the SETUP gate silently passes.
    assert.equal(result.satisfied, false);
    assert.equal(result.reported_gap, undefined, "a corrupt input is not a not-yet-seeded reported gap");
    assert.equal(result.materialization_error, true);
    assert.equal(result.error_code, "seed_surfaces_materialization_error");
    assert.equal(typeof result.reason, "string");
    assert.match(result.reason, /Malformed attack surface JSON/);
    // seed_surface_count is omitted — it is NOT a genuine zero-route count.
    assert.equal(result.seed_surface_count, undefined);
    // The reason redacts absolute paths to a basename: no local session/home leak.
    assert.ok(!result.reason.includes(home), "absolute session/home path must not leak");
    assert.ok(result.reason.includes("attack_surface.json"), "redacted to the basename");
  });
});

test("SETUP -> OPEN_FRONTIER PASSES a not-yet-materialized frontier (reported_gap) but BLOCKS a corrupt one", () => {
  withTempHome(() => {
    // (a) A fresh session whose surface input is not seeded yet: the precondition
    // reports a non-terminal gap, so the SETUP gate advances (RANK != BOUND).
    const unseeded = "unseeded-setup.example.com";
    ensureSessionDir(unseeded);
    assert.equal(fs.existsSync(surfaceIndexPath(unseeded)), false);
    assert.equal(fs.existsSync(attackSurfacePath(unseeded)), false);

    const gapTransition = evaluateLifecycleTransition({
      from_state: "SETUP",
      to_state: "OPEN_FRONTIER",
      target_domain: unseeded,
    });
    assert.deepEqual(
      gapTransition.blockers,
      [],
      "a not-yet-materialized frontier must not block SETUP -> OPEN_FRONTIER",
    );

    // (b) A session whose surface input EXISTS but is corrupt: materialization
    // errors, so the SETUP gate BLOCKS with the distinct materialization-error
    // code instead of silently advancing into OPEN_FRONTIER on broken state.
    const corrupt = "corrupt-setup.example.com";
    ensureSessionDir(corrupt);
    writeFileAtomic(attackSurfacePath(corrupt), "{ this is not valid json");

    const errorTransition = evaluateLifecycleTransition({
      from_state: "SETUP",
      to_state: "OPEN_FRONTIER",
      target_domain: corrupt,
    });
    assert.equal(errorTransition.blockers.length, 1, "the corrupt frontier must block");
    const blocker = errorTransition.blockers[0];
    assert.equal(blocker.code, "seed_surfaces_materialization_error");
    assert.equal(blocker.blocked_by, "seed_surfaces_materialization_error");
    assert.notEqual(blocker.code, "seed_surfaces_absent", "a corrupt input is not a zero-route frontier");
    assert.match(blocker.message, /materialization errored/);
    assert.match(blocker.reason, /Malformed attack surface JSON/);
  });
});

test("seed_surfaces_present requires target_domain", () => {
  assert.throws(
    () => evaluateSchedulerPrecondition("seed_surfaces_present", {}),
    /target_domain/,
  );
});
