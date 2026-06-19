"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  appendFrontierEvent,
} = require("../mcp/lib/frontier-events.js");
const {
  materializeFrontier,
} = require("../mcp/lib/frontier-materializer.js");
const {
  observationsForSurface,
} = require("../mcp/lib/frontier-projections.js");
const {
  surfaceIndexPath,
  attackSurfacePath,
  sessionDir,
} = require("../mcp/lib/paths.js");
const {
  ingestSchemaDoc,
} = require("../mcp/lib/schema-contracts-store.js");
const {
  runAuthDifferential,
} = require("../mcp/lib/auth-differential-runner.js");
const {
  runDocDelta,
} = require("../mcp/lib/doc-delta-runner.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-observation-ledger-"));
  process.env.HOME = home;
  const restore = () => {
    process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  };
  let result;
  try {
    result = fn(home);
  } catch (err) {
    restore();
    throw err;
  }
  if (result && typeof result.then === "function") {
    return result.then(
      (value) => { restore(); return value; },
      (err) => { restore(); throw err; },
    );
  }
  restore();
  return result;
}

function ensureSessionDir(domain) {
  fs.mkdirSync(sessionDir(domain), { recursive: true });
}

test("observationsForSurface returns normalized events in timestamp order", () => {
  withTempHome(() => {
    const domain = "obs-ledger-order.example.com";
    ensureSessionDir(domain);
    appendFrontierEvent({
      target_domain: domain,
      kind: "observation.recorded",
      ts: "2026-05-27T10:02:00.000Z",
      surface_id: "surface:gamma",
      payload: { observation_kind: "http_route", method: "GET", path: "/x" },
      source: { artifact: "route-extraction", tool: "bob_extract_routes" },
    });
    appendFrontierEvent({
      target_domain: domain,
      kind: "observation.recorded",
      ts: "2026-05-27T10:01:00.000Z",
      surface_id: "surface:gamma",
      payload: { observation_kind: "schema_field", endpoint: "/x" },
      source: { artifact: "schema-contracts.jsonl", tool: "bob_ingest_schema_doc" },
    });
    appendFrontierEvent({
      target_domain: domain,
      kind: "observation.recorded",
      ts: "2026-05-27T10:03:00.000Z",
      surface_id: "surface:other",
      payload: { observation_kind: "auth_redirect" },
      source: { artifact: "auth-differential-results.json", tool: "bob_run_auth_differential" },
    });

    const ordered = observationsForSurface(domain, "surface:gamma");
    assert.equal(ordered.length, 2);
    // Earlier timestamp first.
    assert.equal(ordered[0].kind, "schema_field");
    assert.equal(ordered[0].ts, "2026-05-27T10:01:00.000Z");
    assert.equal(ordered[1].kind, "http_route");
    assert.equal(ordered[1].ts, "2026-05-27T10:02:00.000Z");

    // Normalized shape exposes event_id, surface_id, kind, payload, source.
    for (const obs of ordered) {
      assert.equal(obs.surface_id, "surface:gamma");
      assert.ok(typeof obs.event_id === "string" && obs.event_id.startsWith("FE-"));
      assert.ok(obs.source && typeof obs.source === "object");
      assert.ok(typeof obs.source.artifact === "string");
      assert.ok(obs.payload && typeof obs.payload === "object");
    }
  });
});

test("materialized surface-index.json carries observations[] per surface", () => {
  withTempHome(() => {
    const domain = "obs-ledger-materialize.example.com";
    ensureSessionDir(domain);
    appendFrontierEvent({
      target_domain: domain,
      kind: "surface.observed",
      ts: "2026-05-27T00:00:00.000Z",
      surface_id: "surface:billing",
      payload: { title: "Billing API" },
    });
    appendFrontierEvent({
      target_domain: domain,
      kind: "observation.recorded",
      ts: "2026-05-27T00:00:01.000Z",
      surface_id: "surface:billing",
      payload: { observation_kind: "http_route", method: "POST", path: "/billing/charge" },
      source: { artifact: "route-extraction", tool: "bob_extract_routes" },
    });
    appendFrontierEvent({
      target_domain: domain,
      kind: "observation.recorded",
      ts: "2026-05-27T00:00:02.000Z",
      surface_id: "surface:billing",
      payload: { observation_kind: "auth_redirect", endpoint: "/billing/charge" },
      source: { artifact: "auth-differential-results.json", tool: "bob_run_auth_differential" },
    });
    // A non-observation event for the same surface — must NOT appear in observations[].
    appendFrontierEvent({
      target_domain: domain,
      kind: "blocker.asserted",
      ts: "2026-05-27T00:00:03.000Z",
      surface_id: "surface:billing",
      payload: { terminally_blocked: true, reason: "rate_limited" },
    });

    const views = materializeFrontier(domain, {
      write: true,
      now: new Date("2026-05-27T00:01:00.000Z"),
    });

    assert.equal(views.surface_index.surface_count, 1);
    const surface = views.surface_index.surfaces[0];
    assert.equal(surface.surface_id, "surface:billing");
    assert.ok(Array.isArray(surface.observations),
      "materialized surface carries observations[] array");
    assert.equal(surface.observations.length, 2);
    // Ordered by ts.
    assert.equal(surface.observations[0].kind, "http_route");
    assert.equal(surface.observations[1].kind, "auth_redirect");
    // Each observation carries normalized fields.
    for (const obs of surface.observations) {
      assert.ok(typeof obs.event_id === "string");
      assert.equal(obs.surface_id, "surface:billing");
      assert.ok(obs.source && typeof obs.source.artifact === "string");
    }

    // File on disk carries observations[] as well.
    const written = JSON.parse(fs.readFileSync(surfaceIndexPath(domain), "utf8"));
    assert.ok(Array.isArray(written.surfaces[0].observations));
    assert.equal(written.surfaces[0].observations.length, 2);
  });
});

test("materializer hash stays deterministic across re-materializations with observations", () => {
  withTempHome(() => {
    const domain = "obs-ledger-hash.example.com";
    ensureSessionDir(domain);
    appendFrontierEvent({
      target_domain: domain,
      kind: "surface.observed",
      ts: "2026-05-27T00:00:00.000Z",
      surface_id: "surface:account",
      payload: { title: "Account" },
    });
    appendFrontierEvent({
      target_domain: domain,
      kind: "observation.recorded",
      ts: "2026-05-27T00:00:01.000Z",
      surface_id: "surface:account",
      payload: { observation_kind: "schema_field", endpoint: "/account" },
      source: { artifact: "schema-contracts.jsonl", tool: "bob_ingest_schema_doc" },
    });

    const first = materializeFrontier(domain, {
      write: true,
      now: new Date("2026-05-27T00:01:00.000Z"),
    });
    const second = materializeFrontier(domain, {
      write: true,
      now: new Date("2026-05-27T00:02:00.000Z"),
    });
    assert.equal(
      first.surface_index.surface_index_hash,
      second.surface_index.surface_index_hash,
      "same events → same surface_index_hash, even with observations[]",
    );
  });
});

test("ingestSchemaDoc dual-writes legacy corpus AND observation.recorded events", () => {
  withTempHome(() => {
    const domain = "obs-ledger-schema.example.com";
    ensureSessionDir(domain);
    const openapi = JSON.stringify({
      openapi: "3.0.0",
      info: { title: "Test API", version: "1.0" },
      paths: {
        "/users": {
          get: {
            security: [{ bearerAuth: [] }],
            responses: { "200": { description: "ok" } },
          },
        },
      },
      components: {
        securitySchemes: {
          bearerAuth: { type: "http", scheme: "bearer" },
        },
      },
    });
    const result = ingestSchemaDoc({
      target_domain: domain,
      raw_doc: openapi,
      source_uri: "https://example.com/openapi.json",
    });
    assert.ok(result.contract_count >= 1);

    // Legacy: schema-contracts.jsonl on disk.
    const legacyPath = path.join(sessionDir(domain), "schema-contracts.jsonl");
    assert.equal(fs.existsSync(legacyPath), true);
    const legacyContent = fs.readFileSync(legacyPath, "utf8");
    assert.ok(legacyContent.length > 0);

    // Frontier ledger: observation.recorded events recorded.
    const eventsPath = path.join(sessionDir(domain), "frontier-events.jsonl");
    assert.equal(fs.existsSync(eventsPath), true);
    const lines = fs.readFileSync(eventsPath, "utf8")
      .split("\n").filter((line) => line.trim());
    const observationEvents = lines
      .map((line) => JSON.parse(line))
      .filter((event) => event.kind === "observation.recorded");
    assert.ok(observationEvents.length >= 1, "schema ingest emits observation.recorded");
    const firstObs = observationEvents[0];
    assert.equal(firstObs.payload.observation_kind, "schema_field");
    assert.equal(firstObs.source.artifact, "schema-contracts.jsonl");
    assert.equal(firstObs.source.tool, "bob_ingest_schema_doc");
  });
});

test("runAuthDifferential dual-writes legacy results AND observation.recorded events", async () => {
  await new Promise((resolve, reject) => {
    try {
      withTempHome(async () => {
        const domain = "obs-ledger-authdiff.example.com";
        ensureSessionDir(domain);
        const fetch_fn = async ({ auth_profile }) => {
          if (auth_profile === "anon") {
            return { status: 401, body: { error: "auth required" }, sent_with_auth: false };
          }
          return { status: 200, body: { ok: true }, sent_with_auth: true };
        };
        const result = await runAuthDifferential({
          target_domain: domain,
          base_url: "https://example.com",
          endpoints: ["/billing"],
          auth_profiles: ["anon", "admin"],
          fetch_fn,
          profile_metadata: {
            anon: { sent_with_auth: false },
            admin: { sent_with_auth: true, role: "admin" },
          },
        });
        assert.equal(result.summary.endpoints_tested, 1);

        // Legacy artifact persisted.
        const legacyPath = path.join(sessionDir(domain), "auth-differential-results.json");
        assert.equal(fs.existsSync(legacyPath), true);

        // Frontier ledger has the observation event.
        const eventsPath = path.join(sessionDir(domain), "frontier-events.jsonl");
        assert.equal(fs.existsSync(eventsPath), true);
        const lines = fs.readFileSync(eventsPath, "utf8")
          .split("\n").filter((line) => line.trim());
        const observationEvents = lines
          .map((line) => JSON.parse(line))
          .filter((event) => event.kind === "observation.recorded");
        assert.ok(observationEvents.length >= 1, "auth-differential run emits observation.recorded");
        const firstObs = observationEvents[0];
        assert.equal(firstObs.payload.observation_kind, "auth_redirect");
        assert.equal(firstObs.payload.endpoint, "/billing");
        assert.equal(firstObs.source.artifact, "auth-differential-results.json");
        assert.equal(firstObs.source.tool, "bob_run_auth_differential");
        resolve();
      });
    } catch (err) {
      reject(err);
    }
  });
});

test("legacy attack_surface.json write path is preserved (dual-write check)", () => {
  withTempHome(() => {
    const domain = "obs-ledger-dual-write.example.com";
    ensureSessionDir(domain);
    // Simulate the surface-leads.js dual-write path: write legacy
    // attack_surface.json AND append a frontier event. We assert the legacy
    // file is still readable (i.e., dual-write didn't break the legacy path).
    const surfaceObj = {
      domain,
      surfaces: [
        {
          id: "surface:legacy",
          hosts: ["example.com"],
          endpoints: ["/legacy"],
          observations: [
            { kind: "legacy_inline", note: "existing in-place observation" },
          ],
        },
      ],
    };
    fs.writeFileSync(
      attackSurfacePath(domain),
      JSON.stringify(surfaceObj, null, 2),
    );

    // Append an observation event for the same surface.
    appendFrontierEvent({
      target_domain: domain,
      kind: "observation.recorded",
      ts: "2026-05-27T00:00:01.000Z",
      surface_id: "surface:legacy",
      payload: { observation_kind: "http_route", path: "/legacy" },
      source: { artifact: "route-extraction", tool: "bob_extract_routes" },
    });

    // Materialize and confirm both legacy & ledger sources populate.
    materializeFrontier(domain, {
      write: true,
      now: new Date("2026-05-27T00:01:00.000Z"),
    });

    const legacy = JSON.parse(fs.readFileSync(attackSurfacePath(domain), "utf8"));
    assert.equal(legacy.surfaces.length, 1);
    assert.equal(legacy.surfaces[0].id, "surface:legacy");
    assert.ok(Array.isArray(legacy.surfaces[0].observations),
      "legacy inline observations[] still present");
    assert.equal(legacy.surfaces[0].observations[0].kind, "legacy_inline");

    const materialized = JSON.parse(fs.readFileSync(surfaceIndexPath(domain), "utf8"));
    const surface = materialized.surfaces.find((s) => s.surface_id === "surface:legacy");
    assert.ok(surface);
    assert.equal(surface.observations.length, 1);
    assert.equal(surface.observations[0].kind, "http_route");
  });
});
