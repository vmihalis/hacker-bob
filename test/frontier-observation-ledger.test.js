"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  appendFrontierEvent,
  readFrontierEvents,
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
  frontierEventsJsonlPath,
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

// Y-D21 — producer-boundary surface integrity (smart_contract => chain_family),
// enforced fail-closed at the single append funnel rather than at far-downstream
// capability routing.
test("Y-D21: appendFrontierEvent rejects a smart_contract surface.observed missing chain_family", () => {
  withTempHome(() => {
    const domain = "yd21-missing.example.com";
    ensureSessionDir(domain);
    assert.throws(
      () => appendFrontierEvent({
        target_domain: domain,
        kind: "surface.observed",
        surface_id: "sc-no-family",
        payload: { surface_type: "smart_contract", title: "no family" },
      }),
      (err) => err && err.code === "INVALID_ARGUMENTS" && /chain_family/.test(err.message)
        && err.details && err.details.surface_id === "sc-no-family",
      "smart_contract surface.observed without chain_family must be rejected at append",
    );
    // Fail-closed: the malformed event never reached the ledger.
    assert.equal(fs.existsSync(frontierEventsJsonlPath(domain)), false);
  });
});

test("Y-D21: appendFrontierEvent rejects a smart_contract surface.observed with an unknown chain_family", () => {
  withTempHome(() => {
    const domain = "yd21-unknown.example.com";
    ensureSessionDir(domain);
    assert.throws(
      () => appendFrontierEvent({
        target_domain: domain,
        kind: "surface.observed",
        surface_id: "sc-bad-family",
        payload: { surface_type: "smart_contract", chain_family: "bitcoin" },
      }),
      (err) => err && err.code === "INVALID_ARGUMENTS" && /chain_family/.test(err.message),
      "an unknown chain_family must still be rejected (keeps the routing 'register a pack' contract)",
    );
  });
});

test("Y-D21: known chain_family is accepted and chain_family/chain_id/contract_address materialize onto the surface", () => {
  withTempHome(() => {
    const domain = "yd21-ok.example.com";
    ensureSessionDir(domain);
    appendFrontierEvent({
      target_domain: domain,
      kind: "surface.observed",
      surface_id: "sc-distributor",
      payload: {
        surface_type: "smart_contract",
        chain_family: "evm",
        chain_id: "42161",
        contract_address: "0xDf1AC1AC255d91F5f4B1E3B4Aef57c5350F64C7A",
        title: "DistributorV2",
      },
    });
    const views = materializeFrontier(domain, {
      write: true,
      now: new Date("2026-06-20T13:00:00.000Z"),
    });
    const surface = views.surface_index.surfaces.find((s) => s.surface_id === "sc-distributor");
    assert.ok(surface, "smart_contract surface materialized");
    assert.equal(surface.surface_type, "smart_contract");
    assert.equal(surface.chain_family, "evm");
    assert.equal(surface.chain_id, "42161");
    assert.equal(surface.contract_address, "0xDf1AC1AC255d91F5f4B1E3B4Aef57c5350F64C7A");
  });
});

test("Y-D21: surface_type/chain_family casing and dashes are normalized by the guard", () => {
  withTempHome(() => {
    const domain = "yd21-casing.example.com";
    ensureSessionDir(domain);
    assert.doesNotThrow(() => appendFrontierEvent({
      target_domain: domain,
      kind: "surface.observed",
      surface_id: "sc-cased",
      payload: { surface_type: "Smart-Contract", chain_family: "EVM" },
    }));
  });
});

test("Y-D21: non-smart_contract surface.observed without chain_family is accepted (no false positive)", () => {
  withTempHome(() => {
    const domain = "yd21-web.example.com";
    ensureSessionDir(domain);
    assert.doesNotThrow(() => appendFrontierEvent({
      target_domain: domain,
      kind: "surface.observed",
      surface_id: "web-login",
      payload: { surface_type: "web_endpoint", title: "login" },
    }));
    // The wave-handoff re-stamp path carries no surface_type at all and must pass.
    assert.doesNotThrow(() => appendFrontierEvent({
      target_domain: domain,
      kind: "surface.observed",
      surface_id: "web-login",
      payload: { wave: 1, labels: ["promoted_surface_lead"] },
    }));
  });
});

test("Y-D21: the read/replay path is lenient — a pre-existing chain_family-less SC event does not brick reload", () => {
  withTempHome(() => {
    const domain = "yd21-legacy.example.com";
    ensureSessionDir(domain);
    // Simulate a ledger written before Y-D21: a chain_family-less smart_contract
    // surface.observed appended directly, bypassing the append-time guard.
    const legacyEvent = {
      version: 1,
      event_id: "FE-legacy-sc",
      ts: "2026-06-01T00:00:00.000Z",
      target_domain: domain,
      plane: "frontier",
      kind: "surface.observed",
      surface_id: "sc-legacy",
      payload: { surface_type: "smart_contract", title: "legacy, no chain_family" },
    };
    fs.writeFileSync(frontierEventsJsonlPath(domain), `${JSON.stringify(legacyEvent)}\n`);
    // Read and re-materialize must NOT throw (append-only enforcement).
    assert.doesNotThrow(() => readFrontierEvents(domain));
    assert.doesNotThrow(() => materializeFrontier(domain, {
      write: true,
      now: new Date("2026-06-20T13:00:00.000Z"),
    }));
  });
});
