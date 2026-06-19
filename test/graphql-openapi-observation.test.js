"use strict";

// Plane T Cycle T.6 — GraphQL / OpenAPI schema observation.
//
// Tests verify that http-records.js detects two schema shapes carried in JSON
// response bodies:
//
//   - GraphQL introspection responses (URL path matches /graphql, /api/graphql,
//     or /__graphql, OR a top-level data.__schema.types[] array).
//   - OpenAPI 3.x / Swagger 2.0 specs with a paths object containing >= 1
//     entry.
//
// For each detection a single observation.recorded frontier event is emitted
// per (surface_id, schema_fingerprint). The emitted payload carries ONLY a
// sha256 fingerprint plus summary fields — never the full schema document.
// The negative regression scans the emitted JSON for the unique type/path
// strings and fails if any of them leak.
//
// Pact: T-P4 (observation-trigger architectural pattern, parallel to T.5).
// T-R3 (no secret leakage, including no full schema body).

const fs = require("fs");
const os = require("os");
const path = require("path");
const test = require("node:test");
const assert = require("node:assert/strict");

const {
  _resetSchemaObservationDedup,
  detectSchemas,
  recordSchemaObservations,
} = require("../mcp/lib/http-records.js");
const {
  selectCliToolPacks,
} = require("../mcp/lib/cli-tool-packs.js");
const {
  observationsForSurface,
} = require("../mcp/lib/frontier-projections.js");
const {
  sessionDir,
} = require("../mcp/lib/paths.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-schema-observation-"));
  process.env.HOME = home;
  _resetSchemaObservationDedup();
  try {
    return fn(home);
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
    _resetSchemaObservationDedup();
  }
}

function ensureSessionDir(domain) {
  fs.mkdirSync(sessionDir(domain), { recursive: true });
}

function readEvents(domain) {
  const eventsPath = path.join(sessionDir(domain), "frontier-events.jsonl");
  if (!fs.existsSync(eventsPath)) return [];
  return fs.readFileSync(eventsPath, "utf8")
    .split("\n")
    .filter((line) => line.trim())
    .map((line) => JSON.parse(line));
}

function schemaEventsFor(domain, surfaceId, observationKind) {
  return readEvents(domain).filter((event) => (
    event.kind === "observation.recorded"
    && event.surface_id === surfaceId
    && event.payload
    && event.payload.observation_kind === observationKind
  ));
}

// ── Fixture builders ────────────────────────────────────────────────────────

function sampleGraphqlIntrospection({
  types = [
    { kind: "OBJECT", name: "Query", fields: [{ name: "viewer" }] },
    { kind: "OBJECT", name: "Mutation", fields: [{ name: "login" }] },
    { kind: "OBJECT", name: "User", fields: [{ name: "id" }, { name: "email" }] },
    { kind: "SCALAR", name: "ID" },
    { kind: "SCALAR", name: "String" },
  ],
  queryType = { name: "Query" },
  mutationType = { name: "Mutation" },
  subscriptionType = null,
  directives = [],
} = {}) {
  return {
    data: {
      __schema: {
        queryType,
        mutationType,
        subscriptionType,
        types,
        directives,
      },
    },
  };
}

function sampleOpenApi3({
  version = "3.0.0",
  paths = {
    "/users": {
      get: { summary: "list", responses: { 200: { description: "ok" } } },
      post: { summary: "create", responses: { 201: { description: "ok" } } },
    },
    "/users/{id}": {
      get: { summary: "fetch", responses: { 200: { description: "ok" } } },
      delete: { summary: "remove", responses: { 204: { description: "ok" } } },
    },
  },
  securitySchemes = {
    bearerAuth: { type: "http", scheme: "bearer" },
    oauth2Auth: { type: "oauth2", flows: { authorizationCode: { authorizationUrl: "https://example.com/oauth/authorize", tokenUrl: "https://example.com/oauth/token", scopes: {} } } },
    apiKeyAuth: { type: "apiKey", in: "header", name: "X-API-Key" },
  },
} = {}) {
  return {
    openapi: version,
    info: { title: "Sample", version: "1.0.0" },
    paths,
    components: { securitySchemes },
  };
}

function sampleSwagger2({
  paths = {
    "/v1/items": {
      get: { responses: { 200: { description: "ok" } } },
    },
  },
  securityDefinitions = {
    apiKeyAuth: { type: "apiKey", in: "header", name: "X-API-Key" },
  },
} = {}) {
  return {
    swagger: "2.0",
    info: { title: "Legacy", version: "1.0.0" },
    paths,
    securityDefinitions,
  };
}

// ── GraphQL: detection on /graphql path ─────────────────────────────────────

test("graphql introspection response on /graphql path emits one event", () => {
  withTempHome(() => {
    const domain = "graphql-host.example.com";
    ensureSessionDir(domain);
    const surface = "surface:graphql";
    const body = JSON.stringify(sampleGraphqlIntrospection());
    const emitted = recordSchemaObservations({
      target_domain: domain,
      surface_id: surface,
      request_url: "https://graphql-host.example.com/graphql",
      response_body: body,
    });
    assert.equal(emitted.length, 1, "exactly one graphql observation expected");
    const events = schemaEventsFor(domain, surface, "graphql_schema_observed");
    assert.equal(events.length, 1);
    const payload = events[0].payload;
    assert.equal(payload.schema_url, "https://graphql-host.example.com/graphql");
    assert.equal(payload.endpoint_path, "/graphql");
    assert.equal(payload.type_count, 5);
    assert.equal(payload.query_root, "Query");
    assert.equal(payload.mutation_root, "Mutation");
    assert.equal(payload.subscription_root, null);
    assert.equal(payload.has_auth_directive, false);
    assert.equal(typeof payload.schema_fingerprint, "string");
    assert.equal(payload.schema_fingerprint.length, 64);
  });
});

test("graphql introspection on /api/graphql path is detected", () => {
  withTempHome(() => {
    const domain = "api-graphql.example.com";
    ensureSessionDir(domain);
    const surface = "surface:api-graphql";
    const body = JSON.stringify(sampleGraphqlIntrospection());
    recordSchemaObservations({
      target_domain: domain,
      surface_id: surface,
      request_url: "https://api-graphql.example.com/api/graphql",
      response_body: body,
    });
    const events = schemaEventsFor(domain, surface, "graphql_schema_observed");
    assert.equal(events.length, 1);
    assert.equal(events[0].payload.endpoint_path, "/api/graphql");
  });
});

test("graphql introspection on /__graphql path is detected", () => {
  withTempHome(() => {
    const domain = "double-underscore.example.com";
    ensureSessionDir(domain);
    const surface = "surface:dunder";
    const body = JSON.stringify(sampleGraphqlIntrospection());
    recordSchemaObservations({
      target_domain: domain,
      surface_id: surface,
      request_url: "https://double-underscore.example.com/__graphql",
      response_body: body,
    });
    assert.equal(
      schemaEventsFor(domain, surface, "graphql_schema_observed").length,
      1,
    );
  });
});

test("graphql introspection on arbitrary path with __schema body is detected", () => {
  // The spec accepts either a graphql-shaped path OR a body containing
  // data.__schema.types. This covers the body-shape path.
  withTempHome(() => {
    const domain = "shape-only.example.com";
    ensureSessionDir(domain);
    const surface = "surface:shape-only";
    const body = JSON.stringify(sampleGraphqlIntrospection());
    recordSchemaObservations({
      target_domain: domain,
      surface_id: surface,
      request_url: "https://shape-only.example.com/api/some-other-endpoint",
      response_body: body,
    });
    const events = schemaEventsFor(domain, surface, "graphql_schema_observed");
    assert.equal(events.length, 1);
  });
});

test("graphql payload reports has_auth_directive=true when @auth directive present", () => {
  withTempHome(() => {
    const domain = "auth-directive.example.com";
    ensureSessionDir(domain);
    const surface = "surface:auth-dir";
    const introspection = sampleGraphqlIntrospection({
      directives: [
        { name: "auth", locations: ["FIELD_DEFINITION"], args: [] },
      ],
    });
    recordSchemaObservations({
      target_domain: domain,
      surface_id: surface,
      request_url: "https://auth-directive.example.com/graphql",
      response_body: JSON.stringify(introspection),
    });
    const event = schemaEventsFor(domain, surface, "graphql_schema_observed")[0];
    assert.equal(event.payload.has_auth_directive, true);
  });
});

test("graphql payload reports has_introspection_disabled=true when types array is sparse", () => {
  withTempHome(() => {
    const domain = "sparse.example.com";
    ensureSessionDir(domain);
    const surface = "surface:sparse";
    // Sparse introspection: query succeeded but only the bare-minimum types
    // came back. Heuristic flips to true.
    const introspection = sampleGraphqlIntrospection({ types: [] });
    recordSchemaObservations({
      target_domain: domain,
      surface_id: surface,
      request_url: "https://sparse.example.com/graphql",
      response_body: JSON.stringify(introspection),
    });
    const event = schemaEventsFor(domain, surface, "graphql_schema_observed")[0];
    assert.equal(event.payload.has_introspection_disabled, true);
  });
});

// ── GraphQL: negative cases ─────────────────────────────────────────────────

test("response WITHOUT graphql path AND WITHOUT __schema body emits no event", () => {
  withTempHome(() => {
    const domain = "no-graphql.example.com";
    ensureSessionDir(domain);
    const surface = "surface:no-graphql";
    recordSchemaObservations({
      target_domain: domain,
      surface_id: surface,
      request_url: "https://no-graphql.example.com/api/users",
      response_body: JSON.stringify({ users: [{ id: 1, name: "alice" }] }),
    });
    assert.equal(
      schemaEventsFor(domain, surface, "graphql_schema_observed").length,
      0,
    );
  });
});

test("response with graphql path but non-introspection body emits no event", () => {
  withTempHome(() => {
    const domain = "graphql-not-intro.example.com";
    ensureSessionDir(domain);
    const surface = "surface:not-intro";
    recordSchemaObservations({
      target_domain: domain,
      surface_id: surface,
      request_url: "https://graphql-not-intro.example.com/graphql",
      response_body: JSON.stringify({ data: { viewer: { id: 1 } } }),
    });
    assert.equal(
      schemaEventsFor(domain, surface, "graphql_schema_observed").length,
      0,
    );
  });
});

// ── OpenAPI 3 detection ─────────────────────────────────────────────────────

test("OpenAPI 3 JSON response emits openapi_schema_observed event", () => {
  withTempHome(() => {
    const domain = "openapi3.example.com";
    ensureSessionDir(domain);
    const surface = "surface:openapi3";
    const spec = sampleOpenApi3({ version: "3.0.0" });
    const emitted = recordSchemaObservations({
      target_domain: domain,
      surface_id: surface,
      request_url: "https://openapi3.example.com/openapi.json",
      response_body: JSON.stringify(spec),
    });
    assert.equal(emitted.length, 1);
    const events = schemaEventsFor(domain, surface, "openapi_schema_observed");
    assert.equal(events.length, 1);
    const payload = events[0].payload;
    assert.equal(payload.schema_url, "https://openapi3.example.com/openapi.json");
    assert.equal(payload.spec_version, "openapi 3.0.0");
    assert.equal(payload.endpoint_count, 2);
    assert.equal(payload.methods_count, 4);
    assert.deepEqual(
      payload.security_schemes,
      ["apiKeyAuth", "bearerAuth", "oauth2Auth"],
    );
    assert.equal(payload.has_oauth, true);
    assert.equal(payload.has_apikey, true);
    assert.equal(typeof payload.spec_fingerprint, "string");
    assert.equal(payload.spec_fingerprint.length, 64);
  });
});

test("OpenAPI 3.1.x is also accepted via the same spec_version family", () => {
  withTempHome(() => {
    const domain = "openapi31.example.com";
    ensureSessionDir(domain);
    const surface = "surface:openapi31";
    const spec = sampleOpenApi3({ version: "3.1.0" });
    recordSchemaObservations({
      target_domain: domain,
      surface_id: surface,
      request_url: "https://openapi31.example.com/openapi.json",
      response_body: JSON.stringify(spec),
    });
    const event = schemaEventsFor(domain, surface, "openapi_schema_observed")[0];
    assert.equal(event.payload.spec_version, "openapi 3.1.0");
  });
});

test("OpenAPI without paths is NOT treated as a spec", () => {
  withTempHome(() => {
    const domain = "openapi-no-paths.example.com";
    ensureSessionDir(domain);
    const surface = "surface:no-paths";
    recordSchemaObservations({
      target_domain: domain,
      surface_id: surface,
      request_url: "https://openapi-no-paths.example.com/openapi.json",
      response_body: JSON.stringify({ openapi: "3.0.0", info: { title: "x" } }),
    });
    assert.equal(
      schemaEventsFor(domain, surface, "openapi_schema_observed").length,
      0,
    );
  });
});

// ── Swagger 2 detection ─────────────────────────────────────────────────────

test("Swagger 2 JSON response emits openapi_schema_observed with swagger 2.0", () => {
  withTempHome(() => {
    const domain = "swagger2.example.com";
    ensureSessionDir(domain);
    const surface = "surface:swagger2";
    const spec = sampleSwagger2();
    recordSchemaObservations({
      target_domain: domain,
      surface_id: surface,
      request_url: "https://swagger2.example.com/swagger.json",
      response_body: JSON.stringify(spec),
    });
    const events = schemaEventsFor(domain, surface, "openapi_schema_observed");
    assert.equal(events.length, 1);
    const payload = events[0].payload;
    assert.equal(payload.spec_version, "swagger 2.0");
    assert.equal(payload.endpoint_count, 1);
    assert.equal(payload.methods_count, 1);
    assert.deepEqual(payload.security_schemes, ["apiKeyAuth"]);
    assert.equal(payload.has_apikey, true);
    assert.equal(payload.has_oauth, false);
  });
});

// ── Dedup ────────────────────────────────────────────────────────────────────

test("both schemas observed on same surface twice emit one event each (dedup)", () => {
  withTempHome(() => {
    const domain = "dedup.example.com";
    ensureSessionDir(domain);
    const surface = "surface:dedup";
    // First wave: graphql + openapi side by side.
    recordSchemaObservations({
      target_domain: domain,
      surface_id: surface,
      request_url: "https://dedup.example.com/graphql",
      response_body: JSON.stringify(sampleGraphqlIntrospection()),
    });
    recordSchemaObservations({
      target_domain: domain,
      surface_id: surface,
      request_url: "https://dedup.example.com/openapi.json",
      response_body: JSON.stringify(sampleOpenApi3()),
    });
    // Second wave: identical bodies, should not re-emit.
    recordSchemaObservations({
      target_domain: domain,
      surface_id: surface,
      request_url: "https://dedup.example.com/graphql",
      response_body: JSON.stringify(sampleGraphqlIntrospection()),
    });
    recordSchemaObservations({
      target_domain: domain,
      surface_id: surface,
      request_url: "https://dedup.example.com/openapi.json",
      response_body: JSON.stringify(sampleOpenApi3()),
    });
    assert.equal(
      schemaEventsFor(domain, surface, "graphql_schema_observed").length,
      1,
      "graphql_schema_observed must dedup",
    );
    assert.equal(
      schemaEventsFor(domain, surface, "openapi_schema_observed").length,
      1,
      "openapi_schema_observed must dedup",
    );
  });
});

test("same schema on different surface emits per surface (parallel to T.5)", () => {
  withTempHome(() => {
    const domain = "per-surface.example.com";
    ensureSessionDir(domain);
    const spec = sampleOpenApi3();
    recordSchemaObservations({
      target_domain: domain,
      surface_id: "surface:alpha",
      request_url: "https://per-surface.example.com/openapi.json",
      response_body: JSON.stringify(spec),
    });
    recordSchemaObservations({
      target_domain: domain,
      surface_id: "surface:beta",
      request_url: "https://per-surface.example.com/openapi.json",
      response_body: JSON.stringify(spec),
    });
    assert.equal(
      schemaEventsFor(domain, "surface:alpha", "openapi_schema_observed").length,
      1,
    );
    assert.equal(
      schemaEventsFor(domain, "surface:beta", "openapi_schema_observed").length,
      1,
    );
  });
});

// ── Body cap ────────────────────────────────────────────────────────────────

test("response body > 1MB is skipped without crash and no event is emitted", () => {
  withTempHome(() => {
    const domain = "big-body.example.com";
    ensureSessionDir(domain);
    const surface = "surface:big";
    const padding = "x".repeat(1024 * 1024 + 100 * 1024); // ~1.1 MB
    const spec = sampleOpenApi3();
    const body = JSON.stringify({ ...spec, _padding: padding });
    assert.ok(Buffer.byteLength(body, "utf8") > 1024 * 1024);
    assert.doesNotThrow(() => {
      recordSchemaObservations({
        target_domain: domain,
        surface_id: surface,
        request_url: "https://big-body.example.com/openapi.json",
        response_body: body,
      });
    });
    assert.equal(
      schemaEventsFor(domain, surface, "openapi_schema_observed").length,
      0,
    );
    assert.equal(
      schemaEventsFor(domain, surface, "graphql_schema_observed").length,
      0,
    );
  });
});

// ── NEGATIVE REGRESSION: full-schema leakage (T-R3) ─────────────────────────

test("emitted graphql event JSON does NOT contain the full schema document", () => {
  withTempHome(() => {
    const domain = "no-graphql-leak.example.com";
    ensureSessionDir(domain);
    const surface = "surface:no-leak-gql";
    // Embed a unique, easily-grep'd canary string inside a type/field name.
    const canary = "LEAK_CANARY_FIELD_8e3c1c";
    const introspection = sampleGraphqlIntrospection({
      types: [
        { kind: "OBJECT", name: "Query", fields: [{ name: canary }] },
        { kind: "OBJECT", name: "SecretType", fields: [{ name: "password" }] },
        { kind: "SCALAR", name: "ID" },
        { kind: "SCALAR", name: "String" },
      ],
    });
    recordSchemaObservations({
      target_domain: domain,
      surface_id: surface,
      request_url: "https://no-graphql-leak.example.com/graphql",
      response_body: JSON.stringify(introspection),
    });
    const events = schemaEventsFor(domain, surface, "graphql_schema_observed");
    assert.equal(events.length, 1);
    const fullJson = JSON.stringify(events[0]);
    assert.ok(
      !fullJson.includes(canary),
      `regression: canary field name leaked into emitted event ${events[0].event_id}`,
    );
    assert.ok(
      !fullJson.includes("SecretType"),
      "regression: type name leaked into emitted event payload",
    );
    // type_count must be a number, not the array
    assert.equal(typeof events[0].payload.type_count, "number");
    assert.equal(events[0].payload.type_count, 4);
    assert.equal(Array.isArray(events[0].payload.types), false,
      "payload must not carry a types array — only the count");
  });
});

test("emitted openapi event JSON does NOT contain the full spec body", () => {
  withTempHome(() => {
    const domain = "no-openapi-leak.example.com";
    ensureSessionDir(domain);
    const surface = "surface:no-leak-oapi";
    const canaryPath = "/leak-canary-fafafa-resource";
    const spec = sampleOpenApi3({
      paths: {
        [canaryPath]: {
          get: { summary: "leak canary", responses: { 200: { description: "ok" } } },
        },
      },
    });
    recordSchemaObservations({
      target_domain: domain,
      surface_id: surface,
      request_url: "https://no-openapi-leak.example.com/openapi.json",
      response_body: JSON.stringify(spec),
    });
    const events = schemaEventsFor(domain, surface, "openapi_schema_observed");
    assert.equal(events.length, 1);
    const fullJson = JSON.stringify(events[0]);
    assert.ok(
      !fullJson.includes(canaryPath),
      `regression: canary path leaked into emitted event ${events[0].event_id}`,
    );
    assert.ok(
      !fullJson.includes("leak canary"),
      "regression: summary leaked into emitted event payload",
    );
    // payload.paths / payload.components must not exist
    assert.equal(events[0].payload.paths, undefined,
      "payload must not carry the paths object");
    assert.equal(events[0].payload.components, undefined,
      "payload must not carry the components object");
  });
});

// ── End-to-end: observation → pack selection ───────────────────────────────

test("openapi_schema_observed observation surfaces the schemathesis pack", () => {
  withTempHome(() => {
    const domain = "auto-schemathesis.example.com";
    ensureSessionDir(domain);
    const surface = "surface:auto-schemathesis";
    recordSchemaObservations({
      target_domain: domain,
      surface_id: surface,
      request_url: "https://auto-schemathesis.example.com/openapi.json",
      response_body: JSON.stringify(sampleOpenApi3()),
    });
    const observations = observationsForSurface(domain, surface);
    assert.ok(observations.some((o) => o.kind === "openapi_schema_observed"));
    const selected = selectCliToolPacks({
      surface_fingerprint: { kind: "web", host: "auto-schemathesis.example.com" },
      task_lens: "behavior_probe",
      observations,
    });
    const ids = selected.map((pack) => pack.id);
    assert.ok(ids.includes("schemathesis"),
      "openapi_schema_observed must trigger schemathesis pack selection");
  });
});

test("graphql_schema_observed observation surfaces graphql-cop and graphqlcat", () => {
  withTempHome(() => {
    const domain = "auto-gql.example.com";
    ensureSessionDir(domain);
    const surface = "surface:auto-gql";
    recordSchemaObservations({
      target_domain: domain,
      surface_id: surface,
      request_url: "https://auto-gql.example.com/graphql",
      response_body: JSON.stringify(sampleGraphqlIntrospection()),
    });
    const observations = observationsForSurface(domain, surface);
    const selected = selectCliToolPacks({
      surface_fingerprint: { kind: "web", host: "auto-gql.example.com" },
      task_lens: "behavior_probe",
      observations,
    });
    const ids = selected.map((pack) => pack.id);
    assert.ok(ids.includes("graphql-cop"),
      "graphql_schema_observed must trigger graphql-cop pack selection");
    assert.ok(ids.includes("graphqlcat"),
      "graphql_schema_observed must trigger graphqlcat pack selection");
    // clairvoyance is gated on has_introspection_disabled=true; this fixture
    // has a populated types array so it should NOT surface.
    assert.ok(!ids.includes("clairvoyance"),
      "clairvoyance must not surface unless introspection appears disabled");
  });
});

test("graphql introspection that returns empty types surfaces clairvoyance", () => {
  withTempHome(() => {
    const domain = "auto-clairvoyance.example.com";
    ensureSessionDir(domain);
    const surface = "surface:clairvoyance";
    recordSchemaObservations({
      target_domain: domain,
      surface_id: surface,
      request_url: "https://auto-clairvoyance.example.com/graphql",
      response_body: JSON.stringify(sampleGraphqlIntrospection({ types: [] })),
    });
    const observations = observationsForSurface(domain, surface);
    const event = observations.find((o) => o.kind === "graphql_schema_observed");
    assert.ok(event, "graphql_schema_observed must be present");
    assert.equal(event.payload.has_introspection_disabled, true);
    const selected = selectCliToolPacks({
      surface_fingerprint: { kind: "web", host: "auto-clairvoyance.example.com" },
      task_lens: "behavior_probe",
      observations,
    });
    const ids = selected.map((pack) => pack.id);
    assert.ok(ids.includes("clairvoyance"),
      "introspection-disabled signal must trigger clairvoyance");
  });
});

// ── detectSchemas pure-function level ───────────────────────────────────────

test("detectSchemas returns separate detections for graphql + openapi when both present in one body", () => {
  // A response body that ALSO carries the openapi-shape via a wrapper key
  // would not normally happen, but the body-walk treats them as independent
  // shapes when both top-level signatures match.
  const body = JSON.stringify({
    openapi: "3.0.0",
    info: { title: "wrapped" },
    paths: { "/x": { get: { responses: { 200: { description: "ok" } } } } },
    data: { __schema: { queryType: { name: "Q" }, mutationType: null, subscriptionType: null, types: [{ name: "Q", kind: "OBJECT" }] } },
  });
  const detections = detectSchemas({
    request_url: "https://example.com/openapi.json",
    response_body: body,
  });
  const kinds = detections.map((d) => d.observation_kind).sort();
  assert.deepEqual(kinds, ["graphql_schema_observed", "openapi_schema_observed"]);
});

test("detectSchemas returns [] for HTML body", () => {
  const detections = detectSchemas({
    request_url: "https://example.com/",
    response_body: "<html><body>hi</body></html>",
  });
  assert.deepEqual(detections, []);
});
