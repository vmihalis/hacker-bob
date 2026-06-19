"use strict";

// Plane T Cycle T.5 — JWT-as-observation-kind.
//
// These tests verify that http-records.js detects JWT-shaped tokens in three
// locations (Authorization: Bearer header, Set-Cookie, response body JSON
// keys matching access_token / id_token / refresh_token / jwt / token), emits
// a single observation.recorded frontier event per (surface_id, token)
// detection, and — most importantly — never writes the full token to the
// emitted payload. The negative regression scans the emitted JSON for the
// raw token bytes and fails if they appear anywhere.
//
// Pact: T-P4 (observation-trigger architectural pattern). T-R3 (no secret
// leakage). The "full-token-in-event" assertion is load-bearing: if a future
// change adds e.g. a `raw_token` debug field, this test must catch it.

const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");
const test = require("node:test");
const assert = require("node:assert/strict");

const {
  _resetJwtObservationDedup,
  detectJwts,
  parseJwtHeaderAndPayload,
  recordJwtObservations,
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

function base64url(input) {
  return Buffer.from(input, "utf8").toString("base64url");
}

function makeJwt({ header = { alg: "HS256", typ: "JWT" }, payload = {}, signature = "sig" } = {}) {
  const head = base64url(JSON.stringify(header));
  const body = base64url(JSON.stringify(payload));
  // Signature must be base64url-shaped. We use a deterministic stub instead of
  // a real HMAC because the detection code never verifies signatures.
  return `${head}.${body}.${signature}`;
}

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-jwt-observation-"));
  process.env.HOME = home;
  _resetJwtObservationDedup();
  try {
    return fn(home);
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
    _resetJwtObservationDedup();
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

function jwtEventsFor(domain, surfaceId) {
  return readEvents(domain).filter((event) => (
    event.kind === "observation.recorded"
    && event.surface_id === surfaceId
    && event.payload
    && event.payload.observation_kind === "jwt_observed"
  ));
}

const SAMPLE_HEADER = { alg: "RS256", kid: "key-2026", typ: "JWT" };
const SAMPLE_PAYLOAD = {
  iss: "https://issuer.example.com",
  aud: "api.example.com",
  sub: "user-42",
  exp: 1893456000,
  iat: 1700000000,
  nbf: 1700000000,
};

// ─── Detection: Authorization header ────────────────────────────────────────

test("jwt in Authorization: Bearer header emits authorization_header observation", () => {
  withTempHome(() => {
    const domain = "auth-header.example.com";
    ensureSessionDir(domain);
    const surface = "surface:auth-header";
    const token = makeJwt({ header: SAMPLE_HEADER, payload: SAMPLE_PAYLOAD });
    const emitted = recordJwtObservations({
      target_domain: domain,
      surface_id: surface,
      response_headers: { Authorization: `Bearer ${token}` },
      response_body: null,
    });
    assert.equal(emitted.length, 1, "exactly one observation should be emitted");
    const events = jwtEventsFor(domain, surface);
    assert.equal(events.length, 1);
    assert.equal(events[0].payload.token_location, "authorization_header");
    assert.equal(events[0].payload.cookie_name, null);
    assert.equal(events[0].payload.body_path, null);
    assert.equal(events[0].source.artifact, "http-records.jsonl");
  });
});

test("Authorization header lookup is case-insensitive on header name", () => {
  withTempHome(() => {
    const domain = "auth-header-case.example.com";
    ensureSessionDir(domain);
    const token = makeJwt({ payload: SAMPLE_PAYLOAD });
    recordJwtObservations({
      target_domain: domain,
      surface_id: "s:auth-case",
      response_headers: { "AUTHORIZATION": `Bearer ${token}` },
    });
    assert.equal(jwtEventsFor(domain, "s:auth-case").length, 1);
  });
});

// ─── Detection: Set-Cookie ──────────────────────────────────────────────────

test("jwt in Set-Cookie emits set_cookie observation with cookie_name", () => {
  withTempHome(() => {
    const domain = "cookie.example.com";
    ensureSessionDir(domain);
    const surface = "surface:cookie";
    const token = makeJwt({ header: SAMPLE_HEADER, payload: SAMPLE_PAYLOAD });
    recordJwtObservations({
      target_domain: domain,
      surface_id: surface,
      response_headers: {
        "Set-Cookie": `session_jwt=${token}; Path=/; HttpOnly; Secure`,
      },
    });
    const events = jwtEventsFor(domain, surface);
    assert.equal(events.length, 1);
    assert.equal(events[0].payload.token_location, "set_cookie");
    assert.equal(events[0].payload.cookie_name, "session_jwt");
    assert.equal(events[0].payload.body_path, null);
  });
});

// ─── Detection: Response body ───────────────────────────────────────────────

test("jwt under access_token in JSON body emits response_body observation", () => {
  withTempHome(() => {
    const domain = "body.example.com";
    ensureSessionDir(domain);
    const surface = "surface:body";
    const token = makeJwt({ header: SAMPLE_HEADER, payload: SAMPLE_PAYLOAD });
    const body = JSON.stringify({ access_token: token, token_type: "Bearer" });
    recordJwtObservations({
      target_domain: domain,
      surface_id: surface,
      response_body: body,
    });
    const events = jwtEventsFor(domain, surface);
    assert.equal(events.length, 1);
    assert.equal(events[0].payload.token_location, "response_body");
    assert.equal(events[0].payload.body_path, "$.access_token");
  });
});

test("nested body key matching access_token regex is detected", () => {
  withTempHome(() => {
    const domain = "nested.example.com";
    ensureSessionDir(domain);
    const surface = "surface:nested";
    const token = makeJwt({ payload: SAMPLE_PAYLOAD });
    const body = JSON.stringify({ data: { tokens: [{ refresh_token: token }] } });
    recordJwtObservations({
      target_domain: domain,
      surface_id: surface,
      response_body: body,
    });
    const events = jwtEventsFor(domain, surface);
    assert.equal(events.length, 1);
    assert.equal(events[0].payload.token_location, "response_body");
    assert.equal(events[0].payload.body_path, "$.data.tokens[0].refresh_token");
  });
});

// ─── Multi-token / dedup ────────────────────────────────────────────────────

test("multiple distinct JWTs in same response emit distinct events", () => {
  withTempHome(() => {
    const domain = "multi.example.com";
    ensureSessionDir(domain);
    const surface = "surface:multi";
    const access = makeJwt({
      header: SAMPLE_HEADER,
      payload: { ...SAMPLE_PAYLOAD, sub: "user-access" },
    });
    const id = makeJwt({
      header: SAMPLE_HEADER,
      payload: { ...SAMPLE_PAYLOAD, sub: "user-id" },
    });
    const body = JSON.stringify({ access_token: access, id_token: id });
    recordJwtObservations({
      target_domain: domain,
      surface_id: surface,
      response_body: body,
    });
    const events = jwtEventsFor(domain, surface);
    assert.equal(events.length, 2);
    const fps = events.map((event) => event.payload.token_fingerprint);
    assert.notEqual(fps[0], fps[1], "distinct tokens must have distinct fingerprints");
    const paths = events.map((event) => event.payload.body_path).sort();
    assert.deepEqual(paths, ["$.access_token", "$.id_token"]);
  });
});

test("same JWT seen twice for same surface emits one event (dedup)", () => {
  withTempHome(() => {
    const domain = "dedup.example.com";
    ensureSessionDir(domain);
    const surface = "surface:dedup";
    const token = makeJwt({ payload: SAMPLE_PAYLOAD });
    recordJwtObservations({
      target_domain: domain,
      surface_id: surface,
      response_headers: { Authorization: `Bearer ${token}` },
    });
    recordJwtObservations({
      target_domain: domain,
      surface_id: surface,
      response_headers: { Authorization: `Bearer ${token}` },
    });
    assert.equal(jwtEventsFor(domain, surface).length, 1, "dedup must emit once per surface");
  });
});

test("dedup keys on surface_id — same token on different surface emits again", () => {
  withTempHome(() => {
    const domain = "per-surface.example.com";
    ensureSessionDir(domain);
    const token = makeJwt({ payload: SAMPLE_PAYLOAD });
    recordJwtObservations({
      target_domain: domain,
      surface_id: "surface:alpha",
      response_headers: { Authorization: `Bearer ${token}` },
    });
    recordJwtObservations({
      target_domain: domain,
      surface_id: "surface:beta",
      response_headers: { Authorization: `Bearer ${token}` },
    });
    assert.equal(jwtEventsFor(domain, "surface:alpha").length, 1);
    assert.equal(jwtEventsFor(domain, "surface:beta").length, 1);
  });
});

// ─── Header/payload parsing ─────────────────────────────────────────────────

test("parseJwtHeaderAndPayload extracts alg, kid from header", () => {
  const token = makeJwt({
    header: { alg: "RS256", kid: "key-2026", typ: "JWT" },
    payload: SAMPLE_PAYLOAD,
  });
  const parsed = parseJwtHeaderAndPayload(token);
  assert.equal(parsed.header.alg, "RS256");
  assert.equal(parsed.header.kid, "key-2026");
  assert.equal(parsed.header.typ, "JWT");
});

test("emitted event carries header_alg and header_kid", () => {
  withTempHome(() => {
    const domain = "header-claims.example.com";
    ensureSessionDir(domain);
    const surface = "surface:hdr";
    const token = makeJwt({
      header: { alg: "RS256", kid: "key-2026", typ: "JWT" },
      payload: SAMPLE_PAYLOAD,
    });
    recordJwtObservations({
      target_domain: domain,
      surface_id: surface,
      response_headers: { Authorization: `Bearer ${token}` },
    });
    const event = jwtEventsFor(domain, surface)[0];
    assert.equal(event.payload.header_alg, "RS256");
    assert.equal(event.payload.header_kid, "key-2026");
    assert.equal(event.payload.header_typ, "JWT");
  });
});

test("emitted event carries iss, aud, exp; sub is hashed (sha256), not raw", () => {
  withTempHome(() => {
    const domain = "payload-claims.example.com";
    ensureSessionDir(domain);
    const surface = "surface:claims";
    const rawSub = "user-42";
    const token = makeJwt({
      header: SAMPLE_HEADER,
      payload: { ...SAMPLE_PAYLOAD, sub: rawSub },
    });
    recordJwtObservations({
      target_domain: domain,
      surface_id: surface,
      response_headers: { Authorization: `Bearer ${token}` },
    });
    const event = jwtEventsFor(domain, surface)[0];
    assert.equal(event.payload.claim_iss, "https://issuer.example.com");
    assert.equal(event.payload.claim_aud, "api.example.com");
    assert.equal(event.payload.claim_exp, 1893456000);
    assert.equal(event.payload.claim_iat, 1700000000);
    assert.equal(event.payload.claim_nbf, 1700000000);
    const expectedSubHash = crypto.createHash("sha256").update(rawSub, "utf8").digest("hex");
    assert.equal(event.payload.claim_sub_hash, expectedSubHash);
    // The raw sub must NOT appear in the payload.
    assert.ok(!JSON.stringify(event.payload).includes(rawSub),
      "raw sub must not appear in event payload");
  });
});

// ─── NEGATIVE REGRESSION: secret leakage ────────────────────────────────────

test("full JWT string does NOT appear anywhere in the emitted event payload (T-R3)", () => {
  withTempHome(() => {
    const domain = "no-leak.example.com";
    ensureSessionDir(domain);
    const surface = "surface:no-leak";
    const token = makeJwt({
      header: { alg: "HS256", kid: "leak-canary", typ: "JWT" },
      payload: {
        iss: "https://leak-issuer.example.com",
        aud: "leak-audience.example.com",
        sub: "leak-user-canary",
        exp: 1893456000,
      },
    });
    recordJwtObservations({
      target_domain: domain,
      surface_id: surface,
      response_headers: {
        Authorization: `Bearer ${token}`,
        "Set-Cookie": `auth=${token}; Path=/`,
      },
      response_body: JSON.stringify({ access_token: token }),
    });
    const events = jwtEventsFor(domain, surface);
    assert.ok(events.length >= 1, "at least one jwt_observed event expected");
    // Scan the full event document for the raw token. The token must not
    // appear in any field — payload, source, anywhere. The token_fingerprint
    // is sha256 (no overlap with the base64url alphabet → no false positive).
    // The token_snippet is intentionally truncated and includes "..." which
    // can never be a substring of the original JWT.
    for (const event of events) {
      const fullJson = JSON.stringify(event);
      assert.ok(!fullJson.includes(token),
        `regression: full token leaked into emitted event ${event.event_id}`);
      // Also: the signature segment (third "." part) by itself should not
      // appear — a partial leak (header.payload only, without signature) is
      // still a leak.
      const headerSegment = token.split(".")[0];
      const payloadSegment = token.split(".")[1];
      const sigSegment = token.split(".")[2];
      // The snippet truncates each segment so the full segment must not appear.
      assert.ok(!fullJson.includes(`${headerSegment}.${payloadSegment}`),
        `regression: header.payload pair leaked into event ${event.event_id}`);
      assert.ok(!fullJson.includes(sigSegment) || sigSegment.length <= 6,
        `regression: signature segment leaked into event ${event.event_id}`);
    }
  });
});

// ─── Malformed input ────────────────────────────────────────────────────────

test("malformed JWT (only 2 segments) emits no event and does not throw", () => {
  withTempHome(() => {
    const domain = "malformed.example.com";
    ensureSessionDir(domain);
    const surface = "surface:malformed";
    // Looks JWT-shaped (eyJ prefix) but has only 2 segments — must be rejected
    // by the looksLikeJwt regex (3-segment requirement).
    const bogus = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0";
    recordJwtObservations({
      target_domain: domain,
      surface_id: surface,
      response_headers: { Authorization: `Bearer ${bogus}` },
    });
    assert.equal(jwtEventsFor(domain, surface).length, 0);
  });
});

test("JWT with undecodable base64 in header emits no event", () => {
  withTempHome(() => {
    const domain = "bad-b64.example.com";
    ensureSessionDir(domain);
    const surface = "surface:bad-b64";
    // 3 segments, eyJ prefix, but the header decodes to invalid JSON.
    const head = base64url("not-json{");
    const body = base64url(JSON.stringify(SAMPLE_PAYLOAD));
    const bogus = `${head}.${body}.sig`;
    // detectJwts must still match the shape (since it looks JWT-like)…
    const detections = detectJwts({
      response_headers: { Authorization: `Bearer ${bogus}` },
    });
    // …but emission must reject because parseJwtHeaderAndPayload returns null.
    recordJwtObservations({
      target_domain: domain,
      surface_id: surface,
      response_headers: { Authorization: `Bearer ${bogus}` },
    });
    // The bogus token doesn't start with eyJ unless `not-json{` happens to
    // encode that way — confirm shape detection still works.
    assert.ok(Array.isArray(detections));
    // Either it didn't pass shape detection, OR shape passed but emission
    // rejected the unparseable header. Both outcomes satisfy "no event".
    assert.equal(jwtEventsFor(domain, surface).length, 0);
  });
});

test("response body > 1MB is not parsed for JWT (no event)", () => {
  withTempHome(() => {
    const domain = "big-body.example.com";
    ensureSessionDir(domain);
    const surface = "surface:big-body";
    const token = makeJwt({ payload: SAMPLE_PAYLOAD });
    // 1.5 MB of padding around a valid access_token. JSON.parse would succeed
    // but the size cap must skip detection entirely.
    const padding = "x".repeat(1024 * 1024 + 600 * 1024); // ~1.6 MB
    const body = JSON.stringify({ access_token: token, padding });
    assert.ok(Buffer.byteLength(body, "utf8") > 1024 * 1024);
    recordJwtObservations({
      target_domain: domain,
      surface_id: surface,
      response_body: body,
    });
    assert.equal(jwtEventsFor(domain, surface).length, 0,
      "bodies over 1 MB must be skipped");
  });
});

test("body that is not valid JSON emits no event", () => {
  withTempHome(() => {
    const domain = "not-json.example.com";
    ensureSessionDir(domain);
    const surface = "surface:not-json";
    const token = makeJwt({ payload: SAMPLE_PAYLOAD });
    // The token is in the body but the body itself is HTML, not JSON.
    const body = `<html><body>${token}</body></html>`;
    recordJwtObservations({
      target_domain: domain,
      surface_id: surface,
      response_body: body,
    });
    assert.equal(jwtEventsFor(domain, surface).length, 0);
  });
});

// ─── End-to-end: observation → pack selection ───────────────────────────────

test("jwt_observed observation auto-surfaces the jwt-tool pack (T.2 integration)", () => {
  withTempHome(() => {
    const domain = "auto-surface.example.com";
    ensureSessionDir(domain);
    const surface = "surface:auto-surface";
    const token = makeJwt({ header: SAMPLE_HEADER, payload: SAMPLE_PAYLOAD });
    recordJwtObservations({
      target_domain: domain,
      surface_id: surface,
      response_headers: { Authorization: `Bearer ${token}` },
    });
    // Pull observations through the F.4 projection so the test mirrors how a
    // real brief renderer would obtain them.
    const observations = observationsForSurface(domain, surface);
    assert.ok(observations.length >= 1);
    assert.ok(observations.some((o) => o.kind === "jwt_observed"));

    const selected = selectCliToolPacks({
      surface_fingerprint: { kind: "web", host: "api.example.com" },
      task_lens: "behavior_probe",
      observations,
    });
    const ids = selected.map((pack) => pack.id);
    assert.ok(ids.includes("jwt-tool"),
      "jwt_observed observation must trigger jwt-tool pack selection");
  });
});

// ─── Source ref ─────────────────────────────────────────────────────────────

test("emitted event source carries artifact http-records.jsonl and a ref string", () => {
  withTempHome(() => {
    const domain = "source-ref.example.com";
    ensureSessionDir(domain);
    const surface = "surface:src";
    const token = makeJwt({ payload: SAMPLE_PAYLOAD });
    recordJwtObservations({
      target_domain: domain,
      surface_id: surface,
      response_headers: { Authorization: `Bearer ${token}` },
      source_ref: "2026-05-27T12:00:00.000Z GET https://api.example.com/me",
    });
    const event = jwtEventsFor(domain, surface)[0];
    assert.equal(event.source.artifact, "http-records.jsonl");
    assert.equal(typeof event.source.ref, "string");
    assert.ok(event.source.ref.length > 0);
  });
});
