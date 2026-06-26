"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  rejectInvalidArguments,
  decodePathSegments,
  escapeRegExp,
  capturedIdSegmentIsSafe,
  pathTemplateMatchesEndpoint,
  assertReadOnlyPath,
  normalizePathTemplate,
  findRoutedSurface,
  candidateSurfaceEndpoints,
  resolveSurfaceOrigins,
  originFromState,
  urlFromEndpoint,
  resolveBaselineFromSurface,
  isAuthChallenge,
  isLoginRedirect,
  responseLooksLikeLoginPage,
  isResourceShapedResponse,
  auditConfirmRequest,
  assertNoForbiddenInputs,
  SCOPE_VALIDATION_OPTS,
} = require("../mcp/lib/offensive-http-common.js");
const { ERROR_CODES } = require("../mcp/lib/envelope.js");
const { readHttpAuditRecordsFromJsonl } = require("../mcp/lib/http-records.js");
const { routeSurfaces } = require("../mcp/lib/surface-router.js");
const { initSession } = require("../mcp/lib/session-state.js");
const { readSessionStateStrict } = require("../mcp/lib/session-state-store.js");
const { attackSurfacePath, surfaceRoutesPath } = require("../mcp/lib/paths.js");
const {
  resetForTests: resetMaterializationDebounce,
} = require("../mcp/lib/frontier-materialize-debounce.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-offensive-http-common-"));
  process.env.HOME = home;
  return Promise.resolve()
    .then(() => fn(home))
    .finally(() => {
      if (previousHome === undefined) delete process.env.HOME;
      else process.env.HOME = previousHome;
      resetMaterializationDebounce();
      fs.rmSync(home, { recursive: true, force: true });
    });
}

function seedRoutedSurface(domain, surfaceId, endpoint) {
  fs.mkdirSync(path.dirname(attackSurfacePath(domain)), { recursive: true });
  fs.writeFileSync(attackSurfacePath(domain), `${JSON.stringify({
    surfaces: [{
      id: surfaceId,
      title: "Synthetic API account surface",
      surface_type: "web",
      hosts: [domain],
      endpoints: [endpoint],
      tech_stack: ["fixture"],
      priority: "HIGH",
    }],
  }, null, 2)}\n`, "utf8");
  JSON.parse(routeSurfaces({ target_domain: domain }));
}

// Seed + route N web surfaces at once (for the bounded-error-list assertions).
function seedSurfaces(domain, ids) {
  fs.mkdirSync(path.dirname(attackSurfacePath(domain)), { recursive: true });
  fs.writeFileSync(attackSurfacePath(domain), `${JSON.stringify({
    surfaces: ids.map((id) => ({
      id,
      title: "Synthetic surface",
      surface_type: "web",
      hosts: [domain],
      endpoints: [`https://${domain}/p/${encodeURIComponent(id)}`],
      tech_stack: ["fixture"],
      priority: "HIGH",
    })),
  }, null, 2)}\n`, "utf8");
  JSON.parse(routeSurfaces({ target_domain: domain }));
}

// Minimal response mock matching the {status, headers.get, bodyBytes} shape the
// classifier helpers read (mirrors test/offensive-confirmer.test.js).
function mockResponse(status, body = "", headers = {}, extra = {}) {
  const lower = {};
  for (const [k, v] of Object.entries(headers)) lower[String(k).toLowerCase()] = v;
  return {
    status,
    headers: { get(name) { return lower[String(name).toLowerCase()] ?? null; } },
    bodyBytes: Buffer.isBuffer(body) ? body : Buffer.from(body),
    bodyTruncated: false,
    ...extra,
  };
}

// --- assertNoForbiddenInputs: the parameterization payoff (the whole point of PR-B) ---

test("assertNoForbiddenInputs is parameterized: a different toolName + extraFields drive the rejection", () => {
  // The forthcoming bob_http_idor_confirm reuses this guard with its own tool
  // name and its own server-minted-only extra fields. Assert on the concrete
  // message + code so the parameterization (toolName AND the field set) is proven.
  let caught;
  try {
    assertNoForbiddenInputs({ canary: "x" }, "bob_http_idor_confirm", ["canary"]);
  } catch (error) { caught = error; }
  assert.ok(caught, "must throw on an extra field");
  assert.equal(caught.code, ERROR_CODES.INVALID_ARGUMENTS);
  assert.equal(
    caught.message,
    "bob_http_idor_confirm does not accept canary; the request is derived server-side from surface_id and path_template",
  );
  // a base field is still rejected even when the caller only supplies extras
  let baseCaught;
  try {
    assertNoForbiddenInputs({ url: "https://x" }, "bob_http_idor_confirm", ["canary"]);
  } catch (error) { baseCaught = error; }
  assert.ok(baseCaught);
  assert.equal(baseCaught.message, "bob_http_idor_confirm does not accept url; the request is derived server-side from surface_id and path_template");
});

test("assertNoForbiddenInputs back-compat: bob_http_confirm message is byte-identical for every base field", () => {
  const base = ["url", "body", "headers", "severity", "demonstrated_severity", "finding_id", "resource_id", "id"];
  for (const field of base) {
    let caught;
    try {
      assertNoForbiddenInputs({ [field]: "x" }, "bob_http_confirm");
    } catch (error) { caught = error; }
    assert.ok(caught, `${field} must be rejected`);
    assert.equal(caught.code, ERROR_CODES.INVALID_ARGUMENTS);
    assert.equal(
      caught.message,
      `bob_http_confirm does not accept ${field}; the request is derived server-side from surface_id and path_template`,
    );
  }
  // a clean confirmer args object does not throw
  assert.doesNotThrow(() => assertNoForbiddenInputs(
    { target_domain: "x.test", surface_id: "s", oracle_kind: "differential_response", path_template: "/api/accounts/{id}" },
    "bob_http_confirm",
  ));
});

test("assertNoForbiddenInputs guard semantics: nullish args are safe, hasOwnProperty (not truthiness) gates", () => {
  assert.doesNotThrow(() => assertNoForbiddenInputs(null, "bob_http_confirm"));
  assert.doesNotThrow(() => assertNoForbiddenInputs(undefined, "bob_http_confirm"));
  assert.doesNotThrow(() => assertNoForbiddenInputs({}, "bob_http_confirm"));
  // a present-but-empty forbidden field still throws (hasOwnProperty, not truthiness)
  assert.throws(() => assertNoForbiddenInputs({ url: "" }, "bob_http_confirm"), /does not accept url/);
  // extraFields defaults to [] — only the base list applies when omitted
  assert.doesNotThrow(() => assertNoForbiddenInputs({ object_id: "x" }, "bob_http_confirm"));
  // a non-array extraFields is a mis-wiring that would silently weaken the guard
  // (a string spreads into single chars, dropping the intended extra field) — it
  // must fail fast, not degrade security quietly.
  assert.throws(
    () => assertNoForbiddenInputs({}, "bob_http_idor_confirm", "object_id"),
    /forbidden-input guard misconfigured: extraFields must be an array/,
  );
});

// --- rejectInvalidArguments ---

test("rejectInvalidArguments throws a ToolError(INVALID_ARGUMENTS) carrying details", () => {
  let caught;
  try {
    rejectInvalidArguments("boom", { code: "x", path: "/p" });
  } catch (error) { caught = error; }
  assert.ok(caught);
  assert.equal(caught.code, ERROR_CODES.INVALID_ARGUMENTS);
  assert.equal(caught.message, "boom");
  assert.equal(caught.details.path, "/p");
});

// --- escapeRegExp / decodePathSegments ---

test("escapeRegExp escapes regex metacharacters", () => {
  assert.equal(escapeRegExp("a.b+c"), "a\\.b\\+c");
  assert.equal(escapeRegExp("/api/x"), "/api/x");
});

test("decodePathSegments recursively decodes each segment to a fixed point (<=8 passes)", () => {
  assert.equal(decodePathSegments("/api/%2564elete/1"), "/api/delete/1"); // %2564 -> %64 -> d
  assert.equal(decodePathSegments("/api/accounts/known"), "/api/accounts/known"); // no-op
});

// --- capturedIdSegmentIsSafe ---

test("capturedIdSegmentIsSafe accepts clean ids (incl. dotted) and rejects separators/punctuation at any depth", () => {
  for (const ok of ["known", "user.name", "1.2.3", "file.bin", "550e8400-e29b-41d4-a716-446655440000"]) {
    assert.equal(capturedIdSegmentIsSafe(ok), true, `${ok} should be safe`);
  }
  for (const bad of [
    "a/b", "a\\b", "a:b", "a;b", "a,b",
    "known%2Fdelete", "known%252Fdelete", "known%2525252Fdelete", "known%25%32%46delete",
    "known%5Cdelete", "known%3Acapture",
  ]) {
    assert.equal(capturedIdSegmentIsSafe(bad), false, `${bad} should be unsafe`);
  }
  assert.equal(capturedIdSegmentIsSafe(""), false);
  // DOCUMENTED RESIDUAL (see capturedIdSegmentIsSafe comment): a dot-action suffix
  // in a RECORDED id is treated SAFE because real ids legitimately contain dots.
  // Pinned here so a future tightening is a deliberate, test-visible change.
  assert.equal(capturedIdSegmentIsSafe("pay_123.capture"), true);
});

// --- pathTemplateMatchesEndpoint ---

test("pathTemplateMatchesEndpoint matches single-{id} templates and rejects shape/segment mismatches", () => {
  assert.equal(pathTemplateMatchesEndpoint("/api/accounts/{id}", "/api/accounts/known"), true);
  assert.equal(pathTemplateMatchesEndpoint("/api/accounts/{id}", "/api/users/known"), false);
  // captured segment routes to a sub-resource/action -> unsafe -> no match
  assert.equal(pathTemplateMatchesEndpoint("/api/accounts/{id}", "/api/accounts/known%2Fdelete"), false);
  assert.equal(pathTemplateMatchesEndpoint("/api/accounts/{id}", "/api/accounts/known:capture"), false);
  // {id} that matched a multi-segment span is rejected by the [^/]+ capture
  assert.equal(pathTemplateMatchesEndpoint("/api/accounts/{id}", "/api/accounts/a/b"), false);
  // a template without exactly one {id} slot never matches
  assert.equal(pathTemplateMatchesEndpoint("/api/accounts/{id}/{id}", "/api/accounts/a/b"), false);
  assert.equal(pathTemplateMatchesEndpoint("/api/accounts/x", "/api/accounts/x"), false);
});

// --- assertReadOnlyPath / normalizePathTemplate relocation guards ---

test("assertReadOnlyPath (from common) rejects destructive verb collections, allows noun reads", () => {
  assert.doesNotThrow(() => assertReadOnlyPath("https://t.example.test/api/order/123"));
  assert.throws(() => assertReadOnlyPath("https://t.example.test/api/delete/123"), /state-changing path segment/);
  assert.throws(() => assertReadOnlyPath("https://t.example.test/api/%2564elete/123"), /state-changing path segment/);
});

test("normalizePathTemplate (from common) enforces the {id}-final-segment structural boundary", () => {
  assert.equal(normalizePathTemplate("/api/accounts/{id}"), "/api/accounts/{id}");
  assert.doesNotThrow(() => normalizePathTemplate("/api/accounts/{id}.json"));
  assert.throws(() => normalizePathTemplate("/api/accounts/{id}/transfer"), /final path segment/);
  assert.throws(() => normalizePathTemplate("/api/accounts/{id}.capture"), /final path segment/);
  assert.throws(() => normalizePathTemplate("/api/accounts/{id}?fields=all"), /query string/);
});

// --- candidateSurfaceEndpoints ---

test("candidateSurfaceEndpoints yields uri then string endpoints in order, skipping blank/non-string", () => {
  assert.deepEqual(
    candidateSurfaceEndpoints({ uri: "https://x/api", endpoints: ["https://x/a", "", 7, "https://x/b"] }),
    [
      { value: "https://x/api", field: "surface.uri" },
      { value: "https://x/a", field: "surface.endpoints[0]" },
      { value: "https://x/b", field: "surface.endpoints[3]" },
    ],
  );
  assert.deepEqual(candidateSurfaceEndpoints({ endpoints: [] }), []);
  assert.deepEqual(candidateSurfaceEndpoints(null), []);
  assert.deepEqual(candidateSurfaceEndpoints({}), []);
});

// --- resolveSurfaceOrigins ---

test("resolveSurfaceOrigins dedupes stateOrigin + endpoint origins + host-derived origins", () => {
  const origins = resolveSurfaceOrigins({
    uri: "https://api.example.test/v1",
    endpoints: ["https://api.example.test/v1/x", "mailto:a@b.test", "::: not a url"],
    hosts: ["edge.example.test", "https://api.example.test"],
  }, "https://api.example.test");
  assert.equal(origins[0], "https://api.example.test"); // stateOrigin first
  assert.ok(origins.includes("https://edge.example.test")); // bare host, https from stateOrigin protocol
  // dedupe: api.example.test appears via stateOrigin, uri, endpoint, and host -> once
  assert.equal(origins.filter((o) => o === "https://api.example.test").length, 1);
  // mailto / garbage endpoints contribute no origin
  assert.equal(origins.some((o) => o.startsWith("mailto")), false);
});

test("resolveSurfaceOrigins derives host origins with http when stateOrigin is http", () => {
  const origins = resolveSurfaceOrigins({ hosts: ["edge.example.test"] }, "http://api.example.test:8080");
  assert.ok(origins.includes("http://edge.example.test"));
});

// --- isAuthChallenge / isLoginRedirect / responseLooksLikeLoginPage ---

test("isAuthChallenge is true only for 401/403", () => {
  assert.equal(isAuthChallenge({ status: 401 }), true);
  assert.equal(isAuthChallenge({ status: 403 }), true);
  assert.equal(isAuthChallenge({ status: 200 }), false);
  assert.ok(!isAuthChallenge(null));
  assert.ok(!isAuthChallenge(undefined));
});

test("isLoginRedirect matches auth-shaped 3xx Location only", () => {
  assert.equal(isLoginRedirect(mockResponse(302, "", { location: "/login?next=/x" })), true);
  assert.equal(isLoginRedirect(mockResponse(303, "", { location: "https://sso.example.test/" })), true);
  assert.equal(isLoginRedirect(mockResponse(302, "", { location: "/dashboard" })), false);
  assert.equal(isLoginRedirect(mockResponse(200, "", { location: "/login" })), false);
  assert.equal(isLoginRedirect(null), false);
  assert.equal(isLoginRedirect({ status: 302 }), false); // no headers.get
});

test("responseLooksLikeLoginPage needs html/text + a form + a login keyword", () => {
  assert.equal(responseLooksLikeLoginPage(mockResponse(200, "<form><input name=password></form>", { "content-type": "text/html" })), true);
  assert.equal(responseLooksLikeLoginPage(mockResponse(200, "<form><input name=q></form>", { "content-type": "text/html" })), false);
  assert.equal(responseLooksLikeLoginPage(mockResponse(200, "<form>password</form>", { "content-type": "application/json" })), false);
  assert.equal(responseLooksLikeLoginPage({ status: 200, headers: { get: () => "text/html" }, bodyBytes: "not a buffer" }), false);
});

// --- isResourceShapedResponse relocation smoke ---

test("isResourceShapedResponse smoke: recognizes a genuine JSON resource, rejects soft-404 + empty collection", () => {
  assert.equal(isResourceShapedResponse(mockResponse(200, "{\"id\":7,\"email\":\"a@b.test\"}", { "content-type": "application/json" })), true);
  assert.equal(isResourceShapedResponse(mockResponse(200, "{\"error\":\"not found\"}", { "content-type": "application/json" })), false);
  assert.equal(isResourceShapedResponse(mockResponse(200, "{\"items\":[],\"total\":0,\"page\":1}", { "content-type": "application/json" })), false);
  assert.equal(isResourceShapedResponse(mockResponse(401, "{\"id\":7}", { "content-type": "application/json" })), false);
});

// --- findRoutedSurface (I/O) ---

test("findRoutedSurface returns the routed surface and throws on an unknown id", () => withTempHome(() => {
  const domain = "common-find.example.test";
  const surfaceId = "surface:accounts";
  JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}/` }));
  seedRoutedSurface(domain, surfaceId, `https://${domain}/api/accounts/known`);

  const { route, surface } = findRoutedSurface(domain, surfaceId);
  assert.equal(route.surface_id, surfaceId);
  assert.equal(surface.id, surfaceId);

  let caught;
  try { findRoutedSurface(domain, "surface:does-not-exist"); } catch (error) { caught = error; }
  assert.ok(caught);
  assert.equal(caught.code, ERROR_CODES.INVALID_ARGUMENTS);
  assert.match(caught.message, /unknown or unrouted surface_id surface:does-not-exist/);
  // The error lists the routed ids so a caller can self-correct instead of dead-ending.
  assert.match(caught.message, /routed surface_ids: surface:accounts/);
  assert.equal(caught.details.code, "surface_id_unrouted");
}));

test("findRoutedSurface suggests the prefixed id when a caller drops the surface: prefix", () => withTempHome(() => {
  // Regression (smoke-test 2026-06-26): an agent that routed to a producer with "search"
  // instead of "surface:search" got a no-hint error and abandoned the producer (fell back to
  // a hand-rolled scan + manual claim). The error must name the closest routed id so the next
  // call fires — the whole point of routing to the signed producer.
  const domain = "common-find-suggest.example.test";
  const surfaceId = "surface:search";
  JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}/` }));
  seedRoutedSurface(domain, surfaceId, `https://${domain}/search?q=test`);

  let caught;
  try { findRoutedSurface(domain, "search"); } catch (error) { caught = error; }
  assert.ok(caught);
  assert.equal(caught.code, ERROR_CODES.INVALID_ARGUMENTS);
  assert.match(caught.message, /did you mean surface:search\?/);
  assert.match(caught.message, /routed surface_ids: surface:search/);
}));

test("findRoutedSurface caps the listed ids at 20 and reports the full count", () => withTempHome(() => {
  const domain = "common-find-cap.example.test";
  JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}/` }));
  seedSurfaces(domain, Array.from({ length: 21 }, (_, i) => `surface:s${String(i).padStart(2, "0")}`));

  let caught;
  try { findRoutedSurface(domain, "definitely-missing"); } catch (error) { caught = error; }
  assert.ok(caught);
  // The message reports the full count and truncates the list (s00..s19 shown, s20 cut).
  assert.match(caught.message, /\(21 total\)/);
  assert.match(caught.message, /surface:s00/);
  assert.ok(!caught.message.includes("surface:s20"), "the 21st id is beyond the 20-cap");
}));

test("findRoutedSurface clips an oversized routed surface_id to 120 chars in the error", () => withTempHome(() => {
  const domain = "common-find-clip.example.test";
  JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}/` }));
  const longId = `surface:${"x".repeat(140)}`;
  seedSurfaces(domain, [longId]);

  let caught;
  try { findRoutedSurface(domain, "miss"); } catch (error) { caught = error; }
  assert.ok(caught);
  // The message clips the oversized id (119 + ellipsis); the full 140-char value never appears.
  assert.match(caught.message, /…/);
  assert.ok(!caught.message.includes(longId), "the full oversized id is not echoed");
}));

test("findRoutedSurface points a dropped-prefix caller at a QUARANTINED surface (re-run hint)", () => withTempHome(() => {
  // A corrupt route file QUARANTINES surface:search (the v2.1 hunter_agent->evaluator_agent
  // rename shape) so it is absent from the live routes. A dropped-prefix caller ("search")
  // should still be told it exists-but-needs-rerouting, not a bare "unknown".
  const domain = "common-find-quarantine.example.test";
  JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}/` }));
  seedSurfaces(domain, ["surface:keep", "surface:search"]);
  const rp = surfaceRoutesPath(domain);
  const doc = JSON.parse(fs.readFileSync(rp, "utf8"));
  for (const r of doc.routes) {
    if (r.surface_id === "surface:search") { delete r.evaluator_agent; r.hunter_agent = "hunter-agent"; }
  }
  fs.writeFileSync(rp, `${JSON.stringify(doc, null, 2)}\n`);

  let caught;
  try { findRoutedSurface(domain, "search"); } catch (error) { caught = error; }
  assert.ok(caught);
  assert.equal(caught.code, ERROR_CODES.INVALID_ARGUMENTS);
  assert.match(caught.message, /surface:search exists but has a malformed route — re-run bob_route_surfaces/);
}));

test("findRoutedSurface sanitizes control chars in EVERY echo path (caller, listed, suggestion)", () => withTempHome(() => {
  // surface_id AND persisted route ids are echoed into the LLM-facing error. A control char in
  // ANY echoed id — the caller's free-text id, a listed routed id, or the suggested id — must be
  // stripped so it can't forge extra log/message lines. One safe() guards all paths; exercise each
  // with a REAL control char (BEL) so the property is verified, not vacuously true on clean inputs.
  const domain = "common-find-sanitize.example.test";
  JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}/` }));
  // The BEL-bearing routed id survives routing into the live inventory (probed), so it appears in
  // the `listed` echo AND is an exact dropped-prefix suggestion target for the caller below.
  seedSurfaces(domain, ["surface:ev\u0007il", "surface:keep"]);

  // (caller + listed) a newline/tab caller id is sanitized, and the BEL routed id is sanitized in
  // the listed inventory — no raw control char survives from either path.
  let c1;
  try { findRoutedSurface(domain, "a\nb\tc"); } catch (error) { c1 = error; }
  assert.ok(c1);
  assert.match(c1.message, /unknown or unrouted surface_id a·b·c/);
  assert.match(c1.message, /surface:ev·il/);
  assert.ok(!/[\x00-\x1f\x7f]/.test(c1.message), "no raw control char survives (caller + listed paths)");

  // (suggestion) a dropped-prefix caller matching the BEL routed id gets a sanitized "did you mean".
  let c2;
  try { findRoutedSurface(domain, "ev\u0007il"); } catch (error) { c2 = error; }
  assert.ok(c2);
  assert.match(c2.message, /did you mean surface:ev·il\?/);
  assert.ok(!/[\x00-\x1f\x7f]/.test(c2.message), "no raw control char survives the suggestion path");
}));

test("findRoutedSurface sanitizes a control char in the quarantine-hint path", () => withTempHome(() => {
  // The quarantine hint echoes a malformed route's id; a control char in it must be stripped too —
  // the same safe() as every other echo path, not just the live-suggestion/listed paths.
  const domain = "common-find-quarantine-sanitize.example.test";
  JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}/` }));
  seedSurfaces(domain, ["surface:keep", "surface:sea\u0007rch"]);
  const rp = surfaceRoutesPath(domain);
  const doc = JSON.parse(fs.readFileSync(rp, "utf8"));
  // Malform the BEL-bearing route so it drops to malformed_routes (the quarantine branch), mirroring
  // the v2.1 evaluator_agent->hunter_agent rename shape used by the sibling quarantine test.
  for (const r of doc.routes) {
    if (r.surface_id === "surface:sea\u0007rch") { delete r.evaluator_agent; r.hunter_agent = "hunter-agent"; }
  }
  fs.writeFileSync(rp, `${JSON.stringify(doc, null, 2)}\n`);

  let caught;
  try { findRoutedSurface(domain, "sea\u0007rch"); } catch (error) { caught = error; }
  assert.ok(caught);
  assert.match(caught.message, /surface:sea·rch exists but has a malformed route — re-run bob_route_surfaces/);
  assert.ok(!/[\x00-\x1f\x7f]/.test(caught.message), "no raw control char survives the quarantine hint");
}));

test("findRoutedSurface bounds the suggestion lookup on a pathologically long surface_id", () => withTempHome(() => {
  // A huge caller id must not drive key-building (`surface:${id}` + replace) against every candidate:
  // it cannot exact-match a short routed id, so the suggestion is skipped and the echoed value is
  // still clipped. Guards the error path against unbounded work and an unbounded message.
  const domain = "common-find-bound.example.test";
  JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}/` }));
  seedSurfaces(domain, ["surface:real"]);
  const huge = "z".repeat(100000);

  let caught;
  try { findRoutedSurface(domain, huge); } catch (error) { caught = error; }
  assert.ok(caught);
  assert.ok(!caught.message.includes(huge), "the huge caller id is clipped, not echoed in full");
  assert.match(caught.message, /…/, "the echoed caller id is clipped to the bound");
  assert.ok(!/did you mean/.test(caught.message), "no suggestion is attempted for an unmatchable huge id");
  assert.ok(caught.message.length < 1000, "the error message stays bounded");
}));

test("findRoutedSurface sanitizes the surface_id echoed by the malformed-route rejection", () => withTempHome(() => {
  // The malformed-route rejection (reached when the caller's EXACT id is a quarantined route) echoes
  // the agent-controlled surface_id; a control char in it must be stripped by the SAME safe() as the
  // unrouted branch — proving the hardening is function-wide, not an island (the round-6 finding).
  const domain = "common-find-malformed-sanitize.example.test";
  JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}/` }));
  seedSurfaces(domain, ["surface:keep", "surface:bad\u0007id"]);
  const rp = surfaceRoutesPath(domain);
  const doc = JSON.parse(fs.readFileSync(rp, "utf8"));
  for (const r of doc.routes) {
    if (r.surface_id === "surface:bad\u0007id") { delete r.evaluator_agent; r.hunter_agent = "hunter-agent"; }
  }
  fs.writeFileSync(rp, `${JSON.stringify(doc, null, 2)}\n`);

  let caught;
  try { findRoutedSurface(domain, "surface:bad\u0007id"); } catch (error) { caught = error; }
  assert.ok(caught);
  assert.match(caught.message, /surface_id surface:bad·id has a malformed route/);
  assert.ok(!/[\x00-\x1f\x7f]/.test(caught.message), "no raw control char survives the malformed-route rejection");
}));

test("findRoutedSurface sanitizes the surface_id echoed by the routed-but-absent rejection", () => withTempHome(() => {
  // The routed-but-not-present rejection also echoes the agent-controlled surface_id; the same
  // safe() must cover it — the third echo site the function-wide 'uniform' invariant must hold for.
  const domain = "common-find-absent-sanitize.example.test";
  JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}/` }));
  seedSurfaces(domain, ["surface:keep", "surface:gho\u0007st"]); // routes BOTH ids
  // Drop the BEL surface from attack_surface.json so it stays ROUTED but is no longer present.
  fs.writeFileSync(attackSurfacePath(domain), `${JSON.stringify({
    surfaces: [{
      id: "surface:keep", title: "t", surface_type: "web", hosts: [domain],
      endpoints: [`https://${domain}/k`], tech_stack: ["fixture"], priority: "HIGH",
    }],
  }, null, 2)}\n`);

  let caught;
  try { findRoutedSurface(domain, "surface:gho\u0007st"); } catch (error) { caught = error; }
  assert.ok(caught);
  assert.match(caught.message, /surface_id surface:gho·st is routed but not present/);
  assert.ok(!/[\x00-\x1f\x7f]/.test(caught.message), "no raw control char survives the routed-but-absent rejection");
}));

test("findRoutedSurface strips Unicode line/bidi controls from the echoed surface_id", () => withTempHome(() => {
  // safe() must also strip the Unicode log-forging / Trojan-Source set (line/paragraph separators and
  // bidi embeddings/overrides/isolates), not just ASCII controls — else a U+2028 forges a log line and
  // a U+202E (RLO) visually reorders the echoed id. (round-7 Codex/brutalist finding.) String.fromCharCode
  // keeps these out of the source as raw bytes while still exercising the real chars at runtime.
  const RLO = String.fromCharCode(0x202e); // RIGHT-TO-LEFT OVERRIDE (Trojan-Source bidi)
  const LS = String.fromCharCode(0x2028);  // LINE SEPARATOR (a JS/log line terminator)
  const PDI = String.fromCharCode(0x2069); // POP DIRECTIONAL ISOLATE
  const domain = "common-find-unicode-strip.example.test";
  JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}/` }));
  seedSurfaces(domain, ["surface:keep"]);

  let caught;
  try { findRoutedSurface(domain, `a${RLO}b${LS}c${PDI}d`); } catch (error) { caught = error; }
  assert.ok(caught);
  // each stripped char becomes "·": the echoed caller id is a·b·c·d, no raw separator/bidi survives.
  assert.match(caught.message, /unknown or unrouted surface_id a·b·c·d/);
  assert.ok(!caught.message.includes(RLO), "no raw RLO (bidi override) survives");
  assert.ok(!caught.message.includes(LS), "no raw line separator survives");
  assert.ok(!caught.message.includes(PDI), "no raw bidi isolate survives");
}));

// --- originFromState / urlFromEndpoint / resolveBaselineFromSurface (I/O) ---

test("originFromState returns the in-scope origin and rejects a missing/invalid target_url", () => withTempHome(() => {
  const domain = "common-origin.example.test";
  JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}/` }));
  assert.equal(originFromState(domain, { target_url: `https://${domain}/app` }), `https://${domain}`);
  assert.throws(() => originFromState(domain, {}), /requires a web session with target_url/);
  assert.throws(() => originFromState(domain, { target_url: "not a url" }), /not a valid URL/);
}));

test("urlFromEndpoint resolves absolute URLs and absolute paths, rejects bare tokens", () => {
  assert.equal(urlFromEndpoint("https://x.test/api", "https://x.test", "f").toString(), "https://x.test/api");
  assert.equal(urlFromEndpoint("/api/y", "https://x.test", "f").toString(), "https://x.test/api/y");
  assert.throws(() => urlFromEndpoint("api/y", "https://x.test", "f"), /must be an absolute http\(s\) URL or an absolute path/);
});

test("resolveBaselineFromSurface resolves a query-free baseline that matches the template, else throws", () => withTempHome(() => {
  const domain = "common-baseline.example.test";
  JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}/` }));
  const { state } = readSessionStateStrict(domain);
  const surface = { id: "s", hosts: [domain], endpoints: [`https://${domain}/api/accounts/known?fields=all`] };

  const baseline = resolveBaselineFromSurface({ domain, surface, pathTemplate: "/api/accounts/{id}", state });
  // recorded query is dropped for baseline/target symmetry
  assert.equal(baseline.toString(), `https://${domain}/api/accounts/known`);
  assert.equal(baseline.search, "");

  assert.throws(
    () => resolveBaselineFromSurface({ domain, surface, pathTemplate: "/api/users/{id}", state }),
    /path shape does not match any recorded endpoint for surface_id/,
  );
}));

// --- auditConfirmRequest (parameterized toolId attribution) ---

test("auditConfirmRequest writes a breaker-visible record under any toolId and never throws", () => withTempHome(() => {
  const domain = "common-audit.example.test";
  JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}/` }));
  // normalizeHttpAuditRecord PERSISTS `tool` (the toolId) so the circuit breaker can tell a
  // faithful-auth bob_http_scan record (no `tool`) from an offensive-confirmer probe (which audits
  // WITHOUT an auth_profile) — the auth-aware heal-gate only reclassifies the former. Breaker /
  // request-budget VISIBILITY still comes from the record's existence + surface_id/status/url, not
  // from `tool`; a missing toolId cannot make a probe invisible.
  auditConfirmRequest({
    domain,
    surfaceId: "surface:accounts",
    method: "GET",
    url: `https://${domain}/api/accounts/known`,
    egressProfile: "default",
    status: 200,
    startedAt: 1,
    toolId: "bob_http_idor_confirm",
  });
  const records = readHttpAuditRecordsFromJsonl(domain).filter((r) => r.surface_id === "surface:accounts");
  assert.equal(records.length, 1, "the probe must be recorded for circuit-breaker visibility");
  assert.equal(records[0].method, "GET");
  assert.equal(records[0].status, 200);
  // a successful probe records scope_decision "allowed" (a null would make
  // normalizeHttpAuditRecord throw and silently drop the breaker-visibility record)
  assert.equal(records[0].scope_decision, "allowed");
  // `tool` is now persisted (the toolId) — it gates the breaker's faithful-auth heal logic; it
  // never affects breaker-visibility (record existence + surface_id/status/url do that).
  assert.equal(records[0].tool, "bob_http_idor_confirm");
  // defensive audit contract: never throws even with no domain / no toolId
  assert.doesNotThrow(() => auditConfirmRequest({ domain: null }));
}));

// --- SCOPE_VALIDATION_OPTS export contract ---

test("SCOPE_VALIDATION_OPTS is the frozen intentional-no-internal-host-block sentinel", () => {
  assert.deepEqual(SCOPE_VALIDATION_OPTS, { blockInternalHosts: false });
  assert.equal(Object.isFrozen(SCOPE_VALIDATION_OPTS), true);
});
