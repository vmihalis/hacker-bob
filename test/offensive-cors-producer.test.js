"use strict";

// SEEDED test matrix for the bob_http_cors_confirm signed-row PRODUCER.
//
// Every probe goes through an INJECTED fetch_fn returning canned response headers, so no
// live target is needed. The positive fires ONLY when BOTH probes echo their OWN distinct
// server-minted Origin in Access-Control-Allow-Origin AND set ACAC:true — a static ACAO, a
// wildcard, single-origin echo, or reflection-without-credentials all write nothing.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  corsConfirm,
  headerValue,
  acaoEchoes,
  allowsCredentials,
  mintCanaryOriginPair,
  crossSiteFetchHeaders,
  CORS_DEMONSTRATED_CEILING,
} = require("../mcp/lib/offensive-cors-producer.js");
const { OFFENSIVE_TOOL_DEMONSTRATED_CEILING, canonicalizeExploitTarget } = require("../mcp/lib/claims.js");
const { initSession } = require("../mcp/lib/session-state.js");
const { routeSurfaces } = require("../mcp/lib/surface-router.js");
const { ensureHandoffSigningKey } = require("../mcp/lib/handoff-signing-key.js");
const { attackSurfacePath, offensiveRunsJsonlPath } = require("../mcp/lib/paths.js");

const SURFACE_ID = "surface:api";
const ENDPOINT = "/api/data";

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-cors-producer-"));
  process.env.HOME = home;
  return Promise.resolve()
    .then(() => fn(home))
    .finally(() => {
      if (previousHome === undefined) delete process.env.HOME;
      else process.env.HOME = previousHome;
      fs.rmSync(home, { recursive: true, force: true });
    });
}

function setupSession(domain) {
  JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}/` }));
  fs.mkdirSync(path.dirname(attackSurfacePath(domain)), { recursive: true });
  fs.writeFileSync(attackSurfacePath(domain), `${JSON.stringify({
    surfaces: [{
      id: SURFACE_ID,
      title: "Synthetic CORS API surface",
      surface_type: "web",
      hosts: [domain],
      endpoints: [`https://${domain}${ENDPOINT}`],
      tech_stack: ["fixture"],
      priority: "HIGH",
    }],
  }, null, 2)}\n`);
  JSON.parse(routeSurfaces({ target_domain: domain }));
  ensureHandoffSigningKey(domain);
}

function readRows(domain) {
  const p = offensiveRunsJsonlPath(domain);
  if (!fs.existsSync(p)) return [];
  return fs.readFileSync(p, "utf8").split("\n").filter(Boolean).map((line) => JSON.parse(line));
}

// A fetch_fn that ECHOES the request Origin into ACAO with ACAC:true → the dangerous
// credentialed reflected-origin misconfiguration.
function reflectingFetch({ headers }) {
  return Promise.resolve({
    status: 200,
    headers: {
      "access-control-allow-origin": headers.Origin,
      "access-control-allow-credentials": "true",
    },
  });
}

const baseArgs = (domain) => ({ target_domain: domain, surface_id: SURFACE_ID });

// ───────────────────────── pure-helper unit tests ──────────────────────────

test("headerValue reads case-insensitively from a Headers-like object and a plain map", () => {
  const viaGet = { headers: { get: (n) => (n.toLowerCase() === "access-control-allow-origin" ? "https://x" : null) } };
  assert.equal(headerValue(viaGet, "Access-Control-Allow-Origin"), "https://x");
  const viaMap = { headers: { "Access-Control-Allow-Origin": "https://y" } };
  assert.equal(headerValue(viaMap, "access-control-allow-origin"), "https://y");
  assert.equal(headerValue({ headers: {} }, "access-control-allow-origin"), null);
  assert.equal(headerValue({}, "x"), null);
});

test("acaoEchoes requires an EXACT echo (not wildcard, not static)", () => {
  const r = { headers: { "access-control-allow-origin": "https://o.example" } };
  assert.equal(acaoEchoes(r, "https://o.example"), true);
  assert.equal(acaoEchoes(r, "https://other.example"), false);
  assert.equal(acaoEchoes({ headers: { "access-control-allow-origin": "*" } }, "https://o.example"), false);
  assert.equal(acaoEchoes({ headers: {} }, "https://o.example"), false);
});

test("allowsCredentials is true ONLY for the case-sensitive literal 'true' (Fetch Standard)", () => {
  assert.equal(allowsCredentials({ headers: { "access-control-allow-credentials": "true" } }), true);
  // Case-SENSITIVE per the Fetch Standard — browsers reject "TRUE", so we must too (else a
  // signed row would represent a config a browser would not honor).
  assert.equal(allowsCredentials({ headers: { "access-control-allow-credentials": "TRUE" } }), false);
  assert.equal(allowsCredentials({ headers: { "access-control-allow-credentials": "false" } }), false);
  assert.equal(allowsCredentials({ headers: {} }), false);
});

test("mintCanaryOriginPair produces two structurally-dissimilar unguessable origins", () => {
  const [a, b] = mintCanaryOriginPair();
  // Different TLD AND label arrangement so a single suffix/prefix allowlist cannot match both.
  assert.match(a, /^https:\/\/bob-cors-[0-9a-f]{32}\.example$/);
  assert.match(b, /^https:\/\/[0-9a-f]{32}-bobcanary\.test$/);
  assert.notEqual(a, b);
  // Unguessable + non-repeating across calls.
  const [c, d] = mintCanaryOriginPair();
  assert.notEqual(a, c);
  assert.notEqual(b, d);
});

test("crossSiteFetchHeaders emulates a real cross-site credentialed fetch (Origin + Sec-Fetch-*)", () => {
  const h = crossSiteFetchHeaders("https://o.example");
  assert.equal(h.Origin, "https://o.example");
  assert.equal(h["Sec-Fetch-Site"], "cross-site");
  assert.equal(h["Sec-Fetch-Mode"], "cors");
  assert.equal(h["Sec-Fetch-Dest"], "empty");
});

test("CORS ceiling is a frozen hard medium, in lockstep with the claims registry", () => {
  assert.equal(CORS_DEMONSTRATED_CEILING.bob_http_cors_confirm, "medium");
  assert.equal(OFFENSIVE_TOOL_DEMONSTRATED_CEILING.bob_http_cors_confirm, "medium");
});

// ───────────────────────── oracle behavior ─────────────────────────────────

test("positive: arbitrary-origin reflection + credentials mints EXACTLY ONE signed medium row", () => withTempHome(async () => {
  const domain = "cors-positive.example.test";
  setupSession(domain);
  const result = await corsConfirm(baseArgs(domain), { fetch_fn: reflectingFetch });

  assert.equal(result.confirmed, true, JSON.stringify(result));
  assert.equal(result.row_written, true);
  assert.equal(result.offensive_outcome, "exploited_safely");
  assert.equal(result.demonstrated_severity, "medium");
  assert.equal(result.tool_id, "bob_http_cors_confirm");
  assert.equal(result.surface_id, SURFACE_ID);

  const rows = readRows(domain);
  assert.equal(rows.length, 1);
  const row = rows[0];
  assert.equal(row.demonstrated_severity, "medium");
  assert.equal(row.surface_id, SURFACE_ID);
  assert.equal(row.target, canonicalizeExploitTarget(`https://${domain}${ENDPOINT}`));
  assert.ok(row.row_mac && row.row_mac.digest, "row must be MAC-signed");
  for (const h of ["command_hash", "stdout_hash", "stderr_hash"]) {
    assert.match(result[h], /^[0-9a-f]{64}$/);
    assert.equal(result[h], row[h]);
  }
}));

test("negative: a STATIC ACAO (does not echo the minted origin) writes nothing", () => withTempHome(async () => {
  const domain = "cors-static.example.test";
  setupSession(domain);
  const staticFetch = () => Promise.resolve({
    status: 200,
    headers: { "access-control-allow-origin": "https://app.example", "access-control-allow-credentials": "true" },
  });
  const result = await corsConfirm(baseArgs(domain), { fetch_fn: staticFetch });
  assert.equal(result.confirmed, false);
  assert.equal(result.row_written, false);
  assert.equal(result.reason, "acao_does_not_reflect_arbitrary_origin");
  assert.equal(readRows(domain).length, 0);
}));

test("negative: a WILDCARD ACAO writes nothing", () => withTempHome(async () => {
  const domain = "cors-wildcard.example.test";
  setupSession(domain);
  const wildFetch = () => Promise.resolve({
    status: 200,
    headers: { "access-control-allow-origin": "*", "access-control-allow-credentials": "true" },
  });
  const result = await corsConfirm(baseArgs(domain), { fetch_fn: wildFetch });
  assert.equal(result.confirmed, false);
  assert.equal(result.reason, "acao_does_not_reflect_arbitrary_origin");
  assert.equal(readRows(domain).length, 0);
}));

test("negative: reflected origin WITHOUT credentials writes nothing", () => withTempHome(async () => {
  const domain = "cors-nocreds.example.test";
  setupSession(domain);
  const noCredsFetch = ({ headers }) => Promise.resolve({
    status: 200,
    headers: { "access-control-allow-origin": headers.Origin }, // echo, but no ACAC:true
  });
  const result = await corsConfirm(baseArgs(domain), { fetch_fn: noCredsFetch });
  assert.equal(result.confirmed, false);
  assert.equal(result.reason, "reflection_without_credentials");
  assert.equal(readRows(domain).length, 0);
}));

test("negative: a single static value that matches only ONE probe is not arbitrary reflection", () => withTempHome(async () => {
  const domain = "cors-oneonly.example.test";
  setupSession(domain);
  // Capture the first probe's Origin, then echo THAT same value for both probes. Probe 1
  // appears to "echo", but probe 2 (a different minted origin) does NOT match → fail closed.
  let firstOrigin = null;
  const stickyFetch = ({ headers }) => {
    if (firstOrigin === null) firstOrigin = headers.Origin;
    return Promise.resolve({
      status: 200,
      headers: { "access-control-allow-origin": firstOrigin, "access-control-allow-credentials": "true" },
    });
  };
  const result = await corsConfirm(baseArgs(domain), { fetch_fn: stickyFetch });
  assert.equal(result.confirmed, false);
  assert.equal(result.reason, "acao_does_not_reflect_arbitrary_origin");
  assert.equal(readRows(domain).length, 0);
}));

// ───────────────────────── input safety ────────────────────────────────────

test("forbidden inputs (agent-supplied origin/url/header) are rejected", () => withTempHome(async () => {
  const domain = "cors-forbidden.example.test";
  setupSession(domain);
  for (const bad of [{ origin: "https://evil" }, { url: "https://evil/x" }, { header: "X" }, { acao: "*" }]) {
    await assert.rejects(
      () => corsConfirm({ ...baseArgs(domain), ...bad }, { fetch_fn: reflectingFetch }),
      /does not accept|not allowed|forbidden|INVALID/i,
    );
  }
  assert.equal(readRows(domain).length, 0);
}));

test("no-leak: the masked return + the signed row carry only Bob's minted origins + booleans", () => withTempHome(async () => {
  const domain = "cors-noleak.example.test";
  setupSession(domain);
  // The stub also returns an extra header with a secret-shaped value; it must NEVER reach
  // the capture/return (the producer reads only ACAO/ACAC, never the rest of the response).
  const leakyFetch = ({ headers }) => Promise.resolve({
    status: 200,
    headers: {
      "access-control-allow-origin": headers.Origin,
      "access-control-allow-credentials": "true",
      "x-secret": "sk_live_should_never_be_captured",
      "set-cookie": "session=topsecretcookievalue",
    },
  });
  const result = await corsConfirm(baseArgs(domain), { fetch_fn: leakyFetch });
  assert.equal(result.confirmed, true);
  const serialized = JSON.stringify(result) + JSON.stringify(readRows(domain));
  assert.doesNotMatch(serialized, /sk_live_should_never_be_captured|topsecretcookievalue/);
}));

test("negative: a 3xx REDIRECT with reflected ACAO+ACAC writes nothing (opaque, not browser-readable)", () => withTempHome(async () => {
  const domain = "cors-redirect.example.test";
  setupSession(domain);
  const redirectFetch = ({ headers }) => Promise.resolve({
    status: 302,
    headers: { "access-control-allow-origin": headers.Origin, "access-control-allow-credentials": "true", location: "/elsewhere" },
  });
  const result = await corsConfirm(baseArgs(domain), { fetch_fn: redirectFetch });
  assert.equal(result.confirmed, false);
  assert.equal(result.reason, "non_2xx_response_not_browser_readable");
  assert.equal(readRows(domain).length, 0);
}));

test("negative: a 4xx error page with reflected ACAO+ACAC (global CORS middleware) writes nothing", () => withTempHome(async () => {
  const domain = "cors-errpage.example.test";
  setupSession(domain);
  const errorFetch = ({ headers }) => Promise.resolve({
    status: 401,
    headers: { "access-control-allow-origin": headers.Origin, "access-control-allow-credentials": "true" },
  });
  const result = await corsConfirm(baseArgs(domain), { fetch_fn: errorFetch });
  assert.equal(result.confirmed, false);
  assert.equal(result.reason, "non_2xx_response_not_browser_readable");
  assert.equal(readRows(domain).length, 0);
}));

test("partial probe failure: if the second probe errors, no row is written and the error propagates", () => withTempHome(async () => {
  const domain = "cors-partialfail.example.test";
  setupSession(domain);
  let calls = 0;
  const failSecond = ({ headers }) => {
    calls += 1;
    if (calls === 2) return Promise.reject(new Error("network boom"));
    return Promise.resolve({
      status: 200,
      headers: { "access-control-allow-origin": headers.Origin, "access-control-allow-credentials": "true" },
    });
  };
  await assert.rejects(() => corsConfirm(baseArgs(domain), { fetch_fn: failSecond }), /network boom/);
  assert.equal(readRows(domain).length, 0);
}));

// ───────────────────────── host-binding (P1) ───────────────────────────────

test("a RELATIVE endpoint binds to the surface's declared host, NOT the session apex", () => withTempHome(async () => {
  const domain = "cors-hostbind.example.test";
  const surfaceHost = `api.${domain}`; // a DIFFERENT (sub)host than the session apex
  JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}/` }));
  fs.mkdirSync(path.dirname(attackSurfacePath(domain)), { recursive: true });
  fs.writeFileSync(attackSurfacePath(domain), `${JSON.stringify({
    surfaces: [{
      id: SURFACE_ID,
      title: "Surface whose host differs from the session apex",
      surface_type: "web",
      hosts: [surfaceHost],
      endpoints: ["/api/data"], // RELATIVE — must resolve against surfaceHost, not the apex
      tech_stack: ["fixture"],
      priority: "HIGH",
    }],
  }, null, 2)}\n`);
  JSON.parse(routeSurfaces({ target_domain: domain }));
  ensureHandoffSigningKey(domain);

  let probedUrl = null;
  const captureFetch = ({ url, headers }) => {
    probedUrl = url;
    return Promise.resolve({
      status: 200,
      headers: { "access-control-allow-origin": headers.Origin, "access-control-allow-credentials": "true" },
    });
  };
  const result = await corsConfirm(baseArgs(domain), { fetch_fn: captureFetch });
  assert.equal(result.confirmed, true, JSON.stringify(result));
  // The probe + the signed row target are bound to the SURFACE host, not the apex.
  assert.equal(probedUrl, `https://${surfaceHost}/api/data`);
  const rows = readRows(domain);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].target, canonicalizeExploitTarget(`https://${surfaceHost}/api/data`));
}));

// ───────────────────────── Fetch-Metadata defense (P2-a) ───────────────────

test("a target that blocks cross-site Sec-Fetch-Site (Fetch Metadata) mints nothing", () => withTempHome(async () => {
  const domain = "cors-fetchmeta.example.test";
  setupSession(domain);
  let sawCrossSite = false;
  // Reflects ACAO+ACAC for a 2xx, BUT a Fetch-Metadata defense 403s a cross-site request — the
  // exact case where a non-browser Origin-only probe would FALSELY confirm. Our probe sends
  // Sec-Fetch-Site: cross-site, so it is blocked just like the browser → 2xx gate fails closed.
  const fetchMetaFetch = ({ headers }) => {
    if (headers["Sec-Fetch-Site"] === "cross-site") sawCrossSite = true;
    const blocked = headers["Sec-Fetch-Site"] === "cross-site";
    return Promise.resolve({
      status: blocked ? 403 : 200,
      headers: { "access-control-allow-origin": headers.Origin, "access-control-allow-credentials": "true" },
    });
  };
  const result = await corsConfirm(baseArgs(domain), { fetch_fn: fetchMetaFetch });
  assert.equal(sawCrossSite, true, "probe must carry Sec-Fetch-Site: cross-site");
  assert.equal(result.confirmed, false);
  assert.equal(result.reason, "non_2xx_response_not_browser_readable");
  assert.equal(readRows(domain).length, 0);
}));

// ───────────────────── dissimilar canaries (P2-b) ──────────────────────────

test("a single-suffix allowlist (reflects only *.example) is NOT arbitrary reflection → no row", () => withTempHome(async () => {
  const domain = "cors-suffix.example.test";
  setupSession(domain);
  // Server reflects ONLY origins ending in ".example" (a narrow suffix allowlist). The first
  // canary (.example) echoes; the second (.test) does not → the both-must-echo gate fails closed.
  const suffixFetch = ({ headers }) => {
    const origin = headers.Origin;
    const echo = /\.example$/.test(origin) ? origin : "https://app.example";
    return Promise.resolve({
      status: 200,
      headers: { "access-control-allow-origin": echo, "access-control-allow-credentials": "true" },
    });
  };
  const result = await corsConfirm(baseArgs(domain), { fetch_fn: suffixFetch });
  assert.equal(result.confirmed, false);
  assert.equal(result.reason, "acao_does_not_reflect_arbitrary_origin");
  assert.equal(readRows(domain).length, 0);
}));
