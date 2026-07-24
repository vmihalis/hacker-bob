"use strict";

// SEEDED test matrix for the bob_http_xss_reflect reflected-canary XSS FINDER
// signed-row PRODUCER (find-axis MVP).
//
// Every probe goes through an INJECTED fetch_fn that reads the producer-minted
// canary value out of the request URL's locus query param and reflects it into a
// configurable HTML template via a configurable transform (raw / HTML-escaped /
// percent-encoded / placed in a safe lexical context). No live target: the
// surface + a query-bearing recorded endpoint are seeded directly. The positive
// fires ONLY when the inert metacharacter sentinel survives UNESCAPED into an
// HTML-executable context (text node / unquoted attribute) — a context-blind
// substring check would mis-fire on the escaped/safe-context negatives below.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const PRODUCER_PATH = path.join(__dirname, "..", "mcp", "lib", "offensive-reflect-producer.js");
const {
  reflectXss,
  REFLECT_DEMONSTRATED_CEILING,
  htmlContextAt,
  recordedQueryParamNames,
} = require("../mcp/lib/offensive-reflect-producer.js");
const { initSession } = require("../mcp/lib/session-state.js");
const { routeSurfaces } = require("../mcp/lib/surface-router.js");
const { ensureHandoffSigningKey } = require("../mcp/lib/handoff-signing-key.js");
const { attackSurfacePath, offensiveRunsJsonlPath } = require("../mcp/lib/paths.js");
const {
  appendCandidateClaim,
  readCandidateClaims,
  readOffensiveRunRecords,
  canonicalizeExploitTarget,
} = require("../mcp/lib/claims.js");
const { verifyRowWithMac, OFFENSIVE_ROW_MAC_CONTEXT } = require("../mcp/lib/offensive-row-mac.js");
const { resolveOffensiveRowVerifier } = require("../mcp/lib/handoff-signing-key.js");
const { projectExploitRunObservedRef } = require("../mcp/lib/claim-freeze.js");
const {
  resetForTests: resetMaterializationDebounce,
} = require("../mcp/lib/frontier-materialize-debounce.js");
const {
  mintSensitiveShapeSafeToken,
  sensitiveShapesPresent,
} = require("../mcp/lib/offensive-http-common.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-reflect-producer-"));
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

const SURFACE_ID = "surface:search";
const LOCUS = "q";

function seedRoutedSurface(domain, { endpoint, hosts, endpoints } = {}) {
  fs.mkdirSync(path.dirname(attackSurfacePath(domain)), { recursive: true });
  fs.writeFileSync(attackSurfacePath(domain), `${JSON.stringify({
    surfaces: [{
      id: SURFACE_ID,
      title: "Synthetic reflected-search surface",
      surface_type: "web",
      hosts: hosts || [domain],
      endpoints: endpoints || [endpoint || `https://${domain}/search?${LOCUS}=test`],
      tech_stack: ["fixture"],
      priority: "HIGH",
    }],
  }, null, 2)}\n`, "utf8");
  JSON.parse(routeSurfaces({ target_domain: domain }));
}

function setupSession(domain, opts = {}) {
  JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}/` }));
  seedRoutedSurface(domain, opts);
  ensureHandoffSigningKey(domain);
}

function baseArgs(domain, overrides = {}) {
  return {
    target_domain: domain,
    surface_id: SURFACE_ID,
    param_locus: "0",
    oracle_kind: "reflected_context",
    ...overrides,
  };
}

function htmlResponse(status, bodyStr, headers = {}) {
  const lower = {};
  for (const [k, v] of Object.entries(headers)) lower[String(k).toLowerCase()] = v;
  if (!("content-type" in lower)) lower["content-type"] = "text/html; charset=utf-8";
  const bytes = Buffer.from(bodyStr, "utf8");
  return {
    status,
    headers: { get(name) { return lower[String(name).toLowerCase()] ?? null; } },
    bodyBytes: bytes,
    bodyByteLength: bytes.length,
    bodyTruncated: false,
  };
}

function htmlEscape(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

// Default sink: a text node (the classic reflected-XSS sink).
const TEXT_NODE_WRAP = (r) => `<!doctype html><html><body><h1>Results</h1><p>You searched for ${r} today.</p></body></html>`;
const UNQUOTED_ATTR_WRAP = (r) => `<!doctype html><html><body><input type=text value=${r} class=x></body></html>`;
const QUOTED_ATTR_WRAP = (r) => `<!doctype html><html><body><input type="text" value="${r}"></body></html>`;
const SCRIPT_WRAP = (r) => `<!doctype html><html><head><script>var term = "${r}";</script></head><body></body></html>`;
const COMMENT_WRAP = (r) => `<!doctype html><html><body><!-- last query: ${r} --></body></html>`;
const CDATA_WRAP = (r) => `<!doctype html><html><body><svg><![CDATA[ ${r} ]]></svg></body></html>`;
const TITLE_WRAP = (r) => `<!doctype html><html><head><title>${r}</title></head><body></body></html>`;
const TEMPLATE_WRAP = (r) => `<!doctype html><html><body><template><div>${r}</div></template></body></html>`;

// The producer-minted canary value always carries the "bxr" nonce prefix, so the
// fetch_fn finds the injected param by that marker rather than a hardcoded name
// (robust regardless of which recorded param the locus selected).
function injectedCanaryValue(url) {
  for (const [, v] of new URL(url).searchParams.entries()) {
    if (/bxr[0-9a-f]{32}/.test(v)) return v;
  }
  return "";
}

// Reflects the producer-minted locus value into `wrap(transform(value))`.
function reflectFetchFn({
  transform = (v) => v,
  wrap = TEXT_NODE_WRAP,
  contentType,
  status = 200,
  reflect = true,
  throwError = false,
  extraHeaders = {},
} = {}) {
  return async ({ url }) => {
    if (throwError) throw new Error("connect ECONNREFUSED 203.0.113.10:443");
    const value = injectedCanaryValue(url);
    const body = reflect
      ? wrap(transform(value))
      : `<!doctype html><html><body><p>No results to show.</p></body></html>`;
    const headers = { ...extraHeaders };
    if (contentType) headers["content-type"] = contentType;
    return htmlResponse(status, body, headers);
  };
}

async function run(domain, { fetch_fn, args } = {}) {
  return reflectXss(args || baseArgs(domain), { fetch_fn: fetch_fn || reflectFetchFn() });
}

// ───────────────────────── pure-helper unit tests ──────────────────────────

test("canary mint rejects a random hex value that accidentally looks like card PII", () => {
  const accidentalCard = "a4111111111111111aaaaaaaaaaaaaaa";
  const safeHex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  assert.equal(accidentalCard.length, 32);
  assert.equal(sensitiveShapesPresent(`bxr${accidentalCard}`), true);
  let calls = 0;
  const token = mintSensitiveShapeSafeToken("bxr", {
    randomBytes() {
      calls += 1;
      return Buffer.from(calls === 1 ? accidentalCard : safeHex, "hex");
    },
  });
  assert.equal(calls, 2);
  assert.equal(token, `bxr${safeHex}`);
  assert.equal(sensitiveShapesPresent(token), false);
});

test("htmlContextAt classifies executable vs safe reflection contexts (fail-closed)", () => {
  const cases = [
    ["<p>here:NONCE</p>", "text_node"],
    ["<div>NONCE", "text_node"],
    ["<input value=NONCE>", "unquoted_attr"],
    ["<input value=\"NONCE\">", "quoted_attr"],
    ["<input value='NONCE'>", "quoted_attr"],
    ["<script>var a=NONCE", "rawtext"],
    ["<style>a{x:NONCE", "rawtext"],
    ["<title>NONCE", "rcdata"],
    ["<textarea>NONCE", "rcdata"],
    ["<!-- NONCE", "comment"],
    ["<svg><![CDATA[NONCE", "cdata"],
    // a closed script returns to text context
    ["<script>x</script><p>NONCE", "text_node"],
    // a closed quoted attribute returns to tag (unquoted) context
    ["<a href=\"x\" NONCE", "unquoted_attr"],
    // a non-matching end-tag PREFIX does NOT exit raw-text (</scripture> != </script>)
    ["<script>var s=\"</scripture>\"; NONCE", "rawtext"],
    // inert <template> + legacy <plaintext> contents are non-executable → raw-text
    ["<template><div>NONCE", "rawtext"],
    ["<plaintext>NONCE", "rawtext"],
    // <plaintext> is TERMINAL: a literal </plaintext> does NOT exit it
    ["<plaintext>x</plaintext>NONCE", "rawtext"],
    // a reflection inside a <!doctype>/<!…> declaration or <?…> PI is inert
    ["<!doctype html PUBLIC NONCE", "declaration"],
    ["<body><!ENTITY x NONCE", "declaration"],
    ["<?xml version=NONCE", "declaration"],
  ];
  for (const [tpl, want] of cases) {
    const idx = tpl.indexOf("NONCE");
    assert.equal(htmlContextAt(tpl, idx), want, `${JSON.stringify(tpl)} -> ${want}`);
  }
});

test("recordedQueryParamNames de-dups and sorts deterministically", () => {
  const u = new URL("https://x.test/p?z=1&a=2&a=3&m=4");
  assert.deepEqual(recordedQueryParamNames(u), ["a", "m", "z"]);
});

test("REFLECT ceiling is a frozen hard medium", () => {
  assert.equal(REFLECT_DEMONSTRATED_CEILING.reflected_context, "medium");
  assert.equal(Object.isFrozen(REFLECT_DEMONSTRATED_CEILING), true);
});

// MUST-FIX #5: the producer stays strictly in-process on safeFetch.
test("the producer module never requires child_process (strictly in-process)", () => {
  const src = fs.readFileSync(PRODUCER_PATH, "utf8");
  assert.ok(!/require\(\s*['"]child_process['"]\s*\)/.test(src), "must not require child_process");
  assert.ok(!/child_process/.test(src), "must not reference child_process at all");
});

// ───────────────────────── positive ──────────────────────────

test("positive: metachars survive unescaped in a text node → signed MEDIUM row", () => withTempHome(async () => {
  const domain = "reflect-positive-textnode.example.test";
  setupSession(domain);
  const result = await run(domain);

  assert.equal(result.confirmed, true, JSON.stringify(result));
  assert.equal(result.row_written, true);
  assert.equal(result.offensive_outcome, "exploited_safely");
  assert.equal(result.demonstrated_severity, "medium");
  assert.equal(result.tool_id, "bob_http_xss_reflect");
  assert.equal(result.surface_id, SURFACE_ID);
  assert.equal(result.masked_oracle.param, LOCUS);
  assert.equal(result.masked_oracle.context, "text_node");

  const rows = readOffensiveRunRecords(domain);
  assert.equal(rows.length, 1);
  const row = rows[0];
  assert.equal(row.demonstrated_severity, "medium");
  assert.equal(row.surface_id, SURFACE_ID);
  assert.equal(row.tool_id, "bob_http_xss_reflect");
  assert.equal(row.offensive_outcome, "exploited_safely");
  assert.equal(row.dry_run, false);
  assert.equal(row.timed_out, false);
  // value-blind target: query stripped to origin+path.
  assert.equal(row.target, `https://${domain}/search`);
  assert.equal(row.target, canonicalizeExploitTarget(`https://${domain}/search?${LOCUS}=x`));
  // well-formed + MAC-valid. Producer-minted rows are ed25519 (v2).
  assert.equal(row.row_mac.version, 2);
  assert.equal(verifyRowWithMac(OFFENSIVE_ROW_MAC_CONTEXT, row, resolveOffensiveRowVerifier(domain)), true, "row MAC must verify");
  for (const h of ["command_hash", "stdout_hash", "stderr_hash"]) {
    assert.match(result[h], /^[0-9a-f]{64}$/);
    assert.equal(result[h], row[h]);
  }
  // capture file on disk re-hashes to the row's stdout_hash (freeze re-hash path).
  const observed = projectExploitRunObservedRef(domain, { kind: "exploit_run", run_id: row.run_id });
  assert.equal(observed.stdout_hash, row.stdout_hash);
}));

test("positive: metachars survive in an unquoted attribute (tag-break) → signed MEDIUM row", () => withTempHome(async () => {
  const domain = "reflect-positive-unquoted.example.test";
  setupSession(domain);
  const result = await run(domain, { fetch_fn: reflectFetchFn({ wrap: UNQUOTED_ATTR_WRAP }) });
  assert.equal(result.confirmed, true, JSON.stringify(result));
  assert.equal(result.row_written, true);
  assert.equal(result.masked_oracle.context, "unquoted_attr");
  assert.equal(readOffensiveRunRecords(domain).length, 1);
}));

// ───────────────────────── negative matrix (sign nothing) ──────────────────────────

const NEGATIVE_CASES = [
  ["HTML-escaped reflection", { transform: htmlEscape }, "metachars_escaped"],
  ["percent-encoded reflection", { transform: encodeURIComponent }, "metachars_escaped"],
  ["reflection inside a quoted attribute (safe)", { wrap: QUOTED_ATTR_WRAP }, "safe_context"],
  ["reflection inside a JS string (script)", { wrap: SCRIPT_WRAP }, "safe_context"],
  ["reflection inside an HTML comment", { wrap: COMMENT_WRAP }, "safe_context"],
  ["reflection inside CDATA", { wrap: CDATA_WRAP }, "safe_context"],
  ["reflection inside RCDATA <title>", { wrap: TITLE_WRAP }, "safe_context"],
  ["reflection inside an inert <template>", { wrap: TEMPLATE_WRAP }, "safe_context"],
  ["JSON response + nosniff", { contentType: "application/json", extraHeaders: { "x-content-type-options": "nosniff" } }, "content_type_not_html"],
  // exact-essence match: a non-rendered html-ish subtype must NOT be treated as html.
  ["non-exact html content-type (sandboxed subtype)", { contentType: "text/html-sandboxed" }, "content_type_not_html"],
  // auditor F1: a text/html response delivered as a download is not a rendered sink.
  ["served as an attachment download (not rendered)", { extraHeaders: { "content-disposition": "attachment; filename=\"r.html\"" } }, "content_disposition_attachment"],
  ["no reflection at all", { reflect: false }, "nonce_not_reflected"],
  ["WAF 429 rate-limit", { status: 429 }, "waf_or_rate_limit"],
  ["WAF 503 unavailable", { status: 503 }, "waf_or_rate_limit"],
  ["transport error", { throwError: true }, "transport_error"],
];

for (let ni = 0; ni < NEGATIVE_CASES.length; ni += 1) {
  const [label, opts, expectedReason] = NEGATIVE_CASES[ni];
  test(`negative: ${label} mints NOTHING`, () => withTempHome(async () => {
    const domain = `reflect-neg-${ni}.example.test`;
    setupSession(domain);
    const result = await run(domain, { fetch_fn: reflectFetchFn(opts) });
    assert.equal(result.confirmed, false, `${label}: expected blocked, got ${JSON.stringify(result)}`);
    assert.equal(result.reason, expectedReason, `${label}: wrong reason (${result.reason})`);
    assert.equal(result.row_written, false);
    assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false, `${label}: ledger must not exist`);
  }));
}

const MAX_GAP_OVERFLOW = 80; // > the producer's MAX_REFLECTION_GAP (64)
test("negative: a split reflection (markers not contiguous) does NOT read page markup as a surviving metachar", () => withTempHome(async () => {
  // The server reflects the nonce and the end-marker far apart, with legit page
  // markup (containing a raw <>) between them. The bounded-window guard must
  // refuse rather than read the page's own `<` as our surviving sentinel.
  const domain = "reflect-neg-split.example.test";
  setupSession(domain);
  const fetch_fn = async ({ url }) => {
    const value = injectedCanaryValue(url); // nonce + sentinel + endMarker
    const nonce = (/^(bxr[0-9a-f]{32})/.exec(value) || [, value])[1];
    const endMarker = (/(exr[0-9a-f]{32})$/.exec(value) || [, ""])[1];
    const filler = "</p><p>".padEnd(MAX_GAP_OVERFLOW, "x"); // > MAX_REFLECTION_GAP, contains a raw <>
    const body = `<!doctype html><html><body><p>${nonce}${filler}${endMarker}</p></body></html>`;
    return htmlResponse(200, body);
  };
  const result = await run(domain, { fetch_fn });
  assert.equal(result.confirmed, false, JSON.stringify(result));
  assert.equal(result.reason, "reflection_boundary_too_far");
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("negative: a non-adjacent < and > in the bounded window is NOT read as a surviving sentinel (adjacency witness)", () => withTempHome(async () => {
  // The slice between the markers is WITHIN the 64-char gap (so the gap guard does
  // NOT fire) and contains a raw `<` and `>` from page markup (`<br>`), but NOT the
  // adjacent pair `<>`. The adjacency witness (between.includes("<>")) must reject
  // it — a loose "some `<` before some `>`" check would wrongly mint here. This is
  // the load-bearing anti-false-positive mechanism (the split test above exercises
  // only the gap guard).
  const domain = "reflect-neg-adjacency.example.test";
  setupSession(domain);
  const fetch_fn = async ({ url }) => {
    const value = injectedCanaryValue(url);
    const nonce = (/^(bxr[0-9a-f]{32})/.exec(value) || [, value])[1];
    const endMarker = (/(exr[0-9a-f]{32})$/.exec(value) || [, ""])[1];
    // between = "AAA<br>BBB" (10 chars < 64): raw `<` and `>` present, never adjacent.
    const body = `<!doctype html><html><body><p>${nonce}AAA<br>BBB${endMarker}</p></body></html>`;
    return htmlResponse(200, body);
  };
  const result = await run(domain, { fetch_fn });
  assert.equal(result.confirmed, false, JSON.stringify(result));
  assert.equal(result.reason, "metachars_escaped");
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("negative: a </scriptPREFIX> inside <script> does NOT exit raw-text → mints NOTHING (false-positive guard)", () => withTempHome(async () => {
  // The page reflects our value inside a <script> whose body contains the substring
  // "</scripture>" BEFORE the reflection. A prefix-only end-tag check would wrongly
  // exit raw-text and treat the (non-executable) script reflection as a text node.
  const domain = "reflect-neg-scriptprefix.example.test";
  setupSession(domain);
  const fetch_fn = reflectFetchFn({
    wrap: (r) => `<!doctype html><html><head><script>var s = "</scripture>"; var t = ${r};</script></head><body></body></html>`,
  });
  const result = await run(domain, { fetch_fn });
  assert.equal(result.confirmed, false, JSON.stringify(result));
  assert.equal(result.reason, "safe_context");
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("negative: a reflection inside a <!doctype …> declaration is inert → mints NOTHING", () => withTempHome(async () => {
  // The nonce reflects INSIDE a <!doctype …> declaration; the browser consumes it
  // as markup metadata until the next `>`, so it is not an executable text node.
  const domain = "reflect-neg-doctype.example.test";
  setupSession(domain);
  const fetch_fn = reflectFetchFn({
    wrap: (r) => `<!doctype html SYSTEM "about:legacy-compat" ${r}><html><body></body></html>`,
  });
  const result = await run(domain, { fetch_fn });
  assert.equal(result.confirmed, false, JSON.stringify(result));
  assert.equal(result.reason, "safe_context");
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("host binding: a relative endpoint on a subdomain surface signs the SUBDOMAIN target, not the session apex", () => withTempHome(async () => {
  // Session target is the apex; the surface was recorded on a subdomain with a
  // RELATIVE query endpoint. The signed row target must be the subdomain it was
  // recorded on, never the apex (resolveSurfaceOrigins lists the apex first).
  const domain = "reflect-hostbind.example.test";
  setupSession(domain, { hosts: [`api.${domain}`], endpoints: [`/search?${LOCUS}=test`] });
  const result = await run(domain);
  assert.equal(result.confirmed, true, JSON.stringify(result));
  const rows = readOffensiveRunRecords(domain);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].target, `https://api.${domain}/search`);
}));

test("pii safety: a percent-encoded PII shape in a recorded path segment blocks the signed row", () => withTempHome(async () => {
  // The recorded endpoint PATH carries an email, percent-encoded (%40 = @). The
  // canonical-target screen must decode it and refuse to persist it into a signed row.
  const domain = "reflect-pii-path.example.test";
  setupSession(domain, { endpoints: [`https://${domain}/u/alice%40corp.com/search?${LOCUS}=test`] });
  const result = await run(domain);
  assert.equal(result.confirmed, false, JSON.stringify(result));
  assert.equal(result.reason, "proof_target_contains_sensitive_value");
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

// ───────────────────────── locus + scope safety ──────────────────────────

test("locus safety: a surface with NO recorded query param → no_recorded_query_param (no agent URL invented)", () => withTempHome(async () => {
  const domain = "reflect-noquery.example.test";
  setupSession(domain, { endpoint: `https://${domain}/search` }); // path only, no query
  const result = await run(domain);
  assert.equal(result.confirmed, false);
  assert.equal(result.reason, "no_recorded_query_param");
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("locus safety: an action-shaped RECORDED query param (?_method=) is declined before any probe", () => withTempHome(async () => {
  // assertReadOnlyPath runs on the RECORDED endpoint AND the final injected URL.
  // A recorded ?_method= taints the endpoint → the producer refuses before probing.
  const domain = "reflect-action-param.example.test";
  setupSession(domain, { endpoint: `https://${domain}/search?_method=DELETE&${LOCUS}=test` });
  let probed = false;
  const fetch_fn = async (req) => { probed = true; return reflectFetchFn()(req); };
  await assert.rejects(
    () => reflectXss(baseArgs(domain), { fetch_fn }),
    /_method|not allowed/i,
  );
  assert.equal(probed, false, "no probe must fire when the recorded param is action-shaped");
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("locus safety: a verb-shaped recorded query param value is declined", () => withTempHome(async () => {
  const domain = "reflect-verb-value.example.test";
  setupSession(domain, { endpoint: `https://${domain}/api?op=delete&${LOCUS}=test` });
  await assert.rejects(
    () => run(domain),
    /mutation-shaped|not allowed/i,
  );
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("locus safety: param_locus ordinal out of range is rejected", () => withTempHome(async () => {
  const domain = "reflect-locus-oob.example.test";
  setupSession(domain); // one recorded param (q) → ordinal 0 valid, 1 invalid
  await assert.rejects(
    () => run(domain, { args: baseArgs(domain, { param_locus: "1" }) }),
    /out of range/i,
  );
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("input safety: a raw url / param_value / canary smuggling field is rejected", () => withTempHome(async () => {
  const domain = "reflect-forbidden-input.example.test";
  setupSession(domain);
  for (const bad of [{ url: "https://evil.test/x" }, { param_value: "1" }, { canary: "x" }, { param_name: "q" }]) {
    await assert.rejects(
      () => reflectXss(baseArgs(domain, bad), { fetch_fn: reflectFetchFn() }),
      /does not accept/i,
      `must reject smuggling field ${Object.keys(bad)[0]}`,
    );
  }
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("param_locus selects among multiple recorded params (sorted ordinal)", () => withTempHome(async () => {
  // Recorded params {z, a}; sorted → ["a","z"]; ordinal 1 → "z".
  const domain = "reflect-locus-select.example.test";
  setupSession(domain, { endpoint: `https://${domain}/search?z=1&a=2` });
  const seen = [];
  const fetch_fn = async (req) => {
    const u = new URL(req.url);
    seen.push([...u.searchParams.entries()].find(([, v]) => /bxr[0-9a-f]{32}/.test(v))?.[0]);
    return reflectFetchFn()(req);
  };
  const result = await run(domain, { fetch_fn, args: baseArgs(domain, { param_locus: "1" }) });
  assert.equal(result.confirmed, true, JSON.stringify(result));
  assert.equal(result.masked_oracle.param, "z");
  assert.ok(seen.every((p) => p === "z"), `injected param must be z, saw ${JSON.stringify(seen)}`);
}));

// ───────────────────────── round-trip: record → freeze re-hash → ceiling ──────────────────────────

test("round-trip: the minted row backs an exploited_safely claim, then re-hashes at freeze (medium held)", () => withTempHome(async () => {
  const domain = "reflect-roundtrip.example.test";
  setupSession(domain);
  const result = await run(domain);
  assert.equal(result.confirmed, true, JSON.stringify(result));

  const claim = appendCandidateClaim({
    target_domain: domain,
    title: "Reflected XSS sink demonstrated safely",
    summary: "A benign canary + inert metachar sentinel survived unescaped into an HTML text node.",
    severity: "medium",
    exploit_outcome: { outcome: "exploited_safely", safe_oracle: { kind: "reflected_canary" } },
    surface_ids: [SURFACE_ID],
    evidence_refs: [{
      kind: "exploit_run",
      run_id: result.run_id,
      tool_id: result.tool_id,
      target: result.target,
      offensive_outcome: "exploited_safely",
      command_hash: result.command_hash,
      exit_code: result.exit_code,
      stdout_hash: result.stdout_hash,
      stderr_hash: result.stderr_hash,
    }],
  });
  assert.equal(claim.exploit_outcome.outcome, "exploited_safely");
  assert.equal(claim.severity, "medium");

  const [readBack] = readCandidateClaims(domain);
  assert.equal(readBack.claim_hash, claim.claim_hash);

  const row = readOffensiveRunRecords(domain)[0];
  for (let i = 0; i < 3; i += 1) {
    const observed = projectExploitRunObservedRef(domain, { kind: "exploit_run", run_id: row.run_id });
    assert.equal(observed.stdout_hash, row.stdout_hash, `verify round ${i + 1} re-hash must match`);
  }
}));

test("round-trip: a claim severity ABOVE the medium ceiling is rejected", () => withTempHome(async () => {
  const domain = "reflect-ceiling.example.test";
  setupSession(domain);
  const result = await run(domain);
  assert.equal(result.confirmed, true);
  let caught;
  try {
    appendCandidateClaim({
      target_domain: domain,
      title: "Over-severity claim",
      summary: "Attempts to claim high from a medium reflected-XSS row.",
      severity: "high",
      exploit_outcome: { outcome: "exploited_safely", safe_oracle: { kind: "reflected_canary" } },
      surface_ids: [SURFACE_ID],
      evidence_refs: [{
        kind: "exploit_run",
        run_id: result.run_id,
        tool_id: result.tool_id,
        target: result.target,
        offensive_outcome: "exploited_safely",
        command_hash: result.command_hash,
        exit_code: result.exit_code,
        stdout_hash: result.stdout_hash,
        stderr_hash: result.stderr_hash,
      }],
    });
  } catch (error) { caught = error; }
  assert.ok(caught, "over-severity must be rejected");
  assert.equal(caught.details.code, "exploit_proof_severity_exceeds_demonstrated");
}));
