"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const {
  parseHttpScanResult,
  makeHttpScanFetcher,
  makePerCallHttpScanFetcher,
} = require("../mcp/core/http-scan-adapter.js");

test("parseHttpScanResult parses JSON string into normalized observed shape", () => {
  const raw = JSON.stringify({
    status: 200,
    headers: { "Content-Type": "application/json; charset=utf-8" },
    body: JSON.stringify({ id: "u-1", name: "Alice" }),
  });
  const observed = parseHttpScanResult(raw, true);
  assert.equal(observed.status, 200);
  assert.equal(observed.content_type, "application/json");
  assert.deepEqual(observed.body, { id: "u-1", name: "Alice" });
  assert.equal(observed.sent_with_auth, true);
});

test("parseHttpScanResult accepts already-parsed object", () => {
  const observed = parseHttpScanResult({
    status: 204,
    headers: {},
    body: "",
  }, false);
  assert.equal(observed.status, 204);
  assert.equal(observed.content_type, null);
  assert.equal(observed.sent_with_auth, false);
});

test("parseHttpScanResult passes through non-JSON body when content-type is not JSON", () => {
  const observed = parseHttpScanResult({
    status: 200,
    headers: { "content-type": "text/html" },
    body: "<html></html>",
  }, false);
  assert.equal(observed.content_type, "text/html");
  assert.equal(observed.body, "<html></html>");
});

test("parseHttpScanResult tolerates malformed JSON body without throwing", () => {
  const observed = parseHttpScanResult({
    status: 200,
    headers: { "content-type": "application/json" },
    body: "{ not actually json",
  }, true);
  assert.equal(observed.body, "{ not actually json");
});

test("parseHttpScanResult finds content-type with case-insensitive header lookup", () => {
  const observed = parseHttpScanResult({
    status: 200,
    headers: { "CONTENT-TYPE": "application/JSON" },
    body: "{}",
  }, false);
  assert.equal(observed.content_type, "application/JSON");
});

test("parseHttpScanResult surfaces fetch_error envelope when http-scan reports an error", () => {
  const observed = parseHttpScanResult(JSON.stringify({
    error: "connection refused",
    scope_decision: null,
  }), false);
  assert.equal(observed.status, null);
  assert.equal(observed.body, null);
  assert.equal(observed.fetch_error, "connection refused");
});

test("parseHttpScanResult surfaces scope_decision when blocked", () => {
  const observed = parseHttpScanResult(JSON.stringify({
    error: "blocked",
    scope_decision: "blocked",
  }), false);
  assert.equal(observed.fetch_error, "blocked");
  assert.equal(observed.scope_decision, "blocked");
});

test("parseHttpScanResult rejects non-object non-string input", () => {
  assert.throws(() => parseHttpScanResult(123, false), /object or JSON string/);
  assert.throws(() => parseHttpScanResult(null, false), /object or JSON string/);
});

test("parseHttpScanResult rejects malformed JSON string", () => {
  assert.throws(() => parseHttpScanResult("{ not json", false), /not JSON/);
});

test("makeHttpScanFetcher injects auth_profile and reports sent_with_auth", async () => {
  const calls = [];
  const stubHttpScan = async (args) => {
    calls.push(args);
    return JSON.stringify({
      status: 200,
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ ok: true }),
    });
  };
  const fetcher = makeHttpScanFetcher({
    httpScanFn: stubHttpScan,
    target_domain: "example.com",
    auth_profile: "user-a",
  });
  const observed = await fetcher({ url: "https://example.com/users", method: "GET" });
  assert.equal(observed.sent_with_auth, true);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].auth_profile, "user-a");
  assert.equal(calls[0].target_domain, "example.com");
  assert.equal(calls[0].method, "GET");
});

test("makeHttpScanFetcher omits auth_profile when none given", async () => {
  const calls = [];
  const stubHttpScan = async (args) => {
    calls.push(args);
    return JSON.stringify({ status: 200, headers: {}, body: "" });
  };
  const fetcher = makeHttpScanFetcher({
    httpScanFn: stubHttpScan,
    target_domain: "example.com",
  });
  const observed = await fetcher({ url: "https://example.com/health", method: "GET" });
  assert.equal(observed.sent_with_auth, false);
  assert.equal(calls[0].auth_profile, undefined);
});

test("makeHttpScanFetcher forwards block_internal_hosts and egress_profile", async () => {
  const calls = [];
  const stubHttpScan = async (args) => {
    calls.push(args);
    return JSON.stringify({ status: 200, headers: {}, body: "" });
  };
  const fetcher = makeHttpScanFetcher({
    httpScanFn: stubHttpScan,
    target_domain: "example.com",
    block_internal_hosts: true,
    egress_profile: "vpn-proxy",
  });
  await fetcher({ url: "https://example.com/x", method: "GET" });
  assert.equal(calls[0].block_internal_hosts, true);
  assert.equal(calls[0].egress_profile, "vpn-proxy");
});

test("makeHttpScanFetcher rejects invalid configuration", () => {
  assert.throws(
    () => makeHttpScanFetcher({ httpScanFn: null, target_domain: "x" }),
    /httpScanFn/,
  );
  assert.throws(
    () => makeHttpScanFetcher({ httpScanFn: () => {}, target_domain: "" }),
    /target_domain/,
  );
});

test("makePerCallHttpScanFetcher uses auth_profile from per-call args", async () => {
  const calls = [];
  const stubHttpScan = async (args) => {
    calls.push(args);
    return JSON.stringify({ status: 200, headers: {}, body: "" });
  };
  const fetcher = makePerCallHttpScanFetcher({
    httpScanFn: stubHttpScan,
    target_domain: "example.com",
  });
  await fetcher({ url: "https://example.com/x", method: "GET", auth_profile: "admin" });
  await fetcher({ url: "https://example.com/x", method: "GET", auth_profile: "user" });
  assert.equal(calls[0].auth_profile, "admin");
  assert.equal(calls[1].auth_profile, "user");
});

test("makePerCallHttpScanFetcher omits auth_profile when blank and reports sent_with_auth false", async () => {
  const calls = [];
  const stubHttpScan = async (args) => {
    calls.push(args);
    return JSON.stringify({ status: 200, headers: {}, body: "" });
  };
  const fetcher = makePerCallHttpScanFetcher({
    httpScanFn: stubHttpScan,
    target_domain: "example.com",
  });
  const observed = await fetcher({ url: "https://example.com/x", method: "GET" });
  assert.equal(calls[0].auth_profile, undefined);
  assert.equal(observed.sent_with_auth, false);
});

test("makePerCallHttpScanFetcher with freshness:true carries no-cache request headers", async () => {
  const calls = [];
  const stubHttpScan = async (args) => {
    calls.push(args);
    return JSON.stringify({ status: 200, headers: {}, body: "" });
  };
  const fetcher = makePerCallHttpScanFetcher({
    httpScanFn: stubHttpScan,
    target_domain: "example.com",
    freshness: true,
  });
  await fetcher({ url: "https://example.com/orders/1", method: "GET", auth_profile: "admin" });
  assert.deepEqual(calls[0].headers, {
    "Cache-Control": "no-cache, no-store",
    "Pragma": "no-cache",
  });
  // Freshness rides args.headers and never displaces auth_profile forwarding.
  assert.equal(calls[0].auth_profile, "admin");
});

test("makePerCallHttpScanFetcher WITHOUT freshness sends no cache-control headers (default off, non-differential callers unchanged)", async () => {
  const calls = [];
  const stubHttpScan = async (args) => {
    calls.push(args);
    return JSON.stringify({ status: 200, headers: {}, body: "" });
  };
  const fetcher = makePerCallHttpScanFetcher({
    httpScanFn: stubHttpScan,
    target_domain: "example.com",
  });
  await fetcher({ url: "https://example.com/x", method: "GET", auth_profile: "admin" });
  assert.equal("headers" in calls[0], false);
});

test("makePerCallHttpScanFetcher rejects invalid configuration", () => {
  assert.throws(
    () => makePerCallHttpScanFetcher({ httpScanFn: null, target_domain: "x" }),
    /httpScanFn/,
  );
  assert.throws(
    () => makePerCallHttpScanFetcher({ httpScanFn: () => {}, target_domain: "" }),
    /target_domain/,
  );
});
