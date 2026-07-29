"use strict";

// bob_ws_probe security oracle (review hardening). Three properties the brutalist
// review flagged as broken in the original probe, locked here:
//   1. CSWSH is a credentialed differential — a bare foreign-Origin handshake is
//      NEVER reported as a vulnerability (it is the normal state of public WS
//      endpoints), so the probe cannot mint false-positive HIGH findings.
//   2. The connect plan pins the resolved address (connect-time scope) unless the
//      egress proxy owns resolution, closing the check-time/connect-time DNS-rebind
//      divergence (SSRF).
//   3. The python fallback fails closed when an egress proxy or connect-time scope
//      enforcement is required (it can honor neither), instead of connecting from
//      the host's real IP while the audit ledger stamps the configured egress.

const test = require("node:test");
const assert = require("node:assert/strict");

const { EventEmitter } = require("events");
const {
  classifyCswsh,
  wsConnectPlan,
  collectMessagesNative,
  matchJsonRpcResponse,
  buildCallerHeaders,
  cswshArmHeaders,
} = require("../mcp/lib/ws-probe.js");
const { applyAuthProfileHeaders, PROFILE_METADATA_KEYS } = require("../mcp/lib/auth.js");

test("CSWSH: no auth_profile never flags vulnerable, even on an accepted foreign-Origin handshake", () => {
  const accepted = classifyCswsh({ hasAuth: false, authedAccepted: true, controlAccepted: null });
  assert.equal(accepted.cswsh_vulnerable, false, "no ambient credentials → cannot demonstrate CSWSH");
  assert.equal(accepted.foreign_origin_accepted, true, "still surfaces the raw observable");
  assert.match(accepted.cswsh_note, /auth_profile/, "note tells the operator how to actually test it");

  const rejected = classifyCswsh({ hasAuth: false, authedAccepted: false, controlAccepted: null });
  assert.equal(rejected.cswsh_vulnerable, false);
  assert.equal(rejected.foreign_origin_accepted, false);
});

test("CSWSH: flags vulnerable ONLY when credentialed accept differs from uncredentialed reject", () => {
  const vuln = classifyCswsh({ hasAuth: true, authedAccepted: true, controlAccepted: false });
  assert.equal(vuln.cswsh_vulnerable, true, "credential-dependent cross-origin access is the CSWSH signature");
  assert.equal(vuln.unauth_control_accepted, false);
});

test("CSWSH: an open endpoint (both accepted) is NOT a vulnerability", () => {
  const open = classifyCswsh({ hasAuth: true, authedAccepted: true, controlAccepted: true });
  assert.equal(open.cswsh_vulnerable, false, "acceptance does not depend on credentials → open endpoint, not CSWSH");
  assert.match(open.cswsh_note, /open endpoint/);
});

test("CSWSH: credentialed handshake rejected → not vulnerable (Origin enforced)", () => {
  const enforced = classifyCswsh({ hasAuth: true, authedAccepted: false, controlAccepted: false });
  assert.equal(enforced.cswsh_vulnerable, false);
  assert.match(enforced.cswsh_note, /enforced/);
});

test("connect plan: direct egress pins the resolved address (closes DNS-rebind SSRF)", () => {
  const direct = wsConnectPlan({ hasProxy: false, blockInternalHosts: false });
  assert.equal(direct.pinLookup, true, "no proxy → must pin the validated IP at connect time");
  assert.equal(direct.useProxyAgent, false);
});

test("connect plan: proxy egress routes through the agent; pin deferred to the proxy when internal allowed", () => {
  const proxied = wsConnectPlan({ hasProxy: true, blockInternalHosts: false });
  assert.equal(proxied.useProxyAgent, true, "proxy must carry the WS traffic, not a direct socket");
  assert.equal(proxied.pinLookup, false, "the proxy owns resolution when internal hosts are allowed");
});

test("connect plan: proxy + block-internal still pins (defense in depth)", () => {
  const both = wsConnectPlan({ hasProxy: true, blockInternalHosts: true });
  assert.equal(both.useProxyAgent, true);
  assert.equal(both.pinLookup, true, "internal-host block forces a local resolve+validate even with a proxy");
});

test("collectMessagesNative bounds aggregate buffering (no OOM from a hostile stream)", async () => {
  // A hostile in-scope endpoint could stream unbounded frames; the collector must cap
  // total accumulated bytes (the safe-fetch response cap, carried over to the WS path).
  const socket = new EventEmitter();
  socket.terminate = () => {};
  const p = collectMessagesNative(socket, { maxMessages: 1000, timeoutMs: 1000, maxBytes: 1000 });
  // Stream 10 frames of 500 bytes each = 5000 bytes; the 1000-byte cap must stop it.
  for (let i = 0; i < 10; i += 1) socket.emit("message", "x".repeat(500));
  const messages = await p;
  const total = messages.reduce((acc, m) => acc + m.length, 0);
  assert.ok(total <= 1000, `aggregate buffer (${total}) stays within the byte cap`);
  assert.ok(messages.length < 10, "collection stopped before draining the whole hostile stream");
});

test("matchJsonRpcResponse attributes by id, ignoring out-of-order / unsolicited frames", () => {
  const frames = [
    JSON.stringify({ jsonrpc: "2.0", method: "eth_subscription", params: { x: 1 } }), // unsolicited push, no id
    JSON.stringify({ jsonrpc: "2.0", id: 7, result: "0x1" }), // a STALE prior reply
    JSON.stringify({ jsonrpc: "2.0", id: 9, result: "0x2" }), // THIS request
  ];
  assert.equal(matchJsonRpcResponse(frames, 9), frames[2], "picks the frame whose id matches the request");
  assert.equal(matchJsonRpcResponse(frames, 5), null, "no matching id → null (not a misattributed neighbor)");
  assert.equal(matchJsonRpcResponse(["{bad json", JSON.stringify({ id: 3, result: 1 })], 3), "{\"id\":3,\"result\":1}", "skips unparseable frames");
});

test("collectMessagesNative preserves the persistent error sink (no process-crash window)", async () => {
  // The enumerate loop calls collectMessagesNative between sends; if it stripped the
  // connect-time 'error' listener (removeAllListeners), a socket reset between sends
  // would throw an uncatchable ERR_UNHANDLED_ERROR. It must remove ONLY its own
  // listeners, leaving the persistent sink attached.
  const socket = new EventEmitter();
  let sinkHits = 0;
  socket.on("error", () => { sinkHits += 1; }); // stand-in for connectWsNative's sink
  socket.terminate = () => {};

  const p = collectMessagesNative(socket, { maxMessages: 1, timeoutMs: 50 });
  socket.emit("close"); // ends the collection
  await p;

  assert.equal(socket.listenerCount("error"), 1, "the persistent error sink survives collection");
  // An error AFTER collection is absorbed by the surviving sink — no unhandled throw.
  assert.doesNotThrow(() => socket.emit("error", new Error("post-collection reset")));
  assert.equal(sinkHits, 1, "the surviving sink handled the late error");
});

// ── Settable handshake headers (User-Agent / auth-profile credentials) ─────────────
// buildCallerHeaders is the exact function wsProbe uses to assemble the base handshake
// header map handed to connectWsNative (connect.headers); asserting on it is asserting
// at the wsOptions.headers boundary for the no-auth path (extraHeaders === baseHeaders).

test("a settable user_agent reaches the assembled WS handshake headers", () => {
  const headers = buildCallerHeaders("Edge-Passing-UA/2.0", undefined);
  assert.equal(headers["User-Agent"], "Edge-Passing-UA/2.0", "the edge-403-passing UA is carried outbound");
  // Custom headers ride alongside the UA.
  const withCustom = buildCallerHeaders("UA/1", { "X-Probe": "on" });
  assert.deepEqual(withCustom, { "User-Agent": "UA/1", "X-Probe": "on" });
  // No caller headers → empty base (the prior default).
  assert.deepEqual(buildCallerHeaders(undefined, undefined), {});
});

test("auth_profile attaches credential headers while stripping every PROFILE_METADATA_KEY", () => {
  // The exact merge wsProbe performs: applyAuthProfileHeaders(baseHeaders, resolvedProfile).
  const rawProfile = {
    Authorization: "Bearer sekret",
    Cookie: "sid=abc",
    // Bob-local metadata that must NEVER egress as handshake headers:
    credentials: { password: "pw" },
    local_storage: { token: "t" },
    session_storage: { s: "1" },
    synthetic: true,
    email: "bot@synthetic.example",
    email_origin: "temp-mailbox",
    provisioned_via: "bob_auto_signup",
    expires_at: "2030-01-01",
    cookie_jar: { sid: "abc" },
  };
  const base = buildCallerHeaders("UA/1", undefined);
  const outbound = applyAuthProfileHeaders(base, rawProfile);

  assert.equal(outbound.Authorization, "Bearer sekret", "credential header attaches to the handshake");
  assert.equal(outbound.Cookie, "sid=abc");
  assert.equal(outbound["User-Agent"], "UA/1", "the caller UA survives the credential merge");
  for (const metaKey of PROFILE_METADATA_KEYS) {
    assert.ok(!(metaKey in outbound), `PROFILE_METADATA_KEY "${metaKey}" must not egress`);
  }
  // Purity: the base header map is not mutated by the merge.
  assert.deepEqual(base, { "User-Agent": "UA/1" });
});

test("an explicit user_agent overrides a profile-supplied User-Agent (presence rule)", () => {
  const base = buildCallerHeaders("Explicit-UA/9", undefined);
  const outbound = applyAuthProfileHeaders(base, { "User-Agent": "profile-UA", Authorization: "Bearer x" });
  assert.equal(outbound["User-Agent"], "Explicit-UA/9", "caller UA wins over the profile UA");
  assert.equal(outbound.Authorization, "Bearer x", "profile credential still attaches");
});

test("CSWSH negative control carries the base UA but no credential header (regression lock)", () => {
  const baseHeaders = buildCallerHeaders("Edge-UA/3", undefined);
  // extraHeaders = the authed set (base + credentials), as wsProbe assembles it.
  const extraHeaders = applyAuthProfileHeaders(baseHeaders, { Authorization: "Bearer s", Cookie: "sid=1" });
  const arms = cswshArmHeaders({ headers: extraHeaders, baseHeaders, foreignOrigin: "https://evil.example.com" });

  // Both arms carry the transport headers (UA + foreign Origin)...
  assert.equal(arms.authed["User-Agent"], "Edge-UA/3");
  assert.equal(arms.control["User-Agent"], "Edge-UA/3", "the UA-based WAF sees the SAME UA on both arms");
  assert.equal(arms.authed.Origin, "https://evil.example.com");
  assert.equal(arms.control.Origin, "https://evil.example.com");
  // ...and differ ONLY by credential material.
  assert.equal(arms.authed.Authorization, "Bearer s");
  assert.ok(!("Authorization" in arms.control), "control arm carries no credential → no forged CSWSH from a UA-only diff");
  assert.ok(!("Cookie" in arms.control));
});

test("header values with CR/LF or control chars are rejected (request NOT sent)", () => {
  assert.throws(() => buildCallerHeaders("bad\r\nInjected: 1", undefined), /control character/i,
    "a CRLF-bearing user_agent is rejected");
  assert.throws(() => buildCallerHeaders(undefined, { "X-Foo": "a\r\nX-Evil: 1" }), /control character/i,
    "a CRLF-bearing custom header value is rejected");
  assert.throws(() => buildCallerHeaders(undefined, { "X-Foo": "tab\ttab" }), /control character/i,
    "other control chars are rejected too");
  // Malformed header NAME (space / injection) rejected.
  assert.throws(() => buildCallerHeaders(undefined, { "Bad Name": "v" }), /invalid header name/i);
  assert.throws(() => buildCallerHeaders(undefined, { "X\r\nEvil": "v" }), /invalid header name/i);
  // Bounds: too many headers, oversized value.
  const many = {};
  for (let i = 0; i < 17; i += 1) many[`X-H${i}`] = "v";
  assert.throws(() => buildCallerHeaders(undefined, many), /entry cap/i);
  assert.throws(() => buildCallerHeaders("x".repeat(4097), undefined), /exceeds/i);
  // Non-string value rejected.
  assert.throws(() => buildCallerHeaders(undefined, { "X-Foo": 5 }), /must be a string/i);
});

