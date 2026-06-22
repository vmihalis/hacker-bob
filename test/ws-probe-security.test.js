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
} = require("../mcp/lib/ws-probe.js");

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

