"use strict";

// Locks the documented contract of target-intake.parseRpcFlag: it validates the
// url SCHEME ONLY (https:), NOT the destination host. Private/loopback/link-local
// https hosts PASS here by design — the private-host/SSRF DNS preflight
// (sc-egress-policy.filterResolvedPublicRpcEndpoints) is a separate, downstream
// egress gate. These assertions exist to make any future host-validation change
// (or an accidental "public-HTTPS-only" reinterpretation) a loud, deliberate
// decision rather than a silent drift.

const test = require("node:test");
const assert = require("node:assert/strict");

const { parseRpcFlag } = require("../mcp/core/target-intake.js");

test("parseRpcFlag accepts a well-formed https rpc flag (scheme passes)", () => {
  const out = parseRpcFlag("evm:1=https://mainnet.example.com/rpc");
  assert.deepEqual(out, {
    chain_family: "evm",
    chain_id: "1",
    url: "https://mainnet.example.com/rpc",
  });
});

test("parseRpcFlag validates scheme only — private/loopback/link-local https hosts PASS", () => {
  // These are the exact hosts an SSRF/egress gate would reject. parseRpcFlag is
  // NOT that gate, so they must parse successfully (returned, not refused).
  const privateHosts = [
    "https://127.0.0.1:8545/",
    "https://169.254.169.254/latest/meta-data/", // cloud metadata
    "https://10.0.0.5/rpc", // RFC1918
    "https://192.168.1.53/rpc", // RFC1918
    "https://172.16.0.1/rpc", // RFC1918
    "https://localhost/rpc",
  ];
  for (const url of privateHosts) {
    const out = parseRpcFlag(`evm:1=${url}`);
    assert.equal(out.refuse, undefined, `expected ${url} to PASS the scheme-only check`);
    assert.equal(out.url, url);
    assert.equal(out.chain_family, "evm");
  }
});

test("parseRpcFlag refuses non-https schemes by NAME (scheme gate is real)", () => {
  for (const url of [
    "http://mainnet.example.com/rpc",
    "ws://node.example.com",
    "wss://node.example.com",
    "file:///etc/passwd",
  ]) {
    const out = parseRpcFlag(`evm:1=${url}`);
    assert.equal(out.refuse, true, `expected ${url} to be refused`);
    assert.match(out.reason, /non_https_rpc_url/);
  }
});

test("parseRpcFlag refuses an unparseable url by NAME", () => {
  const out = parseRpcFlag("evm:1=:::not-a-url");
  assert.equal(out.refuse, true);
  assert.match(out.reason, /invalid_rpc_url/);
});
