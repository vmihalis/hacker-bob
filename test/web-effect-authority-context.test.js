"use strict";

// A8E — HTTP/WS effects bound to one frozen per-call session-authority context.
//
// Before this node, bob_http_scan (mcp/core/http-scan.js) and bob_ws_probe
// (mcp/domains/web/ws-probe.js) each independently re-read the mutable state.json
// projection (blockInternalHostsRequestPolicy) AND independently re-verified the
// session nucleus a second time inside resolveAndAssertSessionEgressIdentity's
// already-bound fast path -- two independently-timed verified reads per request
// instead of one frozen context captured once. A concurrent write to state.json
// (or a stale ALS/nucleus read) between those two reads could let one axis observe
// a different session projection than the other within the SAME request.
//
// The properties under test: (1) the frozen context's block_internal_hosts_policy
// (session-authority-context.js) is sourced from the verified NUCLEUS, not
// state.json, so it is immune to a direct/concurrent state.json mutation made after
// the context was captured -- proven both in isolation and through a real dispatched
// request against a loopback fixture server; (2) the session-authority-context
// domain-match assertion (authorityContextTargetDomainMismatch) that both handlers
// consult before ever touching a transport; (3) a direct (non-dispatched) call
// fresh-verifies exactly like a dispatched call; (4) safeFetch's existing per-hop
// scope re-validation still rejects an out-of-scope redirect target under the
// context-sourced path; (5) a structural inventory of every safeFetch(...) call site
// under mcp/domains/web/ and mcp/core/http-scan.js, enforcing the oob-collector.js
// OOB exemption stays the sole one; (6) the WS transport (bob_ws_probe) gets the
// identical binding and immunity as HTTP.

const test = require("node:test");
const assert = require("node:assert/strict");
const dns = require("node:dns");
const fs = require("node:fs");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");

const { executeTool } = require("../mcp/core/dispatch/dispatch.js");
const { initSession } = require("../mcp/core/session/session-state.js");
const { httpScan } = require("../mcp/core/http-scan.js");
const { wsProbe } = require("../mcp/domains/web/ws-probe.js");
const {
  authorityContextTargetDomainMismatch,
  getOrVerifySessionAuthorityContext,
} = require("../mcp/core/session/session-authority-context.js");
const {
  blockInternalHostsRequestPolicy,
  composeBlockInternalHostsPolicy,
  readSessionStateStrict,
  writeSessionStateDocument,
} = require("../mcp/core/session/session-state-store.js");

let WsServer = null;
try {
  WsServer = require("ws").Server;
} catch (_) {
  WsServer = null;
}

const ROOT = path.resolve(__dirname, "..");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-web-authority-context-"));
  process.env.HOME = home;
  return Promise.resolve()
    .then(() => fn(home))
    .finally(() => {
      if (previousHome === undefined) delete process.env.HOME;
      else process.env.HOME = previousHome;
      fs.rmSync(home, { recursive: true, force: true });
    });
}

function withDnsHost(host, fn) {
  const originalLookup = dns.lookup;
  dns.lookup = function lookup(hostname, options, callback) {
    if (hostname === host) {
      const cb = typeof options === "function" ? options : callback;
      const opts = typeof options === "object" && options != null ? options : {};
      if (opts.all) cb(null, [{ address: "127.0.0.1", family: 4 }]);
      else cb(null, "127.0.0.1", 4);
      return;
    }
    return originalLookup.call(dns, hostname, options, callback);
  };
  return Promise.resolve()
    .then(fn)
    .finally(() => {
      dns.lookup = originalLookup;
    });
}

function withFixtureServer(handler, fn) {
  const requests = [];
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => {
      const body = Buffer.concat(chunks);
      requests.push({ method: req.method, url: req.url, headers: req.headers, body: body.toString("utf8") });
      handler(req, res, body.toString("utf8"));
    });
  });
  return new Promise((resolve, reject) => {
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => {
      Promise.resolve()
        .then(() => fn(server.address().port, requests))
        .then(resolve, reject)
        .finally(() => { server.close(); });
    });
  });
}

function withWsFixtureServer(fn) {
  if (!WsServer) {
    // The 'ws' npm package is a hard runtime dependency of bob_ws_probe itself
    // (ws-probe.js fails closed with egress_unavailable when absent) -- if it is
    // missing here, the install is broken the same way it would be at runtime.
    throw new Error("the 'ws' npm package is required to run the WS fixture tests");
  }
  const connections = [];
  const server = new WsServer({ host: "127.0.0.1", port: 0 });
  server.on("connection", (socket) => {
    connections.push(socket);
  });
  return new Promise((resolve, reject) => {
    server.on("error", reject);
    server.once("listening", () => {
      Promise.resolve()
        .then(() => fn(server.address().port, connections))
        .then(resolve, reject)
        .finally(() => { server.close(); });
    });
  });
}

function jsonOk(res, payload) {
  res.writeHead(200, { "content-type": "application/json" });
  res.end(JSON.stringify(payload));
}

// Directly mutates state.json on disk, bypassing every validated mutation path
// (initSession / bob_advance_session / etc.) -- simulating either a concurrent
// write from another process or an operator/attacker-tampered file. Used to prove
// the frozen, nucleus-sourced authority context is immune to it.
function mutateStateBlockInternalHosts(domain, blockInternalHosts) {
  const { raw, state } = readSessionStateStrict(domain);
  const nextState = {
    ...state,
    block_internal_hosts: blockInternalHosts,
    block_internal_hosts_source: blockInternalHosts ? "explicit_block" : "explicit_allow",
  };
  writeSessionStateDocument(domain, raw, nextState);
}

test("frozen block_internal_hosts_policy is immune to a direct post-capture state.json mutation (isolated)", () => withTempHome(() => {
  const domain = "a8e-frozen-isolated.example.test";
  JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}` }));

  const context = getOrVerifySessionAuthorityContext(domain);
  assert.equal(context.block_internal_hosts_policy.block_internal_hosts, false);

  mutateStateBlockInternalHosts(domain, true);

  // Control: the legacy direct state.json read DOES observe the mutation.
  const legacyAfterMutation = blockInternalHostsRequestPolicy(domain, {}, { allowMissingSession: false });
  assert.equal(legacyAfterMutation.block_internal_hosts, true, "the mutation must be observable through a fresh state.json read");

  // The frozen context is sourced from the verified nucleus, not state.json, and was
  // captured BEFORE the mutation -- composing against it must still reflect false.
  const composed = composeBlockInternalHostsPolicy(context.block_internal_hosts_policy, {});
  assert.equal(composed.block_internal_hosts, false, "the frozen context must not observe the state.json mutation");

  // A freshly-built context (re-verified after the mutation) is ALSO still false --
  // proving policy authority lives in the nucleus (untouched by the mutation) and
  // state.json really is audit-only input for this decision, not a second source.
  const contextAfterMutation = getOrVerifySessionAuthorityContext(domain);
  assert.equal(contextAfterMutation.block_internal_hosts_policy.block_internal_hosts, false);
}));

test("dispatched bob_http_scan against a loopback target is immune to a state.json block_internal_hosts mutation made after session init", () =>
  withTempHome(() => withFixtureServer((req, res) => jsonOk(res, { ok: true }), (port, requests) => {
    const domain = "a8e-frozen-http.example.test";
    return withDnsHost(domain, async () => {
      JSON.parse(initSession({ target_domain: domain, target_url: `http://${domain}:${port}/` }));

      // Tamper state.json directly to say block_internal_hosts:true. 127.0.0.1 (the
      // fixture server, and what the DNS override resolves this domain to) is a
      // blocked internal address under block_internal_hosts:true -- if the handler
      // re-read this mutated field, the request below would be scope-blocked.
      mutateStateBlockInternalHosts(domain, true);

      const envelope = await executeTool("bob_http_scan", {
        target_domain: domain,
        method: "GET",
        url: `http://${domain}:${port}/probe`,
      });

      assert.equal(envelope.ok, true, JSON.stringify(envelope.error || envelope));
      assert.equal(envelope.data.status, 200);
      assert.equal(requests.length, 1, "the request must have actually reached the loopback fixture server");
    });
  })));

test("wsProbe fresh-verifies for a direct (non-dispatched) call the same as a dispatched call", () =>
  withTempHome(() => {
    if (!WsServer) return;
    return withWsFixtureServer((port, connections) => {
      const domain = "a8e-direct-ws.example.test";
      return withDnsHost(domain, async () => {
        JSON.parse(initSession({ target_domain: domain, target_url: `http://${domain}:${port}/` }));

        // Direct call: no dispatch.js ALS scope active, so getOrVerifySessionAuthorityContext
        // takes the fresh-verify branch, not the ALS-cached branch.
        const direct = JSON.parse(await wsProbe({
          target_domain: domain,
          url: `ws://${domain}:${port}/`,
          mode: "raw",
          messages: [],
          timeout_ms: 300,
        }));
        assert.equal(direct.connected, true, JSON.stringify(direct));

        // Dispatched call: same domain, ALS-scoped context built by dispatch.js.
        const dispatched = await executeTool("bob_ws_probe", {
          target_domain: domain,
          url: `ws://${domain}:${port}/`,
          mode: "raw",
          messages: [],
          timeout_ms: 300,
        });
        assert.equal(dispatched.ok, true, JSON.stringify(dispatched.error || dispatched));
        assert.equal(dispatched.data.connected, true);

        assert.equal(connections.length, 2, "both calls must have actually connected to the fixture server");
      });
    });
  }));

test("dispatched bob_ws_probe against a loopback target is immune to a state.json block_internal_hosts mutation made after session init", () =>
  withTempHome(() => {
    if (!WsServer) return;
    return withWsFixtureServer((port, connections) => {
      const domain = "a8e-frozen-ws.example.test";
      return withDnsHost(domain, async () => {
        JSON.parse(initSession({ target_domain: domain, target_url: `http://${domain}:${port}/` }));
        mutateStateBlockInternalHosts(domain, true);

        const envelope = await executeTool("bob_ws_probe", {
          target_domain: domain,
          url: `ws://${domain}:${port}/`,
          mode: "raw",
          messages: [],
          timeout_ms: 300,
        });

        assert.equal(envelope.ok, true, JSON.stringify(envelope.error || envelope));
        assert.equal(envelope.data.connected, true);
        assert.equal(connections.length, 1, "the WS handshake must have actually reached the loopback fixture server");
      });
    });
  }));

test("dispatched bob_ws_probe blocks and never connects when the URL targets an out-of-scope domain", () =>
  withTempHome(() => {
    if (!WsServer) return;
    return withWsFixtureServer((port, connections) => {
      const domain = "a8e-ws-scope-gate.example.test";
      return withDnsHost(domain, async () => {
        JSON.parse(initSession({ target_domain: domain, target_url: `http://${domain}:${port}/` }));

        const envelope = await executeTool("bob_ws_probe", {
          target_domain: domain,
          url: "wss://out-of-scope-attacker.example.com/",
          mode: "raw",
          messages: [],
          timeout_ms: 300,
        });

        assert.equal(envelope.ok, false);
        assert.equal(connections.length, 0, "an out-of-scope URL must never reach any transport, including this in-domain fixture server");
      });
    });
  }));

test("authorityContextTargetDomainMismatch: the guard both handlers consult before any transport call", () => withTempHome(() => {
  const domainA = "a8e-mismatch-a.example.com";
  const domainB = "a8e-mismatch-b.example.com";
  JSON.parse(initSession({ target_domain: domainA, target_url: `https://${domainA}` }));
  JSON.parse(initSession({ target_domain: domainB, target_url: `https://${domainB}` }));

  const contextA = getOrVerifySessionAuthorityContext(domainA);

  assert.equal(authorityContextTargetDomainMismatch(contextA, domainA), false, "a context must not mismatch its own target_domain");
  assert.equal(authorityContextTargetDomainMismatch(contextA, domainB), true, "a context bound to domain A must mismatch a request for domain B");
  // A missing/unverifiable context (the allowMissingSession fallback branch) must
  // never itself be treated as a mismatch -- it is a DIFFERENT, already-handled
  // degrade path, not a block.
  assert.equal(authorityContextTargetDomainMismatch(null, domainA), false);
}));

test("redirect containment: a same-domain redirect follows through, sourced from the frozen context on both hops", () =>
  withTempHome(() => withFixtureServer((req, res) => {
    if (req.url === "/start") {
      res.writeHead(302, { location: "/final" });
      res.end();
      return;
    }
    jsonOk(res, { landed: true });
  }, (port, requests) => {
    const domain = "a8e-redirect-same-domain.example.test";
    return withDnsHost(domain, async () => {
      JSON.parse(initSession({ target_domain: domain, target_url: `http://${domain}:${port}/` }));

      const envelope = await executeTool("bob_http_scan", {
        target_domain: domain,
        method: "GET",
        url: `http://${domain}:${port}/start`,
        follow_redirects: true,
      });

      assert.equal(envelope.ok, true, JSON.stringify(envelope.error || envelope));
      assert.equal(envelope.data.status, 200);
      assert.match(envelope.data.body, /landed/);
      assert.equal(requests.length, 2, "both the initial request and the followed redirect must have reached the fixture server");
    });
  })));

test("redirect containment: an out-of-scope redirect target is rejected before the second hop is ever sent", () =>
  withTempHome(() => withFixtureServer((req, res) => {
    res.writeHead(302, { location: "http://out-of-scope-attacker.example.com/collect" });
    res.end();
  }, (port, requests) => {
    const domain = "a8e-redirect-cross-domain.example.test";
    return withDnsHost(domain, async () => {
      JSON.parse(initSession({ target_domain: domain, target_url: `http://${domain}:${port}/` }));

      const envelope = await executeTool("bob_http_scan", {
        target_domain: domain,
        method: "GET",
        url: `http://${domain}:${port}/start`,
        follow_redirects: true,
      });

      assert.equal(envelope.ok, false);
      assert.equal(requests.length, 1, "only the first hop (to the in-scope server) may have been sent; the redirect target must never be reached");
    });
  })));

// ── source-inventory: every target-facing safeFetch(...) call site under
// mcp/domains/web/ and mcp/core/http-scan.js must pass targetDomain, except the
// single documented OOB-sink exemption in oob-collector.js. ─────────────────────

const OOB_COLLECTOR_RELATIVE_PATH = path.join("mcp", "domains", "web", "oob-collector.js");

function findSafeFetchCallSites(source) {
  const sites = [];
  const callRe = /safeFetch\(/g;
  let match;
  while ((match = callRe.exec(source)) !== null) {
    const startIdx = match.index;
    const braceStart = source.indexOf("{", startIdx);
    if (braceStart === -1) continue;
    let depth = 0;
    let i = braceStart;
    for (; i < source.length; i += 1) {
      if (source[i] === "{") depth += 1;
      else if (source[i] === "}") {
        depth -= 1;
        if (depth === 0) { i += 1; break; }
      }
    }
    const optionsText = source.slice(braceStart, i);
    const line = source.slice(0, startIdx).split("\n").length;
    sites.push({ line, optionsText });
  }
  return sites;
}

function listJsFiles(relativeDir) {
  const dir = path.join(ROOT, relativeDir);
  return fs.readdirSync(dir, { withFileTypes: true })
    .filter((entry) => entry.isFile() && entry.name.endsWith(".js"))
    .map((entry) => path.join(relativeDir, entry.name));
}

test("source inventory: every target-facing safeFetch call under mcp/domains/web/ and http-scan.js passes targetDomain, except the documented OOB exemption", () => {
  const scannedFiles = [
    ...listJsFiles(path.join("mcp", "domains", "web")),
    path.join("mcp", "core", "http-scan.js"),
  ];

  let totalCallSites = 0;
  let oobCallSiteCount = 0;

  for (const relativePath of scannedFiles) {
    const source = fs.readFileSync(path.join(ROOT, relativePath), "utf8");
    const sites = findSafeFetchCallSites(source);
    totalCallSites += sites.length;
    const isOobCollector = relativePath === OOB_COLLECTOR_RELATIVE_PATH;
    if (isOobCollector) {
      oobCallSiteCount += sites.length;
      // The Bob-to-sink OOB poll fetch is aim-exempt BY DESIGN (it never targets the
      // scanned domain) -- assert there is exactly one such call site, so a future
      // edit that silently adds a SECOND, un-reviewed safeFetch call in this file
      // does not inherit the exemption for free.
      assert.equal(sites.length, 1, "oob-collector.js must have exactly one safeFetch call site (the documented OOB-sink exemption)");
      continue;
    }
    for (const site of sites) {
      // Accept both `targetDomain: expr` and the ES2015 shorthand `targetDomain`
      // (a bare property whose value is the same-named local variable).
      assert.match(
        site.optionsText,
        /\btargetDomain\b\s*[:,}]/,
        `${relativePath}:${site.line} calls safeFetch without a targetDomain option`,
      );
    }
  }

  assert.ok(totalCallSites > oobCallSiteCount, "the scan must have found at least one non-exempt safeFetch call site to actually exercise the assertion above");

  // Guard the second half of the invariant: none of the scanned files bypass
  // safeFetch with a raw HTTP/HTTPS transport of their own (an "uninventoried
  // second way" to reach the network that this scan would otherwise miss
  // entirely). ws-probe.js is a legitimate exception -- it implements the WS
  // transport itself and is covered by its own binding, not this HTTP inventory.
  for (const relativePath of scannedFiles) {
    if (relativePath.endsWith(path.join("web", "ws-probe.js"))) continue;
    const source = fs.readFileSync(path.join(ROOT, relativePath), "utf8");
    assert.doesNotMatch(
      source,
      /require\(["']https?["']\)/,
      `${relativePath} must not require a raw http/https transport module (bypasses the safeFetch inventory)`,
    );
  }
});
