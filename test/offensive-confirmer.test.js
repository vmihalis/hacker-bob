"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const dns = require("node:dns");
const fs = require("node:fs");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");

const {
  executeTool,
} = require("../mcp/lib/dispatch.js");
const {
  assertReadOnlyPath,
  classifyDifferential,
  normalizePathTemplate,
} = require("../mcp/lib/offensive-confirmer.js");
const {
  buildClaimFreeze,
} = require("../mcp/lib/claim-freeze.js");
const {
  readHandoffSigningKey,
} = require("../mcp/lib/handoff-signing-key.js");
const {
  offensiveRunsJsonlPath,
  attackSurfacePath,
  statePath,
  verificationRoundPaths,
} = require("../mcp/lib/paths.js");
const {
  verifyOffensiveRunRowMac,
} = require("../mcp/lib/offensive-row-mac.js");
const {
  routeSurfaces,
} = require("../mcp/lib/surface-router.js");
const {
  initSession,
} = require("../mcp/lib/session-state.js");
const {
  readSessionStateStrict,
} = require("../mcp/lib/session-state-store.js");
const {
  writeFileAtomic,
} = require("../mcp/lib/storage.js");
const {
  buildVerificationAdjudication,
  prepareVerificationEntry,
} = require("../mcp/lib/verification.js");
const {
  writeVerificationRound,
} = require("../mcp/lib/verification-round-store.js");
const recordCandidateClaimTool = require("../mcp/lib/tools/record-candidate-claim.js");
const {
  resetForTests: resetMaterializationDebounce,
} = require("../mcp/lib/frontier-materialize-debounce.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-offensive-confirmer-"));
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
      requests.push({
        method: req.method,
        url: req.url,
        headers: req.headers,
        body,
      });
      handler(req, res, body);
    });
  });
  return new Promise((resolve, reject) => {
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => {
      Promise.resolve()
        .then(() => fn(server.address().port, requests))
        .then(resolve, reject)
        .finally(() => {
          server.close();
        });
    });
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

function enterVerifyV2(domain) {
  const { raw, state } = readSessionStateStrict(domain);
  const entry = prepareVerificationEntry(domain, state, {
    now: new Date("2026-06-01T00:00:00.000Z"),
  });
  writeFileAtomic(statePath(domain), `${JSON.stringify({
    ...raw,
    phase: "VERIFY",
    lifecycle_state: "VERIFY",
    ...entry.state_fields,
  }, null, 2)}\n`);
  return entry.state_fields;
}

function writeV2Round(domain, context, round, result, extra = {}) {
  return JSON.parse(writeVerificationRound({
    target_domain: domain,
    round,
    notes: null,
    verification_attempt_id: context.verification_attempt_id,
    verification_snapshot_hash: context.verification_snapshot_hash,
    round_profile: round,
    results: [result],
    ...extra,
  }));
}

function lowVerificationResult(findingId = "F-1") {
  return {
    finding_id: findingId,
    disposition: "confirmed",
    severity: "low",
    reportable: true,
    reasoning: "Verifier replayed the safe differential proof.",
    confidence: "high",
    confidence_reasons: ["exploit_replay_confirmed"],
    state_sensitive: false,
    artifact_hashes: {},
  };
}

function recordExploitedClaim(domain, surfaceId, exploitRunRef, overrides = {}) {
  return JSON.parse(recordCandidateClaimTool.handler({
    target_domain: domain,
    surface_id: surfaceId,
    title: "Synthetic missing auth gate on account read",
    severity: "info",
    endpoint: "/api/accounts/{id}",
    description: "A synthetic nonexistent account read returned resource-shaped data while the baseline challenged.",
    proof_of_concept: "bob_http_confirm synthetic-id differential_response",
    response_evidence: "Synthetic fixture response only.",
    impact: "Low severity missing authorization gate proof.",
    validated: true,
    exploit_outcome: {
      outcome: "exploited_safely",
      safe_oracle: { kind: "differential_response" },
    },
    evidence_refs: [exploitRunRef],
    ...overrides,
  }));
}

function readOffensiveRows(domain) {
  return fs.readFileSync(offensiveRunsJsonlPath(domain), "utf8")
    .trim()
    .split(/\n/)
    .filter(Boolean)
    .map((line) => JSON.parse(line));
}

test("bob_http_confirm confirms by surface_id, writes a signed low row, and supports claim→freeze→verify", () => withTempHome(() => withFixtureServer((req, res) => {
  if (req.url === "/api/accounts/known") {
    res.writeHead(401, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "auth required" }));
    return;
  }
  if (/^\/api\/accounts\/bob-synthetic-nonexistent-/.test(req.url)) {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ id: "synthetic", status: "missing-but-readable" }));
    return;
  }
  res.writeHead(404, { "content-type": "application/json" });
  res.end(JSON.stringify({ error: "not found" }));
}, (port, requests) => {
  const domain = "confirm-surface.example.test";
  const surfaceId = "surface:accounts";
  return withDnsHost(domain, async () => {
    JSON.parse(initSession({
      target_domain: domain,
      target_url: `http://${domain}:${port}/`,
    }));
    seedRoutedSurface(domain, surfaceId, `http://${domain}:${port}/api/accounts/known`);

    const envelope = await executeTool("bob_http_confirm", {
      target_domain: domain,
      surface_id: surfaceId,
      oracle_kind: "differential_response",
      path_template: "/api/accounts/{id}",
    });
    assert.equal(envelope.ok, true, envelope.error && envelope.error.message);
    const confirmed = envelope.data;
    assert.equal(confirmed.confirmed, true);
    assert.equal(confirmed.surface_id, surfaceId);
    assert.equal(confirmed.demonstrated_severity, "low");
    assert.equal(confirmed.exploit_run.kind, "exploit_run");
    assert.match(confirmed.run_id, /^oconf-/);

    assert.deepEqual(requests.map((entry) => entry.method), ["GET", "GET"]);
    assert.equal(requests.every((entry) => entry.body.length === 0), true);
    assert.equal(requests[0].url, "/api/accounts/known");
    assert.match(requests[1].url, /^\/api\/accounts\/bob-synthetic-nonexistent-/);

    const [row] = readOffensiveRows(domain);
    assert.equal(row.run_id, confirmed.run_id);
    assert.equal(row.surface_id, surfaceId);
    assert.equal(row.finding_id, undefined);
    assert.equal(row.demonstrated_severity, "low");
    assert.equal(verifyOffensiveRunRowMac(row, readHandoffSigningKey(domain)), true);
    assert.equal(fs.existsSync(row.request_path), true);
    assert.equal(fs.existsSync(row.response_path), true);

    const recorded = recordExploitedClaim(domain, surfaceId, confirmed.exploit_run);
    assert.equal(recorded.recorded, true);
    assert.equal(recorded.finding_id, "F-1");

    buildClaimFreeze(domain, { write: true, now: new Date("2026-06-01T00:00:00.000Z") });
    const context = enterVerifyV2(domain);
    writeV2Round(domain, context, "brutalist", lowVerificationResult("F-1"));
    writeV2Round(domain, context, "balanced", lowVerificationResult("F-1"));
    const adjudication = JSON.parse(buildVerificationAdjudication({ target_domain: domain }));
    writeV2Round(domain, context, "final", lowVerificationResult("F-1"), {
      adjudication_plan_hash: adjudication.adjudication_plan_hash,
    });
    const finalRound = JSON.parse(fs.readFileSync(verificationRoundPaths(domain, "final").json, "utf8"));
    assert.equal(finalRound.results[0].severity, "low");
    assert.equal(finalRound.results[0].confidence_reasons.includes("exploit_replay_confirmed"), true);
  });
})));

test("recording exploited_safely without a confirmer row is rejected", () => withTempHome(() => {
  const domain = "confirm-negative.example.test";
  const surfaceId = "surface:accounts";
  JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}/` }));
  seedRoutedSurface(domain, surfaceId, `https://${domain}/api/accounts/known`);
  assert.throws(
    () => recordExploitedClaim(domain, surfaceId, {
      kind: "exploit_run",
      run_id: "oconf-missing",
      tool_id: "bob_http_confirm",
      target: `https://${domain}/api/accounts/bob-synthetic-nonexistent-missing`,
      offensive_outcome: "exploited_safely",
      command_hash: "a".repeat(64),
      exit_code: 0,
      stdout_hash: "b".repeat(64),
      stderr_hash: "c".repeat(64),
    }),
    (error) => error && error.details && error.details.code === "exploit_proof_unbacked_exploit_run_evidence",
  );
}));

test("bob_http_confirm schema rejects raw URL, body, severity, finding_id, and unsafe methods", () => withTempHome(async () => {
  const base = {
    target_domain: "schema-confirm.example.test",
    surface_id: "surface:any",
    oracle_kind: "differential_response",
    path_template: "/api/accounts/{id}",
  };
  for (const [field, value] of [
    ["url", "https://schema-confirm.example.test/api/accounts/1"],
    ["body", "{}"],
    ["severity", "critical"],
    ["finding_id", "F-1"],
    ["headers", { "X-HTTP-Method-Override": "DELETE" }],
  ]) {
    const envelope = await executeTool("bob_http_confirm", { ...base, [field]: value });
    assert.equal(envelope.ok, false, `${field} should be rejected`);
    assert.match(envelope.error.message, new RegExp(field));
  }
  const methodEnvelope = await executeTool("bob_http_confirm", { ...base, method: "POST" });
  assert.equal(methodEnvelope.ok, false);
  assert.match(methodEnvelope.error.message, /method must be one of GET, HEAD, OPTIONS/);
}));

test("differential classifier requires a baseline auth challenge and target resource shape", () => {
  const response = (status, body = "{}", headers = { "content-type": "application/json" }) => ({
    status,
    headers: {
      get(name) {
        return headers[String(name).toLowerCase()] || null;
      },
    },
    bodyBytes: Buffer.from(body),
    bodyByteLength: Buffer.byteLength(body),
    bodyTruncated: false,
  });

  assert.equal(classifyDifferential({
    baselineResponse: response(401),
    targetResponse: response(200, "{\"id\":7,\"email\":\"a@b.test\"}"),
    method: "GET",
  }).outcome, "exploited_safely");
  assert.equal(classifyDifferential({
    baselineResponse: response(200),
    targetResponse: response(200),
    method: "GET",
  }).outcome, "blocked_by_infra");
  assert.equal(classifyDifferential({
    baselineResponse: response(401),
    targetResponse: response(403),
    method: "GET",
  }).outcome, "blocked_by_defense");
  assert.equal(classifyDifferential({
    baselineResponse: response(401),
    targetResponse: response(404),
    method: "GET",
  }).outcome, "blocked_by_defense");
});

test("differential classifier refuses to mint a row for non-resource 200 bodies", () => {
  const response = (status, body = "{}", headers = { "content-type": "application/json" }) => ({
    status,
    headers: {
      get(name) {
        return headers[String(name).toLowerCase()] || null;
      },
    },
    bodyBytes: Buffer.from(body),
    bodyByteLength: Buffer.byteLength(body),
    bodyTruncated: false,
  });
  const target = (body, headers) => classifyDifferential({
    baselineResponse: response(401),
    targetResponse: response(200, body, headers),
    method: "GET",
  });

  // soft-404 / error envelope / empty collections / null payload at HTTP 200
  assert.notEqual(target("{\"error\":\"not found\"}").outcome, "exploited_safely");
  assert.notEqual(target("{\"message\":\"no such account\"}").outcome, "exploited_safely");
  assert.notEqual(target("{\"data\":null}").outcome, "exploited_safely");
  assert.notEqual(target("{\"results\":[]}").outcome, "exploited_safely");
  // empty paginated collection with metadata siblings (the common empty-list shape)
  assert.notEqual(target("{\"items\":[],\"total\":0,\"page\":1}").outcome, "exploited_safely");
  assert.notEqual(target("{\"results\":[],\"count\":0,\"has_more\":false}").outcome, "exploited_safely");
  assert.notEqual(target("[]").outcome, "exploited_safely");
  assert.notEqual(target("{}").outcome, "exploited_safely");
  // generic status / health objects from a catch-all handler are not resources
  assert.notEqual(target("{\"ok\":true}").outcome, "exploited_safely");
  assert.notEqual(target("{\"success\":false}").outcome, "exploited_safely");
  assert.notEqual(target("{\"service\":\"api\",\"region\":\"us\"}").outcome, "exploited_safely");
  // SPA / app-shell HTML
  assert.notEqual(
    target("<html><body><div id=\"root\"></div></body></html>", { "content-type": "text/html" }).outcome,
    "exploited_safely",
  );
  // XML status/error envelope is NOT a resource; text/plain markup is length-floored
  assert.notEqual(
    target("<response><status>ok</status><code>0</code></response>", { "content-type": "application/xml" }).outcome,
    "exploited_safely",
  );
  assert.notEqual(
    target("<response><status>ok</status></response>", { "content-type": "text/plain" }).outcome,
    "exploited_safely",
  );
  // genuine resource bodies still confirm
  assert.equal(target("{\"id\":42,\"email\":\"a@b.test\"}").outcome, "exploited_safely");
  assert.equal(target("[{\"id\":1}]").outcome, "exploited_safely");
  // a non-empty list with metadata is a real resource
  assert.equal(target("{\"items\":[{\"id\":1}],\"total\":1,\"page\":1}").outcome, "exploited_safely");
  // compact single-field XML record confirms (recall)
  assert.equal(
    target("<account><balance>5000</balance></account>", { "content-type": "application/xml" }).outcome,
    "exploited_safely",
  );

  // unknown / missing content-type fails CLOSED (catch-all "OK" manufacture vector)
  assert.notEqual(target("OK", {}).outcome, "exploited_safely");
  assert.notEqual(target("OK", { "content-type": "application/octet-stream" }).outcome, "exploited_safely");

  // a genuine LARGE JSON resource (>16KB) must still confirm — no window truncation
  const bigRecord = JSON.stringify({ id: 7, email: "a@b.test", notes: "x".repeat(40000) });
  assert.equal(bigRecord.length > 16384, true);
  assert.equal(target(bigRecord).outcome, "exploited_safely");

  // structured XML record confirms; tiny non-structured text does not
  assert.equal(
    target("<user><id>5</id><email>a@b.test</email></user>", { "content-type": "application/xml" }).outcome,
    "exploited_safely",
  );

  // HEAD/OPTIONS carry no body to inspect -> never a proof row
  assert.notEqual(classifyDifferential({
    baselineResponse: response(401),
    targetResponse: { status: 200, headers: { get: () => null }, bodyBytes: Buffer.alloc(0), bodyByteLength: 0, bodyTruncated: false },
    method: "HEAD",
  }).outcome, "exploited_safely");
});

test("normalizePathTemplate requires {id} to be the final path segment (structural read-only boundary)", () => {
  // direct resource reads pass — including singular noun-collections that are
  // verb homographs (these must NOT be rejected)
  for (const tmpl of ["/api/accounts/{id}", "/api/order/{id}", "/api/transfer/{id}", "/api/charge/{id}", "/api/block/{id}", "/api/run/{id}", "/api/accounts/{id}.json"]) {
    assert.doesNotThrow(() => normalizePathTemplate(tmpl), `${tmpl} should be accepted`);
  }
  // any segment AFTER {id} (action or sub-resource) is rejected — this is what
  // structurally closes the "GET a mutation verb against the real id" class,
  // independent of any verb denylist
  for (const tmpl of ["/api/accounts/{id}/transfer", "/api/payments/{id}/capture", "/api/servers/{id}/restart", "/api/keys/{id}/regenerate", "/api/users/{id}/enable", "/api/users/{id}/profile"]) {
    assert.throws(() => normalizePathTemplate(tmpl), /final path segment/, `${tmpl} should be rejected`);
  }
  // percent-encoded separators after {id} (single and double encoded) are rejected too
  for (const tmpl of ["/api/payments/{id}%2Fcapture", "/api/payments/{id}%252Fcapture"]) {
    assert.throws(() => normalizePathTemplate(tmpl), /final path segment/, `${tmpl} should be rejected`);
  }
  // a query string is rejected (baseline/target must be query-symmetric)
  assert.throws(() => normalizePathTemplate("/api/accounts/{id}?fields=all"), /query string/);
});

test("assertReadOnlyPath rejects destructive verb-named collections (narrow, decoded), allows noun reads", () => {
  // read-shaped paths (incl. verb-homograph nouns) pass
  for (const url of ["https://t.example.test/api/accounts/123", "https://t.example.test/api/posts/123", "https://t.example.test/api/order/123", "https://t.example.test/api/charge/123"]) {
    assert.doesNotThrow(() => assertReadOnlyPath(url), `${url} should pass`);
  }
  // unambiguous destructive verb as a collection segment is rejected
  for (const verb of ["delete", "remove", "destroy", "reset", "revoke", "deactivate", "purge"]) {
    assert.throws(
      () => assertReadOnlyPath(`https://t.example.test/api/${verb}/123`),
      /state-changing path segment/,
      `${verb} must be rejected`,
    );
  }
  // double percent-encoded verb is recursively decoded before the check
  assert.throws(
    () => assertReadOnlyPath("https://t.example.test/api/%2564elete/123"),
    /state-changing path segment/,
  );
});
