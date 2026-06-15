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
  ensureHandoffSigningKey,
  readHandoffSigningKey,
} = require("../mcp/lib/handoff-signing-key.js");
const {
  offensiveRunsJsonlPath,
  attackSurfacePath,
  statePath,
  verificationRoundPaths,
} = require("../mcp/lib/paths.js");
const {
  signOffensiveRunRow,
  verifyOffensiveRunRowMac,
} = require("../mcp/lib/offensive-row-mac.js");
const {
  readHttpAuditRecordsFromJsonl,
} = require("../mcp/lib/http-records.js");
const {
  canonicalizeExploitTarget,
} = require("../mcp/lib/claims.js");
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

// bob_http_confirm is NEGATIVE-ONLY (it never mints a signed row), so the #108
// proof contract is exercised here with a HAND-WRITTEN signed row — the same way
// the next-PR producer will write one. Mirrors the seed helper in
// test/severity-rise-guard.test.js.
function seedSignedLowRow(domain, surfaceId) {
  const target = canonicalizeExploitTarget(`https://${domain}/api/accounts/known`);
  const ref = {
    kind: "exploit_run",
    run_id: "oconf-seed-low-1",
    tool_id: "bob_http_confirm",
    target,
    offensive_outcome: "exploited_safely",
    command_hash: "a".repeat(64),
    exit_code: 0,
    stdout_hash: "b".repeat(64),
    stderr_hash: "c".repeat(64),
  };
  const row = {
    version: 1,
    target_domain: domain,
    run_id: ref.run_id,
    tool_id: ref.tool_id,
    target: ref.target,
    offensive_outcome: "exploited_safely",
    dry_run: false,
    timed_out: false,
    command_hash: ref.command_hash,
    exit_code: ref.exit_code,
    stdout_hash: ref.stdout_hash,
    stderr_hash: ref.stderr_hash,
    demonstrated_severity: "low",
    surface_id: surfaceId,
  };
  signOffensiveRunRow(row, ensureHandoffSigningKey(domain));
  const filePath = offensiveRunsJsonlPath(domain);
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, `${JSON.stringify(row)}\n`, "utf8");
  return { row, ref };
}

function readOffensiveRows(domain) {
  return fs.readFileSync(offensiveRunsJsonlPath(domain), "utf8")
    .trim()
    .split(/\n/)
    .filter(Boolean)
    .map((line) => JSON.parse(line));
}

test("bob_http_confirm is negative-only: a resource-shaped synthetic response is reported, never signed", () => withTempHome(() => withFixtureServer((req, res) => {
  if (req.url === "/api/accounts/known") {
    res.writeHead(401, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "auth required" }));
    return;
  }
  // A non-existent synthetic id returning resource-shaped data is a catch-all /
  // server-variance signal, NOT a sound per-object exposure. The confirmer must
  // report it as a diagnostic negative and write NO signed offensive-runs row.
  if (/^\/api\/accounts\/bob-synthetic-nonexistent-/.test(req.url)) {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ id: "synthetic", email: "leak@b.test" }));
    return;
  }
  res.writeHead(404, { "content-type": "application/json" });
  res.end(JSON.stringify({ error: "not found" }));
}, (port, requests) => {
  const domain = "confirm-negonly.example.test";
  const surfaceId = "surface:accounts";
  return withDnsHost(domain, async () => {
    JSON.parse(initSession({ target_domain: domain, target_url: `http://${domain}:${port}/` }));
    seedRoutedSurface(domain, surfaceId, `http://${domain}:${port}/api/accounts/known`);

    const envelope = await executeTool("bob_http_confirm", {
      target_domain: domain,
      surface_id: surfaceId,
      oracle_kind: "differential_response",
      path_template: "/api/accounts/{id}",
    });
    assert.equal(envelope.ok, true, envelope.error && envelope.error.message);
    const confirmed = envelope.data;
    assert.equal(confirmed.confirmed, false);
    assert.equal(confirmed.row_written, false);
    assert.equal(confirmed.reason, "synthetic_id_resource_shape_not_provable");
    assert.equal(confirmed.exploit_run, undefined);
    assert.equal(confirmed.run_id, undefined);
    // baseline + a SINGLE synthetic probe (no second probe in negative-only)
    assert.deepEqual(requests.map((entry) => entry.method), ["GET", "GET"]);
    assert.equal(requests[0].url, "/api/accounts/known");
    assert.match(requests[1].url, /^\/api\/accounts\/bob-synthetic-nonexistent-/);
    // and NO signed offensive-runs row was written
    assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
    // BUT both probes ARE recorded in http-audit.jsonl (circuit-breaker visibility) —
    // a successful probe writes scope_decision:"allowed" (a null would make
    // normalizeHttpAuditRecord throw, silently dropping the record).
    const audit = readHttpAuditRecordsFromJsonl(domain).filter((r) => r.surface_id === surfaceId);
    assert.equal(audit.length, 2);
    assert.equal(audit.every((r) => r.scope_decision === "allowed"), true);
  });
})));

test("bob_http_confirm rejects recorded endpoints whose id segment hides an action route", () => withTempHome(async () => {
  // The unauth baseline GET hits the REAL recorded id, so an id segment that can
  // route to a sub-resource/action must be rejected — whether it hides a path
  // separator (encoded at ANY depth, incl. split-hex %25%32%46) or carries
  // action/matrix punctuation (: ; ,), literal or escaped. These live in the
  // surface record, so normalizePathTemplate never sees them.
  const maliciousIds = [
    "known%2Fdelete",       // single-encoded separator
    "known%252Fdelete",     // double-encoded
    "known%2525252Fdelete", // deep-encoded
    "known%25%32%46delete", // split-hex encoding of %2F
    "known%5Cdelete",       // encoded backslash
    "known:capture",        // matrix/action colon
    "known;delete",         // matrix semicolon
    "known%3Acapture",      // percent-escaped colon
  ];
  let i = 0;
  for (const idSeg of maliciousIds) {
    i += 1;
    const domain = `confirm-encsep-${i}.example.test`;
    const surfaceId = "surface:accounts";
    JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}/` }));
    seedRoutedSurface(domain, surfaceId, `https://${domain}/api/accounts/${idSeg}`);
    const envelope = await executeTool("bob_http_confirm", {
      target_domain: domain,
      surface_id: surfaceId,
      oracle_kind: "differential_response",
      path_template: "/api/accounts/{id}",
    });
    assert.equal(envelope.ok, false, `${idSeg} should be rejected`);
    assert.match(envelope.error.message, /path shape does not match/, `${idSeg} reject message`);
  }
}));

test("a hand-written signed low row supports claim→freeze→verify (info→low)", () => withTempHome(() => {
  // The #108 proof contract end-to-end, exercised with a SEEDED signed row (the
  // confirmer is negative-only; the real producer is a follow-up).
  const domain = "confirm-contract.example.test";
  const surfaceId = "surface:accounts";
  JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}/` }));
  seedRoutedSurface(domain, surfaceId, `https://${domain}/api/accounts/known`);

  const { ref } = seedSignedLowRow(domain, surfaceId);
  const [row] = readOffensiveRows(domain);
  assert.equal(row.run_id, ref.run_id);
  assert.equal(row.surface_id, surfaceId);
  assert.equal(row.finding_id, undefined);
  assert.equal(row.demonstrated_severity, "low");
  assert.equal(verifyOffensiveRunRowMac(row, readHandoffSigningKey(domain)), true);

  const recorded = recordExploitedClaim(domain, surfaceId, ref);
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
}));

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

test("malformed exploit_outcome surfaces as INVALID_ARGUMENTS, not INTERNAL_ERROR", () => withTempHome(async () => {
  // exploit_outcome:{outcome:"exploited_safely"} without safe_oracle passes the
  // JSON schema but fails normalizeExploitOutcome; it must be a caller-facing
  // INVALID_ARGUMENTS (wrapped ToolError), not a swallowed-as-server-fault Error.
  const domain = "confirm-badoutcome.example.test";
  const surfaceId = "surface:accounts";
  JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}/` }));
  seedRoutedSurface(domain, surfaceId, `https://${domain}/api/accounts/known`);
  const envelope = await executeTool("bob_record_candidate_claim", {
    target_domain: domain, surface_id: surfaceId, title: "t", severity: "info",
    endpoint: "/api/accounts/{id}", description: "d", proof_of_concept: "p",
    response_evidence: "r", impact: "i", validated: true,
    exploit_outcome: { outcome: "exploited_safely" },
  });
  assert.equal(envelope.ok, false);
  assert.equal(envelope.error.code, "INVALID_ARGUMENTS");
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

test("differential classifier (negative-only) maps the differential to a diagnostic outcome and never mints a row", () => {
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

  // a resource-shaped target on a synthetic non-existent id is reported as a
  // diagnostic negative — NEVER exploited_safely, never a write_row
  const leakish = classifyDifferential({
    baselineResponse: response(401),
    targetResponse: response(200, "{\"id\":7,\"email\":\"a@b.test\"}"),
  });
  assert.equal(leakish.reason, "synthetic_id_resource_shape_not_provable");
  assert.equal(leakish.exploited, false);
  assert.notEqual(leakish.outcome, "exploited_safely");
  assert.equal(leakish.write_row, undefined);
  assert.equal(leakish.requires_second_probe, undefined);
  // baseline not an auth challenge -> infra negative
  assert.equal(classifyDifferential({
    baselineResponse: response(200),
    targetResponse: response(200),
  }).reason, "baseline_not_auth_challenge");
  // target still auth-gated / not-found -> blocked_by_defense
  assert.equal(classifyDifferential({
    baselineResponse: response(401),
    targetResponse: response(403),
  }).outcome, "blocked_by_defense");
  assert.equal(classifyDifferential({
    baselineResponse: response(401),
    targetResponse: response(404),
  }).reason, "target_not_found_secure_response");
});

test("differential classifier distinguishes resource-shaped from non-resource targets (still never mints a row)", () => {
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
  // A baseline auth-challenge + a 200 target: the only variable is whether the
  // body is resource-shaped. Resource-shaped -> diagnostic "not provable" reason;
  // non-resource -> "not resource shaped". Neither ever mints a row.
  const NOT_RESOURCE = "target_response_not_resource_shaped";
  const RESOURCE = "synthetic_id_resource_shape_not_provable";
  const reasonFor = (body, headers) => classifyDifferential({
    baselineResponse: response(401),
    targetResponse: response(200, body, headers),
  }).reason;

  // soft-404 / error envelope / empty collections / null payload at HTTP 200
  assert.equal(reasonFor("{\"error\":\"not found\"}"), NOT_RESOURCE);
  assert.equal(reasonFor("{\"message\":\"no such account\"}"), NOT_RESOURCE);
  assert.equal(reasonFor("{\"data\":null}"), NOT_RESOURCE);
  assert.equal(reasonFor("{\"results\":[]}"), NOT_RESOURCE);
  // empty paginated collection with metadata siblings (the common empty-list shape)
  assert.equal(reasonFor("{\"items\":[],\"total\":0,\"page\":1}"), NOT_RESOURCE);
  assert.equal(reasonFor("{\"results\":[],\"count\":0,\"has_more\":false}"), NOT_RESOURCE);
  assert.equal(reasonFor("[]"), NOT_RESOURCE);
  assert.equal(reasonFor("{}"), NOT_RESOURCE);
  // generic status / health objects from a catch-all handler are not resources
  assert.equal(reasonFor("{\"ok\":true}"), NOT_RESOURCE);
  assert.equal(reasonFor("{\"success\":false}"), NOT_RESOURCE);
  assert.equal(reasonFor("{\"service\":\"api\",\"region\":\"us\"}"), NOT_RESOURCE);
  // SPA / app-shell HTML
  assert.equal(reasonFor("<html><body><div id=\"root\"></div></body></html>", { "content-type": "text/html" }), NOT_RESOURCE);
  // XML status/error envelope is NOT a resource; text/plain markup is length-floored
  assert.equal(reasonFor("<response><status>ok</status><code>0</code></response>", { "content-type": "application/xml" }), NOT_RESOURCE);
  assert.equal(reasonFor("<response><status>ok</status></response>", { "content-type": "text/plain" }), NOT_RESOURCE);
  // unknown / missing content-type fails CLOSED (catch-all "OK" manufacture vector)
  assert.equal(reasonFor("OK", {}), NOT_RESOURCE);
  assert.equal(reasonFor("OK", { "content-type": "application/octet-stream" }), NOT_RESOURCE);

  // genuine resource bodies are recognized as resource-shaped (still no row)
  assert.equal(reasonFor("{\"id\":42,\"email\":\"a@b.test\"}"), RESOURCE);
  assert.equal(reasonFor("[{\"id\":1}]"), RESOURCE);
  // a non-empty list with metadata is a real resource
  assert.equal(reasonFor("{\"items\":[{\"id\":1}],\"total\":1,\"page\":1}"), RESOURCE);
  // compact single-field XML record (recall)
  assert.equal(reasonFor("<account><balance>5000</balance></account>", { "content-type": "application/xml" }), RESOURCE);
  // a genuine LARGE JSON resource (>16KB) must still be recognized — no window truncation
  const bigRecord = JSON.stringify({ id: 7, email: "a@b.test", notes: "x".repeat(40000) });
  assert.equal(bigRecord.length > 16384, true);
  assert.equal(reasonFor(bigRecord), RESOURCE);
  // structured XML record is resource-shaped
  assert.equal(reasonFor("<user><id>5</id><email>a@b.test</email></user>", { "content-type": "application/xml" }), RESOURCE);

  // HEAD/OPTIONS carry no body to inspect -> not resource shaped, never a row
  assert.equal(classifyDifferential({
    baselineResponse: response(401),
    targetResponse: { status: 200, headers: { get: () => null }, bodyBytes: Buffer.alloc(0), bodyByteLength: 0, bodyTruncated: false },
  }).reason, NOT_RESOURCE);
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
  // percent-encoded separators after {id} are rejected at ANY encoding depth
  for (const tmpl of ["/api/payments/{id}%2Fcapture", "/api/payments/{id}%252Fcapture", "/api/payments/{id}%2525252Fcapture", "/api/payments/{id}%5Ccapture"]) {
    assert.throws(() => normalizePathTemplate(tmpl), /final path segment/, `${tmpl} should be rejected`);
  }
  // same-segment action / matrix suffixes after {id} (no literal slash) are rejected too
  for (const tmpl of ["/api/payments/{id}:capture", "/api/accounts/{id};delete", "/api/users/{id},merge", "/api/users/{id}-summary"]) {
    assert.throws(() => normalizePathTemplate(tmpl), /final path segment/, `${tmpl} should be rejected`);
  }
  // a verb-shaped dot suffix is NOT an inert extension and is rejected; only known
  // data-format extensions (.json/.xml/...) pass
  for (const tmpl of ["/api/payments/{id}.capture", "/api/accounts/{id}.delete", "/api/servers/{id}.restart"]) {
    assert.throws(() => normalizePathTemplate(tmpl), /final path segment/, `${tmpl} should be rejected`);
  }
  for (const tmpl of ["/api/accounts/{id}.json", "/api/accounts/{id}.xml", "/api/accounts/{id}.csv"]) {
    assert.doesNotThrow(() => normalizePathTemplate(tmpl), `${tmpl} should be accepted`);
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
