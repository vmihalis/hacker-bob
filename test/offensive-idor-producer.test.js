"use strict";

// SEEDED test matrix for the bob_http_idor_confirm signed-row PRODUCER.
//
// Every probe goes through an INJECTED fetch_fn returning canned per-(identity,
// object) bodies that carry REAL viewer-scoped variance (per-request timestamp +
// viewer-id echo) so two reads of the "same" object by different viewers differ
// byte-for-byte. The positive therefore fires ONLY on canary-FIELD presence at a
// parsed leaf — a re-introduced whole-body `==` would FAIL this suite. No live
// target, no live signup: the three identities are seeded with synthetic
// provenance directly, and the producer-created objects/canaries are seeded via
// the `provision` injection.

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  idorConfirm,
  IDOR_ORACLE_DEMONSTRATED_CEILING,
  canaryAt,
  discoverCanaryFieldPath,
  ownScopeIsPrivate,
  tenantDiscriminator,
  piiScan,
  profileHasProvenance,
} = require("../mcp/lib/offensive-idor-producer.js");
const { initSession } = require("../mcp/lib/session-state.js");
const { routeSurfaces } = require("../mcp/lib/surface-router.js");
const { writeAuthFile, resolveAuthJsonPath } = require("../mcp/lib/auth.js");
const { ensureHandoffSigningKey } = require("../mcp/lib/handoff-signing-key.js");
const { attackSurfacePath, offensiveRunsJsonlPath, offensiveRunsDir } = require("../mcp/lib/paths.js");
const {
  appendCandidateClaim,
  readCandidateClaims,
  readOffensiveRunRecords,
  canonicalizeExploitTarget,
} = require("../mcp/lib/claims.js");
const { projectExploitRunObservedRef } = require("../mcp/lib/claim-freeze.js");
const {
  resetForTests: resetMaterializationDebounce,
} = require("../mcp/lib/frontier-materialize-debounce.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-idor-producer-"));
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

const CANARY_B = "b".repeat(64);
const CANARY_A = "a".repeat(64);
const CANARY_C = "c".repeat(64);

function seedRoutedSurface(domain, surfaceId, endpoint, { hosts, endpoints } = {}) {
  fs.mkdirSync(path.dirname(attackSurfacePath(domain)), { recursive: true });
  fs.writeFileSync(attackSurfacePath(domain), `${JSON.stringify({
    surfaces: [{
      id: surfaceId,
      title: "Synthetic API account surface",
      surface_type: "web",
      hosts: hosts || [domain],
      endpoints: endpoints || [endpoint],
      tech_stack: ["fixture"],
      priority: "HIGH",
    }],
  }, null, 2)}\n`, "utf8");
  JSON.parse(routeSurfaces({ target_domain: domain }));
}

// Seed three synthetic auth profiles with provenance flags so the INERT gate is
// satisfied in-test (nothing stamps these in production).
function seedSyntheticProfiles(domain, { provenance = true } = {}) {
  const flags = provenance
    ? { synthetic: true, email_origin: "temp_email", provisioned_via: "bob_auto_signup" }
    : {};
  const mk = (tag) => ({
    Authorization: `Bearer eyJ${tag}token`,
    email: `eval_${tag}@example.test`,
    ...flags,
  });
  const authPath = resolveAuthJsonPath(domain);
  writeAuthFile(authPath, `${JSON.stringify({
    version: 2,
    profiles: { identity_a: mk("a"), identity_b: mk("b"), identity_c: mk("c") },
  }, null, 2)}\n`);
}

const SURFACE_ID = "surface:accounts";
const PATH_TEMPLATE = "/api/accounts/{id}";
const OBJ_A = "obj-a-100";
const OBJ_B = "obj-b-200";
const OBJ_C = "obj-c-300";

function endpointFor(domain) {
  return `https://${domain}/api/accounts/${OBJ_B}`;
}

// A resource body carrying REAL per-VIEWER variance + a canary at a nested leaf.
// The variance is keyed to `viewer` (a per-identity timestamp + viewer-id + csrf)
// so two reads by the SAME viewer are byte-identical (P0 stability holds) but a
// read by a DIFFERENT viewer differs byte-for-byte — which is exactly what a
// re-introduced whole-body `==` oracle would choke on, while the canary-field
// oracle still fires.
function resourceBody({ canary, scope, viewer, objId = OBJ_B, includeCanary = true }) {
  // Deterministic per-viewer variance (NOT random per call) so P0 (same viewer
  // twice) is stable while P1(B) vs P2(A) genuinely differ.
  const seed = crypto.createHash("sha256").update(`${viewer}|${objId}`).digest("hex");
  return {
    id: objId,
    kind: "account",
    name: "synthetic record",
    owner_scope: scope,
    viewer_id: viewer,
    server_ts: `2026-06-16T00:00:${seed.slice(0, 2)}.${seed.slice(2, 5)}Z`,
    csrf: seed.slice(0, 16),
    details: { secret: { token: includeCanary ? canary : "no-canary" } },
  };
}

// Build a mock safe-fetch response with a JSON body + headers.
function jsonResponse(status, bodyObj, headers = {}) {
  const lower = {};
  for (const [k, v] of Object.entries(headers)) lower[String(k).toLowerCase()] = v;
  const body = typeof bodyObj === "string" ? bodyObj : JSON.stringify(bodyObj);
  const bytes = Buffer.from(body, "utf8");
  return {
    status,
    headers: { get(name) { return lower[String(name).toLowerCase()] ?? null; } },
    bodyBytes: bytes,
    bodyByteLength: bytes.length,
    bodyTruncated: false,
  };
}

function challenge(status = 403) {
  const bytes = Buffer.from(JSON.stringify({ error: "forbidden" }), "utf8");
  return { status, headers: { get: () => null }, bodyBytes: bytes, bodyByteLength: bytes.length, bodyTruncated: false };
}

// The DEFAULT sound-positive fetch router. Distinguishes probes by the
// Authorization header (A/B/C/anon) and the requested object id in the URL.
// O_B carries scope "tenant-B"; O_A carries scope "tenant-A". Anon + C are denied
// O_B; B is denied O_A. The canary appears in P1 (B reads O_B) and P2 (A reads
// O_B) at the same nested leaf, never in P3/P4/P5.
function soundFetchFn(domain, overrides = {}) {
  let calls = 0;
  return async ({ url, headers }) => {
    calls += 1;
    const auth = headers && headers.Authorization ? String(headers.Authorization) : "";
    const isA = auth.includes("eyJatoken");
    const isB = auth.includes("eyJbtoken");
    const isC = auth.includes("eyJctoken");
    const u = new URL(url);
    const wantsOB = u.pathname.includes(OBJ_B);
    const wantsOA = u.pathname.includes(OBJ_A);
    const wantsOC = u.pathname.includes(OBJ_C);

    if (overrides.handler) {
      const r = overrides.handler({ url, headers, isA, isB, isC, wantsOB, wantsOA, wantsOC, calls });
      if (r) return r;
    }

    // Anon (no creds) reading anything → 401/403, no canary.
    if (!isA && !isB && !isC) return challenge(overrides.anonStatus || 403);

    if (wantsOB) {
      // Viewer key is the IDENTITY (stable across that identity's reads) so P0
      // (two B reads) is byte-identical while P1(B) vs P2(A) differ.
      if (isB) {
        return jsonResponse(200, resourceBody({ canary: CANARY_B, scope: "tenant-B", viewer: "viewer-B" }));
      }
      if (isA) {
        // The cross-tenant read — A receives B's canary at the same leaf.
        return jsonResponse(
          200,
          resourceBody({ canary: CANARY_B, scope: "tenant-B", viewer: "viewer-A" }),
          overrides.p2Headers || {},
        );
      }
      if (isC) {
        // C handed the SAME id → TRUE deny (401/403 only) by default.
        return overrides.p5 ? overrides.p5({ calls }) : challenge(403);
      }
    }
    if (wantsOA) {
      if (isA) {
        return jsonResponse(200, resourceBody({ canary: CANARY_A, scope: "tenant-A", viewer: "viewer-A", objId: OBJ_A }));
      }
      // B (or C) reading A's object → partitioned (deny/404).
      return overrides.p6 ? overrides.p6({ calls }) : challenge(403);
    }
    if (wantsOC) {
      // C reading its OWN object O_C → 200 + C's canary (proves C authenticates,
      // the P7 leg). A/B reading O_C → partitioned deny.
      if (isC) {
        return overrides.p7 ? overrides.p7({ calls }) : jsonResponse(200, resourceBody({ canary: CANARY_C, scope: "tenant-C", viewer: "viewer-C", objId: OBJ_C }));
      }
      return challenge(403);
    }
    return challenge(404);
  };
}

function baseArgs(domain) {
  return {
    target_domain: domain,
    surface_id: SURFACE_ID,
    oracle_kind: "differential_response",
    path_template: PATH_TEMPLATE,
    method: "GET",
    identity_a_profile: "identity_a",
    identity_b_profile: "identity_b",
    identity_c_profile: "identity_c",
  };
}

function soundProvision() {
  return {
    object_a: OBJ_A,
    object_b: OBJ_B,
    object_c: OBJ_C,
    canary_a: CANARY_A,
    canary_b: CANARY_B,
    canary_c: CANARY_C,
    // Owner readback discovers FIELD_PATH = ["details","secret","token"].
    owner_readback_b: { id: OBJ_B, owner_scope: "tenant-B", details: { secret: { token: CANARY_B } } },
  };
}

function setupSession(domain, { provenance = true, hosts, endpoints } = {}) {
  JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}/` }));
  seedRoutedSurface(domain, SURFACE_ID, endpointFor(domain), { hosts, endpoints });
  seedSyntheticProfiles(domain, { provenance });
  ensureHandoffSigningKey(domain);
}

async function run(domain, { fetch_fn, provision, args } = {}) {
  return idorConfirm(args || baseArgs(domain), {
    fetch_fn: fetch_fn || soundFetchFn(domain),
    provision: provision || soundProvision(),
  });
}

// ───────────────────────── pure-helper unit tests ──────────────────────────

test("canaryAt walks an exact leaf path, never a substring", () => {
  const body = { details: { secret: { token: CANARY_B } }, note: `x${CANARY_B}x` };
  assert.equal(canaryAt(body, ["details", "secret", "token"]), CANARY_B);
  // a substring occurrence at a DIFFERENT leaf is not the field path
  assert.equal(canaryAt(body, ["note"]), `x${CANARY_B}x`);
  assert.equal(canaryAt(body, ["missing"]), null);
  assert.equal(canaryAt(null, ["a"]), null);
  assert.equal(canaryAt(body, []), null);
});

test("discoverCanaryFieldPath finds the reflected leaf path or null", () => {
  assert.deepEqual(
    discoverCanaryFieldPath({ a: { b: { c: CANARY_B } } }, CANARY_B),
    ["a", "b", "c"],
  );
  assert.equal(discoverCanaryFieldPath({ a: "nope" }, CANARY_B), null);
});

test("ownScopeIsPrivate rejects shared/default/demo/sandbox heuristic scopes", () => {
  assert.equal(ownScopeIsPrivate("tenant-B"), true);
  for (const shared of ["shared", "default", "demo", "sandbox", "public", "global"]) {
    assert.equal(ownScopeIsPrivate(shared), false, `${shared} must not be a private scope`);
  }
  assert.equal(ownScopeIsPrivate(""), false);
  assert.equal(ownScopeIsPrivate(null), false);
});

test("tenantDiscriminator reads the first well-known key", () => {
  assert.deepEqual(tenantDiscriminator({ owner_scope: "B" }), { key: "owner_scope", value: "B" });
  assert.equal(tenantDiscriminator({}), null);
});

test("piiScan EXACT-matches provisioned mailboxes only (no eval_* prefix hole), aborts on foreign PII", () => {
  // The actual provisioned synthetic address passes (exact allowlist match).
  assert.deepEqual(piiScan({ email: "eval_a@example.test" }, ["eval_a@example.test"]), []);
  // An eval_*-prefixed address that is NOT a provisioned mailbox is now FLAGGED —
  // the prefix is no longer a free pass (a real eval_uator@victim.com would
  // otherwise defeat the synthetic-only AC-5 guarantee).
  const prefixImposter = piiScan({ email: "eval_uator@victim.com" }, ["eval_a@example.test"]);
  assert.equal(prefixImposter.length, 1);
  assert.equal(prefixImposter[0].type, "email");
  // an eval_ address with an empty allowlist is flagged too (no implicit prefix pass)
  assert.equal(piiScan({ email: "eval_x@example.test" }, []).length, 1);
  // a clearly-foreign address is flagged
  const foreign = piiScan({ email: "victim@gmail.com" }, []);
  assert.equal(foreign.length, 1);
  assert.equal(foreign[0].type, "email");
  // a phone shape is never allowlisted
  assert.ok(piiScan({ phone: "+1 (415) 555-0142" }, []).length >= 1);
});

test("profileHasProvenance requires all three synthetic flags", () => {
  assert.equal(profileHasProvenance({ synthetic: true, email_origin: "temp_email", provisioned_via: "bob_auto_signup" }), true);
  assert.equal(profileHasProvenance({ synthetic: true, email_origin: "temp_email" }), false);
  assert.equal(profileHasProvenance({}), false);
  assert.equal(profileHasProvenance(null), false);
});

test("IDOR ceiling is a frozen hard medium", () => {
  assert.equal(IDOR_ORACLE_DEMONSTRATED_CEILING.differential_response, "medium");
  assert.equal(Object.isFrozen(IDOR_ORACLE_DEMONSTRATED_CEILING), true);
});

// ───────────────────────── AC-6 positive ──────────────────────────

test("AC-6 positive: a sound cross-tenant read mints EXACTLY ONE signed medium row", () => withTempHome(async () => {
  const domain = "idor-positive.example.test";
  setupSession(domain);
  const result = await run(domain);

  assert.equal(result.confirmed, true, JSON.stringify(result));
  assert.equal(result.row_written, true);
  assert.equal(result.offensive_outcome, "exploited_safely");
  assert.equal(result.demonstrated_severity, "medium");
  assert.equal(result.tool_id, "bob_http_idor_confirm");
  assert.equal(result.surface_id, SURFACE_ID);
  // exactly ONE row
  const rows = readOffensiveRunRecords(domain);
  assert.equal(rows.length, 1);
  const row = rows[0];
  assert.equal(row.demonstrated_severity, "medium");
  assert.equal(row.surface_id, SURFACE_ID);
  assert.equal(row.target, canonicalizeExploitTarget(endpointFor(domain)));
  assert.ok(row.row_mac && row.row_mac.digest, "row must be MAC-signed");
  // three hashes returned + on the row
  for (const h of ["command_hash", "stdout_hash", "stderr_hash"]) {
    assert.match(result[h], /^[0-9a-f]{64}$/);
    assert.equal(result[h], row[h]);
  }
  // capture file on disk re-hashes to the row's stdout_hash (freeze re-hash path)
  const observed = projectExploitRunObservedRef(domain, { kind: "exploit_run", run_id: row.run_id });
  assert.equal(observed.stdout_hash, row.stdout_hash);
}));

test("AC-6 positive is canary-FIELD, not whole-body: per-viewer variance does NOT block", () => withTempHome(async () => {
  // The soundFetchFn injects a fresh server_ts/csrf/viewer_id on every read, so
  // P1 and P2 bodies differ byte-for-byte. A whole-body `==` oracle would block
  // here; the canary-field oracle still fires.
  const domain = "idor-variance.example.test";
  setupSession(domain);
  const result = await run(domain);
  assert.equal(result.confirmed, true, JSON.stringify(result));
}));

// ───────────────────────── AC-2 (provenance + cardinality) ──────────────────────────

test("AC-2 cardinality: a multi-endpoint surface refuses to confirm", () => withTempHome(async () => {
  const domain = "idor-multi-endpoint.example.test";
  JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}/` }));
  seedRoutedSurface(domain, SURFACE_ID, endpointFor(domain), {
    endpoints: [endpointFor(domain), `https://${domain}/api/accounts/other`],
  });
  seedSyntheticProfiles(domain);
  ensureHandoffSigningKey(domain);
  await assert.rejects(() => run(domain), /single-endpoint/);
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("AC-2 cardinality: a multi-HOST single-endpoint surface refuses to confirm", () => withTempHome(async () => {
  const domain = "idor-multi-host.example.test";
  JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}/` }));
  // single endpoint string, but two hosts → resolveSurfaceOrigins > 1
  seedRoutedSurface(domain, SURFACE_ID, `/api/accounts/${OBJ_B}`, {
    hosts: [domain, `api.${domain}`],
    endpoints: [`/api/accounts/${OBJ_B}`],
  });
  seedSyntheticProfiles(domain);
  ensureHandoffSigningKey(domain);
  await assert.rejects(() => run(domain), /single-(endpoint|host)/);
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("AC-2 (non-circular): a path_template that does not match the surface's RECORDED endpoint refuses to bind", () => withTempHome(async () => {
  // The agent can plant any endpoint into surface.endpoints[] via
  // bob_append_frontier_event, but the producer binds path_template to the
  // surface's RECORDED endpoint via resolveBaselineFromSurface — the SAME binding
  // the read-only confirmer uses. A template that PASSES the {id}-final rule but
  // does NOT match the recorded endpoint's path shape is rejected BEFORE any probe
  // (and before the provision/provenance gates), so an agent cannot point the
  // producer at an off-route target and have it sign a row for it. This is the
  // operator-locked AC-2 non-circularity binding (it replaced an earlier
  // tautological http-audit scan-trail check that matched the producer's own
  // just-written probe row).
  const domain = "idor-ac2-offroute.example.test";
  JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}/` }));
  // The surface records ONLY /api/accounts/<id>; the agent asks for /api/secrets/{id}.
  seedRoutedSurface(domain, SURFACE_ID, `https://${domain}/api/accounts/${OBJ_B}`);
  seedSyntheticProfiles(domain);
  ensureHandoffSigningKey(domain);
  const args = { ...baseArgs(domain), path_template: "/api/secrets/{id}" };
  await assert.rejects(
    () => idorConfirm(args, { fetch_fn: soundFetchFn(domain), provision: soundProvision() }),
    /path shape does not match any recorded endpoint/,
  );
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("GAP E (mint #23): a template with a trailing segment after {id} is rejected by normalizePathTemplate", () => withTempHome(async () => {
  // {id} must be the final path segment (direct resource reads only); a sub-resource
  // template is rejected up front by normalizePathTemplate, before any probe.
  const domain = "idor-gape-subresource.example.test";
  JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}/` }));
  seedRoutedSurface(domain, SURFACE_ID, `https://${domain}/api/accounts/${OBJ_B}`);
  seedSyntheticProfiles(domain);
  ensureHandoffSigningKey(domain);
  const args = { ...baseArgs(domain), path_template: "/api/accounts/{id}/sub" };
  await assert.rejects(
    () => idorConfirm(args, { fetch_fn: soundFetchFn(domain), provision: soundProvision() }),
    /\{id\} must terminate the final path segment/,
  );
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

// ───────────────────────── AC-3 (severity) ──────────────────────────

test("AC-3: agent-supplied severity / sensitivity is rejected with the producer's tool name", () => withTempHome(async () => {
  const domain = "idor-ac3-input.example.test";
  setupSession(domain);
  await assert.rejects(
    () => idorConfirm({ ...baseArgs(domain), severity: "critical" }, { fetch_fn: soundFetchFn(domain), provision: soundProvision() }),
    /bob_http_idor_confirm does not accept severity/,
  );
  await assert.rejects(
    () => idorConfirm({ ...baseArgs(domain), sensitivity: "high" }, { fetch_fn: soundFetchFn(domain), provision: soundProvision() }),
    /bob_http_idor_confirm does not accept sensitivity/,
  );
  await assert.rejects(
    () => idorConfirm({ ...baseArgs(domain), object_id: "x" }, { fetch_fn: soundFetchFn(domain), provision: soundProvision() }),
    /bob_http_idor_confirm does not accept object_id/,
  );
}));

test("AC-3: the row severity is HARDCODED medium even with PII-shaped synthetic fields", () => withTempHome(async () => {
  const domain = "idor-ac3-medium.example.test";
  setupSession(domain);
  // Synthetic eval_* email + pentest_user name in the body (allowlisted PII).
  // Deterministic per viewer so P0 (two B reads) stays stable.
  const fetch_fn = soundFetchFn(domain, {
    handler: ({ isA, isB, wantsOB }) => {
      if (wantsOB && (isA || isB)) {
        return jsonResponse(200, {
          id: OBJ_B, owner_scope: "tenant-B", contact: "eval_b@example.test", name: "pentest_user",
          viewer_id: isB ? "viewer-B" : "viewer-A",
          details: { secret: { token: CANARY_B } },
        });
      }
      return null;
    },
  });
  const result = await run(domain, { fetch_fn });
  assert.equal(result.confirmed, true, JSON.stringify(result));
  assert.equal(result.demonstrated_severity, "medium");
}));

// ───────────────────────── AC-5 (safety) ──────────────────────────

test("AC-5: a profile lacking synthetic provenance refuses to sign (INERT invariant)", () => withTempHome(async () => {
  const domain = "idor-ac5-provenance.example.test";
  setupSession(domain, { provenance: false });
  const result = await run(domain);
  assert.equal(result.confirmed, false);
  assert.equal(result.reason, "identity_provenance_not_synthetic");
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("AC-5: with no provision (live arm absent), the object is not self-provisioned → blocked, inert", () => withTempHome(async () => {
  const domain = "idor-ac5-noprovision.example.test";
  setupSession(domain);
  // Call the handler the way the MCP dispatcher would (no injection) — the
  // production INERT path: no provision → object_not_self_provisioned.
  const result = await idorConfirm(baseArgs(domain));
  assert.equal(result.confirmed, false);
  assert.equal(result.reason, "object_not_self_provisioned");
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("AC-5: a fresh O_B carrying FOREIGN PII → shared_object_store, sign nothing", () => withTempHome(async () => {
  const domain = "idor-ac5-foreign-pii.example.test";
  setupSession(domain);
  const provision = {
    ...soundProvision(),
    owner_readback_b: { id: OBJ_B, owner_scope: "tenant-B", leaked: "victim@gmail.com", details: { secret: { token: CANARY_B } } },
  };
  const result = await run(domain, { provision });
  assert.equal(result.confirmed, false);
  assert.equal(result.reason, "shared_object_store");
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("AC-5: expanded foreign PII appearing in the P2 cross-tenant body → blocked_operator_pii", () => withTempHome(async () => {
  const domain = "idor-ac5-p2-pii.example.test";
  setupSession(domain);
  const fetch_fn = soundFetchFn(domain, {
    handler: ({ isA, wantsOB }) => {
      if (wantsOB && isA) {
        // P2 (A reads O_B) carries a real victim email — the expanded-related-record vector.
        return jsonResponse(200, {
          id: OBJ_B, owner_scope: "tenant-B", related_user: "victim@gmail.com", viewer_id: "viewer-A",
          details: { secret: { token: CANARY_B } },
        });
      }
      return null;
    },
  });
  const result = await run(domain, { fetch_fn });
  assert.equal(result.confirmed, false);
  assert.equal(result.reason, "non_synthetic_pii_in_response");
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("AC-5: canary not reflected in the owner readback → canary_not_reflected", () => withTempHome(async () => {
  const domain = "idor-ac5-no-reflect.example.test";
  setupSession(domain);
  const provision = { ...soundProvision(), owner_readback_b: { id: OBJ_B, owner_scope: "tenant-B", details: {} } };
  const result = await run(domain, { provision });
  assert.equal(result.confirmed, false);
  assert.equal(result.reason, "canary_not_reflected");
}));

// ───────────────────────── AC-6 negative matrix ──────────────────────────

const NEGATIVE_CASES = [
  ["public P4-200 (anon can read O_B)", { anonStatus: 200 }, "object_not_access_controlled", null],
  ["P5 200-without-canary (id collision) → p5_ambiguous", {
    p5: () => jsonResponse(200, { id: OBJ_B, owner_scope: "tenant-C", details: { secret: { token: "different" } }, server_ts: "x" }),
  }, "p5_ambiguous", null],
  ["P5 404 (not-found ambiguous)", { p5: () => challenge(404) }, "p5_not_found_ambiguous", null],
  ["P5 200 WITH O_B's canary (authenticated-shared)", {
    p5: () => jsonResponse(200, { id: OBJ_B, owner_scope: "tenant-B", details: { secret: { token: CANARY_B } }, server_ts: "x" }),
  }, "p5_authenticated_shared", null],
  ["asymmetric P6-200 (B can read O_A — not partitioned)", {
    p6: () => jsonResponse(200, { id: OBJ_A, owner_scope: "tenant-A", details: { secret: { token: CANARY_A } }, server_ts: "x" }),
  }, "p6_not_partitioned", null],
  ["cache-HIT on P2 (edge cross-fill)", { p2Headers: { "X-Cache": "HIT" } }, "cache_shared_response", null],
];

for (let ni = 0; ni < NEGATIVE_CASES.length; ni += 1) {
  const [label, overrides, expectedReason] = NEGATIVE_CASES[ni];
  test(`AC-6 negative: ${label} mints NOTHING`, () => withTempHome(async () => {
    const domain = `idor-neg-${ni}.example.test`;
    setupSession(domain);
    const result = await run(domain, { fetch_fn: soundFetchFn(domain, overrides) });
    assert.equal(result.confirmed, false, `${label}: expected blocked, got ${JSON.stringify(result)}`);
    assert.equal(result.reason, expectedReason, `${label}: wrong reason`);
    assert.equal(result.row_written, false);
    assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false, `${label}: ledger must not exist`);
  }));
}

test("AC-6 negative: P2 does NOT carry the canary (no cross-tenant read) → blocked", () => withTempHome(async () => {
  const domain = "idor-neg-no-cross.example.test";
  setupSession(domain);
  const fetch_fn = soundFetchFn(domain, {
    handler: ({ isA, wantsOB }) => {
      if (wantsOB && isA) {
        // A reads O_B but the server returns a same-shaped resource WITHOUT B's
        // canary (proper object-level auth — A never receives B's bytes). The
        // primary-witness leg fails: no canary at the field path in P2.
        return jsonResponse(200, resourceBody({ canary: "not-b-canary".padEnd(64, "0"), scope: "tenant-B", viewer: "viewer-A" }));
      }
      return null;
    },
  });
  const result = await run(domain, { fetch_fn });
  assert.equal(result.confirmed, false);
  assert.equal(result.reason, "canary_absent_p2_no_cross_tenant_read");
  assert.equal(result.row_written, false);
}));

test("AC-6 negative: volatile P0 (B's own reads differ) → volatile_object", () => withTempHome(async () => {
  const domain = "idor-neg-volatile.example.test";
  setupSession(domain);
  // Make B-as-B reads structurally differ (extra key on the 2nd read) so the
  // canonicalJson P0 stability check fails.
  let bRead = 0;
  const fetch_fn = soundFetchFn(domain, {
    handler: ({ isB, wantsOB }) => {
      if (wantsOB && isB) {
        bRead += 1;
        const body = { id: OBJ_B, owner_scope: "tenant-B", details: { secret: { token: CANARY_B } } };
        if (bRead === 2) body.extra_structural_key = "volatile";
        return jsonResponse(200, body);
      }
      return null;
    },
  });
  const result = await run(domain, { fetch_fn });
  assert.equal(result.confirmed, false);
  assert.equal(result.reason, "volatile_object");
}));

test("AC-6 negative: truncated P2 body → blocked, sign nothing", () => withTempHome(async () => {
  const domain = "idor-neg-truncated.example.test";
  setupSession(domain);
  const fetch_fn = soundFetchFn(domain, {
    handler: ({ isA, wantsOB }) => {
      if (wantsOB && isA) {
        const r = jsonResponse(200, resourceBody({ canary: CANARY_B, scope: "tenant-B", viewer: "A" }));
        r.bodyTruncated = true;
        return r;
      }
      return null;
    },
  });
  const result = await run(domain, { fetch_fn });
  assert.equal(result.confirmed, false);
  assert.equal(result.reason, "body_truncated");
}));

test("AC-6 negative: P2′ canary drops on the fresh URL (eventual consistency) → blocked", () => withTempHome(async () => {
  const domain = "idor-neg-p2prime.example.test";
  setupSession(domain);
  const fetch_fn = soundFetchFn(domain, {
    handler: ({ isA, wantsOB, url }) => {
      if (wantsOB && isA && url.includes("_bobcb=")) {
        // P2′ (fresh URL variant) loses the canary → not a durable origin read.
        return jsonResponse(200, { id: OBJ_B, owner_scope: "tenant-B", details: { secret: { token: "gone" } }, server_ts: "x" });
      }
      return null;
    },
  });
  const result = await run(domain, { fetch_fn });
  assert.equal(result.confirmed, false);
  assert.equal(result.reason, "canary_did_not_survive_fresh_url");
}));

test("AC-6 negative: same tenant / absent discriminator → identities_collided_not_provable", () => withTempHome(async () => {
  const domain = "idor-neg-same-tenant.example.test";
  setupSession(domain);
  const fetch_fn = soundFetchFn(domain, {
    handler: ({ isA, isB, wantsOB, wantsOA }) => {
      // A's own object reports the SAME scope as B's → discriminator does not differ.
      if (wantsOA && isA) {
        return jsonResponse(200, { id: OBJ_A, owner_scope: "tenant-B", details: { secret: { token: CANARY_A } }, server_ts: "x" });
      }
      return null;
    },
  });
  const result = await run(domain, { fetch_fn });
  assert.equal(result.confirmed, false);
  assert.equal(result.reason, "identities_collided_not_provable");
}));

test("AC-6 negative: P1 own-scope is a SHARED scope → own_scope_not_private", () => withTempHome(async () => {
  const domain = "idor-neg-shared-scope.example.test";
  setupSession(domain);
  const fetch_fn = soundFetchFn(domain, {
    handler: ({ isA, isB, wantsOB }) => {
      if (wantsOB && (isA || isB)) {
        return jsonResponse(200, { id: OBJ_B, owner_scope: "default", viewer_id: isB ? "viewer-B" : "viewer-A", details: { secret: { token: CANARY_B } } });
      }
      return null;
    },
  });
  const result = await run(domain, { fetch_fn });
  assert.equal(result.confirmed, false);
  assert.equal(result.reason, "own_scope_not_private");
}));

// ───────────────────────── round-2 review hardening ──────────────────────────

test("read-only guard: a verb-prefixed recorded endpoint (/api/reset/{id}) is rejected before any probe", () => withTempHome(async () => {
  // normalizePathTemplate forces {id} to be the FINAL segment, but a verb-NAMED
  // collection BEFORE the id still resolves through resolveBaselineFromSurface, so
  // the producer applies assertReadOnlyPath (the same guard the read-only confirmer
  // runs on its baseline). A recorded /api/reset/<id> endpoint is rejected as a
  // state-changing path before any object is provisioned or probed.
  const domain = "idor-readonly-verb.example.test";
  JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}/` }));
  seedRoutedSurface(domain, SURFACE_ID, `https://${domain}/api/reset/${OBJ_B}`);
  seedSyntheticProfiles(domain);
  ensureHandoffSigningKey(domain);
  const args = { ...baseArgs(domain), path_template: "/api/reset/{id}" };
  await assert.rejects(
    () => idorConfirm(args, { fetch_fn: soundFetchFn(domain), provision: soundProvision() }),
    /state-changing path segment/,
  );
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("AC-5 safety: Bob-local profile metadata (provenance flags + synthetic mailbox) is never sent as an outbound header", () => withTempHome(async () => {
  // The auth profile co-mingles real headers (Authorization) with Bob-local fields
  // (synthetic/email_origin/provisioned_via/email). buildHeaderProfile Object.assigns
  // its first arg verbatim, so the producer must strip the metadata before building
  // outbound headers — otherwise it would leak provenance + the synthetic mailbox
  // to the target once armed.
  const domain = "idor-header-leak.example.test";
  setupSession(domain);
  const seenHeaderKeys = new Set();
  const base = soundFetchFn(domain);
  const fetch_fn = async (req) => {
    for (const key of Object.keys(req.headers || {})) seenHeaderKeys.add(key);
    return base(req);
  };
  const result = await run(domain, { fetch_fn });
  assert.equal(result.confirmed, true, JSON.stringify(result));
  for (const leaky of ["synthetic", "email_origin", "provisioned_via", "email", "local_storage", "credentials"]) {
    assert.ok(!seenHeaderKeys.has(leaky), `outbound headers must not carry Bob-local field "${leaky}"; saw [${[...seenHeaderKeys].join(", ")}]`);
  }
  // the genuine auth header IS still sent
  assert.ok(seenHeaderKeys.has("Authorization"), "Authorization header must still be sent");
}));

test("AC-5: foreign PII appearing ONLY in the cache-bust P2′ proof body → blocked_operator_pii", () => withTempHome(async () => {
  const domain = "idor-ac5-p2prime-pii.example.test";
  setupSession(domain);
  const fetch_fn = soundFetchFn(domain, {
    handler: ({ isA, wantsOB, url }) => {
      if (wantsOB && isA && url.includes("_bobcb=")) {
        // P2′ (fresh URL) returns an EXPANDED body carrying a real victim email; the
        // cached P2 stays clean. Without scanning P2′ this would sign.
        return jsonResponse(200, {
          id: OBJ_B, owner_scope: "tenant-B", related_user: "victim@gmail.com", viewer_id: "viewer-A",
          details: { secret: { token: CANARY_B } },
        });
      }
      return null;
    },
  });
  const result = await run(domain, { fetch_fn });
  assert.equal(result.confirmed, false);
  assert.equal(result.reason, "non_synthetic_pii_in_response");
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("AC-6 negative: a P5 401/403 deny body that STILL leaks B's canary → p5_canary_in_deny_body", () => withTempHome(async () => {
  // A defensive server can return 403 while still echoing the object in the error
  // envelope — identity C actually received B's bytes, so the access-control leg is
  // not a true deny and the producer must refuse to sign.
  const domain = "idor-neg-p5-canary-deny.example.test";
  setupSession(domain);
  const fetch_fn = soundFetchFn(domain, {
    p5: () => jsonResponse(403, { error: "forbidden", details: { secret: { token: CANARY_B } } }),
  });
  const result = await run(domain, { fetch_fn });
  assert.equal(result.confirmed, false);
  assert.equal(result.reason, "p5_canary_in_deny_body");
  assert.equal(result.row_written, false);
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("AC-6 negative: P3 is not provably identity A's own object (no A-canary) → p3_not_identity_a_object", () => withTempHome(async () => {
  // P3 supplies identity A's tenant discriminator (#14); if A's read of O_A does
  // not reflect A's OWN canary, the cross-tenant distinctness is not grounded and
  // the producer signs nothing.
  const domain = "idor-neg-p3-not-a.example.test";
  setupSession(domain);
  const fetch_fn = soundFetchFn(domain, {
    handler: ({ isA, wantsOA }) => {
      if (wantsOA && isA) {
        return jsonResponse(200, { id: OBJ_A, owner_scope: "tenant-A", details: { secret: { token: "not-a-canary" } }, server_ts: "x" });
      }
      return null;
    },
  });
  const result = await run(domain, { fetch_fn });
  assert.equal(result.confirmed, false);
  assert.equal(result.reason, "p3_not_identity_a_object");
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

// ───────────────────────── round-3 review hardening ──────────────────────────

test("AC-6 negative: a P6 401/403 deny body that STILL leaks A's canary → p6_canary_in_deny_body", () => withTempHome(async () => {
  // Symmetric to the P5 deny-body scan: a B->O_A control request that returns 403
  // but still echoes A's object means the tenant partition is false.
  const domain = "idor-neg-p6-canary-deny.example.test";
  setupSession(domain);
  const fetch_fn = soundFetchFn(domain, {
    p6: () => jsonResponse(403, { error: "forbidden", details: { secret: { token: CANARY_A } } }),
  });
  const result = await run(domain, { fetch_fn });
  assert.equal(result.confirmed, false);
  assert.equal(result.reason, "p6_canary_in_deny_body");
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("AC-6 negative: identity C cannot read its OWN object (stale creds) → identity_c_not_authenticated", () => withTempHome(async () => {
  // P5's authenticated-but-shared exclusion only holds if C is genuinely
  // authenticated. If C cannot read O_C, its 401/403 on O_B is just "C not logged
  // in" (same as anon) and proves nothing — the producer must refuse to sign.
  const domain = "idor-neg-c-stale.example.test";
  setupSession(domain);
  const fetch_fn = soundFetchFn(domain, { p7: () => challenge(403) });
  const result = await run(domain, { fetch_fn });
  assert.equal(result.confirmed, false);
  assert.equal(result.reason, "identity_c_not_authenticated");
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("AC-5 safety: a self-provisioned id with a path separator → object_id_unsafe_segment", () => withTempHome(async () => {
  // encodeURIComponent only ENCODES the id — it does not reject it. A server-minted
  // id carrying a `/` could route to a sub-resource once a router decodes it, so the
  // producer rejects any id that is not a clean single path segment.
  const domain = "idor-neg-unsafe-id.example.test";
  setupSession(domain);
  const provision = { ...soundProvision(), object_b: "obj/b/200" };
  const result = await run(domain, { provision });
  assert.equal(result.confirmed, false);
  assert.equal(result.reason, "object_id_unsafe_segment");
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("AC-6 negative: a TRUNCATED cache-bust P2′ body → body_truncated (P2′ now in the truncation gate)", () => withTempHome(async () => {
  const domain = "idor-neg-p2prime-trunc.example.test";
  setupSession(domain);
  const fetch_fn = soundFetchFn(domain, {
    handler: ({ isA, wantsOB, url }) => {
      if (wantsOB && isA && url.includes("_bobcb=")) {
        const r = jsonResponse(200, { id: OBJ_B, owner_scope: "tenant-B", details: { secret: { token: CANARY_B } } });
        r.bodyTruncated = true;
        return r;
      }
      return null;
    },
  });
  const result = await run(domain, { fetch_fn });
  assert.equal(result.confirmed, false);
  assert.equal(result.reason, "body_truncated");
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("AC-6 negative: an OVERSIZED cache-bust P2′ body → object_too_large (P2′ now in the size gate)", () => withTempHome(async () => {
  const domain = "idor-neg-p2prime-large.example.test";
  setupSession(domain);
  const fetch_fn = soundFetchFn(domain, {
    handler: ({ isA, wantsOB, url }) => {
      if (wantsOB && isA && url.includes("_bobcb=")) {
        return jsonResponse(200, {
          id: OBJ_B, owner_scope: "tenant-B", filler: "x".repeat(300 * 1024),
          details: { secret: { token: CANARY_B } },
        });
      }
      return null;
    },
  });
  const result = await run(domain, { fetch_fn });
  assert.equal(result.confirmed, false);
  assert.equal(result.reason, "object_too_large");
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("AC-6 negative: a shared cache is in the path on P2 (Age:0, no MISS label) → cannot_prove_origin_read_through_cache", () => withTempHome(async () => {
  // The canary survives, responseIsSharedCacheable does NOT fire (Age:0, no HIT,
  // private suppresses the speculative branch), but a cache that emits Age means a
  // shared cache is in the path — so without an affirmative MISS the producer cannot
  // prove this was an origin read (vs a query-ignoring cache cross-fill) and fails
  // closed. Adversarial-audit finding (wf_cf30cbfe-540).
  const domain = "idor-neg-cache-crossfill.example.test";
  setupSession(domain);
  const fetch_fn = soundFetchFn(domain, { p2Headers: { Age: "0", "Cache-Control": "private" } });
  const result = await run(domain, { fetch_fn });
  assert.equal(result.confirmed, false);
  assert.equal(result.reason, "cannot_prove_origin_read_through_cache");
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("AC-6 positive: a labeled CDN MISS on the cross-tenant read still confirms (origin proven)", () => withTempHome(async () => {
  // A cache IN the path that affirmatively labels its MISS is a proven origin fetch,
  // so #15b does not block — the cross-tenant read still mints a row.
  const domain = "idor-pos-cdn-miss.example.test";
  setupSession(domain);
  const fetch_fn = soundFetchFn(domain, { p2Headers: { "X-Cache": "MISS", "CF-Cache-Status": "MISS" } });
  const result = await run(domain, { fetch_fn });
  assert.equal(result.confirmed, true, JSON.stringify(result));
  assert.equal(result.row_written, true);
}));

// ───────────────────────── round-4 review hardening ──────────────────────────

test("AC-6 negative: P2 is a 401/403 error envelope echoing B's canary (not a resource read) → p2_not_resource_shaped", () => withTempHome(async () => {
  const domain = "idor-neg-p2-errorenvelope.example.test";
  setupSession(domain);
  const fetch_fn = soundFetchFn(domain, {
    handler: ({ isA, wantsOB }) => {
      if (wantsOB && isA) {
        // A's read is a 403 envelope that merely ECHOES B's canary at the leaf — a
        // reflected error, not a genuine cross-tenant resource read.
        return jsonResponse(403, { error: "forbidden", details: { secret: { token: CANARY_B } } });
      }
      return null;
    },
  });
  const result = await run(domain, { fetch_fn });
  assert.equal(result.confirmed, false);
  assert.equal(result.reason, "p2_not_resource_shaped");
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("AC-6 negative: a TRUNCATED anon P4 body → p4_body_truncated", () => withTempHome(async () => {
  const domain = "idor-neg-p4-trunc.example.test";
  setupSession(domain);
  const fetch_fn = soundFetchFn(domain, {
    handler: ({ isA, isB, isC, wantsOB }) => {
      if (wantsOB && !isA && !isB && !isC) {
        const r = challenge(403);
        r.bodyTruncated = true; // anon body truncated → a canary could hide past the cap
        return r;
      }
      return null;
    },
  });
  const result = await run(domain, { fetch_fn });
  assert.equal(result.confirmed, false);
  assert.equal(result.reason, "p4_body_truncated");
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("AC-6 negative: O_C is publicly readable (anon gets canary_c) → o_c_public_canary_leaked", () => withTempHome(async () => {
  // If O_C is public, C reading it proves nothing about C's authentication, so the
  // P5 authenticated-but-shared exclusion would be unsound.
  const domain = "idor-neg-oc-public.example.test";
  setupSession(domain);
  const fetch_fn = soundFetchFn(domain, {
    handler: ({ isA, isB, isC, wantsOC }) => {
      if (wantsOC && !isA && !isB && !isC) {
        return jsonResponse(200, resourceBody({ canary: CANARY_C, scope: "tenant-C", viewer: "anon", objId: OBJ_C }));
      }
      return null;
    },
  });
  const result = await run(domain, { fetch_fn });
  assert.equal(result.confirmed, false);
  assert.equal(result.reason, "o_c_public_canary_leaked");
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("AC-6 negative: O_C is not access-controlled (anon 200 without canary) → o_c_not_access_controlled", () => withTempHome(async () => {
  const domain = "idor-neg-oc-notgated.example.test";
  setupSession(domain);
  const fetch_fn = soundFetchFn(domain, {
    handler: ({ isA, isB, isC, wantsOC }) => {
      if (wantsOC && !isA && !isB && !isC) {
        return jsonResponse(200, { id: OBJ_C, owner_scope: "tenant-C", details: { secret: { token: "no-canary" } } });
      }
      return null;
    },
  });
  const result = await run(domain, { fetch_fn });
  assert.equal(result.confirmed, false);
  assert.equal(result.reason, "o_c_not_access_controlled");
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("AC-6 positive: a standardized Cache-Status: fwd=miss still confirms (proven origin)", () => withTempHome(async () => {
  const domain = "idor-pos-cachestatus-miss.example.test";
  setupSession(domain);
  const fetch_fn = soundFetchFn(domain, { p2Headers: { "Cache-Status": "ExampleCache; fwd=miss" } });
  const result = await run(domain, { fetch_fn });
  assert.equal(result.confirmed, true, JSON.stringify(result));
  assert.equal(result.row_written, true);
}));

test("AC-6 negative: a Cache-Status header present without a MISS label → cannot_prove_origin_read_through_cache", () => withTempHome(async () => {
  const domain = "idor-neg-cachestatus-ambiguous.example.test";
  setupSession(domain);
  const fetch_fn = soundFetchFn(domain, { p2Headers: { "Cache-Status": "ExampleCache" } });
  const result = await run(domain, { fetch_fn });
  assert.equal(result.confirmed, false);
  assert.equal(result.reason, "cannot_prove_origin_read_through_cache");
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

// ───────────────────────── round-5 review hardening ──────────────────────────

test("AC-6 positive: Cache-Control: s-maxage=0 still confirms (revalidate is not a shared-cache hazard)", () => withTempHome(async () => {
  // s-maxage=0 forces shared caches to revalidate every time — not a cross-principal
  // hazard. Matching the bare token would false-negative every CDN-revalidated read.
  const domain = "idor-pos-smaxage0.example.test";
  setupSession(domain);
  const fetch_fn = soundFetchFn(domain, { p2Headers: { "Cache-Control": "s-maxage=0" } });
  const result = await run(domain, { fetch_fn });
  assert.equal(result.confirmed, true, JSON.stringify(result));
  assert.equal(result.row_written, true);
}));

test("AC-6 positive: a Via header (generic proxy, not a cache) still confirms", () => withTempHome(async () => {
  // Via is set by ANY forward/reverse proxy or gateway, not just caches, so it must
  // not count as shared-cache-in-path evidence (would over-block proxied deployments).
  const domain = "idor-pos-via.example.test";
  setupSession(domain);
  const fetch_fn = soundFetchFn(domain, { p2Headers: { Via: "1.1 proxy.example" } });
  const result = await run(domain, { fetch_fn });
  assert.equal(result.confirmed, true, JSON.stringify(result));
  assert.equal(result.row_written, true);
}));

test("AC-6 negative: CF-Cache-Status: UPDATING (stale-cache serve, not origin) → cannot_prove_origin_read_through_cache", () => withTempHome(async () => {
  // UPDATING / REVALIDATED serve a stale cached body while refreshing — the body came
  // from cache, NOT a fresh origin fetch, so it must not be trusted as a proven MISS.
  const domain = "idor-neg-cf-updating.example.test";
  setupSession(domain);
  const fetch_fn = soundFetchFn(domain, { p2Headers: { "CF-Cache-Status": "UPDATING" } });
  const result = await run(domain, { fetch_fn });
  assert.equal(result.confirmed, false);
  assert.equal(result.reason, "cannot_prove_origin_read_through_cache");
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("AC-5 safety: a self-provisioned id of '..' (path traversal) → object_id_unsafe_segment", () => withTempHome(async () => {
  const domain = "idor-neg-dotdot-id.example.test";
  setupSession(domain);
  const provision = { ...soundProvision(), object_b: ".." };
  const result = await run(domain, { provision });
  assert.equal(result.confirmed, false);
  assert.equal(result.reason, "object_id_unsafe_segment");
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

// ───────────────────────── round-6 review hardening ──────────────────────────

test("AC-5: foreign PII in a DUPLICATE (shadowed) JSON key evades parse but the raw-body scan catches it → blocked", () => withTempHome(async () => {
  const domain = "idor-neg-dupkey-pii.example.test";
  setupSession(domain);
  const fetch_fn = soundFetchFn(domain, {
    handler: ({ isA, wantsOB }) => {
      if (wantsOB && isA) {
        // Raw JSON with a duplicate `contact` key: JSON.parse keeps the synthetic LAST
        // value, but the foreign address is still in the raw bytes.
        return jsonResponse(200, `{"id":"${OBJ_B}","owner_scope":"tenant-B","viewer_id":"viewer-A","contact":"victim@gmail.com","contact":"eval_a@example.test","details":{"secret":{"token":"${CANARY_B}"}}}`);
      }
      return null;
    },
  });
  const result = await run(domain, { fetch_fn });
  assert.equal(result.confirmed, false);
  assert.equal(result.reason, "non_synthetic_pii_in_response");
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("AC-5: an injected JWT credential in the P2 proof body → non_synthetic_secret_in_response", () => withTempHome(async () => {
  const domain = "idor-neg-secret-body.example.test";
  setupSession(domain);
  const fetch_fn = soundFetchFn(domain, {
    handler: ({ isA, wantsOB }) => {
      if (wantsOB && isA) {
        return jsonResponse(200, {
          id: OBJ_B, owner_scope: "tenant-B", viewer_id: "viewer-A",
          session: "eyJhbGciOiJIUzI1NiIsImtpZCI6IjEifQ.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
          details: { secret: { token: CANARY_B } },
        });
      }
      return null;
    },
  });
  const result = await run(domain, { fetch_fn });
  assert.equal(result.confirmed, false);
  assert.equal(result.reason, "non_synthetic_secret_in_response");
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("AC-6 negative: P5 deny body that \\u-escapes B's canary (decodes to it) → p5_canary_in_deny_body", () => withTempHome(async () => {
  const domain = "idor-neg-p5-uescape.example.test";
  setupSession(domain);
  const escaped = "\\u0062".repeat(64); // decodes to "b" * 64 === CANARY_B
  const fetch_fn = soundFetchFn(domain, {
    p5: () => jsonResponse(403, `{"error":"forbidden","leaked":"${escaped}"}`),
  });
  const result = await run(domain, { fetch_fn });
  assert.equal(result.confirmed, false);
  assert.equal(result.reason, "p5_canary_in_deny_body");
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("AC-6 positive: an underscore-delimited X-Cache: TCP_MISS still confirms (proven origin)", () => withTempHome(async () => {
  const domain = "idor-pos-tcp-miss.example.test";
  setupSession(domain);
  const fetch_fn = soundFetchFn(domain, { p2Headers: { "X-Cache": "TCP_MISS" } });
  const result = await run(domain, { fetch_fn });
  assert.equal(result.confirmed, true, JSON.stringify(result));
  assert.equal(result.row_written, true);
}));

test("AC-6 negative: a quoted Cache-Control: s-maxage=\"60\" is a shared-cache hazard → cache_shared_response", () => withTempHome(async () => {
  const domain = "idor-neg-smaxage-quoted.example.test";
  setupSession(domain);
  const fetch_fn = soundFetchFn(domain, { p2Headers: { "Cache-Control": 's-maxage="60"' } });
  const result = await run(domain, { fetch_fn });
  assert.equal(result.confirmed, false);
  assert.equal(result.reason, "cache_shared_response");
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("AC-2 safety: a recorded endpoint with double-encoded traversal (%252e%252e) is rejected by assertReadOnlyPath", () => withTempHome(async () => {
  const domain = "idor-neg-traversal.example.test";
  JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}/` }));
  seedRoutedSurface(domain, SURFACE_ID, `https://${domain}/api/%252e%252e/admin/${OBJ_B}`);
  seedSyntheticProfiles(domain);
  ensureHandoffSigningKey(domain);
  const args = { ...baseArgs(domain), path_template: "/api/%252e%252e/admin/{id}" };
  await assert.rejects(
    () => idorConfirm(args, { fetch_fn: soundFetchFn(domain), provision: soundProvision() }),
    /path-traversal/,
  );
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

// ───────────────────────── round-trip: record → freeze re-hash → verify ──────────────────────────

test("round-trip: a minted row backs an exploited_safely claim, then re-hashes at freeze (medium held)", () => withTempHome(async () => {
  const domain = "idor-roundtrip.example.test";
  setupSession(domain);
  const result = await run(domain);
  assert.equal(result.confirmed, true, JSON.stringify(result));

  // The evaluator copies the producer's returned values verbatim into the ref.
  const claim = appendCandidateClaim({
    target_domain: domain,
    title: "Cross-tenant IDOR demonstrated safely",
    summary: "Identity A read identity B's object across the tenant boundary (canary witness).",
    severity: "medium",
    exploit_outcome: { outcome: "exploited_safely", safe_oracle: { kind: "differential_response" } },
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

  // 3 verify rounds: re-hash the frozen <run_id>.stdout (never re-attack); medium held.
  const row = readOffensiveRunRecords(domain)[0];
  for (let i = 0; i < 3; i += 1) {
    const observed = projectExploitRunObservedRef(domain, { kind: "exploit_run", run_id: row.run_id });
    assert.equal(observed.stdout_hash, row.stdout_hash, `verify round ${i + 1} re-hash must match`);
  }
}));

test("round-trip: a claim severity ABOVE the medium ceiling is rejected", () => withTempHome(async () => {
  const domain = "idor-ceiling.example.test";
  setupSession(domain);
  const result = await run(domain);
  assert.equal(result.confirmed, true);
  let caught;
  try {
    appendCandidateClaim({
      target_domain: domain,
      title: "Over-severity claim",
      summary: "Attempts to claim critical from a medium IDOR row.",
      severity: "critical",
      exploit_outcome: { outcome: "exploited_safely", safe_oracle: { kind: "differential_response" } },
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

test("round-trip: a claim citing the row under a DIFFERENT surface is rejected (#111)", () => withTempHome(async () => {
  const domain = "idor-surface-bind.example.test";
  setupSession(domain);
  const result = await run(domain);
  assert.equal(result.confirmed, true);
  let caught;
  try {
    appendCandidateClaim({
      target_domain: domain,
      title: "Surface laundering attempt",
      summary: "Cites an IDOR row produced for a different surface.",
      severity: "medium",
      exploit_outcome: { outcome: "exploited_safely", safe_oracle: { kind: "differential_response" } },
      surface_ids: ["surface:some-other"],
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
  assert.ok(caught, "surface mismatch must be rejected");
  assert.equal(caught.details.code, "exploit_proof_row_surface_mismatch");
}));
