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
  liveProvision,
  createObject,
  idorProvisionAuthorizedFor,
  IDOR_PROVISION_ENV,
} = require("../mcp/lib/offensive-idor-producer.js");
const { assertCreateCollectionShapeSafe } = require("../mcp/lib/offensive-http-common.js");
const { validateAgainstSchema } = require("../mcp/lib/tool-validation.js");
const idorDescriptor = require("../mcp/lib/tools/bob-http-idor-confirm.js");
const { initSession } = require("../mcp/lib/session-state.js");
const { routeSurfaces } = require("../mcp/lib/surface-router.js");
const { writeAuthFile, resolveAuthJsonPath, authStore } = require("../mcp/lib/auth.js");
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

test("tenantDiscriminator reads the first well-known key (and coerces only SAFE integers)", () => {
  assert.deepEqual(tenantDiscriminator({ owner_scope: "B" }), { key: "owner_scope", value: "B" });
  assert.equal(tenantDiscriminator({}), null);
  // Integer tenant IDs (common in real REST APIs) are coerced to their string form.
  assert.deepEqual(tenantDiscriminator({ org_id: 7 }), { key: "org_id", value: "7" });
  // A precision-unsafe magnitude (>= 2^53) is NOT coerced — its String() form is unreliable and
  // could collide two distinct tenants; reject it so the read soft-gates instead of mis-comparing.
  assert.equal(tenantDiscriminator({ org_id: Number.MAX_SAFE_INTEGER + 1 }), null);
  // A float is not a tenant id either.
  assert.equal(tenantDiscriminator({ org_id: 42.5 }), null);
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

test("profileHasProvenance requires all three synthetic flags AND the synthetic mailbox", () => {
  const full = { synthetic: true, email_origin: "temp_email", provisioned_via: "bob_auto_signup", email: "eval_a@example.test" };
  assert.equal(profileHasProvenance(full), true);
  // The three markers without the synthetic mailbox must NOT pass — mint condition #17
  // (allowedEmails) depends on profile.email, so the gate requires the full four-field stamp.
  assert.equal(profileHasProvenance({ synthetic: true, email_origin: "temp_email", provisioned_via: "bob_auto_signup" }), false);
  assert.equal(profileHasProvenance({ ...full, email: "" }), false);
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
  assert.deepEqual(result.confidence_signals, [], "a fully-proven fire carries NO confidence signals");
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

// PR-PROV end-to-end: arm the three identities through the REAL production stamp path
// (authStore with the 2nd-arg provenance the bob_auto_signup seam passes) instead of the
// raw file-writer `seedSyntheticProfiles`. Proves the stamp the producer's mint
// condition #18 reads is exactly what authStore persists, so the production arming path
// actually drives the signer.
test("AC-6 via production stamp: identities armed by authStore(2nd-arg provenance) mint EXACTLY ONE signed medium row", () => withTempHome(async () => {
  const domain = "idor-prov-stamp.example.test";
  JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}/` }));
  seedRoutedSurface(domain, SURFACE_ID, endpointFor(domain));
  for (const tag of ["a", "b", "c"]) {
    authStore({
      target_domain: domain,
      profile_name: `identity_${tag}`,
      headers: { Authorization: `Bearer eyJ${tag}token` },
    }, {
      provenance: {
        synthetic: true,
        email_origin: "temp_email",
        provisioned_via: "bob_auto_signup",
        email: `eval_${tag}@example.test`,
      },
    });
  }
  ensureHandoffSigningKey(domain);

  const result = await run(domain);
  assert.equal(result.confirmed, true, JSON.stringify(result));
  assert.equal(result.row_written, true);
  assert.equal(result.offensive_outcome, "exploited_safely");
  assert.equal(result.demonstrated_severity, "medium");
  const rows = readOffensiveRunRecords(domain);
  assert.equal(rows.length, 1);
  assert.ok(rows[0].row_mac && rows[0].row_mac.digest, "row must be MAC-signed");
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

test("AC-6 negative: PROVABLY same tenant (A and B both report owner_scope tenant-B) → identities_collided_same_tenant (still blocks)", () => withTempHome(async () => {
  const domain = "idor-neg-same-tenant.example.test";
  setupSession(domain);
  const fetch_fn = soundFetchFn(domain, {
    handler: ({ isA, isB, wantsOB, wantsOA }) => {
      // A's own object reports the SAME scope value as B's → A and B are PROVABLY one tenant.
      if (wantsOA && isA) {
        return jsonResponse(200, { id: OBJ_A, owner_scope: "tenant-B", details: { secret: { token: CANARY_A } }, server_ts: "x" });
      }
      return null;
    },
  });
  const result = await run(domain, { fetch_fn });
  // PROVABLY same tenant is positive evidence AGAINST a cross-tenant break, so #14 stays a
  // HARD refutation here (it is NOT the "unprovable" case the demotion targets) — nothing is
  // signed. The T6/T7-style UNPROVABLE cases (missing/mismatched key) still mint with a signal.
  assert.equal(result.confirmed, false);
  assert.equal(result.reason, "identities_collided_same_tenant");
  assert.equal(result.row_written, false);
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("AC-6 negative: P1 own-scope is an EXPLICIT shared scope (\"default\") → own_scope_explicitly_shared (blocks)", () => withTempHome(async () => {
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
  // An EXPLICIT shared scope ("default") is positive evidence the object is shared, NOT
  // B-private — it stays a HARD refutation (only a MISSING scope key soft-gates).
  assert.equal(result.confirmed, false);
  assert.equal(result.reason, "own_scope_explicitly_shared");
  assert.equal(result.row_written, false);
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("AC-6 negative: owner readback marks O_B with an explicit shared scope while P1 omits it → own_scope_explicitly_shared (blocks)", () => withTempHome(async () => {
  // The live P1/P2 cross-principal reads OMIT every owning-scope key (which on its own would only
  // SOFT-gate to own_scope_missing). But the producer's OWN owner readback — already trusted to
  // discover the canary field (#20) and screen create-time PII (#24) — marks O_B "public". That
  // authoritative shared label is positive evidence O_B is shared, so it HARD-blocks even though P1
  // dropped the key; a soft-gated LOW mint here would mislabel a shared object as a cross-tenant read.
  const domain = "idor-neg-readback-shared.example.test";
  setupSession(domain);
  const fetch_fn = soundFetchFn(domain, {
    handler: ({ isA, isB, wantsOB }) => {
      if (wantsOB && (isA || isB)) {
        const body = resourceBody({ canary: CANARY_B, scope: "tenant-B", viewer: isB ? "viewer-B" : "viewer-A" });
        delete body.owner_scope; // P1/P2 echo NO owning-scope key
        return jsonResponse(200, body);
      }
      return null;
    },
  });
  const provision = {
    ...soundProvision(),
    owner_readback_b: { id: OBJ_B, owner_scope: "public", details: { secret: { token: CANARY_B } } },
  };
  const result = await run(domain, { fetch_fn, provision });
  assert.equal(result.confirmed, false, JSON.stringify(result));
  assert.equal(result.reason, "own_scope_explicitly_shared");
  assert.equal(result.row_written, false);
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("AC-6 soft preserved: a PRIVATE-scope owner readback does NOT clear the P1 own_scope_missing soft-gate", () => withTempHome(async () => {
  // Asymmetric rule: the readback can only STRENGTHEN a block (explicit-shared), never clear the
  // P1-side soft-gate. P1 omits the owning-scope key (account_id only) while the readback carries a
  // PRIVATE scope ("tenant-B"). The cross-principal proof body still does not demonstrate B-private
  // ownership to a reviewer, so own_scope_missing must still fire and the fire mints at LOW.
  const domain = "idor-soft-readback-private.example.test";
  setupSession(domain);
  const fetch_fn = soundFetchFn(domain, {
    handler: ({ isA, isB, wantsOB }) => {
      if (wantsOB && (isA || isB)) {
        return jsonResponse(200, { id: OBJ_B, account_id: "acct-b-1", viewer_id: isB ? "viewer-B" : "viewer-A", details: { secret: { token: CANARY_B } } });
      }
      return null;
    },
  });
  // soundProvision()'s readback carries owner_scope:"tenant-B" (private) — must NOT upgrade the fire.
  const result = await run(domain, { fetch_fn });
  assert.equal(result.confirmed, true, JSON.stringify(result));
  assert.equal(result.row_written, true);
  assert.ok(result.confidence_signals.some((s) => s.gate === "own_scope_missing"));
  assert.equal(result.demonstrated_severity, "low");
  assert.equal(result.masked_oracle.relation.own_scope_private, false);
}));

test("AC-6 negative: owner readback hides a shared label in a SECONDARY alias (owner_scope private + workspace_id 'public') → blocks", () => withTempHome(async () => {
  // #13 must scan EVERY owning-scope alias, not just the first ownScopeOf match. P1/P2 omit scope;
  // the readback's primary alias is private (owner_scope:"tenant-B") but a secondary alias is
  // shared (workspace_id:"public"). The shared label is positive evidence O_B is shared → block.
  const domain = "idor-neg-readback-multialias.example.test";
  setupSession(domain);
  const fetch_fn = soundFetchFn(domain, {
    handler: ({ isA, isB, wantsOB }) => {
      if (wantsOB && (isA || isB)) {
        const body = resourceBody({ canary: CANARY_B, scope: "tenant-B", viewer: isB ? "viewer-B" : "viewer-A" });
        delete body.owner_scope;
        return jsonResponse(200, body);
      }
      return null;
    },
  });
  const provision = {
    ...soundProvision(),
    owner_readback_b: { id: OBJ_B, owner_scope: "tenant-B", workspace_id: "public", details: { secret: { token: CANARY_B } } },
  };
  const result = await run(domain, { fetch_fn, provision });
  assert.equal(result.confirmed, false, JSON.stringify(result));
  assert.equal(result.reason, "own_scope_explicitly_shared");
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("AC-6 negative: the signed A→B proof read (P2/P2′) explicitly says owner_scope 'public' while P1 omits it → blocks", () => withTempHome(async () => {
  // #13 must screen the SUCCESSFUL proof reads (P2/P2′), not just P1 + the readback. Here the
  // readback is private and P1 omits the key, but the A→B proof body whose canary signs the row
  // itself carries owner_scope:"public" — positive shared evidence inside the signed proof → block.
  const domain = "idor-neg-proofread-shared.example.test";
  setupSession(domain);
  const fetch_fn = soundFetchFn(domain, {
    handler: ({ isA, isB, wantsOB }) => {
      if (wantsOB && isB) {
        const body = resourceBody({ canary: CANARY_B, scope: "tenant-B", viewer: "viewer-B" });
        delete body.owner_scope; // P0/P1 omit the scope key
        return jsonResponse(200, body);
      }
      if (wantsOB && isA) {
        return jsonResponse(200, resourceBody({ canary: CANARY_B, scope: "public", viewer: "viewer-A" }));
      }
      return null;
    },
  });
  const result = await run(domain, { fetch_fn });
  assert.equal(result.confirmed, false, JSON.stringify(result));
  assert.equal(result.reason, "own_scope_explicitly_shared");
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("AC-6 negative: owner readback B-scope collides with A's own scope (same tenant) even though P1 omits the key → blocks", () => withTempHome(async () => {
  // #14 same-tenant guard must fold the owner readback's B-scope when P1 omits owning-scope keys.
  // P1/P2 omit scope; the readback puts B in tenant "acme" and A's own object (P3) is also "acme",
  // so A and B are provably the SAME tenant → hard block (not a soft mint).
  const domain = "idor-neg-readback-sametenant.example.test";
  setupSession(domain);
  const fetch_fn = soundFetchFn(domain, {
    handler: ({ isA, isB, wantsOB, wantsOA }) => {
      if (wantsOB && (isA || isB)) {
        const body = resourceBody({ canary: CANARY_B, scope: "tenant-B", viewer: isB ? "viewer-B" : "viewer-A" });
        delete body.owner_scope; // P1/P2 omit the owning-scope key
        return jsonResponse(200, body);
      }
      if (wantsOA && isA) {
        return jsonResponse(200, resourceBody({ canary: CANARY_A, scope: "acme", viewer: "viewer-A", objId: OBJ_A }));
      }
      return null;
    },
  });
  const provision = {
    ...soundProvision(),
    owner_readback_b: { id: OBJ_B, owner_scope: "acme", details: { secret: { token: CANARY_B } } },
  };
  const result = await run(domain, { fetch_fn, provision });
  assert.equal(result.confirmed, false, JSON.stringify(result));
  assert.equal(result.reason, "identities_collided_same_tenant");
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("AC-6 negative: A and B share an INTEGER org_id (numeric tenant) → identities_collided_same_tenant (blocks)", () => withTempHome(async () => {
  // Real REST APIs commonly use INTEGER tenant IDs. A and B both carry org_id:7 (a NUMBER), so they
  // are provably the same tenant. Without numeric coercion these are typeof "number", escape the
  // string-only scope reads, and the same-tenant BOLA would be mislabeled a cross-tenant IDOR; the
  // scopeValueString coercion must surface them so #14 hard-blocks.
  const domain = "idor-neg-integer-sametenant.example.test";
  setupSession(domain);
  const fetch_fn = soundFetchFn(domain, {
    handler: ({ isA, isB, wantsOB, wantsOA }) => {
      if (wantsOB && (isA || isB)) {
        return jsonResponse(200, { id: OBJ_B, org_id: 7, viewer_id: isB ? "viewer-B" : "viewer-A", details: { secret: { token: CANARY_B } } });
      }
      if (wantsOA && isA) {
        return jsonResponse(200, { id: OBJ_A, org_id: 7, viewer_id: "viewer-A", details: { secret: { token: CANARY_A } } });
      }
      return null;
    },
  });
  const result = await run(domain, { fetch_fn });
  assert.equal(result.confirmed, false, JSON.stringify(result));
  assert.equal(result.reason, "identities_collided_same_tenant");
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("AC-6 negative: A and B share an UNSAFE-magnitude numeric org_id (>2^53) → own_scope_unusable_numeric (no precision false-mint)", () => withTempHome(async () => {
  // A 64-bit tenant id above 2^53 already lost precision in JSON.parse, so scopeValueString drops it
  // to null. Were that read as "scope absent", two SAME-tenant objects (both org_id 9007199254740993)
  // would soft-mint a LOW cross-tenant row. A present-but-unsafe discriminator cannot prove DISTINCT
  // tenants → hard block instead of downgrading to "missing" (Codex PR#136 P1).
  const domain = "idor-neg-unsafe-numeric.example.test";
  setupSession(domain);
  const UNSAFE = 9007199254740993; // 2^53 + 1 — JSON.parse already rounded this to ...992
  const fetch_fn = soundFetchFn(domain, {
    handler: ({ isA, isB, wantsOB, wantsOA }) => {
      if (wantsOB && (isA || isB)) {
        return jsonResponse(200, { id: OBJ_B, org_id: UNSAFE, viewer_id: isB ? "viewer-B" : "viewer-A", details: { secret: { token: CANARY_B } } });
      }
      if (wantsOA && isA) {
        return jsonResponse(200, { id: OBJ_A, org_id: UNSAFE, viewer_id: "viewer-A", details: { secret: { token: CANARY_A } } });
      }
      return null;
    },
  });
  const result = await run(domain, { fetch_fn });
  assert.equal(result.confirmed, false, JSON.stringify(result));
  assert.equal(result.reason, "own_scope_unusable_numeric");
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("AC-6 negative: P1/readback omit scope but the A→B PROOF body (P2/P2′) reveals O_B in A's tenant → identities_collided_same_tenant (proof-read fold, Codex PR#136 P1)", () => withTempHome(async () => {
  // P1 (B's self-read) and the owner readback omit the owning-scope key, so the OLD same-tenant guard
  // (P1 + readback only) saw no collision and would soft-mint. But the signed A→B proof bodies (P2/P2′)
  // themselves carry org_id "acme" == A's P3 scope — positive evidence O_B sits in A's tenant. Folding
  // the proof bodies into the same-tenant guard hard-refutes it (they are already trusted for the
  // explicit-shared hard block, so they must also feed the positive same-tenant refutation).
  const domain = "idor-neg-proofread-sametenant.example.test";
  setupSession(domain);
  const fetch_fn = soundFetchFn(domain, {
    handler: ({ isA, isB, wantsOB, wantsOA }) => {
      if (wantsOB && isB) {
        // P1/P0a/P0b — B's self-read OMITS the owning-scope key (byte-stable across B's reads).
        return jsonResponse(200, { id: OBJ_B, viewer_id: "viewer-B", details: { secret: { token: CANARY_B } } });
      }
      if (wantsOB && isA) {
        // P2/P2′ — the A→B proof read REVEALS O_B sits in A's tenant ("acme").
        return jsonResponse(200, { id: OBJ_B, org_id: "acme", viewer_id: "viewer-A", details: { secret: { token: CANARY_B } } });
      }
      if (wantsOA && isA) {
        // P3 — A's own object is in tenant "acme".
        return jsonResponse(200, { id: OBJ_A, org_id: "acme", viewer_id: "viewer-A", details: { secret: { token: CANARY_A } } });
      }
      return null;
    },
  });
  // Readback also omits the owning-scope key, so the same-tenant signal comes ONLY from the proof fold.
  const provision = { ...soundProvision(), owner_readback_b: { id: OBJ_B, details: { secret: { token: CANARY_B } } } };
  const result = await run(domain, { fetch_fn, provision });
  assert.equal(result.confirmed, false, JSON.stringify(result));
  assert.equal(result.reason, "identities_collided_same_tenant");
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("AC-6 negative: NESTED-envelope same tenant (org_id under {data:{...}}) → identities_collided_same_tenant (nested scope scan, Codex PR#136)", () => withTempHome(async () => {
  // The resource sits one level under a {data:{...}} envelope (common in real REST APIs), so the
  // owning-scope is NOT a top-level key. Before nested scanning, owningScopeValues saw nothing -> the
  // same-tenant guard missed the collision and the SAME-tenant pair soft-minted at LOW. Scanning one
  // level into the envelope surfaces the nested org_id so #14 hard-blocks. Canary stays at the
  // top-level details.secret.token leaf (only the SCOPE is nested).
  const domain = "idor-neg-nested-sametenant.example.test";
  setupSession(domain);
  const fetch_fn = soundFetchFn(domain, {
    handler: ({ isA, isB, wantsOB, wantsOA }) => {
      if (wantsOB && (isA || isB)) {
        return jsonResponse(200, { id: OBJ_B, data: { org_id: 7 }, viewer_id: isB ? "viewer-B" : "viewer-A", details: { secret: { token: CANARY_B } } });
      }
      if (wantsOA && isA) {
        return jsonResponse(200, { id: OBJ_A, data: { org_id: 7 }, viewer_id: "viewer-A", details: { secret: { token: CANARY_A } } });
      }
      return null;
    },
  });
  // Readback omits scope, so the nested top-level proof bodies are the only same-tenant signal.
  const provision = { ...soundProvision(), owner_readback_b: { id: OBJ_B, details: { secret: { token: CANARY_B } } } };
  const result = await run(domain, { fetch_fn, provision });
  assert.equal(result.confirmed, false, JSON.stringify(result));
  assert.equal(result.reason, "identities_collided_same_tenant");
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("AC-6 negative: JSON:API same tenant (org_id under {data:{attributes:{...}}}) → identities_collided_same_tenant (two-level scope scan, Codex PR#136)", () => withTempHome(async () => {
  // JSON:API nests the resource TWO levels under {data:{attributes:{...}}}, so the owning-scope is not
  // at the top level NOR one level down. The one-level scan missed it and the SAME-tenant pair could
  // soft-mint at LOW; the bounded two-level envelope scan reaches data.attributes so #14 hard-blocks.
  const domain = "idor-neg-jsonapi-sametenant.example.test";
  setupSession(domain);
  const fetch_fn = soundFetchFn(domain, {
    handler: ({ isA, isB, wantsOB, wantsOA }) => {
      if (wantsOB && (isA || isB)) {
        return jsonResponse(200, { data: { type: "account", id: OBJ_B, attributes: { org_id: 7 } }, viewer_id: isB ? "viewer-B" : "viewer-A", details: { secret: { token: CANARY_B } } });
      }
      if (wantsOA && isA) {
        return jsonResponse(200, { data: { type: "account", id: OBJ_A, attributes: { org_id: 7 } }, viewer_id: "viewer-A", details: { secret: { token: CANARY_A } } });
      }
      return null;
    },
  });
  const provision = { ...soundProvision(), owner_readback_b: { id: OBJ_B, details: { secret: { token: CANARY_B } } } };
  const result = await run(domain, { fetch_fn, provision });
  assert.equal(result.confirmed, false, JSON.stringify(result));
  assert.equal(result.reason, "identities_collided_same_tenant");
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
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

test("AC-6 positive: a public/s-maxage Cache-Control directive with NO cache in path confirms (directive is an origin hint, not cache evidence)", () => withTempHome(async () => {
  // A bare public / s-maxage directive is the origin saying "this MAY be cached"; with
  // no Age/X-Cache/cache-status header, no cache acted on this response, so it is an
  // origin read — flagging it would false-negative legit IDORs on cacheable resources.
  const domain = "idor-pos-smaxage-directive.example.test";
  setupSession(domain);
  const fetch_fn = soundFetchFn(domain, { p2Headers: { "Cache-Control": 'public, s-maxage="60"' } });
  const result = await run(domain, { fetch_fn });
  assert.equal(result.confirmed, true, JSON.stringify(result));
  assert.equal(result.row_written, true);
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

// ───────────────────────── round-7 review hardening ──────────────────────────

test("AC-6 positive: X-Served-By (Fastly/Heroku node id on every response) does not over-block", () => withTempHome(async () => {
  const domain = "idor-pos-xservedby.example.test";
  setupSession(domain);
  const fetch_fn = soundFetchFn(domain, { p2Headers: { "X-Served-By": "cache-lhr1234-LHR" } });
  const result = await run(domain, { fetch_fn });
  assert.equal(result.confirmed, true, JSON.stringify(result));
  assert.equal(result.row_written, true);
}));

test("AC-6 positive: CDN-Cache-Control (origin-authored directive) does not over-block", () => withTempHome(async () => {
  const domain = "idor-pos-cdncc.example.test";
  setupSession(domain);
  const fetch_fn = soundFetchFn(domain, { p2Headers: { "CDN-Cache-Control": "max-age=60" } });
  const result = await run(domain, { fetch_fn });
  assert.equal(result.confirmed, true, JSON.stringify(result));
  assert.equal(result.row_written, true);
}));

test("AC-6 negative: P5 deny body with the canary \\u-escaped in a SHADOWED duplicate key → p5_canary_in_deny_body", () => withTempHome(async () => {
  const domain = "idor-neg-p5-escaped-shadow.example.test";
  setupSession(domain);
  const escaped = "\\u0062".repeat(64); // decodes to "b" * 64 === CANARY_B
  const fetch_fn = soundFetchFn(domain, {
    p5: () => jsonResponse(403, `{"detail":"forbidden","leaked":"${escaped}","leaked":"clean"}`),
  });
  const result = await run(domain, { fetch_fn });
  assert.equal(result.confirmed, false);
  assert.equal(result.reason, "p5_canary_in_deny_body");
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("AC-5: foreign PII \\u-escaped in a SHADOWED duplicate key (evades raw + parse) → blocked", () => withTempHome(async () => {
  const domain = "idor-neg-escaped-shadow-pii.example.test";
  setupSession(domain);
  const escapedForeign = [...("victim@gmail.com")].map((c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`).join("");
  const fetch_fn = soundFetchFn(domain, {
    handler: ({ isA, wantsOB }) => {
      if (wantsOB && isA) {
        return jsonResponse(200, `{"id":"${OBJ_B}","owner_scope":"tenant-B","viewer_id":"viewer-A","contact":"${escapedForeign}","contact":"eval_a@example.test","details":{"secret":{"token":"${CANARY_B}"}}}`);
      }
      return null;
    },
  });
  const result = await run(domain, { fetch_fn });
  assert.equal(result.confirmed, false);
  assert.equal(result.reason, "non_synthetic_pii_in_response");
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("AC-2 safety: a // network-path-reference path_template is rejected (resolves to a different host)", () => withTempHome(async () => {
  const domain = "idor-neg-netpath.example.test";
  JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}/` }));
  seedRoutedSurface(domain, SURFACE_ID, endpointFor(domain));
  seedSyntheticProfiles(domain);
  ensureHandoffSigningKey(domain);
  const args = { ...baseArgs(domain), path_template: "//evil.test/{id}" };
  await assert.rejects(
    () => idorConfirm(args, { fetch_fn: soundFetchFn(domain), provision: soundProvision() }),
    /network-path reference/,
  );
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("AC-6 negative: P3 (A's own object) leaks B's canary at a NON-discovered field → canary_viewer_echoed_p3", () => withTempHome(async () => {
  const domain = "idor-neg-p3-canary-elsewhere.example.test";
  setupSession(domain);
  const fetch_fn = soundFetchFn(domain, {
    handler: ({ isA, wantsOA }) => {
      if (wantsOA && isA) {
        // O_A is resource-shaped and carries A's OWN canary at the leaf (prove-A
        // passes), but ALSO leaks B's canary in a stray field (cross-contamination) —
        // the field-path-only check missed this; the full-body scan catches it.
        return jsonResponse(200, {
          id: OBJ_A, owner_scope: "tenant-A", viewer_id: "viewer-A", stray_ref: CANARY_B,
          details: { secret: { token: CANARY_A } },
        });
      }
      return null;
    },
  });
  const result = await run(domain, { fetch_fn });
  assert.equal(result.confirmed, false);
  assert.equal(result.reason, "canary_viewer_echoed_p3");
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

// ─────────────────── round-7 (adversarial-audit wf_b61d6918-693) hardening ───────────────────

test("AC-6 negative: nginx X-Cache-Status: HIT (no Age, private body) is a shared-cache cross-fill → cache_shared_response", () => withTempHome(async () => {
  const domain = "idor-neg-nginx-hit.example.test";
  setupSession(domain);
  const fetch_fn = soundFetchFn(domain, { p2Headers: { "X-Cache-Status": "HIT", "Cache-Control": "private, no-store" } });
  const result = await run(domain, { fetch_fn });
  assert.equal(result.confirmed, false);
  assert.equal(result.reason, "cache_shared_response");
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("AC-6 negative: Google x-goog-cache-status: hit (no Age) → cache_shared_response", () => withTempHome(async () => {
  const domain = "idor-neg-goog-hit.example.test";
  setupSession(domain);
  const fetch_fn = soundFetchFn(domain, { p2Headers: { "x-goog-cache-status": "hit" } });
  const result = await run(domain, { fetch_fn });
  assert.equal(result.confirmed, false);
  assert.equal(result.reason, "cache_shared_response");
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("AC-6 positive: nginx X-Cache-Status: MISS still confirms (proven origin)", () => withTempHome(async () => {
  const domain = "idor-pos-nginx-miss.example.test";
  setupSession(domain);
  const fetch_fn = soundFetchFn(domain, { p2Headers: { "X-Cache-Status": "MISS" } });
  const result = await run(domain, { fetch_fn });
  assert.equal(result.confirmed, true, JSON.stringify(result));
  assert.equal(result.row_written, true);
}));

test("AC-5: a spaced/grouped credit-card number in the P2 proof body → non_synthetic_pii_in_response", () => withTempHome(async () => {
  const domain = "idor-neg-formatted-pan.example.test";
  setupSession(domain);
  const fetch_fn = soundFetchFn(domain, {
    handler: ({ isA, wantsOB }) => {
      if (wantsOB && isA) {
        return jsonResponse(200, {
          id: OBJ_B, owner_scope: "tenant-B", viewer_id: "viewer-A", billing: "4111 1111 1111 1111",
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

test("AC-5: a trailing-dot FQDN email (victim@corp.com.) in the P2 proof body → non_synthetic_pii_in_response", () => withTempHome(async () => {
  const domain = "idor-neg-fqdn-email.example.test";
  setupSession(domain);
  const fetch_fn = soundFetchFn(domain, {
    handler: ({ isA, wantsOB }) => {
      if (wantsOB && isA) {
        return jsonResponse(200, {
          id: OBJ_B, owner_scope: "tenant-B", viewer_id: "viewer-A", contact: "victim@corp.com.",
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

// ───────────────────────── round-8 review hardening ──────────────────────────

test("AC-2: a single endpoint on an in-scope SUBDOMAIN confirms (session base not counted as a 2nd host)", () => withTempHome(async () => {
  const domain = "idor-subdomain-host.example.test";
  JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}/` }));
  seedRoutedSurface(domain, SURFACE_ID, `https://api.${domain}/api/accounts/${OBJ_B}`, { hosts: [`api.${domain}`] });
  seedSyntheticProfiles(domain);
  ensureHandoffSigningKey(domain);
  const result = await run(domain);
  assert.equal(result.confirmed, true, JSON.stringify(result));
  assert.equal(result.row_written, true);
}));

test("AC-6 negative: X-Cache-Hits: 1 (Varnish/Fastly numeric hit, no Age) → cache_shared_response", () => withTempHome(async () => {
  const domain = "idor-neg-xcachehits.example.test";
  setupSession(domain);
  const fetch_fn = soundFetchFn(domain, { p2Headers: { "X-Cache-Hits": "1" } });
  const result = await run(domain, { fetch_fn });
  assert.equal(result.confirmed, false);
  assert.equal(result.reason, "cache_shared_response");
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("AC-6 negative: X-Cache-Hits: 0 alone is NOT a proven miss → cannot_prove_origin_read_through_cache", () => withTempHome(async () => {
  // A numeric 0-hit count means a cache is in path but is weaker/cross-CDN-ambiguous as
  // origin proof (it could mask a cross-principal hit), so without an EXPLICIT miss token
  // the producer fails closed rather than trusting it as an origin read.
  const domain = "idor-neg-xcachehits0.example.test";
  setupSession(domain);
  const fetch_fn = soundFetchFn(domain, { p2Headers: { "X-Cache-Hits": "0" } });
  const result = await run(domain, { fetch_fn });
  assert.equal(result.confirmed, false);
  assert.equal(result.reason, "cannot_prove_origin_read_through_cache");
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("AC-5: a multi-character-separated credit-card number → non_synthetic_pii_in_response", () => withTempHome(async () => {
  const domain = "idor-neg-multisep-pan.example.test";
  setupSession(domain);
  const fetch_fn = soundFetchFn(domain, {
    handler: ({ isA, wantsOB }) => {
      if (wantsOB && isA) {
        return jsonResponse(200, { id: OBJ_B, owner_scope: "tenant-B", viewer_id: "viewer-A", billing: "4111  1111 - 1111.1111", details: { secret: { token: CANARY_B } } });
      }
      return null;
    },
  });
  const result = await run(domain, { fetch_fn });
  assert.equal(result.confirmed, false);
  assert.equal(result.reason, "non_synthetic_pii_in_response");
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("AC-5: a fine-grained GitHub PAT (github_pat_) in the proof body → non_synthetic_secret_in_response", () => withTempHome(async () => {
  const domain = "idor-neg-ghpat.example.test";
  setupSession(domain);
  const fetch_fn = soundFetchFn(domain, {
    handler: ({ isA, wantsOB }) => {
      if (wantsOB && isA) {
        return jsonResponse(200, { id: OBJ_B, owner_scope: "tenant-B", viewer_id: "viewer-A", tok: "github_pat_11ABCDEFG0abcdefghijkl_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789", details: { secret: { token: CANARY_B } } });
      }
      return null;
    },
  });
  const result = await run(domain, { fetch_fn });
  assert.equal(result.confirmed, false);
  assert.equal(result.reason, "non_synthetic_secret_in_response");
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

// ───────────────────────── round-9 review hardening ──────────────────────────

test("AC-6 negative: public, s-maxage=60 with X-Cache-Hits: 0 → cannot_prove_origin (X-Cache-Hits:0 is a cache-in-path signal, not a proven miss)", () => withTempHome(async () => {
  const domain = "idor-neg-smaxage-xch0.example.test";
  setupSession(domain);
  const fetch_fn = soundFetchFn(domain, { p2Headers: { "Cache-Control": "public, s-maxage=60", "X-Cache-Hits": "0" } });
  const result = await run(domain, { fetch_fn });
  assert.equal(result.confirmed, false);
  assert.equal(result.reason, "cannot_prove_origin_read_through_cache");
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("AC-6 negative: a HIT layer is not overridden by another layer's MISS → cache_shared_response", () => withTempHome(async () => {
  const domain = "idor-neg-hit-over-miss.example.test";
  setupSession(domain);
  const fetch_fn = soundFetchFn(domain, { p2Headers: { "X-Cache": "HIT", "CF-Cache-Status": "MISS" } });
  const result = await run(domain, { fetch_fn });
  assert.equal(result.confirmed, false);
  assert.equal(result.reason, "cache_shared_response");
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("AC-5 safety: a self-provisioned id that is a PERCENT-ENCODED canary → canary_reflected_in_object_id", () => withTempHome(async () => {
  const domain = "idor-neg-encoded-canary-id.example.test";
  setupSession(domain);
  const provision = { ...soundProvision(), object_b: "%62".repeat(64) }; // decodes to "b"*64 === CANARY_B
  const result = await run(domain, { provision });
  assert.equal(result.confirmed, false);
  assert.equal(result.reason, "canary_reflected_in_object_id");
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("AC-6 negative: a truncated P3 (A's own object) → p3_body_truncated", () => withTempHome(async () => {
  const domain = "idor-neg-p3-trunc.example.test";
  setupSession(domain);
  const fetch_fn = soundFetchFn(domain, {
    handler: ({ isA, wantsOA }) => {
      if (wantsOA && isA) {
        const r = jsonResponse(200, resourceBody({ canary: CANARY_A, scope: "tenant-A", viewer: "viewer-A", objId: OBJ_A }));
        r.bodyTruncated = true;
        return r;
      }
      return null;
    },
  });
  const result = await run(domain, { fetch_fn });
  assert.equal(result.confirmed, false);
  assert.equal(result.reason, "p3_body_truncated");
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("AC-5: an injected OpenAI-style key (sk-proj-) in the proof body → non_synthetic_secret_in_response", () => withTempHome(async () => {
  const domain = "idor-neg-openai-key.example.test";
  setupSession(domain);
  const fetch_fn = soundFetchFn(domain, {
    handler: ({ isA, wantsOB }) => {
      if (wantsOB && isA) {
        return jsonResponse(200, { id: OBJ_B, owner_scope: "tenant-B", viewer_id: "viewer-A", apikey: "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCD", details: { secret: { token: CANARY_B } } });
      }
      return null;
    },
  });
  const result = await run(domain, { fetch_fn });
  assert.equal(result.confirmed, false);
  assert.equal(result.reason, "non_synthetic_secret_in_response");
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

// ───────────────────────── round-11 review hardening ──────────────────────────

test("AC-6 negative: P5 deny body with a PERCENT-encoded canary (decodes to it) → p5_canary_in_deny_body", () => withTempHome(async () => {
  const domain = "idor-neg-p5-pctenc.example.test";
  setupSession(domain);
  const pctCanary = "%62".repeat(64); // decodes to "b" * 64 === CANARY_B
  const fetch_fn = soundFetchFn(domain, {
    p5: () => jsonResponse(403, `{"error":"forbidden","leaked":"${pctCanary}"}`),
  });
  const result = await run(domain, { fetch_fn });
  assert.equal(result.confirmed, false);
  assert.equal(result.reason, "p5_canary_in_deny_body");
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("AC-5: foreign PII as a PERCENT-encoded value in the proof body → non_synthetic_pii_in_response", () => withTempHome(async () => {
  const domain = "idor-neg-pctenc-pii.example.test";
  setupSession(domain);
  const pctEmail = [...("victim@gmail.com")].map((c) => `%${c.charCodeAt(0).toString(16).padStart(2, "0")}`).join("");
  const fetch_fn = soundFetchFn(domain, {
    handler: ({ isA, wantsOB }) => {
      if (wantsOB && isA) {
        return jsonResponse(200, `{"id":"${OBJ_B}","owner_scope":"tenant-B","viewer_id":"viewer-A","contact":"${pctEmail}","details":{"secret":{"token":"${CANARY_B}"}}}`);
      }
      return null;
    },
  });
  const result = await run(domain, { fetch_fn });
  assert.equal(result.confirmed, false);
  assert.equal(result.reason, "non_synthetic_pii_in_response");
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("AC-5 safety: a control-object id (object_a) that is a percent-encoded canary → canary_reflected_in_object_id", () => withTempHome(async () => {
  const domain = "idor-neg-obja-encoded-canary.example.test";
  setupSession(domain);
  const provision = { ...soundProvision(), object_a: "%61".repeat(64) }; // decodes to "a" * 64 === CANARY_A
  const result = await run(domain, { provision });
  assert.equal(result.confirmed, false);
  assert.equal(result.reason, "canary_reflected_in_object_id");
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("AC-6 soft: account_id is NOT an owning-scope/tenant key → own_scope_missing + identities_collided_not_provable, mints at LOW", () => withTempHome(async () => {
  // account_id is NOT an owning-scope/tenant key, so an O_B body carrying ONLY account_id
  // exposes no private owner scope (#13 MISSING) AND no tenant discriminator (#14). Both are
  // ABSENCE-of-evidence, so they demote to confidence signals and the canary-proven read
  // still mints — but at LOW severity (the unproven attribution is claim-visible), not medium.
  const domain = "idor-neg-accountid-not-tenant.example.test";
  setupSession(domain);
  const fetch_fn = soundFetchFn(domain, {
    handler: ({ isA, isB, wantsOB }) => {
      if (wantsOB && (isA || isB)) {
        return jsonResponse(200, { id: OBJ_B, account_id: "acct-b-1", viewer_id: isB ? "viewer-B" : "viewer-A", details: { secret: { token: CANARY_B } } });
      }
      return null;
    },
  });
  const result = await run(domain, { fetch_fn });
  assert.equal(result.confirmed, true, JSON.stringify(result));
  assert.equal(result.row_written, true);
  assert.deepEqual(result.confidence_signals.map((s) => s.gate).sort(), ["identities_collided_not_provable", "own_scope_missing"]);
  assert.equal(result.demonstrated_severity, "low");
  assert.equal(result.masked_oracle.relation.own_scope_private, false);
  assert.equal(result.masked_oracle.relation.tenants_distinct, false);
  assert.equal(readOffensiveRunRecords(domain)[0].demonstrated_severity, "low");
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), true);
}));

test("soft-gated fire: confidence_signals are hash-bound into the durable stderr capture and survive re-projection", () => withTempHome(async () => {
  // A canary-proven cross-tenant read where A and B cannot be shown distinct at the same
  // tenant key (#14 trips as a signal). The fire still mints; the #14 signal must be
  // hash-bound into the signed row's stderr capture so the freeze re-hash + grader see it.
  const domain = "idor-soft-gated-roundtrip.example.test";
  setupSession(domain);
  const fetch_fn = soundFetchFn(domain, {
    handler: ({ isA, wantsOA }) => {
      // A's own object echoes NO tenant key, so A and B cannot be shown DISTINCT at the same
      // key (#14 UNPROVABLE → a non-blocking signal; the canary-proven read still mints).
      if (wantsOA && isA) {
        return jsonResponse(200, { id: OBJ_A, details: { secret: { token: CANARY_A } }, server_ts: "x" });
      }
      return null;
    },
  });
  const result = await run(domain, { fetch_fn });
  assert.equal(result.confirmed, true, JSON.stringify(result));
  assert.equal(result.row_written, true);
  assert.equal(result.demonstrated_severity, "low", "a soft-gated fire is stamped LOW, not medium");
  assert.deepEqual(result.confidence_signals.map((s) => s.gate).sort(), ["identities_collided_not_provable"]);
  // the masked return echoes the same signals the diagnostic bundle captured
  assert.deepEqual(result.masked_oracle.confidence_signals, result.confidence_signals);

  const rows = readOffensiveRunRecords(domain);
  assert.equal(rows.length, 1);
  const row = rows[0];
  assert.equal(row.demonstrated_severity, "low", "the signed row carries the LOW soft-gate severity");
  assert.ok(row.row_mac && row.row_mac.digest, "row must be MAC-signed");
  assert.equal(row.stderr_hash, result.stderr_hash);

  // the signal text is physically in the frozen stderr capture, and that capture re-hashes
  // to the signed row's stderr_hash → the confidence_signals are hash-bound, not free text.
  const stderrFile = path.join(offensiveRunsDir(domain), `${row.run_id}.stderr`);
  const stderrBytes = fs.readFileSync(stderrFile);
  assert.match(stderrBytes.toString("utf8"), /identities_collided_not_provable/);
  const recomputed = crypto.createHash("sha256").update(stderrBytes).digest("hex");
  assert.equal(recomputed, row.stderr_hash, "stderr capture must re-hash to the signed stderr_hash");

  // the stdout identity hash is stable across 3 re-projections (the freeze re-hash path).
  for (let i = 0; i < 3; i += 1) {
    const observed = projectExploitRunObservedRef(domain, { kind: "exploit_run", run_id: row.run_id });
    assert.equal(observed.stdout_hash, row.stdout_hash);
  }
}));

test("AC-6 negative: same tenant under DIFFERENT alias keys (org_id vs tenant_id, both \"acme\") → identities_collided_same_tenant (blocks)", () => withTempHome(async () => {
  // Codex PR#136: B's object carries org_id and A's own object carries tenant_id, but BOTH
  // resolve to the same tenant value "acme". Same value across aliases is positive evidence of
  // one tenant — it must HARD-block, not soft-gate (which would mislabel a same-tenant BOLA as
  // this producer's cross-tenant IDOR).
  const domain = "idor-neg-cross-alias-same-tenant.example.test";
  setupSession(domain);
  const fetch_fn = soundFetchFn(domain, {
    handler: ({ isA, isB, wantsOB, wantsOA }) => {
      if (wantsOB && (isA || isB)) {
        return jsonResponse(200, { id: OBJ_B, org_id: "acme", viewer_id: isB ? "viewer-B" : "viewer-A", details: { secret: { token: CANARY_B } } });
      }
      if (wantsOA && isA) {
        return jsonResponse(200, { id: OBJ_A, tenant_id: "acme", details: { secret: { token: CANARY_A } }, server_ts: "x" });
      }
      return null;
    },
  });
  const result = await run(domain, { fetch_fn });
  assert.equal(result.confirmed, false);
  assert.equal(result.reason, "identities_collided_same_tenant");
  assert.equal(result.row_written, false);
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("AC-6 negative: same tenant via a SECONDARY alias key (A owner_scope:x + tenant_id:acme, B org_id:acme) → identities_collided_same_tenant (blocks)", () => withTempHome(async () => {
  // Brutalist PR#136: A's PRIMARY discriminator (owner_scope:"x") differs from B's
  // (org_id:"acme"), but A ALSO carries tenant_id:"acme" — a value shared under a SECONDARY
  // key. A same value ANYWHERE across the owning-scope keys = one tenant = HARD block, not a
  // soft-gated mint. (A first-discriminator-only comparison would have missed this.)
  const domain = "idor-neg-secondary-alias-same-tenant.example.test";
  setupSession(domain);
  const fetch_fn = soundFetchFn(domain, {
    handler: ({ isA, isB, wantsOB, wantsOA }) => {
      if (wantsOB && (isA || isB)) {
        return jsonResponse(200, { id: OBJ_B, org_id: "acme", viewer_id: isB ? "viewer-B" : "viewer-A", details: { secret: { token: CANARY_B } } });
      }
      if (wantsOA && isA) {
        return jsonResponse(200, { id: OBJ_A, owner_scope: "x", tenant_id: "acme", details: { secret: { token: CANARY_A } }, server_ts: "x" });
      }
      return null;
    },
  });
  const result = await run(domain, { fetch_fn });
  assert.equal(result.confirmed, false);
  assert.equal(result.reason, "identities_collided_same_tenant");
  assert.equal(result.row_written, false);
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

// ───────────────────────── round-12 review hardening ──────────────────────────

test("AC-6 negative: a percent-encoded canary survives a stray literal % (100%) in the same deny body → p5_canary_in_deny_body", () => withTempHome(async () => {
  // A whole-string decodeURIComponent would THROW on the stray `%` in "100%" and leave
  // the %62%62 canary undecoded; the per-triplet decode handles each %XX independently.
  const domain = "idor-neg-p5-pct-stray.example.test";
  setupSession(domain);
  const pctCanary = "%62".repeat(64);
  const fetch_fn = soundFetchFn(domain, {
    p5: () => jsonResponse(403, `{"progress":"100%","error":"forbidden","leaked":"${pctCanary}"}`),
  });
  const result = await run(domain, { fetch_fn });
  assert.equal(result.confirmed, false);
  assert.equal(result.reason, "p5_canary_in_deny_body");
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("AC-5 safety: a method-override header in an auth profile is NOT sent on the read probe", () => withTempHome(async () => {
  const domain = "idor-neg-method-override.example.test";
  JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}/` }));
  seedRoutedSurface(domain, SURFACE_ID, endpointFor(domain));
  const flags = { synthetic: true, email_origin: "temp_email", provisioned_via: "bob_auto_signup" };
  const mk = (tag) => ({ Authorization: `Bearer eyJ${tag}token`, "X-HTTP-Method-Override": "DELETE", email: `eval_${tag}@example.test`, ...flags });
  writeAuthFile(resolveAuthJsonPath(domain), `${JSON.stringify({ version: 2, profiles: { identity_a: mk("a"), identity_b: mk("b"), identity_c: mk("c") } }, null, 2)}\n`);
  ensureHandoffSigningKey(domain);
  const seen = new Set();
  const base = soundFetchFn(domain);
  const fetch_fn = async (req) => { for (const k of Object.keys(req.headers || {})) seen.add(k.toLowerCase()); return base(req); };
  const result = await run(domain, { fetch_fn });
  assert.equal(result.confirmed, true, JSON.stringify(result));
  assert.ok(!seen.has("x-http-method-override"), `method override must be stripped; saw [${[...seen].join(", ")}]`);
  assert.ok(seen.has("authorization"), "Authorization must still be sent");
}));

test("AC-5 safety: a self-provisioned id that is an email (email-as-id) → object_id_contains_sensitive_value", () => withTempHome(async () => {
  const domain = "idor-neg-email-id.example.test";
  setupSession(domain);
  const provision = { ...soundProvision(), object_b: "victim@gmail.com" };
  const result = await run(domain, { provision });
  assert.equal(result.confirmed, false);
  assert.equal(result.reason, "object_id_contains_sensitive_value");
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("AC-5: a credit-card number with escaped whitespace (4111\\n1111...) → non_synthetic_pii_in_response", () => withTempHome(async () => {
  const domain = "idor-neg-escaped-ws-pan.example.test";
  setupSession(domain);
  const fetch_fn = soundFetchFn(domain, {
    handler: ({ isA, wantsOB }) => {
      if (wantsOB && isA) {
        return jsonResponse(200, `{"id":"${OBJ_B}","owner_scope":"tenant-B","viewer_id":"viewer-A","billing":"4111\\n1111\\t1111 1111","details":{"secret":{"token":"${CANARY_B}"}}}`);
      }
      return null;
    },
  });
  const result = await run(domain, { fetch_fn });
  assert.equal(result.confirmed, false);
  assert.equal(result.reason, "non_synthetic_pii_in_response");
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

// ───────────────────────── round-13 review hardening ──────────────────────────

test("AC-5 safety: a percent-encoded email-as-id is decoded before the screen → object_id_contains_sensitive_value", () => withTempHome(async () => {
  const domain = "idor-neg-encoded-email-id.example.test";
  setupSession(domain);
  const pctEmail = [...("victim@gmail.com")].map((c) => `%${c.charCodeAt(0).toString(16).padStart(2, "0")}`).join("");
  const provision = { ...soundProvision(), object_b: pctEmail };
  const result = await run(domain, { provision });
  assert.equal(result.confirmed, false);
  assert.equal(result.reason, "object_id_contains_sensitive_value");
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("AC-6 negative: P5 deny body with a LAYERED-encoded canary (percent-of-\\u) → p5_canary_in_deny_body", () => withTempHome(async () => {
  const domain = "idor-neg-p5-layered.example.test";
  setupSession(domain);
  const layered = "%5Cu0062".repeat(64); // percent-decode → b → "b"; 64× === CANARY_B
  const fetch_fn = soundFetchFn(domain, {
    p5: () => jsonResponse(403, `{"error":"forbidden","leaked":"${layered}"}`),
  });
  const result = await run(domain, { fetch_fn });
  assert.equal(result.confirmed, false);
  assert.equal(result.reason, "p5_canary_in_deny_body");
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("AC-5 safety: an email in a FIXED path segment of the proof target → proof_target_contains_sensitive_value", () => withTempHome(async () => {
  const domain = "idor-neg-target-email.example.test";
  JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}/` }));
  seedRoutedSurface(domain, SURFACE_ID, `https://${domain}/api/users/victim@x.com/${OBJ_B}`);
  seedSyntheticProfiles(domain);
  ensureHandoffSigningKey(domain);
  const args = { ...baseArgs(domain), path_template: "/api/users/victim@x.com/{id}" };
  const result = await idorConfirm(args, { fetch_fn: soundFetchFn(domain), provision: soundProvision() });
  assert.equal(result.confirmed, false);
  assert.equal(result.reason, "proof_target_contains_sensitive_value");
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("AC-5 safety: a Host header in an auth profile is NOT sent on the probe (vhost/smuggling)", () => withTempHome(async () => {
  const domain = "idor-neg-host-header.example.test";
  JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}/` }));
  seedRoutedSurface(domain, SURFACE_ID, endpointFor(domain));
  const flags = { synthetic: true, email_origin: "temp_email", provisioned_via: "bob_auto_signup" };
  const mk = (tag) => ({ Authorization: `Bearer eyJ${tag}token`, Host: "evil.example.test", email: `eval_${tag}@example.test`, ...flags });
  writeAuthFile(resolveAuthJsonPath(domain), `${JSON.stringify({ version: 2, profiles: { identity_a: mk("a"), identity_b: mk("b"), identity_c: mk("c") } }, null, 2)}\n`);
  ensureHandoffSigningKey(domain);
  const seen = new Set();
  const base = soundFetchFn(domain);
  const fetch_fn = async (req) => { for (const k of Object.keys(req.headers || {})) seen.add(k.toLowerCase()); return base(req); };
  const result = await run(domain, { fetch_fn });
  assert.equal(result.confirmed, true, JSON.stringify(result));
  assert.ok(!seen.has("host"), `Host must be stripped; saw [${[...seen].join(", ")}]`);
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

// ── PR-D live self-provisioning (the operator-armed write arm) ───────────────────
// A STATEFUL mock: the producer MINTS its own 256-bit canaries, so the mock must echo each
// create's canary back through that object's reads. POST /api/accounts (the derived create
// endpoint) assigns OBJ_A/B/C in creation order + records {canary, owner}; GET /api/accounts/{id}
// applies the broken "A may read O_B" access (selective, not universal) reflecting the object's
// minted canary at leaf `note`. This drives the FULL live arm (create→readback→P0-P8→mint).
function liveArmFetchFn({ field = "note" } = {}) {
  const created = []; // creation order: [{ id, canary, owner }]
  const postedBodies = []; // the parsed JSON body of every create POST (for asserting fields are sent)
  const ids = [OBJ_A, OBJ_B, OBJ_C];
  let posts = 0;
  const fn = async ({ url, method, headers, body }) => {
    const u = new URL(url);
    const auth = headers && headers.Authorization ? String(headers.Authorization) : "";
    const who = auth.includes("eyJatoken") ? "A" : auth.includes("eyJbtoken") ? "B" : auth.includes("eyJctoken") ? "C" : null;
    if (String(method || "GET").toUpperCase() === "POST" && u.pathname === "/api/accounts") {
      posts += 1;
      const parsed = JSON.parse(body || "{}");
      postedBodies.push(parsed);
      // ENFORCE the declared canary_field: the canary MUST arrive in `field` — a regression that ignores
      // canary_field and writes the canary elsewhere yields NO canary here, so the oracle never fires.
      const v = parsed[field];
      const canary = typeof v === "string" && /^[0-9a-f]{64}$/.test(v) ? v : undefined;
      const id = ids[created.length] || `obj-extra-${created.length}`;
      created.push({ id, canary, owner: who });
      return jsonResponse(201, { id, owner: who, [field]: canary }); // server-minted id captured by id_field
    }
    // Match the EXACT bound account route (not endsWith) — a target-binding regression that read a
    // different path ending in the id must NOT pass (CR).
    const obj = created.find((o) => u.pathname === `/api/accounts/${o.id}`);
    if (!obj) return challenge(404);
    if (!who) return challenge(401);                                   // anon → deny (P4/P8)
    const allowed = obj.owner === who || (obj.owner === "B" && who === "A"); // broken: A reads O_B (the IDOR)
    if (!allowed) return challenge(403);                               // C→O_B, B→O_A (true deny)
    // canary at the SAME leaf `field` in readback + P1 + P2; per-viewer variance keeps P0 stable while P1≠P2.
    return jsonResponse(200, { id: obj.id, kind: "account", owner_scope: `tenant-${obj.owner}`, viewer_id: `viewer-${who}`, [field]: obj.canary });
  };
  fn.postCount = () => posts;
  fn.postedBodies = () => postedBodies;
  return fn;
}

test("PR-D idorProvisionAuthorizedFor: target-BOUND (=== domain), rejects bare flag / mismatch / unset", () => {
  const saved = process.env[IDOR_PROVISION_ENV];
  try {
    process.env[IDOR_PROVISION_ENV] = "idor-live.example.test";
    assert.equal(idorProvisionAuthorizedFor("idor-live.example.test"), true);
    assert.equal(idorProvisionAuthorizedFor("other.example.test"), false, "must not arm a DIFFERENT target");
    process.env[IDOR_PROVISION_ENV] = "1";
    assert.equal(idorProvisionAuthorizedFor("idor-live.example.test"), false, "a bare 1 must not arm");
    delete process.env[IDOR_PROVISION_ENV];
    assert.equal(idorProvisionAuthorizedFor("idor-live.example.test"), false, "unset → inert");
  } finally {
    if (saved === undefined) delete process.env[IDOR_PROVISION_ENV]; else process.env[IDOR_PROVISION_ENV] = saved;
  }
});

test("PR-D: UNARMED live arm (no provision, env not set) stays INERT → blocked_by_design", () => withTempHome(async () => {
  const domain = "idor-unarmed.example.test";
  setupSession(domain);
  const saved = process.env[IDOR_PROVISION_ENV];
  delete process.env[IDOR_PROVISION_ENV];
  try {
    const mock = liveArmFetchFn();
    const result = await idorConfirm({ ...baseArgs(domain), canary_field: "note" }, { fetch_fn: mock });
    assert.equal(result.confirmed, false);
    assert.equal(result.offensive_outcome, "blocked_by_design");
    assert.equal(result.reason, "object_not_self_provisioned");
    assert.equal(readOffensiveRunRecords(domain).length, 0, "unarmed → no row");
    assert.equal(mock.postCount(), 0, "unarmed → ZERO create POSTs (no live write before the block)");
  } finally {
    if (saved !== undefined) process.env[IDOR_PROVISION_ENV] = saved;
  }
}));

test("PR-D: armed create inputs carrying PII / SECRET / ENCODED values are refused BEFORE any write → blocked_operator_pii", () => withTempHome(async () => {
  const domain = "idor-createbody-pii.example.test";
  setupSession(domain);
  const saved = process.env[IDOR_PROVISION_ENV];
  process.env[IDOR_PROVISION_ENV] = domain;
  try {
    // The production gate screens EVERY written byte (body + canary_field name) with layered decoding for
    // BOTH piiScan AND secretShapesIn. Each case must block BEFORE any create POST.
    const cases = [
      { label: "raw email PII", args: { create_body: { contact: "leaked-victim@example.test" } } },
      { label: "percent-encoded email PII", args: { create_body: { contact: "victim%40example.test" } } },
      { label: "AWS secret shape", args: { create_body: { backup: "AKIAIOSFODNN7EXAMPLE" } } },
      { label: "PII in the canary_field NAME", args: { canary_field: "note_for_leaked-victim@example.test" } },
    ];
    for (const c of cases) {
      const mock = liveArmFetchFn();
      const result = await idorConfirm({ ...baseArgs(domain), canary_field: "note", ...c.args }, { fetch_fn: mock });
      assert.equal(result.confirmed, false, `${c.label}: ${JSON.stringify(result)}`);
      assert.equal(result.offensive_outcome, "blocked_operator_pii", c.label);
      assert.equal(result.reason, "create_inputs_contain_sensitive_value", c.label);
      assert.equal(mock.postCount(), 0, `${c.label}: ZERO create POSTs before the screen blocks`);
    }
  } finally {
    if (saved === undefined) delete process.env[IDOR_PROVISION_ENV]; else process.env[IDOR_PROVISION_ENV] = saved;
  }
}));

test("PR-D: PII in a fixed path segment flows into the derived createUrl and is refused BEFORE any write", () => withTempHome(async () => {
  const domain = "idor-createurl-pii.example.test";
  // Record a surface whose endpoint carries an SSN in a FIXED path segment, so the AC-2-bound
  // path_template derives a createUrl that embeds it. The pre-write screen must catch the URL bytes too.
  JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}/` }));
  seedRoutedSurface(domain, SURFACE_ID, `https://${domain}/api/u/123-45-6789/notes/${OBJ_B}`);
  seedSyntheticProfiles(domain, {});
  ensureHandoffSigningKey(domain);
  const saved = process.env[IDOR_PROVISION_ENV];
  process.env[IDOR_PROVISION_ENV] = domain;
  try {
    const mock = liveArmFetchFn();
    const result = await idorConfirm(
      { ...baseArgs(domain), path_template: "/api/u/123-45-6789/notes/{id}", canary_field: "note" },
      { fetch_fn: mock },
    );
    assert.equal(result.confirmed, false, JSON.stringify(result));
    assert.equal(result.offensive_outcome, "blocked_operator_pii");
    assert.equal(result.reason, "create_inputs_contain_sensitive_value");
    assert.equal(mock.postCount(), 0, "ZERO create POSTs when the derived createUrl carries PII");
  } finally {
    if (saved === undefined) delete process.env[IDOR_PROVISION_ENV]; else process.env[IDOR_PROVISION_ENV] = saved;
  }
}));

test("PR-D liveProvision: creates O_A/O_B/O_C IN ORDER, captures server ids + distinct canaries, reads B back", () => withTempHome(async () => {
  const domain = "idor-liveprovision.example.test";
  setupSession(domain);
  // Use a NON-default canary field end-to-end: if liveProvision ignored canaryField and wrote to "note",
  // the mock (which only accepts the canary at `secret_note`) would capture no canary → readback empty.
  const mock = liveArmFetchFn({ field: "secret_note" });
  const idHeaders = (tag) => ({ headers: { Authorization: `Bearer eyJ${tag}token` } });
  const provision = await liveProvision({
    idA: idHeaders("a"), idB: idHeaders("b"), idC: idHeaders("c"),
    createUrl: `https://${domain}/api/accounts`,
    canaryField: "secret_note", idField: "id", createBody: {},
    pathTemplate: PATH_TEMPLATE, origin: `https://${domain}`,
    probeBase: { fetchFn: mock, method: "GET", domain, surfaceId: SURFACE_ID, egressProfile: "default", blockInternalHosts: false, agent: null, startedAt: Date.now() },
  });
  assert.equal(provision.object_a, OBJ_A);
  assert.equal(provision.object_b, OBJ_B);
  assert.equal(provision.object_c, OBJ_C);
  for (const c of [provision.canary_a, provision.canary_b, provision.canary_c]) assert.match(c, /^[0-9a-f]{64}$/);
  assert.equal(new Set([provision.canary_a, provision.canary_b, provision.canary_c]).size, 3, "canaries pairwise-distinct");
  assert.equal(mock.postCount(), 3, "exactly three creates");
  // owner readback of B carries B's minted canary at the DECLARED leaf `secret_note` (path is an array).
  assert.deepEqual(discoverCanaryFieldPath(provision.owner_readback_b, provision.canary_b), ["secret_note"]);
}));

test("PR-D live arm (armed, no provision): full create→readback→P0-P8→signed MEDIUM mint", () => withTempHome(async () => {
  const domain = "idor-livearm.example.test";
  setupSession(domain);
  const saved = process.env[IDOR_PROVISION_ENV];
  process.env[IDOR_PROVISION_ENV] = domain;
  try {
    const mock = liveArmFetchFn();
    const result = await idorConfirm({ ...baseArgs(domain), canary_field: "note" }, { fetch_fn: mock });
    assert.equal(result.confirmed, true, JSON.stringify(result));
    assert.equal(result.row_written, true);
    assert.equal(result.offensive_outcome, "exploited_safely");
    assert.equal(result.demonstrated_severity, "medium", "synthetic objects → HARD medium");
    assert.equal(mock.postCount(), 3, "the live arm created exactly three objects (A/B/C)");
    const rows = readOffensiveRunRecords(domain);
    assert.equal(rows.length, 1);
    assert.equal(rows[0].demonstrated_severity, "medium");
    assert.ok(rows[0].row_mac && rows[0].row_mac.digest, "minted row is MAC-signed");
    // masked rail: the signed row carries NONE of the three identity mailboxes NOR their auth-token markers.
    const rowText = fs.readFileSync(offensiveRunsJsonlPath(domain), "utf8");
    for (const leak of ["eval_a@example.test", "eval_b@example.test", "eval_c@example.test", "eyJatoken", "eyJbtoken", "eyJctoken"]) {
      assert.ok(!rowText.includes(leak), `signed row must not leak identity secret: ${leak}`);
    }
  } finally {
    if (saved === undefined) delete process.env[IDOR_PROVISION_ENV]; else process.env[IDOR_PROVISION_ENV] = saved;
  }
}));

// ── PR-D review round 3: write-surface hardening (Codex P1/P2) ───────────────────

test("PR-D r3 (Codex P1): armed HEAD is rejected GET-only BEFORE any live provisioning (no write)", () => withTempHome(async () => {
  const domain = "idor-head.example.test";
  setupSession(domain);
  const saved = process.env[IDOR_PROVISION_ENV];
  process.env[IDOR_PROVISION_ENV] = domain;
  try {
    const mock = liveArmFetchFn();
    await assert.rejects(
      idorConfirm({ ...baseArgs(domain), method: "HEAD", canary_field: "note" }, { fetch_fn: mock }),
      /requires method GET/,
      "armed HEAD must be rejected before provisioning",
    );
    assert.equal(mock.postCount(), 0, "HEAD → ZERO create POSTs (body-less probes can never mint, so nothing is written)");
  } finally {
    if (saved === undefined) delete process.env[IDOR_PROVISION_ENV]; else process.env[IDOR_PROVISION_ENV] = saved;
  }
}));

test("PR-D r3 (Codex P1): an action-shaped derived create collection (/api/transfer) is refused BEFORE any write", () => withTempHome(async () => {
  const domain = "idor-action-path.example.test";
  // The read template /api/transfer/{id} passes assertReadOnlyPath (transfer is an allowed action-NOUN
  // for a GET-by-id), but the DERIVED collection POST /api/transfer would execute a transfer.
  JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}/` }));
  seedRoutedSurface(domain, SURFACE_ID, `https://${domain}/api/transfer/${OBJ_B}`);
  seedSyntheticProfiles(domain, {});
  ensureHandoffSigningKey(domain);
  const saved = process.env[IDOR_PROVISION_ENV];
  process.env[IDOR_PROVISION_ENV] = domain;
  try {
    const mock = liveArmFetchFn();
    await assert.rejects(
      idorConfirm({ ...baseArgs(domain), path_template: "/api/transfer/{id}", canary_field: "note" }, { fetch_fn: mock }),
      /action-shaped segment/,
      "an action-shaped create collection must be refused",
    );
    assert.equal(mock.postCount(), 0, "ZERO create POSTs to a state-changing endpoint");
  } finally {
    if (saved === undefined) delete process.env[IDOR_PROVISION_ENV]; else process.env[IDOR_PROVISION_ENV] = saved;
  }
}));

test("PR-D r3 (Codex P2): createObject captures a string / safe-int id but REJECTS an unsafe-int (rounded) id", () => withTempHome(async () => {
  const domain = "idor-numeric-id.example.test";
  setupSession(domain);
  const mkFetch = (idValue) => async ({ body }) => jsonResponse(201, { id: idValue, owner: "A", note: JSON.parse(body || "{}").note });
  const probeBase = (fetchFn) => ({ fetchFn, method: "GET", domain, surfaceId: SURFACE_ID, egressProfile: "default", blockInternalHosts: false, agent: null, startedAt: Date.now() });
  const call = (idValue) => createObject({
    createUrl: `https://${domain}/api/accounts`, headers: {}, canaryField: "note",
    canary: "a".repeat(64), idField: "id", createBody: {}, probeBase: probeBase(mkFetch(idValue)),
  });
  assert.equal((await call("acc_42")).id, "acc_42", "string id captured");
  assert.equal((await call(42)).id, 42, "safe-int id captured");
  // 2^53 (9007199254740992) is NOT a safe integer — a 64-bit id here was already rounded by JSON.parse,
  // so it must read as "no id captured" rather than address a different resource in the readback.
  assert.equal((await call(9007199254740992)).id, undefined, "unsafe-int id rejected (no capture)");
}));

test("PR-D r3 (Codex P2): an oversized create_body is refused BEFORE any write", () => withTempHome(async () => {
  const domain = "idor-bigbody.example.test";
  setupSession(domain);
  const saved = process.env[IDOR_PROVISION_ENV];
  process.env[IDOR_PROVISION_ENV] = domain;
  try {
    const mock = liveArmFetchFn();
    const result = await idorConfirm(
      { ...baseArgs(domain), canary_field: "note", create_body: { blob: "x".repeat(9000) } },
      { fetch_fn: mock },
    );
    assert.equal(result.confirmed, false, JSON.stringify(result));
    assert.equal(result.offensive_outcome, "blocked_by_design");
    assert.equal(result.reason, "create_body_too_large");
    assert.equal(mock.postCount(), 0, "an oversized create_body is never POSTed to the target");
  } finally {
    if (saved === undefined) delete process.env[IDOR_PROVISION_ENV]; else process.env[IDOR_PROVISION_ENV] = saved;
  }
}));

test("PR-D r3 (Codex P2): prototype-pollution field names (__proto__/constructor/prototype) are refused BEFORE any write", () => withTempHome(async () => {
  const domain = "idor-proto.example.test";
  setupSession(domain);
  const saved = process.env[IDOR_PROVISION_ENV];
  process.env[IDOR_PROVISION_ENV] = domain;
  try {
    const cases = [
      { label: "canary_field __proto__", args: { canary_field: "__proto__" } },
      { label: "id_field constructor", args: { canary_field: "note", id_field: "constructor" } },
      { label: "canary_field prototype", args: { canary_field: "prototype" } },
      // JSON.parse defines `__proto__` as an OWN key, so a create_body parsed from JSON carries it here.
      { label: "create_body __proto__ key", args: { canary_field: "note", create_body: JSON.parse('{"__proto__":{"polluted":true}}') } },
    ];
    for (const c of cases) {
      const mock = liveArmFetchFn();
      const result = await idorConfirm({ ...baseArgs(domain), ...c.args }, { fetch_fn: mock });
      assert.equal(result.confirmed, false, `${c.label}: ${JSON.stringify(result)}`);
      assert.equal(result.offensive_outcome, "blocked_by_design", c.label);
      assert.equal(result.reason, "reserved_field_name", c.label);
      assert.equal(mock.postCount(), 0, `${c.label}: ZERO create POSTs`);
    }
  } finally {
    if (saved === undefined) delete process.env[IDOR_PROVISION_ENV]; else process.env[IDOR_PROVISION_ENV] = saved;
  }
}));

// ── PR-D review round 4: deeper create-contract subversion (Codex / CodeRabbit P2) ───────────────

test("PR-D r4: a camelCase action collection (/api/transferFunds) is refused BEFORE any write", () => withTempHome(async () => {
  const domain = "idor-camel.example.test";
  JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}/` }));
  seedRoutedSurface(domain, SURFACE_ID, `https://${domain}/api/transferFunds/${OBJ_B}`);
  seedSyntheticProfiles(domain, {});
  ensureHandoffSigningKey(domain);
  const saved = process.env[IDOR_PROVISION_ENV];
  process.env[IDOR_PROVISION_ENV] = domain;
  try {
    const mock = liveArmFetchFn();
    await assert.rejects(
      idorConfirm({ ...baseArgs(domain), path_template: "/api/transferFunds/{id}", canary_field: "note" }, { fetch_fn: mock }),
      /action-shaped segment/,
    );
    assert.equal(mock.postCount(), 0, "camelCase action endpoint → ZERO POSTs");
  } finally {
    if (saved === undefined) delete process.env[IDOR_PROVISION_ENV]; else process.env[IDOR_PROVISION_ENV] = saved;
  }
}));

test("PR-D r4: a commerce collection (/api/orders) is refused BEFORE any write", () => withTempHome(async () => {
  const domain = "idor-orders.example.test";
  JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}/` }));
  seedRoutedSurface(domain, SURFACE_ID, `https://${domain}/api/orders/${OBJ_B}`);
  seedSyntheticProfiles(domain, {});
  ensureHandoffSigningKey(domain);
  const saved = process.env[IDOR_PROVISION_ENV];
  process.env[IDOR_PROVISION_ENV] = domain;
  try {
    const mock = liveArmFetchFn();
    await assert.rejects(
      idorConfirm({ ...baseArgs(domain), path_template: "/api/orders/{id}", canary_field: "note" }, { fetch_fn: mock }),
      /action-shaped segment/,
    );
    assert.equal(mock.postCount(), 0, "/api/orders create → ZERO POSTs");
  } finally {
    if (saved === undefined) delete process.env[IDOR_PROVISION_ENV]; else process.env[IDOR_PROVISION_ENV] = saved;
  }
}));

test("PR-D r4: a root-level derived create endpoint (/{id} → POST /) is refused BEFORE any write", () => withTempHome(async () => {
  const domain = "idor-root.example.test";
  JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}/` }));
  seedRoutedSurface(domain, SURFACE_ID, `https://${domain}/${OBJ_B}`);
  seedSyntheticProfiles(domain, {});
  ensureHandoffSigningKey(domain);
  const saved = process.env[IDOR_PROVISION_ENV];
  process.env[IDOR_PROVISION_ENV] = domain;
  try {
    const mock = liveArmFetchFn();
    const result = await idorConfirm({ ...baseArgs(domain), path_template: "/{id}", canary_field: "note" }, { fetch_fn: mock });
    assert.equal(result.confirmed, false, JSON.stringify(result));
    assert.equal(result.offensive_outcome, "blocked_by_design");
    assert.equal(result.reason, "create_collection_is_root");
    assert.equal(mock.postCount(), 0, "POST to site root is never sent");
  } finally {
    if (saved === undefined) delete process.env[IDOR_PROVISION_ENV]; else process.env[IDOR_PROVISION_ENV] = saved;
  }
}));

test("PR-D r4: create-contract subversion via canary_field / create_body is refused BEFORE any write", () => withTempHome(async () => {
  const domain = "idor-contract.example.test";
  setupSession(domain);
  const saved = process.env[IDOR_PROVISION_ENV];
  process.env[IDOR_PROVISION_ENV] = domain;
  try {
    const cases = [
      // canary_field that masquerades as the tenant/owner scope the oracle reads as private proof.
      { label: "canary_field owner_scope", args: { canary_field: "owner_scope" }, reason: "canary_field_overlaps_scope_key" },
      { label: "canary_field tenant_id", args: { canary_field: "tenant_id" }, reason: "canary_field_overlaps_scope_key" },
      // client-supplied server-minted id (upsert-on-create would use an attacker-chosen object id).
      { label: "client-supplied id", args: { canary_field: "note", create_body: { id: "known-object-42" } }, reason: "create_body_client_supplied_id" },
      { label: "client-supplied id (custom id_field)", args: { canary_field: "note", id_field: "account_id", create_body: { account_id: "victim-7" } }, reason: "create_body_client_supplied_id" },
      // nested prototype-pollution shape (top-level check alone would miss it).
      { label: "nested __proto__", args: { canary_field: "note", create_body: JSON.parse('{"nested":{"__proto__":{"polluted":true}}}') }, reason: "reserved_field_name" },
      // body-level method / action dispatch.
      { label: "_method override", args: { canary_field: "note", create_body: { _method: "DELETE" } }, reason: "create_body_action_override" },
      { label: "action dispatch", args: { canary_field: "note", create_body: { action: "run" } }, reason: "create_body_action_override" },
      // oversized canary_field NAME (the cap must include the field name, not just createBody).
      { label: "oversized canary_field name", args: { canary_field: `note_${"x".repeat(9000)}` }, reason: "create_body_too_large" },
    ];
    for (const c of cases) {
      const mock = liveArmFetchFn();
      const result = await idorConfirm({ ...baseArgs(domain), ...c.args }, { fetch_fn: mock });
      assert.equal(result.confirmed, false, `${c.label}: ${JSON.stringify(result)}`);
      assert.equal(result.offensive_outcome, "blocked_by_design", c.label);
      assert.equal(result.reason, c.reason, c.label);
      assert.equal(mock.postCount(), 0, `${c.label}: ZERO create POSTs`);
    }
  } finally {
    if (saved === undefined) delete process.env[IDOR_PROVISION_ENV]; else process.env[IDOR_PROVISION_ENV] = saved;
  }
}));

// ── PR-D review round 5: canary/id alias, matrix suffix, create_body schema (Codex / CodeRabbit) ──

test("PR-D r5 (Codex/CR): canary_field aliasing id_field is refused BEFORE any write", () => withTempHome(async () => {
  const domain = "idor-canary-id-alias.example.test";
  setupSession(domain);
  const saved = process.env[IDOR_PROVISION_ENV];
  process.env[IDOR_PROVISION_ENV] = domain;
  try {
    const cases = [
      // default id_field is "id", so canary_field:"id" puts the minted canary in the object-id slot.
      { label: "canary_field id (default id_field)", args: { canary_field: "id" } },
      { label: "canary_field === custom id_field", args: { canary_field: "account_id", id_field: "account_id" } },
    ];
    for (const c of cases) {
      const mock = liveArmFetchFn();
      const result = await idorConfirm({ ...baseArgs(domain), ...c.args }, { fetch_fn: mock });
      assert.equal(result.confirmed, false, `${c.label}: ${JSON.stringify(result)}`);
      assert.equal(result.offensive_outcome, "blocked_by_design", c.label);
      assert.equal(result.reason, "canary_field_aliases_id_field", c.label);
      assert.equal(mock.postCount(), 0, `${c.label}: ZERO create POSTs (canary never written into the id slot)`);
    }
  } finally {
    if (saved === undefined) delete process.env[IDOR_PROVISION_ENV]; else process.env[IDOR_PROVISION_ENV] = saved;
  }
}));

test("PR-D r5 (Codex P1): assertCreateCollectionShapeSafe blocks camelCase / matrix-suffix / commerce, allows resource nouns", () => {
  const blocked = ["/api/transferFunds", "/api/refundOrder", "/api/transfer;v=1", "/api/transfer%3bv=1", "/api/orders", "/api/transfer", "/api/withdraw"];
  const allowed = ["/api/accounts", "/api/notes", "/api/users", "/api/documents", "/api/profiles"];
  for (const p of blocked) {
    assert.throws(() => assertCreateCollectionShapeSafe(`https://h${p}`, "t"), /action-shaped segment/, `expected BLOCK: ${p}`);
  }
  for (const p of allowed) {
    assert.doesNotThrow(() => assertCreateCollectionShapeSafe(`https://h${p}`, "t"), `expected ALLOW: ${p}`);
  }
});

test("PR-D r5 (Codex): create_body schema accepts arbitrary synthetic fields (additionalProperties)", () => {
  // The descriptor's create_body must NOT be a closed object, or the documented synthetic skeleton is
  // unusable on APIs that require non-canary create fields (the handler screens content at runtime).
  assert.equal(idorDescriptor.inputSchema.properties.create_body.additionalProperties, true);
  const args = {
    target_domain: "d", surface_id: "s", oracle_kind: "differential_response",
    path_template: "/api/x/{id}", method: "GET",
    identity_a_profile: "a", identity_b_profile: "b", identity_c_profile: "c",
    canary_field: "note", create_body: { name: "synthetic", title: "t", count: 3 },
  };
  assert.doesNotThrow(() => validateAgainstSchema(args, idorDescriptor.inputSchema, []));
});

test("PR-D r5: an armed run with a synthetic non-canary create_body field still mints a signed MEDIUM", () => withTempHome(async () => {
  const domain = "idor-synthetic-body.example.test";
  setupSession(domain);
  const saved = process.env[IDOR_PROVISION_ENV];
  process.env[IDOR_PROVISION_ENV] = domain;
  try {
    const mock = liveArmFetchFn();
    const result = await idorConfirm({ ...baseArgs(domain), canary_field: "note", create_body: { name: "synthetic", title: "t" } }, { fetch_fn: mock });
    assert.equal(result.confirmed, true, JSON.stringify(result));
    assert.equal(result.demonstrated_severity, "medium");
    assert.equal(mock.postCount(), 3, "synthetic body field flows through; canary still overrides note");
    // The synthetic fields must ACTUALLY be in each POST body (would still pass postCount if dropped, CR).
    const bodies = mock.postedBodies();
    assert.equal(bodies.length, 3);
    for (const b of bodies) {
      assert.equal(b.name, "synthetic", "create_body.name reached the target");
      assert.equal(b.title, "t", "create_body.title reached the target");
      assert.match(b.note, /^[0-9a-f]{64}$/, "canary still overrides canary_field");
    }
  } finally {
    if (saved === undefined) delete process.env[IDOR_PROVISION_ENV]; else process.env[IDOR_PROVISION_ENV] = saved;
  }
}));

// ── PR-D review round 6: alias / normalization bypasses of the create-contract guards (Codex P1) ──

test("PR-D r6 (Codex P1): canary_field / create_body alias bypasses are refused BEFORE any write", () => withTempHome(async () => {
  const domain = "idor-aliases.example.test";
  setupSession(domain);
  const saved = process.env[IDOR_PROVISION_ENV];
  process.env[IDOR_PROVISION_ENV] = domain;
  try {
    const cases = [
      // #3 canary_field aliasing a scope discriminator via camelCase/kebab normalization.
      { label: "canary_field tenantId (camelCase scope)", args: { canary_field: "tenantId" }, reason: "canary_field_overlaps_scope_key" },
      { label: "canary_field org-id (kebab scope)", args: { canary_field: "org-id" }, reason: "canary_field_overlaps_scope_key" },
      { label: "canary_field OwnerScope (Pascal scope)", args: { canary_field: "OwnerScope" }, reason: "canary_field_overlaps_scope_key" },
      // #2 client-id ALIAS in create_body (beyond the exact id_field), incl. nested.
      { label: "create_body object_id", args: { canary_field: "note", create_body: { object_id: "known-object" } }, reason: "create_body_client_supplied_id" },
      { label: "create_body resourceId (camelCase)", args: { canary_field: "note", create_body: { resourceId: "x" } }, reason: "create_body_client_supplied_id" },
      { label: "create_body nested id", args: { canary_field: "note", create_body: { data: { id: "x" } } }, reason: "create_body_client_supplied_id" },
      // #4 owning-scope key in create_body → scope drift during the write (incl. alias + nested envelope).
      { label: "create_body tenant_id", args: { canary_field: "note", create_body: { tenant_id: "victim-org" } }, reason: "create_body_scope_field" },
      { label: "create_body workspaceId (camelCase)", args: { canary_field: "note", create_body: { workspaceId: "victim-ws" } }, reason: "create_body_scope_field" },
      { label: "create_body nested org_id envelope", args: { canary_field: "note", create_body: { meta: { org_id: "victim" } } }, reason: "create_body_scope_field" },
    ];
    for (const c of cases) {
      const mock = liveArmFetchFn();
      const result = await idorConfirm({ ...baseArgs(domain), ...c.args }, { fetch_fn: mock });
      assert.equal(result.confirmed, false, `${c.label}: ${JSON.stringify(result)}`);
      assert.equal(result.offensive_outcome, "blocked_by_design", c.label);
      assert.equal(result.reason, c.reason, c.label);
      assert.equal(mock.postCount(), 0, `${c.label}: ZERO create POSTs`);
    }
  } finally {
    if (saved === undefined) delete process.env[IDOR_PROVISION_ENV]; else process.env[IDOR_PROVISION_ENV] = saved;
  }
}));

// ── PR-D review round 8: canary_field id-alias, create_body URL values, audit preflight (Codex P1) ──

test("PR-D r8 (Codex P1): canary_field that ALIASES the id field (uuid/object_id/case) is refused BEFORE any write", () => withTempHome(async () => {
  const domain = "idor-canary-idalias.example.test";
  setupSession(domain);
  const saved = process.env[IDOR_PROVISION_ENV];
  process.env[IDOR_PROVISION_ENV] = domain;
  try {
    for (const cf of ["uuid", "object_id", "resourceId", "ID", "guid"]) {
      const mock = liveArmFetchFn();
      const result = await idorConfirm({ ...baseArgs(domain), canary_field: cf }, { fetch_fn: mock });
      assert.equal(result.confirmed, false, `${cf}: ${JSON.stringify(result)}`);
      assert.equal(result.reason, "canary_field_aliases_id_field", cf);
      assert.equal(mock.postCount(), 0, `${cf}: ZERO create POSTs (canary never lands in the id slot)`);
    }
  } finally {
    if (saved === undefined) delete process.env[IDOR_PROVISION_ENV]; else process.env[IDOR_PROVISION_ENV] = saved;
  }
}));

test("PR-D r8 (Codex P1): a URL-valued create_body field is refused BEFORE any write", () => withTempHome(async () => {
  const domain = "idor-url-body.example.test";
  setupSession(domain);
  const saved = process.env[IDOR_PROVISION_ENV];
  process.env[IDOR_PROVISION_ENV] = domain;
  try {
    const cases = [
      { label: "avatar_url http", create_body: { avatar_url: "http://169.254.169.254/latest/meta-data/" } },
      { label: "callback_url https", create_body: { callback_url: "https://attacker.example/hook" } },
      { label: "protocol-relative", create_body: { ref: "//internal.svc/x" } },
      { label: "nested webhook url", create_body: { config: { webhook: "http://internal:8080/" } } },
    ];
    for (const c of cases) {
      const mock = liveArmFetchFn();
      const result = await idorConfirm({ ...baseArgs(domain), canary_field: "note", create_body: c.create_body }, { fetch_fn: mock });
      assert.equal(result.confirmed, false, `${c.label}: ${JSON.stringify(result)}`);
      assert.equal(result.offensive_outcome, "blocked_by_design", c.label);
      assert.equal(result.reason, "create_body_url_value", c.label);
      assert.equal(mock.postCount(), 0, `${c.label}: ZERO create POSTs (no SSRF/callback URL sent)`);
    }
  } finally {
    if (saved === undefined) delete process.env[IDOR_PROVISION_ENV]; else process.env[IDOR_PROVISION_ENV] = saved;
  }
}));

test("PR-D r8 (Codex P1): createObject pre-flights the audit — an unauditable create POST never fires", () => withTempHome(async () => {
  const domain = "idor-preflight-audit.example.test";
  setupSession(domain);
  let posted = false;
  const fetchFn = async () => { posted = true; return jsonResponse(201, { id: OBJ_A, note: "x" }); };
  // probeBase.domain falsy forces auditConfirmRequest -> false (the audit can't be recorded), standing in
  // for an unwritable http-audit.jsonl. The preflight must abort BEFORE the POST, so fetchFn is never called.
  await assert.rejects(
    createObject({
      createUrl: `https://${domain}/api/accounts`, headers: {}, canaryField: "note",
      canary: "a".repeat(64), idField: "id", createBody: {},
      probeBase: { fetchFn, method: "GET", domain: "", surfaceId: SURFACE_ID, egressProfile: "default", blockInternalHosts: false, agent: null, startedAt: Date.now() },
    }),
    /audit preflight write failed/,
  );
  assert.equal(posted, false, "the mutating POST must NOT fire when the audit cannot be recorded");
}));

// ── PR-D review round 9: array URLs, GraphQL ops, malformed-escape paths, raw-readback PII (Codex) ──

test("PR-D r9 (Codex P1): a URL inside a create_body ARRAY is refused BEFORE any write", () => withTempHome(async () => {
  const domain = "idor-arr-url.example.test";
  setupSession(domain);
  const saved = process.env[IDOR_PROVISION_ENV];
  process.env[IDOR_PROVISION_ENV] = domain;
  try {
    const cases = [
      { label: "url in top-level array", create_body: { callbacks: ["http://169.254.169.254/latest/meta-data/"] } },
      { label: "url in nested array", create_body: { config: { hooks: ["https://attacker.example/h"] } } },
    ];
    for (const c of cases) {
      const mock = liveArmFetchFn();
      const result = await idorConfirm({ ...baseArgs(domain), canary_field: "note", create_body: c.create_body }, { fetch_fn: mock });
      assert.equal(result.confirmed, false, `${c.label}: ${JSON.stringify(result)}`);
      assert.equal(result.reason, "create_body_url_value", c.label);
      assert.equal(mock.postCount(), 0, `${c.label}: ZERO create POSTs`);
    }
  } finally {
    if (saved === undefined) delete process.env[IDOR_PROVISION_ENV]; else process.env[IDOR_PROVISION_ENV] = saved;
  }
}));

test("PR-D r9 (Codex P1): a GraphQL mutation operation in create_body is refused; a benign 'mutation' word is not", () => withTempHome(async () => {
  const domain = "idor-graphql.example.test";
  setupSession(domain);
  const saved = process.env[IDOR_PROVISION_ENV];
  process.env[IDOR_PROVISION_ENV] = domain;
  try {
    for (const op of ['mutation { deleteUser(id: 1) }', 'mutation Evil($x:ID!){ x }', 'subscription { onData }']) {
      const mock = liveArmFetchFn();
      const result = await idorConfirm({ ...baseArgs(domain), canary_field: "note", create_body: { query: op } }, { fetch_fn: mock });
      assert.equal(result.reason, "create_body_graphql_operation", op);
      assert.equal(mock.postCount(), 0, `${op}: ZERO create POSTs`);
    }
    // A benign value that merely contains the word "mutation" (no operation shape) must NOT be blocked → mints.
    const mock = liveArmFetchFn();
    const ok = await idorConfirm({ ...baseArgs(domain), canary_field: "note", create_body: { notes: "mutation rate: 0.5 per cycle" } }, { fetch_fn: mock });
    assert.equal(ok.confirmed, true, JSON.stringify(ok));
    assert.equal(ok.demonstrated_severity, "medium");
  } finally {
    if (saved === undefined) delete process.env[IDOR_PROVISION_ENV]; else process.env[IDOR_PROVISION_ENV] = saved;
  }
}));

test("PR-D r9 (Codex P1): assertCreateCollectionShapeSafe recovers valid escapes behind a malformed one", () => {
  // A valid %3b (;) / %2f (/) masked by a later malformed %zz must still surface the action verb.
  for (const p of ["/api/transfer%3bv=%zz", "/api/transfer%2faction%zz", "/api/refund%3bzz=%gg"]) {
    assert.throws(() => assertCreateCollectionShapeSafe(`https://h${p}`, "t"), /action-shaped segment/, `expected BLOCK: ${p}`);
  }
  assert.doesNotThrow(() => assertCreateCollectionShapeSafe("https://h/api/accounts%zz", "t"), "a malformed escape on a benign noun still passes");
});

test("PR-D r9 (Codex P2): foreign PII present only in RAW readback bytes (parsed-clean) is caught by #24", () => withTempHome(async () => {
  const domain = "idor-rawpii.example.test";
  setupSession(domain);
  // Parsed readback is clean (canary at the discovered leaf, no PII), but the RAW bytes carry a foreign
  // email in a shadowed duplicate key that JSON.parse drops — the parsed-only scan would miss it.
  const provision = {
    ...soundProvision(),
    owner_readback_b_raw: `{"details":{"secret":{"token":"${CANARY_B}"}},"contact":"victim-foreign@evil.test","contact":"clean"}`,
  };
  const result = await run(domain, { provision });
  assert.equal(result.confirmed, false, JSON.stringify(result));
  assert.equal(result.reason, "shared_object_store");
}));
