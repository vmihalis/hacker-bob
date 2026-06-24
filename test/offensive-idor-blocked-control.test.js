"use strict";

// The IDOR producer's POST-EXECUTION server-denied legs are the honest NEGATIVE
// CONTROL leg of a finding differential: the safe/authorized variant ACTUALLY RAN
// (the probes fired + were audited) and the server BLOCKED it. Those legs now emit a
// MAC-signed blocked_by_defense row (row_written:true), on the SAME surface, with a
// command_hash DISTINCT from a positive (a true safe-variant differs in request
// shape). PRE-REQUEST refusals (provenance/provision/scope) fire BEFORE any probe and
// must stay unsigned (row_written:false) — there is no executed observation to sign.

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const { idorConfirm } = require("../mcp/lib/offensive-idor-producer.js");
const { initSession } = require("../mcp/lib/session-state.js");
const { routeSurfaces } = require("../mcp/lib/surface-router.js");
const { writeAuthFile, resolveAuthJsonPath } = require("../mcp/lib/auth.js");
const { ensureHandoffSigningKey } = require("../mcp/lib/handoff-signing-key.js");
const { verifyOffensiveRunRowMac } = require("../mcp/lib/offensive-row-mac.js");
const { attackSurfacePath, offensiveRunsJsonlPath } = require("../mcp/lib/paths.js");
const { readOffensiveRunRecords } = require("../mcp/lib/claims.js");
const {
  resetForTests: resetMaterializationDebounce,
} = require("../mcp/lib/frontier-materialize-debounce.js");

const SURFACE_ID = "surface:accounts";
const PATH_TEMPLATE = "/api/accounts/{id}";
const OBJ_A = "obj-a-100";
const OBJ_B = "obj-b-200";
const OBJ_C = "obj-c-300";
const CANARY_A = "a".repeat(64);
const CANARY_B = "b".repeat(64);
const CANARY_C = "c".repeat(64);

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-idor-blocked-"));
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

function endpointFor(domain) { return `https://${domain}/api/accounts/${OBJ_B}`; }

function resourceBody({ canary, scope, viewer, objId = OBJ_B }) {
  const seed = crypto.createHash("sha256").update(`${viewer}|${objId}`).digest("hex");
  return {
    id: objId, kind: "account", name: "synthetic record", owner_scope: scope,
    viewer_id: viewer, server_ts: `2026-06-16T00:00:${seed.slice(0, 2)}.${seed.slice(2, 5)}Z`,
    csrf: seed.slice(0, 16), details: { secret: { token: canary } },
  };
}

function jsonResponse(status, bodyObj, headers = {}) {
  const lower = {};
  for (const [k, v] of Object.entries(headers)) lower[String(k).toLowerCase()] = v;
  const bytes = Buffer.from(JSON.stringify(bodyObj), "utf8");
  return {
    status, headers: { get(name) { return lower[String(name).toLowerCase()] ?? null; } },
    bodyBytes: bytes, bodyByteLength: bytes.length, bodyTruncated: false,
  };
}

function challenge(status = 403) {
  const bytes = Buffer.from(JSON.stringify({ error: "forbidden" }), "utf8");
  return { status, headers: { get: () => null }, bodyBytes: bytes, bodyByteLength: bytes.length, bodyTruncated: false };
}

function soundFetchFn(domain, overrides = {}) {
  return async ({ url, headers }) => {
    const auth = headers && headers.Authorization ? String(headers.Authorization) : "";
    const isA = auth.includes("eyJatoken");
    const isB = auth.includes("eyJbtoken");
    const isC = auth.includes("eyJctoken");
    const u = new URL(url);
    const wantsOB = u.pathname.includes(OBJ_B);
    const wantsOA = u.pathname.includes(OBJ_A);
    const wantsOC = u.pathname.includes(OBJ_C);
    if (overrides.handler) {
      const r = overrides.handler({ isA, isB, isC, wantsOB, wantsOA, wantsOC });
      if (r) return r;
    }
    if (!isA && !isB && !isC) return challenge(overrides.anonStatus || 403);
    if (wantsOB) {
      if (isB) return jsonResponse(200, resourceBody({ canary: CANARY_B, scope: "tenant-B", viewer: "viewer-B" }));
      if (isA) return jsonResponse(200, resourceBody({ canary: CANARY_B, scope: "tenant-B", viewer: "viewer-A" }), overrides.p2Headers || {});
      if (isC) return challenge(403);
    }
    if (wantsOA) {
      if (isA) return jsonResponse(200, resourceBody({ canary: CANARY_A, scope: "tenant-A", viewer: "viewer-A", objId: OBJ_A }));
      return challenge(403);
    }
    if (wantsOC) {
      if (isC) return jsonResponse(200, resourceBody({ canary: CANARY_C, scope: "tenant-C", viewer: "viewer-C", objId: OBJ_C }));
      return challenge(403);
    }
    return challenge(404);
  };
}

function baseArgs(domain) {
  return {
    target_domain: domain, surface_id: SURFACE_ID, oracle_kind: "differential_response",
    path_template: PATH_TEMPLATE, method: "GET",
    identity_a_profile: "identity_a", identity_b_profile: "identity_b", identity_c_profile: "identity_c",
  };
}

function soundProvision() {
  return {
    object_a: OBJ_A, object_b: OBJ_B, object_c: OBJ_C,
    canary_a: CANARY_A, canary_b: CANARY_B, canary_c: CANARY_C,
    owner_readback_b: { id: OBJ_B, owner_scope: "tenant-B", details: { secret: { token: CANARY_B } } },
  };
}

function seedRoutedSurface(domain) {
  fs.mkdirSync(path.dirname(attackSurfacePath(domain)), { recursive: true });
  fs.writeFileSync(attackSurfacePath(domain), `${JSON.stringify({
    surfaces: [{
      id: SURFACE_ID, title: "Synthetic API account surface", surface_type: "web",
      hosts: [domain], endpoints: [endpointFor(domain)], tech_stack: ["fixture"], priority: "HIGH",
    }],
  }, null, 2)}\n`, "utf8");
  JSON.parse(routeSurfaces({ target_domain: domain }));
}

function seedSyntheticProfiles(domain, { provenance = true } = {}) {
  const flags = provenance
    ? { synthetic: true, email_origin: "temp_email", provisioned_via: "bob_auto_signup" }
    : {};
  const mk = (tag) => ({ Authorization: `Bearer eyJ${tag}token`, email: `eval_${tag}@example.test`, ...flags });
  writeAuthFile(resolveAuthJsonPath(domain), `${JSON.stringify({
    version: 2, profiles: { identity_a: mk("a"), identity_b: mk("b"), identity_c: mk("c") },
  }, null, 2)}\n`);
}

function setupSession(domain, { provenance = true } = {}) {
  JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}/` }));
  seedRoutedSurface(domain);
  seedSyntheticProfiles(domain, { provenance });
  ensureHandoffSigningKey(domain);
}

// A sound positive (single signed exploited_safely row), to read its command_hash.
async function positiveCommandHash(domain) {
  setupSession(domain);
  const result = await idorConfirm(baseArgs(domain), { fetch_fn: soundFetchFn(domain), provision: soundProvision() });
  assert.equal(result.offensive_outcome, "exploited_safely", JSON.stringify(result));
  return result.command_hash;
}

function assertSignedBlockedControl(domain, result) {
  assert.equal(result.confirmed, false);
  assert.equal(result.row_written, true, "a server-denied safe variant signs a control row");
  assert.equal(result.offensive_outcome, "blocked_by_defense");
  const rows = readOffensiveRunRecords(domain);
  assert.equal(rows.length, 1, "exactly one signed control row");
  const row = rows[0];
  assert.equal(row.offensive_outcome, "blocked_by_defense");
  assert.equal(row.surface_id, SURFACE_ID, "the control binds the finding surface");
  assert.equal(row.exit_code, 0, "a server-denied response is a completed execution");
  assert.equal(row.dry_run, false);
  assert.equal(row.timed_out, false);
  assert.ok(verifyOffensiveRunRowMac(row, ensureHandoffSigningKey(domain)), "the control row verifies its MAC");
  assert.equal(result.run_id, row.run_id);
  return row;
}

test("object_not_access_controlled (anon-200) is an UNSIGNED precondition failure — an anon-readable object is not a defense block, so NOTHING is signed", () => withTempHome(async () => {
  const domain = "idor-blk-anon200.example.test";
  setupSession(domain);
  const result = await idorConfirm(baseArgs(domain), {
    fetch_fn: soundFetchFn(domain, { anonStatus: 200 }),
    provision: soundProvision(),
  });
  assert.equal(result.reason, "object_not_access_controlled");
  // An anon read that returns 200 (object anonymously reachable) is the OPPOSITE of a
  // server denial: there is no privilege boundary for the cross-tenant read to cross
  // and no defense fired. Signing a blocked_by_defense control here would be dishonest
  // (it would assert a flip that never happened), so the leg returns UNSIGNED.
  assert.equal(result.offensive_outcome, "blocked_by_design", "an anon-200 read is a precondition failure, not a defense observation");
  assert.equal(result.row_written, false, "a non-denied anon read signs NOTHING");
  assert.equal(readOffensiveRunRecords(domain).length, 0, "no offensive row is written for a precondition failure");
}));

test("canary_absent_p2_no_cross_tenant_read signs a blocked_by_defense control with a DISTINCT command_hash from a positive", () => withTempHome(async () => {
  const posHash = await positiveCommandHash("idor-blk-posref-2.example.test");
  const domain = "idor-blk-nocross.example.test";
  setupSession(domain);
  const result = await idorConfirm(baseArgs(domain), {
    fetch_fn: soundFetchFn(domain, {
      handler: ({ wantsOB, isA }) => (wantsOB && isA
        // A reads O_B but the server returns a same-shaped resource WITHOUT B's canary
        // (proper object-level auth). The primary-witness leg fails -> server-denied.
        ? jsonResponse(200, resourceBody({ canary: "not-b-canary".padEnd(64, "0"), scope: "tenant-B", viewer: "viewer-A" }))
        : null),
    }),
    provision: soundProvision(),
  });
  assert.equal(result.reason, "canary_absent_p2_no_cross_tenant_read");
  const row = assertSignedBlockedControl(domain, result);
  assert.notEqual(row.command_hash, posHash, "the control's request shape differs from the positive's");
}));

// ── PRE-REQUEST refusals fire BEFORE any probe and stay UNSIGNED ──────────────

test("a provenance pre-request refusal (no synthetic flags) is UNSIGNED (row_written:false, no ledger)", () => withTempHome(async () => {
  const domain = "idor-blk-prov.example.test";
  setupSession(domain, { provenance: false });
  const result = await idorConfirm(baseArgs(domain), { fetch_fn: soundFetchFn(domain), provision: soundProvision() });
  assert.equal(result.confirmed, false);
  assert.equal(result.reason, "identity_provenance_not_synthetic");
  assert.equal(result.row_written, false);
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false, "no ledger for a pre-request refusal");
}));

test("a provision pre-request refusal (no objects) is UNSIGNED (row_written:false, no ledger)", () => withTempHome(async () => {
  const domain = "idor-blk-noprov.example.test";
  setupSession(domain);
  const result = await idorConfirm(baseArgs(domain), { fetch_fn: soundFetchFn(domain), provision: null });
  assert.equal(result.confirmed, false);
  assert.equal(result.reason, "object_not_self_provisioned");
  assert.equal(result.row_written, false);
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false, "no ledger for a pre-request refusal");
}));
