"use strict";

// Plane Y Cycle Y.5 (rev 4 O1) — Wave brief respects technique-pack scorer.
//
// Pact: if `selected_packs[0].score > 0`, the renderer's technique section
// MUST surface `selected_packs[0].id` rather than fall back to a generic
// pack. The brief composition path already feeds the scorer output through
// to `technique_packs.selected[]`; this test pins the contract by seeding a
// fixture surface whose fingerprint matches `jwt-oauth` (tech: jwt /
// hints: jwt_oauth) and asserting the top selected pack id is jwt-oauth,
// NOT the historical `generic-rest-api` fallback that fires only when the
// scorer returns an empty selected[] set.
//
// Y-R27 acknowledgement: this is a renderer-site fix. If a future surface
// fingerprint emission lacks JWT signals when JWT is genuinely present, the
// fix lands in Plane Z (the fingerprint emission path, NOT this assertion).

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  attackSurfacePath,
  sessionDir,
  statePath,
} = require("../mcp/lib/paths.js");
const {
  readAssignmentBrief,
} = require("../mcp/lib/assignment-brief.js");
const {
  startWave,
} = require("../mcp/lib/waves.js");
const {
  writeFileAtomic,
} = require("../mcp/lib/storage.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bob-y5-scorer-"));
  process.env.HOME = tempHome;
  try {
    return fn(tempHome);
  } finally {
    if (previousHome === undefined) {
      delete process.env.HOME;
    } else {
      process.env.HOME = previousHome;
    }
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
}

function uniqueDomain(prefix) {
  return `${prefix}-${crypto.randomBytes(4).toString("hex")}.example`;
}

function seedSessionState(domain) {
  fs.mkdirSync(sessionDir(domain), { recursive: true });
  writeFileAtomic(statePath(domain), `${JSON.stringify({
    target: domain,
    target_url: `https://${domain}`,
    deep_mode: false,
    phase: "EVALUATE",
    evaluation_wave: 0,
    pending_wave: null,
    total_findings: 0,
    explored: [],
    terminally_blocked: [],
    prereq_registry_snapshots: [],
    blocked_prereq_history: [],
    terminal_block_clear_history: [],
    dead_ends: [],
    waf_blocked_endpoints: [],
    lead_surface_ids: [],
    scope_exclusions: [],
    hold_count: 0,
    auth_status: "pending",
    operator_note: null,
    verification_schema_version: null,
    verification_attempt_id: null,
    verification_snapshot_hash: null,
  }, null, 2)}\n`);
}

function seedAttackSurface(domain, surfaces) {
  fs.mkdirSync(sessionDir(domain), { recursive: true });
  writeFileAtomic(attackSurfacePath(domain), `${JSON.stringify({ surfaces }, null, 2)}\n`);
}

function startSingleSurfaceWave(domain, surfaceId) {
  return JSON.parse(startWave({
    target_domain: domain,
    wave_number: 1,
    assignments: [{ agent: "a1", surface_id: surfaceId }],
  }));
}

test("wave brief surfaces jwt-oauth as the top selected technique pack when surface carries JWT signals (O1)", () => {
  withTempHome(() => {
    const domain = uniqueDomain("y5-scorer");
    const surfaceId = "auth-api";
    seedSessionState(domain);
    seedAttackSurface(domain, [{
      id: surfaceId,
      surface_type: "api",
      hosts: [`https://auth.${domain}`],
      title: "OAuth + JWT authn API",
      description: "Token issuance and verification endpoints with JWKS publication.",
      // JWT scorer signals — both `tech` and explicit `hints` per the
      // evaluator-techniques.json jwt-oauth pack match block.
      tech_stack: ["jwt", "oauth", "oidc"],
      endpoints: ["/oauth/token", "/.well-known/jwks.json", "/oauth/callback", "/authorize"],
      interesting_params: ["redirect_uri", "client_id", "state", "code", "scope"],
      bug_class_hints: ["jwt_oauth", "auth"],
      high_value_flows: ["token issuance", "callback"],
      evidence: ["JWKS public", "OAuth callback exposed"],
    }]);
    startSingleSurfaceWave(domain, surfaceId);

    const brief = JSON.parse(readAssignmentBrief({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      egress_profile: "default",
      block_internal_hosts: false,
    }));

    assert.ok(brief.technique_packs, "technique_packs slice MUST be present");
    assert.ok(Array.isArray(brief.technique_packs.selected), "technique_packs.selected MUST be an array");
    assert.ok(brief.technique_packs.selected.length > 0, "scorer MUST return at least one pack");

    const top = brief.technique_packs.selected[0];
    assert.ok(
      Number.isFinite(top.score) && top.score > 0,
      "top selected pack MUST have score > 0",
    );
    assert.equal(
      top.id,
      "jwt-oauth",
      `top-scoring pack MUST be jwt-oauth (got ${top.id}); generic-rest-api fallback MUST NOT pre-empt a higher-scoring specific pack`,
    );

    const ids = brief.technique_packs.selected.map((pack) => pack.id);
    assert.ok(
      !ids.includes("generic-rest-api") || ids.indexOf("generic-rest-api") > ids.indexOf("jwt-oauth"),
      `generic-rest-api MUST NOT appear before jwt-oauth in selected[] (got order: ${ids.join(", ")})`,
    );
  });
});
