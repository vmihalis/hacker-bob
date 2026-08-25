"use strict";

// Depth (A1) — the id-bearing obligation carried into the evaluator brief.
// wave-assignment-store freezes id_bearing (the detector result), the id-bearing
// endpoint TEMPLATES, and auth_differential_required onto the MCP-owned,
// route-time-immutable assignment. readAssignmentBrief must surface the
// known-mandatory cross-tenant experiment for an id-bearing surface so the
// brief promises exactly what the finalize/grade gate will require, sourced
// ONLY from those route-frozen fields (never re-derived from agent-writable
// attack_surface.json). These tests prove: (a) an id-bearing surface's brief
// carries id_bearing_obligation with the frozen '/api/orders/{id}' template,
// (b) a non-id-bearing surface omits the key entirely (drop-empty-keys), and
// (c) the endpoint list is bounded by ID_BEARING_ENDPOINT_BRIEF_LIMIT with an
// omitted counter when it overflows.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  attackSurfacePath,
  sessionDir,
  statePath,
} = require("../mcp/core/io/paths.js");
const {
  startWave,
} = require("../mcp/core/waves/waves.js");
const {
  readAssignmentBrief,
  ID_BEARING_ENDPOINT_BRIEF_LIMIT,
} = require("../mcp/core/session/assignment-brief.js");
const { writeFileAtomic } = require("../mcp/core/io/storage.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bob-id-bearing-brief-"));
  process.env.HOME = tempHome;
  try {
    return fn(tempHome);
  } finally {
    if (previousHome === undefined) delete process.env.HOME;
    else process.env.HOME = previousHome;
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
}

function seedSessionState(domain) {
  fs.mkdirSync(sessionDir(domain), { recursive: true });
  const state = {
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
    verification_entered_at: null,
  };
  writeFileAtomic(statePath(domain), `${JSON.stringify(state, null, 2)}\n`);
  const nucleusPath = require("../mcp/core/io/paths.js").sessionNucleusPath(domain);
  if (!fs.existsSync(nucleusPath)) {
    const { buildSessionNucleus } = require("../mcp/core/governance/index.js");
    const { writeJsonDocument } = require("../mcp/core/io/storage.js");
    const nucleus = buildSessionNucleus({
      target_domain: domain,
      target_url: state.target_url,
      scope_policy: {
        target_url: state.target_url,
        checkpoint_mode: state.checkpoint_mode,
        deep_mode: state.deep_mode,
        block_internal_hosts: state.block_internal_hosts ?? false,
        allow_internal_hosts: false,
      },
      egress_identity: {
        egress_profile: state.egress_profile,
        egress_region: state.egress_region,
        proxy_configured: state.proxy_configured,
        egress_profile_identity_hash: state.egress_profile_identity_hash,
        egress_profile_identity_version: state.egress_profile_identity_version,
      },
      auth_context: { auth_status: state.auth_status || "pending" },
      operator_constraint: {},
      lifecycle_state: state.lifecycle_state || "SETUP",
    });
    writeJsonDocument(nucleusPath, nucleus);
  }
}

function seedSurfaces(domain, surfaces) {
  fs.mkdirSync(sessionDir(domain), { recursive: true });
  writeFileAtomic(attackSurfacePath(domain), `${JSON.stringify({ surfaces }, null, 2)}\n`);
}

function apiSurface(id, host, endpoints) {
  return {
    id,
    surface_type: "api",
    hosts: [host],
    title: "API surface",
    tech_stack: ["Express"],
    endpoints,
  };
}

function callBrief(domain, agent) {
  return JSON.parse(readAssignmentBrief({
    target_domain: domain,
    wave: "w1",
    agent,
    egress_profile: "default",
    block_internal_hosts: false,
  }));
}

test("an id_bearing surface brief carries the route-frozen obligation", () => {
  withTempHome(() => {
    const domain = "id-bearing-brief.example.com";
    const surfaceId = "surface-orders";
    seedSessionState(domain);
    seedSurfaces(domain, [apiSurface(surfaceId, `api.${domain}`, ["/api/orders/123"])]);
    startWave({
      target_domain: domain,
      wave_number: 1,
      assignments: [{ agent: "a1", surface_id: surfaceId }],
    });

    const brief = callBrief(domain, "a1");
    const obligation = brief.id_bearing_obligation;
    assert.ok(obligation, "id_bearing surface brief must carry id_bearing_obligation");
    assert.equal(obligation.id_bearing, true);
    assert.ok(
      Array.isArray(obligation.id_bearing_endpoints)
        && obligation.id_bearing_endpoints.includes("/api/orders/{id}"),
      "obligation must carry the route-frozen '/api/orders/{id}' template",
    );
    assert.equal(typeof obligation.obligation, "string");
    assert.ok(obligation.obligation.length > 0, "obligation guidance must be non-empty");
    // Names the tools + the flip fallback per the fixed guidance literal.
    assert.match(obligation.obligation, /bob_list_auth_profiles/);
    assert.match(obligation.obligation, /bob_run_auth_differential/);
    assert.ok(
      obligation.id_bearing_endpoints_limits
        && typeof obligation.id_bearing_endpoints_limits === "object"
        && !Array.isArray(obligation.id_bearing_endpoints_limits),
      "obligation must carry an id_bearing_endpoints_limits object",
    );
  });
});

test("a non-id_bearing surface brief omits the obligation key entirely", () => {
  withTempHome(() => {
    const domain = "non-id-bearing-brief.example.com";
    const surfaceId = "surface-health";
    seedSessionState(domain);
    seedSurfaces(domain, [apiSurface(surfaceId, `api.${domain}`, ["/api/health"])]);
    startWave({
      target_domain: domain,
      wave_number: 1,
      assignments: [{ agent: "a1", surface_id: surfaceId }],
    });

    const brief = callBrief(domain, "a1");
    assert.equal(brief.id_bearing_obligation, undefined);
    assert.ok(
      !Object.prototype.hasOwnProperty.call(brief, "id_bearing_obligation"),
      "drop-empty-keys: the key must be absent, not present-and-empty",
    );
  });
});

test("an over-cap id_bearing endpoint set is bounded with omitted>0", () => {
  withTempHome(() => {
    const domain = "id-bearing-overcap-brief.example.com";
    const surfaceId = "surface-many";
    const letters = "abcdefghijklmnopqrstuvwxyz";
    const endpoints = [];
    // Distinct collection prefixes so each templatizes to a DISTINCT
    // /api/<col>/{id} template (concrete ids all collapse to {id} and would
    // otherwise dedupe to one), overflowing the endpoint brief cap.
    for (let i = 0; i < ID_BEARING_ENDPOINT_BRIEF_LIMIT + 5; i += 1) {
      const col = `${letters[Math.floor(i / 26)]}${letters[i % 26]}`;
      endpoints.push(`/api/${col}/123`);
    }
    seedSessionState(domain);
    seedSurfaces(domain, [apiSurface(surfaceId, `api.${domain}`, endpoints)]);
    startWave({
      target_domain: domain,
      wave_number: 1,
      assignments: [{ agent: "a1", surface_id: surfaceId }],
    });

    const brief = callBrief(domain, "a1");
    const obligation = brief.id_bearing_obligation;
    assert.ok(obligation, "over-cap id_bearing surface brief must still carry the obligation");
    assert.ok(
      obligation.id_bearing_endpoints.length <= ID_BEARING_ENDPOINT_BRIEF_LIMIT,
      "id_bearing_endpoints must be bounded by the brief cap",
    );
    assert.ok(
      obligation.id_bearing_endpoints_limits.omitted > 0,
      "the limits object must report omitted endpoints when over-cap",
    );
  });
});
