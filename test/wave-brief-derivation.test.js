"use strict";

// Plane Y Cycle Y.5 — Wave-scheduler derivation tests.
//
// Y.5 ships:
//   - mcp/lib/wave-brief-derivation.js exporting buildWaveBriefDerivation —
//     the caller-side helper that builds a synthetic Surface node, threads
//     friction_history (Y-P5 / Y-P6) and target_class (rev-4 O5) into the
//     pure derivePackForNode, and returns a bounded summary.
//   - mcp/lib/assignment-brief.js readAssignmentBrief: wires the helper
//     into the wave-side brief; new top-level `wave_brief_derivation`
//     field surfaces the synthetic node id + derived allowed tools.
//
// Coverage:
//   1. Friction history with a `tool_absent` record (wanted_tool absent
//      from default web pack) widens the brief's
//      wave_brief_derivation.allowed_tools_for_node[] per Y-P6.
//   2. Friction selector wave-scopes by surface_id — a friction on a
//      different surface does NOT bleed into the brief's derivation.
//   3. include_inadequacy default is false — voluntary tool_inadequate
//      frictions are quarantined out of the derivation per Y-P11.

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
} = require("../mcp/core/io/paths.js");
const {
  readAssignmentBrief,
  buildWaveBriefDerivation,
} = require("../mcp/core/session/assignment-brief.js");
const {
  startWave,
} = require("../mcp/core/waves/waves.js");
const {
  writeFileAtomic,
} = require("../mcp/core/io/storage.js");
const {
  appendFrontierEvent,
} = require("../mcp/core/frontier/frontier-events.js");
const {
  routeSurfacesInternal,
} = require("../mcp/core/frontier/surface-router.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bob-y5-derivation-"));
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

function makeFrictionPayload(overrides) {
  return Object.assign({
    observation_kind: "capability_friction_observed",
    run_id: "run_y5_derivation",
    node_id: "TG-S-y5",
    wanted_tool: "bob_aptos_run",
    purpose: "fetch_target_response",
    fallback_used: "bash_curl",
    friction_kind: "tool_absent",
    detected_by: "agent_self_report",
    rationale: "needed aptos query for an evm-bridged token endpoint",
    surface_id: "web-api",
  }, overrides);
}

function seedFrictionEvent(domain, payload) {
  return appendFrontierEvent({
    target_domain: domain,
    kind: "observation.recorded",
    payload,
  });
}

test("buildWaveBriefDerivation UNIONs friction wanted_tool into allowed_tools_for_node[] (Y-P6)", () => {
  withTempHome(() => {
    const domain = uniqueDomain("y5-friction");
    const surfaceId = "web-api";
    seedSessionState(domain);
    seedAttackSurface(domain, [{
      id: surfaceId,
      surface_type: "api",
      hosts: [`https://api.${domain}`],
      title: "User and billing API",
      tech_stack: ["Express"],
      endpoints: ["/api/users"],
    }]);
    startSingleSurfaceWave(domain, surfaceId);

    const frictionPayload = makeFrictionPayload({ surface_id: surfaceId, wanted_tool: "bob_aptos_run" });
    seedFrictionEvent(domain, frictionPayload);

    const brief = JSON.parse(readAssignmentBrief({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      egress_profile: "default",
      block_internal_hosts: false,
    }));

    assert.ok(brief.wave_brief_derivation, "wave_brief_derivation slice MUST be present");
    assert.equal(brief.wave_brief_derivation.friction_history_count, 1);
    assert.ok(
      brief.wave_brief_derivation.added_tools.includes("bob_aptos_run"),
      "wanted_tool from friction history MUST be UNIONed into added_tools[] (Y-P6)",
    );
  });
});

test("buildWaveBriefDerivation wave-scopes by surface_id — other-surface frictions are excluded (Y-P5)", () => {
  withTempHome(() => {
    const domain = uniqueDomain("y5-scope");
    const surfaceA = "web-api";
    const surfaceB = "other-surface";
    seedSessionState(domain);
    seedAttackSurface(domain, [
      {
        id: surfaceA,
        surface_type: "api",
        hosts: [`https://api.${domain}`],
        title: "A",
        tech_stack: ["Express"],
        endpoints: ["/api/users"],
      },
      {
        id: surfaceB,
        surface_type: "api",
        hosts: [`https://other.${domain}`],
        title: "B",
        tech_stack: ["Express"],
        endpoints: ["/api/other"],
      },
    ]);
    startSingleSurfaceWave(domain, surfaceA);

    // Friction recorded against surfaceB MUST NOT influence the brief for
    // the surfaceA assignment.
    seedFrictionEvent(
      domain,
      makeFrictionPayload({ surface_id: surfaceB, wanted_tool: "bob_aptos_run" }),
    );

    const brief = JSON.parse(readAssignmentBrief({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      egress_profile: "default",
      block_internal_hosts: false,
    }));

    assert.ok(brief.wave_brief_derivation);
    assert.equal(brief.wave_brief_derivation.friction_history_count, 0);
    assert.equal(
      brief.wave_brief_derivation.added_tools.includes("bob_aptos_run"),
      false,
      "wave scope MUST exclude frictions recorded against different surfaces",
    );
  });
});

test("buildWaveBriefDerivation routes an EVM smart_contract surface to the EVM capability pack, not the web default (BUG-A)", () => {
  withTempHome(() => {
    // Fallback path: no surface-routes.json on disk, so the derivation must
    // route off the in-hand surfaceObj's chain_family.
    const fallbackDomain = uniqueDomain("y5-sc-evm-fallback");
    const fallback = buildWaveBriefDerivation({
      surfaceObj: { id: "sc-evm-1", surface_type: "smart_contract", chain_family: "evm" },
      surfaceId: "sc-evm-1",
      waveNumber: 1,
      frontierEvents: [],
      queuePolicy: null,
      domain: fallbackDomain,
      explicitTargetClass: null,
      includeInadequacy: false,
    });
    assert.equal(
      fallback.capability_pack,
      "smart_contract_evm",
      "EVM smart_contract surface MUST derive the EVM pack via the surfaceObj fallback, not the web default",
    );
    // The wave brief carries only the routed pack id, not the full tool union
    // (inlining it would leak cross-lens tools). A smart_contract surface
    // resolving to smart_contract_evm and never to web is the routing property
    // under test; the smart_contract_evm -> EVM tool mapping is covered by
    // test/capability-pack-derivation.test.js.
    assert.notEqual(fallback.capability_pack, "web");

    // Routes path: a real surface-routes.json produced by the canonical
    // router carries chain_family, so readSurfaceRoutesStrict resolves the
    // EVM pack the same way.
    const routesDomain = uniqueDomain("y5-sc-evm-routes");
    fs.mkdirSync(sessionDir(routesDomain), { recursive: true });
    const surfaces = [{
      id: "sc-evm-1",
      surface_type: "smart_contract",
      chain_family: "evm",
      title: "Vault",
      addresses: ["0x0000000000000000000000000000000000000001"],
      chain: "ethereum",
    }];
    routeSurfacesInternal(routesDomain, { attackSurfaceInfo: { source: "agent", document: { surfaces } } });
    const routed = buildWaveBriefDerivation({
      surfaceObj: surfaces[0],
      surfaceId: "sc-evm-1",
      waveNumber: 1,
      frontierEvents: [],
      queuePolicy: null,
      domain: routesDomain,
      explicitTargetClass: null,
      includeInadequacy: false,
    });
    assert.equal(routed.capability_pack, "smart_contract_evm");
    assert.notEqual(routed.capability_pack, "web");
  });
});

test("buildWaveBriefDerivation default quarantines tool_inadequate frictions (Y-P11)", () => {
  // Direct call rather than through the full brief: feeding tool_inadequate
  // through appendFrontierEvent requires a real witness event, but the
  // wave-scope quarantine is a property of the caller-side selector — call
  // it directly with the inadequate record to exercise the boundary.
  const derivation = buildWaveBriefDerivation({
    surfaceObj: { id: "s1", surface_type: "api" },
    surfaceId: "s1",
    waveNumber: 1,
    frontierEvents: [
      {
        kind: "observation.recorded",
        payload: {
          observation_kind: "capability_friction_observed",
          run_id: "r",
          node_id: "TG-S-1",
          wanted_tool: "bob_http_scan",
          friction_kind: "tool_inadequate",
          inadequacy_mode: "body_truncated",
          detected_by: "agent_self_report",
          surface_id: "s1",
        },
      },
    ],
    queuePolicy: null,
    explicitTargetClass: null,
    includeInadequacy: false,
  });

  assert.equal(
    derivation.friction_history_count,
    0,
    "tool_inadequate quarantined by default (Y-P11)",
  );
});

test("buildWaveBriefDerivation records an unroutable smart_contract surface as no pack, never web, without throwing", () => {
  withTempHome(() => {
    // An ambiguous smart_contract surface (no chain_family) is unroutable. The
    // wave brief must derive a null capability_pack (never the web default) and
    // must not throw — Y-D21 normally guarantees SC surfaces carry chain_family,
    // so this locks the defensive path.
    const domain = uniqueDomain("y5-sc-unroutable");
    const result = buildWaveBriefDerivation({
      surfaceObj: { id: "sc-unroutable-1", surface_type: "smart_contract" },
      surfaceId: "sc-unroutable-1",
      waveNumber: 1,
      frontierEvents: [],
      queuePolicy: null,
      domain,
      explicitTargetClass: null,
      includeInadequacy: false,
    });
    assert.equal(result.capability_pack, null, "unroutable SC derives no capability pack");
    assert.notEqual(result.capability_pack, "web", "unroutable SC is never routed to the web default");
  });
});
