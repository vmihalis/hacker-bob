"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  readPipelineAnalytics,
} = require("../mcp/core/telemetry/pipeline-analytics.js");
const { appendFrontierEvent } = require("../mcp/core/frontier/frontier-events.js");
const { initSession } = require("../mcp/core/session/session-state.js");
const { sessionDir, surfaceRoutesPath } = require("../mcp/core/io/paths.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-pack-friction-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    if (previousHome === undefined) delete process.env.HOME;
    else process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

// Seed a real session with (i) one routable surface route (web pack) and
// (ii) a capability_friction_observed frontier event for that surface with a
// known wanted_tool, so the analytics row carries a pack_friction_summary that
// joins surface_id -> capability_pack.
function seedSession(domain, { surfaceId, wantedTool }) {
  initSession({ target_domain: domain, target_url: `https://${domain}/` });
  fs.mkdirSync(sessionDir(domain), { recursive: true });
  // A valid, routable surface route: readSurfaceRoutesStrict validates
  // capability_pack/evaluator_agent/brief_profile against the pack registry, so
  // the "web" pack fields must match.
  const routesDocument = {
    version: 1,
    route_version: 1,
    routes: [
      {
        surface_id: surfaceId,
        capability_pack: "web",
        capability_pack_version: 1,
        evaluator_agent: "evaluator-agent",
        brief_profile: "web",
      },
    ],
  };
  fs.writeFileSync(surfaceRoutesPath(domain), `${JSON.stringify(routesDocument, null, 2)}\n`, "utf8");
  appendFrontierEvent({
    target_domain: domain,
    kind: "observation.recorded",
    surface_id: surfaceId,
    payload: {
      observation_kind: "capability_friction_observed",
      surface_id: surfaceId,
      friction_kind: "tool_absent",
      wanted_tool: wantedTool,
    },
    source: { artifact: "wave-merge", tool: "bob_log_capability_friction" },
  });
}

test("pack_friction_summary appears in a mode:\"session\" analytics row", () => {
  withTempHome(() => {
    const domain = "pack-friction-session.example.com";
    const surfaceId = "surface-ws";
    const wantedTool = "bob_ws_probe";
    seedSession(domain, { surfaceId, wantedTool });

    const analytics = JSON.parse(readPipelineAnalytics({ target_domain: domain }));
    assert.equal(analytics.mode, "session");
    const row = analytics.sessions[0];
    const summary = row.pack_friction_summary;
    assert.ok(summary, "row must carry pack_friction_summary");
    assert.ok(summary.web, "web pack bucket must be present");
    assert.ok(summary.web[wantedTool], "wanted_tool bucket must be present");
    assert.ok(summary.web[wantedTool].count >= 1);
    assert.ok(summary.web[wantedTool].surface_ids.includes(surfaceId));
  });
});

test("pack_friction_summary appears in a mode:\"cross_session\" analytics row (U1 rollup gap closed)", () => {
  withTempHome(() => {
    const domain = "pack-friction-cross.example.com";
    const surfaceId = "surface-ws";
    const wantedTool = "bob_ws_probe";
    seedSession(domain, { surfaceId, wantedTool });

    const analytics = JSON.parse(readPipelineAnalytics({}));
    assert.equal(analytics.mode, "cross_session");
    const row = analytics.sessions.find((s) => s.target_domain === domain);
    assert.ok(row, "the seeded session must appear in the cross-session rollup");
    const summary = row.pack_friction_summary;
    assert.ok(summary, "cross-session row must carry pack_friction_summary");
    assert.ok(summary.web && summary.web[wantedTool], "web/wanted_tool bucket must be present");
    assert.ok(summary.web[wantedTool].surface_ids.includes(surfaceId));
  });
});

test("a session with no routes or frontier log fails open to pack_friction_summary: {}", () => {
  withTempHome(() => {
    const domain = "pack-friction-empty.example.com";
    initSession({ target_domain: domain, target_url: `https://${domain}/` });

    const analytics = JSON.parse(readPipelineAnalytics({ target_domain: domain }));
    assert.deepEqual(analytics.sessions[0].pack_friction_summary, {});
  });
});
