"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const { getCapabilityPack, selectWebEvaluatorPack } = require("../mcp/lib/capability-packs.js");
const { buildSurfaceRoutesDocument } = require("../mcp/lib/surface-router.js");
const {
  surfaceExposesIdBearingCollection,
  surfaceIdBearingEndpoints,
} = require("../mcp/lib/offensive-idor-producer.js");

function webSurfaceInfo(domain, surface) {
  return { source: "test", document: { surfaces: [{
    id: "S-1",
    uri: `https://${domain}/api/orders/123`,
    hosts: [`https://${domain}`],
    endpoints: ["/api/orders/123"],
    ...surface,
  }] } };
}

test("web_fanout pack is a SPREAD variant of web — only evaluator_agent/id differ (no drift)", () => {
  const web = getCapabilityPack("web");
  const fanout = getCapabilityPack("web_fanout");
  assert.equal(fanout.id, "web_fanout");
  assert.equal(fanout.evaluator_agent, "evaluator-fanout");
  assert.equal(fanout.brief_profile, web.brief_profile);
  assert.equal(fanout.completion_gate, web.completion_gate);
  assert.equal(fanout.capability_pack_version, web.capability_pack_version);
  assert.deepEqual(fanout.verifier, web.verifier);
  assert.deepEqual(fanout.evidence, web.evidence);
  assert.deepEqual(fanout.role_bundles, web.role_bundles);
});

test("selectWebEvaluatorPack routes id-bearing web -> web_fanout ONLY when nesting can fire", () => {
  const web = { capability_pack: "web" };
  const pol = { max_spawn_depth: 3 };
  // id-bearing + nesting enabled -> fanout (arms the child plan)
  assert.equal(selectWebEvaluatorPack(web, { idBearing: true, spawnDepth: 3, queuePolicy: pol }).id, "web_fanout");
  // nesting disabled (depth<=1) -> flat (avoid the transition-blind downgrade for nothing)
  assert.equal(selectWebEvaluatorPack(web, { idBearing: true, spawnDepth: 1, queuePolicy: { max_spawn_depth: 1 } }).id, "web");
  // not id-bearing (and HIGH opt-in off) -> flat
  assert.equal(selectWebEvaluatorPack(web, { idBearing: false, spawnDepth: 3, queuePolicy: pol }).id, "web");
  // HIGH-priority opt-in ON -> fanout even without id-bearing
  assert.equal(selectWebEvaluatorPack(web, { idBearing: false, highPriority: true, spawnDepth: 3, queuePolicy: { max_spawn_depth: 3, web_fanout_on_high_priority: true } }).id, "web_fanout");
  // operator opt-out -> flat
  assert.equal(selectWebEvaluatorPack(web, { idBearing: true, spawnDepth: 3, queuePolicy: { max_spawn_depth: 3, route_high_value_to_fanout: false } }).id, "web");
  // multi-auth is NOT a trigger (session-global precondition, not high-value)
  assert.equal(selectWebEvaluatorPack(web, { idBearing: false, spawnDepth: 3, queuePolicy: pol }).id, "web");
  // SC/OSS surfaces are never rerouted
  assert.equal(selectWebEvaluatorPack({ capability_pack: "evm" }, { idBearing: true, spawnDepth: 3, queuePolicy: pol }), null);
});

test("routing to web_fanout PRESERVES the earned-done obligation (id_bearing + flag + frozen endpoints untouched)", () => {
  const domain = "web-fanout.example.com";
  const doc = buildSurfaceRoutesDocument(domain, {
    attackSurfaceInfo: webSurfaceInfo(domain, { priority: "HIGH" }),
    idBearingDetector: surfaceExposesIdBearingCollection,
    idBearingEndpoints: surfaceIdBearingEndpoints,
    authProfileCount: 2,
    queuePolicy: { max_spawn_depth: 3 },
  });
  const route = doc.routes.find((r) => r.surface_id === "S-1");
  // Nesting is armed:
  assert.equal(route.capability_pack, "web_fanout");
  assert.equal(route.evaluator_agent, "evaluator-fanout");
  // EARNED-DONE SURVIVES THE REROUTE: the completion obligation fields are untouched. A child
  // sub-evaluator reuses the parent (wave,agent) and re-reads THIS assignment, so the AD1 gate
  // still fires — nesting cannot bypass the just-shipped earned-done gate.
  assert.equal(route.id_bearing, true);
  assert.equal(route.auth_differential_required, true);
  assert.deepEqual(route.id_bearing_endpoints, ["/api/orders/{id}"]);
});

test("flag OFF keeps an id-bearing web surface on the flat evaluator-agent (earned-done still applies)", () => {
  const domain = "web-fanout-off.example.com";
  const doc = buildSurfaceRoutesDocument(domain, {
    attackSurfaceInfo: webSurfaceInfo(domain, {}),
    idBearingDetector: surfaceExposesIdBearingCollection,
    idBearingEndpoints: surfaceIdBearingEndpoints,
    authProfileCount: 2,
    queuePolicy: { max_spawn_depth: 3, route_high_value_to_fanout: false },
  });
  const route = doc.routes.find((r) => r.surface_id === "S-1");
  assert.equal(route.capability_pack, "web");
  assert.equal(route.evaluator_agent, "evaluator-agent");
  assert.equal(route.id_bearing, true);
  assert.equal(route.auth_differential_required, true);
});
