"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  CAPABILITY_PACKS,
  dispatchableCapabilityPacks,
  getCapabilityPack,
  selectWebEvaluatorPack,
  techniqueCompatibilityPackId,
} = require("../mcp/core/capability/capability-packs.js");
const { buildSurfaceRoutesDocument } = require("../mcp/core/frontier/surface-router.js");
const {
  surfaceExposesIdBearingCollection,
  surfaceIdBearingEndpoints,
} = require("../mcp/domains/web/offensive-idor-producer.js");

function withClaudeHost(fn, { agentTeams = true } = {}) {
  // The router gates the reroute on the HOST-AWARE effective spawn depth (effectiveSpawnDepth
  // returns 1 when Claude's agent-teams flag is absent), so a web_fanout route only appears
  // on an explicitly enabled Claude runtime.
  const prev = process.env.BOB_CLIENT;
  const prevAgentTeams = process.env.CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS;
  process.env.BOB_CLIENT = "claude";
  if (agentTeams) process.env.CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS = "1";
  else delete process.env.CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS;
  try {
    return fn();
  } finally {
    if (prev === undefined) delete process.env.BOB_CLIENT;
    else process.env.BOB_CLIENT = prev;
    if (prevAgentTeams === undefined) delete process.env.CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS;
    else process.env.CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS = prevAgentTeams;
  }
}

function webSurfaceInfo(domain, surface) {
  return { source: "test", document: { surfaces: [{
    id: "S-1",
    uri: `https://${domain}/api/orders/123`,
    hosts: [`https://${domain}`],
    endpoints: ["/api/orders/123"],
    // Non-empty so the fan-out will actually produce (bug_class × auth) cells; without cells the
    // router keeps the surface flat (no transition-blind role for a fan-out that won't fire).
    bug_class_hints: ["idor"],
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
  assert.equal(fanout.technique_compatibility_pack, "web");
  assert.equal(techniqueCompatibilityPackId("web_fanout"), "web");
  assert.equal(techniqueCompatibilityPackId("smart_contract_evm"), "smart_contract_evm");
});

test("technique compatibility targets are closed, known, and self-resolving for every dispatchable capability pack", () => {
  for (const packId of dispatchableCapabilityPacks().map((pack) => pack.id)) {
    const targetId = techniqueCompatibilityPackId(packId);
    assert.ok(CAPABILITY_PACKS[targetId], `${packId} must resolve to a registered technique target`);
    assert.equal(
      techniqueCompatibilityPackId(targetId),
      targetId,
      `${packId} must terminate at a canonical self-resolving target (no chains or cycles)`,
    );
  }
  assert.equal(techniqueCompatibilityPackId("physical"), null);
});

test("technique compatibility is directed from consumer to canonical target, not variant equivalence", () => {
  const { assertTechniquePackMatchesCapability } = require("../mcp/core/dispatch/technique-packs.js");
  const canonicalWebTechnique = { id: "canonical-web", capability_packs: ["web"] };
  const variantTaggedTechnique = { id: "variant-only", capability_packs: ["web_fanout"] };

  assert.doesNotThrow(() => assertTechniquePackMatchesCapability(canonicalWebTechnique, "web"));
  assert.doesNotThrow(() => assertTechniquePackMatchesCapability(canonicalWebTechnique, "web_fanout"));
  assert.throws(
    () => assertTechniquePackMatchesCapability(variantTaggedTechnique, "web"),
    /not compatible with capability_pack web/,
  );
  assert.throws(
    () => assertTechniquePackMatchesCapability(variantTaggedTechnique, "web_fanout"),
    /not compatible with capability_pack web_fanout/,
  );
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

test("routing to web_fanout PRESERVES the earned-done obligation (id_bearing + flag + frozen endpoints untouched)", () => withClaudeHost(() => {
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
}));

test("default Claude stays flat when the experimental agent-teams runtime flag is absent", () => withClaudeHost(() => {
  const domain = "web-fanout-agent-teams-off.example.com";
  const doc = buildSurfaceRoutesDocument(domain, {
    attackSurfaceInfo: webSurfaceInfo(domain, { priority: "HIGH" }),
    idBearingDetector: surfaceExposesIdBearingCollection,
    idBearingEndpoints: surfaceIdBearingEndpoints,
    authProfileCount: 2,
    queuePolicy: { max_spawn_depth: 3 },
  });
  const route = doc.routes.find((entry) => entry.surface_id === "S-1");
  assert.equal(route.capability_pack, "web");
  assert.equal(route.evaluator_agent, "evaluator-agent");
  assert.equal(route.id_bearing, true, "the security obligation is independent of host topology");
}, { agentTeams: false }));

test("flag OFF keeps an id-bearing web surface on the flat evaluator-agent (earned-done still applies)", () => withClaudeHost(() => {
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
}));

test("a NON-claude host keeps an id-bearing web surface FLAT (host-blind routing fix — no transition-blind downgrade for a fan-out that can never fire)", () => {
  const prev = process.env.BOB_CLIENT;
  process.env.BOB_CLIENT = "codex";
  try {
    const domain = "web-fanout-nonclaude.example.com";
    const doc = buildSurfaceRoutesDocument(domain, {
      attackSurfaceInfo: webSurfaceInfo(domain, { priority: "HIGH" }),
      idBearingDetector: surfaceExposesIdBearingCollection,
      idBearingEndpoints: surfaceIdBearingEndpoints,
      authProfileCount: 2,
      queuePolicy: { max_spawn_depth: 3 },
    });
    const route = doc.routes.find((r) => r.surface_id === "S-1");
    // On a non-nesting host, effectiveSpawnDepth clamps to 1, so the surface stays flat.
    assert.equal(route.capability_pack, "web");
    assert.equal(route.evaluator_agent, "evaluator-agent");
    // Earned-done still applies (id_bearing is host-independent).
    assert.equal(route.id_bearing, true);
    assert.equal(route.auth_differential_required, true);
  } finally {
    if (prev === undefined) delete process.env.BOB_CLIENT;
    else process.env.BOB_CLIENT = prev;
  }
});

test("bob_write_wave_handoff PERSISTS discovered_pivots (the transition-blind fanout role's pivot uplink)", () => {
  const prevHome = process.env.HOME;
  process.env.HOME = fs.mkdtempSync(path.join(os.tmpdir(), "web-fanout-pivots-"));
  try {
    const paths = require("../mcp/core/io/paths.js");
    const { initSession, advanceSession } = require("../mcp/core/session/session-state.js");
    const { startWave, writeWaveHandoff } = require("../mcp/core/waves/waves.js");
    const domain = "pivots.example.com";
    JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}` }));
    fs.writeFileSync(paths.attackSurfacePath(domain), JSON.stringify({ surfaces: [
      { id: "S-1", uri: `https://${domain}/api/orders/1`, hosts: [`https://${domain}`], endpoints: ["/api/orders/1"] },
    ] }));
    JSON.parse(advanceSession({ target_domain: domain, to_state: "OPEN_FRONTIER" }));
    const started = JSON.parse(startWave({ target_domain: domain, wave_number: 1, assignments: [{ agent: "a1", surface_id: "S-1" }] }));
    JSON.parse(writeWaveHandoff({
      target_domain: domain, wave: "w1", agent: "a1", surface_id: "S-1", surface_status: "partial",
      handoff_token: started.assignments[0].handoff_token, summary: "s", content: "# H",
      discovered_pivots: [{ from_surface: "S-1", to_surface: "S-2", kind: "shared_session", trust_assumption: "same cookie jar" }],
    }));
    const json = JSON.parse(fs.readFileSync(path.join(paths.sessionDir(domain), "handoff-w1-a1.json"), "utf8"));
    // Previously dropped from the handoff literal — a transition-blind evaluator-fanout's only
    // documented cross-surface uplink would be silently lost. It is now signed onto the handoff.
    assert.deepEqual(json.discovered_pivots, [{ from_surface: "S-1", to_surface: "S-2", kind: "shared_session", trust_assumption: "same cookie jar" }]);
  } finally {
    if (prevHome === undefined) delete process.env.HOME;
    else process.env.HOME = prevHome;
  }
});

test("child_fanout_plan is nesting-level aware — a nested re-read DECREMENTS and leafs out (no runaway recursion)", () => {
  const prevHome = process.env.HOME;
  const prevClient = process.env.BOB_CLIENT;
  const prevAgentTeams = process.env.CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS;
  process.env.HOME = fs.mkdtempSync(path.join(os.tmpdir(), "web-fanout-depth-"));
  process.env.BOB_CLIENT = "claude";
  try {
    const { buildChildFanoutPlanForSurface } = require("../mcp/core/session/assignment-brief.js");
    const { initSession } = require("../mcp/core/session/session-state.js");
    const domain = "nest-depth.example.com";
    JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}` }));
    const surfaceObj = { id: "S-1", uri: `https://${domain}/api/orders/1`, bug_class_hints: ["idor"] };
    const args = { domain, surfaceObj, surfaceId: "S-1", coverageSummary: null, wave: "w1" };
    delete process.env.CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS;
    assert.equal(buildChildFanoutPlanForSurface(args), null,
      "default Claude emits no child plan while agent teams are disabled");
    process.env.CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS = "1";
    // Claude's native ceiling is two evaluator levels: the wave root gets one
    // child edge even though the queue policy requests depth 3.
    assert.equal(buildChildFanoutPlanForSurface(args).remaining_depth, 1);
    // The spawned child receives the decremented depth 0 and is therefore a
    // leaf; Bob's child role has no Agent grant and cannot recursively spawn.
    assert.equal(buildChildFanoutPlanForSurface({ ...args, remainingDepthOverride: 0 }), null);
  } finally {
    if (prevHome === undefined) delete process.env.HOME; else process.env.HOME = prevHome;
    if (prevClient === undefined) delete process.env.BOB_CLIENT; else process.env.BOB_CLIENT = prevClient;
    if (prevAgentTeams === undefined) delete process.env.CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS;
    else process.env.CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS = prevAgentTeams;
  }
});

test("selectTechniquePacksForSurface treats web_fanout as web (no technique-guidance loss on reroute)", () => {
  const { selectTechniquePacksForSurface } = require("../mcp/core/dispatch/technique-packs.js");
  const surface = { id: "S-1", uri: "https://x.example.com/api/orders/123", hosts: ["https://x.example.com"] };
  const web = selectTechniquePacksForSurface(surface, { capabilityPack: "web" });
  const fanout = selectTechniquePacksForSurface(surface, { capabilityPack: "web_fanout" });
  assert.ok(web.selected.length > 0, "web must yield technique packs");
  assert.deepEqual(fanout.selected.map((p) => p.id), web.selected.map((p) => p.id),
    "web_fanout must get the SAME technique packs as web");
});

test("web_fanout technique compatibility survives select -> full read -> completion log -> finalize while unrelated packs remain rejected", () => {
  const prevHome = process.env.HOME;
  const prevClient = process.env.BOB_CLIENT;
  const prevAgentTeams = process.env.CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS;
  process.env.HOME = fs.mkdtempSync(path.join(os.tmpdir(), "web-fanout-techniques-"));
  process.env.BOB_CLIENT = "claude";
  process.env.CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS = "1";
  try {
    const paths = require("../mcp/core/io/paths.js");
    const { initSession, advanceSession } = require("../mcp/core/session/session-state.js");
    const { startWave, writeWaveHandoff } = require("../mcp/core/waves/waves.js");
    const {
      logTechniqueAttempt,
      readTechniquePackForTool,
      readTechniquePackReadRecordsFromJsonl,
      selectTechniquePacks,
    } = require("../mcp/core/dispatch/technique-packs.js");
    const { finalizeAgentRun } = require("../mcp/core/session/agent-run-completion.js");
    const { mergeWaveHandoffsInternal } = require("../mcp/core/waves/wave-handoff-store.js");
    const { ERROR_CODES, ToolError } = require("../mcp/core/io/envelope.js");

    const domain = "web-fanout-techniques.example.com";
    JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}` }));
    fs.writeFileSync(paths.attackSurfacePath(domain), JSON.stringify({ surfaces: [
      {
        id: "S-web",
        uri: `https://${domain}/api/orders/123`,
        hosts: [`https://${domain}`],
        endpoints: ["/api/orders/123"],
        bug_class_hints: ["idor"],
      },
      {
        id: "S-evm",
        surface_type: "smart_contract",
        chain_family: "evm",
      },
    ] }));
    JSON.parse(advanceSession({ target_domain: domain, to_state: "OPEN_FRONTIER" }));
    const started = JSON.parse(startWave({
      target_domain: domain,
      wave_number: 1,
      assignments: [
        { agent: "a1", surface_id: "S-web" },
        { agent: "a2", surface_id: "S-evm" },
      ],
    }));
    const webAssignment = started.assignments.find((entry) => entry.agent === "a1");
    const evmAssignment = started.assignments.find((entry) => entry.agent === "a2");
    assert.equal(webAssignment.capability_pack, "web_fanout");
    assert.equal(evmAssignment.capability_pack, "smart_contract_evm");

    const selection = JSON.parse(selectTechniquePacks({
      target_domain: domain,
      surface_id: "S-web",
    }));
    assert.equal(selection.capability_pack, "web_fanout", "route metadata remains the routing variant");
    assert.ok(selection.technique_packs.length > 0);
    const packId = selection.technique_packs[0].id;
    assert.ok(selection.technique_packs[0].capability_packs.includes("web"));

    const full = JSON.parse(readTechniquePackForTool({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "S-web",
      pack_id: packId,
      mode: "full",
    }));
    assert.equal(full.mode, "full");
    assert.equal(full.technique_pack.id, packId);
    assert.equal(full.full_read_budget.full_packs_read, 1);
    const readRows = readTechniquePackReadRecordsFromJsonl(domain);
    assert.equal(readRows.length, 1);
    assert.equal(readRows[0].capability_pack, "web_fanout", "audit metadata preserves the assigned route");

    for (const operation of [
      () => readTechniquePackForTool({
        target_domain: domain,
        wave: "w1",
        agent: "a2",
        surface_id: "S-evm",
        pack_id: packId,
        mode: "full",
      }),
      () => logTechniqueAttempt({
        target_domain: domain,
        wave: "w1",
        agent: "a2",
        surface_id: "S-evm",
        pack_id: packId,
        status: "attempted",
        evidence: "A web-only technique must not be accepted for an unrelated EVM assignment.",
      }),
    ]) {
      assert.throws(operation, (error) => {
        assert.ok(error instanceof ToolError);
        assert.equal(error.code, ERROR_CODES.INVALID_ARGUMENTS);
        assert.match(error.message, /not compatible with capability_pack smart_contract_evm/);
        return true;
      });
    }

    const logged = JSON.parse(logTechniqueAttempt({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "S-web",
      pack_id: packId,
      status: "attempted",
      evidence: "Executed the selected web technique against the assigned fanout surface.",
    }));
    assert.equal(logged.appended, 1);
    assert.equal(logged.record.capability_pack, "web_fanout", "attempt metadata preserves the assigned route");

    JSON.parse(writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "S-web",
      surface_status: "partial",
      handoff_token: webAssignment.handoff_token,
      summary: "Technique executed; the surface remains partial for further auth-depth work.",
      content: "# Web fanout technique regression handoff",
    }));
    const finalized = JSON.parse(finalizeAgentRun({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "S-web",
    }));
    assert.equal(finalized.status, "allowed");
    assert.equal(finalized.handoff.surface_status, "partial");

    const { merge } = mergeWaveHandoffsInternal(domain, 1);
    assert.ok(merge.received_agents.includes("a1"));
    assert.ok(merge.provenance.verified_agents.includes("a1"));
    assert.ok(merge.partial_surface_ids.includes("S-web"));
    assert.ok(!merge.missing_surface_ids.includes("S-web"));
  } finally {
    fs.rmSync(process.env.HOME, { recursive: true, force: true });
    if (prevHome === undefined) delete process.env.HOME; else process.env.HOME = prevHome;
    if (prevClient === undefined) delete process.env.BOB_CLIENT; else process.env.BOB_CLIENT = prevClient;
    if (prevAgentTeams === undefined) delete process.env.CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS;
    else process.env.CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS = prevAgentTeams;
  }
});
