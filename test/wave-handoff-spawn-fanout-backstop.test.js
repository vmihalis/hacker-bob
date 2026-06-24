"use strict";

// Live detective backstop on actuated fan-out at the MCP-owned wave-handoff
// write site. The pure validator (validateSpawnFanout in nested-spawn.js) is
// unit-tested in nested-spawn.test.js; these tests prove it is WIRED at a live
// enforcement point so a worker that self-reports a child outside its
// brain-derived spawn budget is mechanically rejected, while:
//   - a leaf worker that reports NO children writes its handoff unchanged
//     (no regression for every normal evaluator and the flat fan-out workers),
//   - the opt-in nested spawn-capable evaluator that reports a child of the
//     pinned spawn type within its budget still succeeds.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const { attackSurfacePath, sessionDir } = require("../mcp/lib/paths.js");
const { writeFileAtomic } = require("../mcp/lib/storage.js");
const { initSession, advanceSession } = require("../mcp/lib/session-state.js");
const { startWave } = require("../mcp/lib/waves.js");
const { writeWaveHandoff } = require("../mcp/lib/waves/wave-assignment-store.js");
const {
  DEFAULT_QUEUE_POLICY,
  LEAN_PROFILE,
  normalizeQueuePolicy,
  writeQueuePolicy,
} = require("../mcp/lib/queue-policy.js");

const HINTS = ["idor", "ssrf", "xss", "ssti", "auth_bypass"];
const SPAWN_CHILD_TYPE = "evaluator-fanout";

function withClaudeHome(fn) {
  const prevHome = process.env.HOME;
  const prevClient = process.env.BOB_CLIENT;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-spawn-backstop-"));
  process.env.HOME = home;
  process.env.BOB_CLIENT = "claude"; // nesting is claude-only
  try {
    return fn(home);
  } finally {
    process.env.HOME = prevHome;
    if (prevClient === undefined) delete process.env.BOB_CLIENT;
    else process.env.BOB_CLIENT = prevClient;
    try { fs.rmSync(home, { recursive: true, force: true }); } catch {}
  }
}

function seedSurfaces(domain, surfaces) {
  writeFileAtomic(attackSurfacePath(domain), `${JSON.stringify({ surfaces }, null, 2)}\n`);
}

function bootstrap(domain, surfaces, policyOverride) {
  JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}` }));
  seedSurfaces(domain, surfaces);
  JSON.parse(advanceSession({ target_domain: domain, to_state: "OPEN_FRONTIER" }));
  writeQueuePolicy(domain, normalizeQueuePolicy({ ...DEFAULT_QUEUE_POLICY, ...policyOverride }));
}

function startAndToken(domain, surfaceId, agent = "a1") {
  const start = JSON.parse(startWave({
    target_domain: domain,
    wave_number: 1,
    assignments: [{ agent, surface_id: surfaceId }],
  }));
  return start.assignments[0].handoff_token;
}

function baseHandoffArgs(domain, surfaceId, token, agent = "a1") {
  return {
    target_domain: domain,
    wave: "w1",
    agent,
    surface_id: surfaceId,
    surface_status: "complete",
    handoff_token: token,
    summary: "surface fully covered",
    content: "# Handoff\n\nFinal handoff body",
  };
}

test("a leaf worker that reports a spawned child is mechanically rejected at the write site", () => {
  withClaudeHome(() => {
    const domain = "leaf-rejects.example.com";
    const surfaceId = "surface:api";
    // Lean override (depth 1) => no nesting plan => depth-0 leaf budget for every
    // worker, so a leaf reporting a child must be rejected at the write site.
    bootstrap(domain, [{ id: surfaceId, hosts: [`https://${domain}`], priority: "HIGH", bug_class_hints: HINTS }], LEAN_PROFILE);
    const token = startAndToken(domain, surfaceId);

    assert.throws(
      () => writeWaveHandoff({
        ...baseHandoffArgs(domain, surfaceId, token),
        spawned_children: [{ subagent_type: SPAWN_CHILD_TYPE }],
      }),
      /spawn budget|leaf evaluator must not fan out/i,
      "a leaf reporting a child must be rejected",
    );
    // The rejection happens before the handoff lands on disk.
    assert.equal(
      fs.existsSync(path.join(sessionDir(domain), "handoff-w1-a1.json")),
      false,
      "no handoff JSON is written when the spawn budget is violated",
    );
  });
});

test("a leaf worker that reports no children writes its handoff unchanged", () => {
  withClaudeHome(() => {
    const domain = "leaf-clean.example.com";
    const surfaceId = "surface:api";
    bootstrap(domain, [{ id: surfaceId, hosts: [`https://${domain}`], priority: "HIGH", bug_class_hints: HINTS }], {});
    const token = startAndToken(domain, surfaceId);

    const result = JSON.parse(writeWaveHandoff(baseHandoffArgs(domain, surfaceId, token)));
    assert.ok(result.written_json, "the handoff is written when no children are reported");
    const handoff = JSON.parse(fs.readFileSync(result.written_json, "utf8"));
    assert.deepEqual(handoff.spawned_children, [], "an empty spawned_children round-trips");
  });
});

test("an empty spawned_children array on a leaf worker is accepted", () => {
  withClaudeHome(() => {
    const domain = "leaf-empty-array.example.com";
    const surfaceId = "surface:api";
    bootstrap(domain, [{ id: surfaceId, hosts: [`https://${domain}`], priority: "HIGH", bug_class_hints: HINTS }], {});
    const token = startAndToken(domain, surfaceId);

    const result = JSON.parse(writeWaveHandoff({
      ...baseHandoffArgs(domain, surfaceId, token),
      spawned_children: [],
    }));
    assert.ok(result.written_json, "an explicit empty array is within a leaf budget");
  });
});

test("an opt-in nested spawn-capable worker may report a child of the pinned type within budget", () => {
  withClaudeHome(() => {
    const domain = "nested-parent.example.com";
    const surfaceId = "surface:api";
    // Opt into nesting (depth>1) on the claude host so the surface gets a real
    // fan-out plan with remaining_depth>0 and a positive child width.
    bootstrap(domain, [{ id: surfaceId, hosts: [`https://${domain}`], priority: "HIGH", bug_class_hints: HINTS }], {
      max_spawn_depth: 3,
      max_spawn_children: 8,
    });
    const token = startAndToken(domain, surfaceId);

    const result = JSON.parse(writeWaveHandoff({
      ...baseHandoffArgs(domain, surfaceId, token),
      spawned_children: [{ subagent_type: SPAWN_CHILD_TYPE }],
    }));
    assert.ok(result.written_json, "a budgeted nested parent's reported child is accepted");
    const handoff = JSON.parse(fs.readFileSync(result.written_json, "utf8"));
    assert.equal(handoff.spawned_children.length, 1, "the reported child round-trips into the handoff");
    assert.equal(handoff.spawned_children[0].subagent_type, SPAWN_CHILD_TYPE);
  });
});

test("a nested worker that reports a child of a foreign subagent type is rejected", () => {
  withClaudeHome(() => {
    const domain = "nested-foreign-type.example.com";
    const surfaceId = "surface:api";
    bootstrap(domain, [{ id: surfaceId, hosts: [`https://${domain}`], priority: "HIGH", bug_class_hints: HINTS }], {
      max_spawn_depth: 3,
      max_spawn_children: 8,
    });
    const token = startAndToken(domain, surfaceId);

    assert.throws(
      () => writeWaveHandoff({
        ...baseHandoffArgs(domain, surfaceId, token),
        spawned_children: [{ subagent_type: "chain" }],
      }),
      /allowlist|spawn budget/i,
      "a child outside the pinned spawn-type allowlist must be rejected even when nesting is on",
    );
  });
});
