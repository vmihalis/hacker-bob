"use strict";

// bob_finalize_node auto-synthesizes capability_friction_observed on an X.6
// tool_constraint_violation so the friction→pack-widening loop does not depend
// on voluntary agent reporting. Each violating tool the agent reached for
// outside allowed_tools_for_node[] becomes exactly one tool_absent synthetic
// (detected_by = "mcp_runtime_auto_emit"), idempotent via the Y-P3 6-tuple, and
// coexisting with any voluntary agent_self_report for the same tool (Y-P11).

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const { TOOL_HANDLERS } = require("../mcp/core/dispatch/tool-registry.js");
const {
  appendFrontierEvent,
  readFrontierEvents,
  capabilityFrictionPayloads,
} = require("../mcp/core/frontier/frontier-events.js");
const {
  TASK_GRAPH_NODE_ID_PREFIX,
  appendHypothesisProposal,
} = require("../mcp/core/waves/task-graph-events.js");
const {
  materializeTaskGraph,
} = require("../mcp/core/waves/task-graph-materializer.js");
const {
  appendContract,
} = require("../mcp/core/contract/index.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-auto-friction-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function seedSession(domain) {
  appendFrontierEvent({
    target_domain: domain,
    kind: "surface.observed",
    ts: "2026-05-31T00:00:00.000Z",
    surface_id: "surface:auth",
    payload: { title: "seed" },
  });
}

const KNOWN_TOOL = "bob_http_scan";

function baseContractInput({
  contractId = "C-auto-friction-base",
  severity = "high",
  predicate = { tool: KNOWN_TOOL, match: { path: "$.status", equals: 200 } },
} = {}) {
  return {
    contract_id: contractId,
    severity_floor: severity,
    invariants: [{ id: "I1", statement: "Auth token cannot escalate roles." }],
    witnesses: [{ id: "W1", kind: "tool_output_match", predicate }],
    production_paths: [{
      description: "Invoke the canonical web producer.",
      tool_call_pattern: [{ tool: KNOWN_TOOL }],
    }],
  };
}

function seedContractedNode(domain, proposalId, surfaceRefs = ["surface:auth"]) {
  appendHypothesisProposal({
    target_domain: domain,
    ts: "2026-05-31T00:01:00.000Z",
    hypothesis_statement: "An attacker can replay JWTs against the EVM vault.",
    surface_refs: surfaceRefs,
    proposal_id: proposalId,
  });
  materializeTaskGraph(domain, { write: true });
  const nodeId = `${TASK_GRAPH_NODE_ID_PREFIX}H-${proposalId}`;
  appendContract({
    target_domain: domain,
    node_id: nodeId,
    contract: baseContractInput(),
    ts: "2026-05-31T00:02:00.000Z",
  });
  materializeTaskGraph(domain, { write: true });
  return nodeId;
}

function autoEmitFrictionsFor(domain, wantedTool) {
  return capabilityFrictionPayloads(readFrontierEvents(domain), {}).filter(
    (p) => p.detected_by === "mcp_runtime_auto_emit" && p.wanted_tool === wantedTool,
  );
}

test("finalize_node auto-emits exactly one tool_absent friction per violating tool, idempotent across re-finalize, coexisting with a voluntary self-report", () => {
  withTempHome(() => {
    const domain = "auto-friction.example.com";
    seedSession(domain);
    const nodeId = seedContractedNode(domain, "HP-auto-friction");

    const prep = JSON.parse(TOOL_HANDLERS.bob_prepare_node({
      target_domain: domain,
      node_id: nodeId,
    }));
    // Out-of-band tool: registered (so agent_output is parseable) but outside
    // the routed pack for this Hypothesis node.
    const outOfBand = "bob_init_session";
    assert.ok(
      !prep.allowed_tools_for_node.includes(outOfBand),
      `precondition: ${outOfBand} must be outside allowed_tools_for_node[]`,
    );

    // ── First finalize → tool_constraint_violation + one synthetic ──────────
    const result = JSON.parse(TOOL_HANDLERS.bob_finalize_node({
      target_domain: domain,
      node_id: nodeId,
      prep_token: prep.prep_token,
      agent_output: {
        tool_invocations: [
          { tool: KNOWN_TOOL, output: { status: 200 } },
          { tool: outOfBand, args: { target_url: "https://example.com" } },
        ],
      },
    }));
    assert.equal(result.to_state, "failed");
    assert.equal(result.failure_reason.reason, "tool_constraint_violation");

    let synthetics = autoEmitFrictionsFor(domain, outOfBand);
    assert.equal(synthetics.length, 1, "exactly one synthetic on first finalize");
    const synthetic = synthetics[0];
    assert.equal(synthetic.detected_by, "mcp_runtime_auto_emit");
    assert.equal(synthetic.wanted_tool, outOfBand);
    assert.equal(synthetic.friction_kind, "tool_absent");
    assert.equal(synthetic.node_id, nodeId);
    // No impossible witness ref on a tool_absent synthetic (Y-P11 disjointness).
    assert.equal(synthetic.inadequate_invocation_ref, undefined);
    assert.equal(synthetic.inadequacy_mode, undefined);

    // surface_id equals the seeded node's surface_refs[0].
    const liveDoc = materializeTaskGraph(domain, { write: false }).document;
    const liveNode = liveDoc.nodes.find((n) => n.node_id === nodeId);
    const expectedSurface = liveNode.surface_refs[0];
    assert.ok(
      typeof expectedSurface === "string" && expectedSurface.length > 0,
      "seeded node carries a non-empty surface_refs[0]",
    );
    assert.equal(synthetic.surface_id, expectedSurface);

    // ── Re-contract failed→contracted, re-prepare, re-finalize (idempotent) ──
    const reAttach = JSON.parse(TOOL_HANDLERS.bob_attach_contract({
      target_domain: domain,
      node_id: nodeId,
      contract: baseContractInput({ contractId: "C-auto-friction-retry" }),
    }));
    assert.equal(reAttach.from_state, "failed", "re-contract emits failed → contracted");
    assert.equal(reAttach.to_state, "contracted");
    materializeTaskGraph(domain, { write: true });

    const prep2 = JSON.parse(TOOL_HANDLERS.bob_prepare_node({
      target_domain: domain,
      node_id: nodeId,
    }));
    assert.ok(
      !prep2.allowed_tools_for_node.includes(outOfBand),
      "precondition holds on re-prepare",
    );
    const result2 = JSON.parse(TOOL_HANDLERS.bob_finalize_node({
      target_domain: domain,
      node_id: nodeId,
      prep_token: prep2.prep_token,
      agent_output: {
        tool_invocations: [
          { tool: KNOWN_TOOL, output: { status: 200 } },
          { tool: outOfBand, args: { target_url: "https://example.com" } },
        ],
      },
    }));
    assert.equal(result2.to_state, "failed");
    assert.equal(result2.failure_reason.reason, "tool_constraint_violation");

    synthetics = autoEmitFrictionsFor(domain, outOfBand);
    assert.equal(
      synthetics.length,
      1,
      "idempotent: re-finalize with the same runId fallback does NOT double-count",
    );

    // ── Coexistence (Y-P11): a voluntary agent_self_report for the SAME tool ─
    JSON.parse(TOOL_HANDLERS.bob_log_capability_friction({
      target_domain: domain,
      run_id: "voluntary-run",
      node_id: nodeId,
      wanted_tool: outOfBand,
      purpose: "other",
      fallback_used: "none",
      friction_kind: "tool_absent",
      detected_by: "agent_self_report",
      rationale: "Voluntary self-report for the same wanted_tool.",
    }));

    const allForTool = capabilityFrictionPayloads(readFrontierEvents(domain), {}).filter(
      (p) => p.wanted_tool === outOfBand,
    );
    assert.equal(allForTool.length, 2, "voluntary + synthetic coexist for the same tool");
    const detectedBySet = new Set(allForTool.map((p) => p.detected_by));
    assert.deepEqual(
      [...detectedBySet].sort(),
      ["agent_self_report", "mcp_runtime_auto_emit"],
      "distinct detected_by legs keep voluntary and synthetic separate (Y-P11)",
    );
  });
});
