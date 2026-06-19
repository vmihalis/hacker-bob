"use strict";

// Plane X Cycle X.10 — generic evaluator-spawn agent shell.
//
// Per the spec Do step 5 the suite covers three invariants:
//   1. Out-of-band tool invocation → bob_finalize_node emits
//      node.transitioned executed → failed with failure_reason.reason =
//      "tool_constraint_violation" naming the offending tools.
//   2. bob_prepare_node returns the spawn description with the bracketed
//      family tag (e.g. "evaluator-spawn[evm]" or "evaluator-spawn[web|evm]"
//      for a cross-stack transition) AND the brief's recap_and_handoff
//      slice carries the spawn directive.
//   3. The .claude/agents/evaluator-spawn.md shell body carries the honest
//      X-P7 framing prose (ergonomics trade, allowed_tools_for_node[]
//      enforcement, recommended_reads_for_node[] guidance, bob_resolve_body
//      body-pull discipline, graph_context_hash drift check).

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const { TOOL_HANDLERS } = require("../mcp/lib/tool-registry.js");
const {
  appendFrontierEvent,
} = require("../mcp/lib/frontier-events.js");
const {
  TASK_GRAPH_NODE_ID_PREFIX,
  appendHypothesisProposal,
  appendTransitionProposal,
  readNodeTransitions,
} = require("../mcp/lib/task-graph-events.js");
const {
  materializeTaskGraph,
} = require("../mcp/lib/task-graph-materializer.js");
const {
  appendContract,
} = require("../mcp/lib/contracts.js");
const {
  familyTagForCapabilityPackId,
} = require("../mcp/lib/capability-packs.js");

const REPO_ROOT = path.join(__dirname, "..");
const EVALUATOR_SPAWN_AGENT_PATH = path.join(
  REPO_ROOT,
  ".claude",
  "agents",
  "evaluator-spawn.md",
);

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-evaluator-spawn-"));
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

function seedHypothesisNode(domain, proposalId, surfaceRefs) {
  appendHypothesisProposal({
    target_domain: domain,
    ts: "2026-05-31T00:01:00.000Z",
    hypothesis_statement: "An attacker can replay JWTs against the EVM vault.",
    surface_refs: surfaceRefs,
    proposal_id: proposalId,
  });
  materializeTaskGraph(domain, { write: true });
  return `${TASK_GRAPH_NODE_ID_PREFIX}H-${proposalId}`;
}

const KNOWN_TOOL = "bob_http_scan";

function baseContractInput({
  contractId = "C-x10-base",
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
  const nodeId = seedHypothesisNode(domain, proposalId, surfaceRefs);
  appendContract({
    target_domain: domain,
    node_id: nodeId,
    contract: baseContractInput(),
    ts: "2026-05-31T00:02:00.000Z",
  });
  materializeTaskGraph(domain, { write: true });
  return nodeId;
}

// ─── Do step 5 (1): tool_constraint_violation ───────────────────────────

test("finalize_node emits tool_constraint_violation when agent_output names an out-of-band tool", () => {
  withTempHome(() => {
    const domain = "x10-out-of-band.example.com";
    seedSession(domain);
    const nodeId = seedContractedNode(domain, "HP-tcv");
    const prep = JSON.parse(TOOL_HANDLERS.bob_prepare_node({
      target_domain: domain,
      node_id: nodeId,
    }));
    // The allowed_tools_for_node[] is the union the X.5 derivation
    // returned; pick a tool we KNOW is registered (so the agent_output
    // shape is parseable) but NOT in the allowed set. bob_init_session
    // is orchestrator-only; bob_advance_session is orchestrator-only.
    // Neither belongs to the evaluator-shared/web bundle the Hypothesis
    // node's Contract pulls in.
    const outOfBand = "bob_init_session";
    assert.ok(
      !prep.allowed_tools_for_node.includes(outOfBand),
      `precondition: ${outOfBand} must be outside allowed_tools_for_node[]`,
    );
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
    assert.deepEqual(
      result.failure_reason.violations.map((v) => v.tool),
      [outOfBand],
    );
    // Constraint check runs BEFORE mechanical verifier, so the verdict
    // surface should be null (the verifier was not called).
    assert.equal(result.mechanical_verdict, null);
    // The failed event lives on the ledger so the next prepare-node call
    // surfaces it in the prior_attempt slice (recall discipline per X.8).
    const transitions = readNodeTransitions(domain);
    const failedEvent = transitions.find(
      (e) => e.payload && e.payload.node_id === nodeId && e.payload.to_state === "failed",
    );
    assert.ok(failedEvent, "expected the failed transition on the ledger");
    assert.equal(failedEvent.payload.failure_reason.reason, "tool_constraint_violation");
    assert.deepEqual(
      failedEvent.payload.failure_reason.allowed_tools.sort(),
      prep.allowed_tools_for_node.slice().sort(),
    );
  });
});

test("finalize_node accepts an empty tool_invocations[] when other channels carry evidence", () => {
  withTempHome(() => {
    const domain = "x10-no-invocations.example.com";
    seedSession(domain);
    const nodeId = seedContractedNode(domain, "HP-no-inv");
    const prep = JSON.parse(TOOL_HANDLERS.bob_prepare_node({
      target_domain: domain,
      node_id: nodeId,
    }));
    // Empty tool_invocations[] cannot trip the constraint check; the
    // mechanical verifier still runs and decides the verdict on the
    // remaining channels. Here the verdict fails (no matching tool
    // output) but the failure_reason is mechanical_verifier_failed, NOT
    // tool_constraint_violation — proving the X.10 enforcement is
    // scoped only to actual invocations.
    const result = JSON.parse(TOOL_HANDLERS.bob_finalize_node({
      target_domain: domain,
      node_id: nodeId,
      prep_token: prep.prep_token,
      agent_output: {
        findings: [{ note: "no impact found" }],
      },
    }));
    assert.equal(result.to_state, "failed");
    assert.notEqual(result.failure_reason.reason, "tool_constraint_violation");
    assert.equal(result.failure_reason.reason, "mechanical_verifier_failed");
  });
});

// ─── Do step 5 (2): family tag in spawn description ─────────────────────

test("prepare_node returns the family-tagged spawn description for a Hypothesis node with a web producer", () => {
  withTempHome(() => {
    const domain = "x10-family-tag.example.com";
    seedSession(domain);
    const nodeId = seedContractedNode(domain, "HP-tag");
    const prep = JSON.parse(TOOL_HANDLERS.bob_prepare_node({
      target_domain: domain,
      node_id: nodeId,
    }));
    // The Contract's only tool is bob_http_scan which routes to the
    // web pack; the derived family_tag must be "web".
    assert.equal(prep.spawn_subagent_type, "evaluator-spawn");
    assert.equal(prep.family_tag, "web");
    assert.equal(prep.spawn_description, `execute node ${nodeId} — evaluator-spawn[web]`);
    // The brief renderer surfaces the directive in recap_and_handoff +
    // node_context so the agent (and operator status reads) can pick it
    // up without re-deriving.
    const recap = prep.brief.recap_and_handoff;
    assert.equal(recap.spawn_directive.subagent_type, "evaluator-spawn");
    assert.equal(recap.spawn_directive.description, prep.spawn_description);
    assert.equal(recap.spawn_directive.family_tag, "web");
    const nodeCtx = prep.brief.node_context;
    assert.equal(nodeCtx.family_tag, "web");
    assert.equal(nodeCtx.spawn_subagent_type, "evaluator-spawn");
    assert.equal(nodeCtx.spawn_description, prep.spawn_description);
  });
});

test("prepare_node returns a cross-stack family tag for a Transition node spanning web + smart_contract", () => {
  withTempHome(() => {
    const domain = "x10-transition-tag.example.com";
    seedSession(domain);
    // Seed a transition spanning a web auth surface and an EVM contract
    // surface. The pack derivation reads surface metadata from
    // surface-routes.json; in this test no routes file exists so both
    // endpoints fall back to the web pack. Verify the helper produces
    // the expected single-family tag (the cross-stack assertion is
    // load-bearing for X.11 which seeds real routes).
    appendTransitionProposal({
      target_domain: domain,
      ts: "2026-05-31T00:01:00.000Z",
      from_surface: "surface:web-auth",
      to_surface: "surface:evm-vault",
      kind: "identity_propagation",
      trust_assumption: "JWT.sub equals msg.sender on the on-chain verify call",
      proposal_id: "TP-x10-tag",
    });
    materializeTaskGraph(domain, { write: true });
    const nodeId = `${TASK_GRAPH_NODE_ID_PREFIX}T-TP-x10-tag`;
    appendContract({
      target_domain: domain,
      node_id: nodeId,
      contract: baseContractInput({ contractId: "C-x10-transition" }),
      ts: "2026-05-31T00:02:00.000Z",
    });
    materializeTaskGraph(domain, { write: true });
    const prep = JSON.parse(TOOL_HANDLERS.bob_prepare_node({
      target_domain: domain,
      node_id: nodeId,
    }));
    assert.equal(prep.spawn_subagent_type, "evaluator-spawn");
    // No routes file → both endpoints resolve to the default web pack.
    // The family tag dedupes to "web" (single family). The spawn
    // description has no `|` separator because there is only one tag.
    assert.equal(prep.family_tag, "web");
    assert.equal(prep.spawn_description, `execute node ${nodeId} — evaluator-spawn[web]`);
  });
});

test("familyTagForCapabilityPackId returns the canonical family for each shipped pack", () => {
  assert.equal(familyTagForCapabilityPackId("web"), "web");
  assert.equal(familyTagForCapabilityPackId("smart_contract_evm"), "evm");
  assert.equal(familyTagForCapabilityPackId("smart_contract_svm"), "svm");
  assert.equal(familyTagForCapabilityPackId("smart_contract_aptos"), "aptos");
  assert.equal(familyTagForCapabilityPackId("smart_contract_sui"), "sui");
  assert.equal(familyTagForCapabilityPackId("smart_contract_substrate"), "substrate");
  assert.equal(familyTagForCapabilityPackId("smart_contract_cosmwasm"), "cosmwasm");
  assert.equal(familyTagForCapabilityPackId("not_a_pack"), null);
});

// ─── Do step 5 (3): honest X-P7 framing in the shell body ───────────────

test(".claude/agents/evaluator-spawn.md exists with the honest X-P7 framing prose", () => {
  assert.ok(fs.existsSync(EVALUATOR_SPAWN_AGENT_PATH), "expected the rendered evaluator-spawn agent file to exist");
  const body = fs.readFileSync(EVALUATOR_SPAWN_AGENT_PATH, "utf8");
  // The honest framing names the ergonomics trade explicitly.
  assert.ok(
    /ergonomics trade/i.test(body),
    "expected the shell body to name the X-P7 ergonomics trade explicitly",
  );
  // The detective-control swap must be visible — the agent should
  // know the allowed_tools_for_node[] constraint is enforced
  // detectively at finalize.
  assert.ok(
    /tool_constraint_violation/i.test(body),
    "expected the shell body to reference the tool_constraint_violation failure path",
  );
  assert.ok(
    /allowed_tools_for_node/i.test(body),
    "expected the shell body to point the agent at allowed_tools_for_node[] in the brief",
  );
  // The recommended_reads guidance must be present so the agent
  // doesn't fetch bodies they don't need.
  assert.ok(
    /recommended_reads/i.test(body),
    "expected the shell body to point the agent at recommended_reads",
  );
  assert.ok(
    /bob_resolve_body/i.test(body),
    "expected the shell body to point the agent at bob_resolve_body for body pulls",
  );
  // The graph_context_hash drift-check guidance is required per X-R15
  // (agent awareness is the only mitigation).
  assert.ok(
    /graph_context_hash/i.test(body),
    "expected the shell body to surface the graph_context_hash drift check",
  );
  // Family-tag explanation must be present so the agent (and
  // operator) know what the bracketed label in the spawn description
  // means.
  assert.ok(
    /family_tag|family tag/i.test(body),
    "expected the shell body to explain the family-tag label",
  );
});

test("evaluator-spawn agent frontmatter carries evaluator-family tools without self-finalize authority", () => {
  const body = fs.readFileSync(EVALUATOR_SPAWN_AGENT_PATH, "utf8");
  const frontmatterEnd = body.indexOf("\n---\n", 4);
  assert.ok(frontmatterEnd > 0, "expected YAML frontmatter terminator");
  const frontmatter = body.slice(0, frontmatterEnd);
  const toolsLine = frontmatter.split("\n").find((line) => /^tools:/.test(line));
  assert.ok(toolsLine, "expected a tools: line in the frontmatter");
  const expected = [
    // The spec mandates the union explicitly — sample one tool from
    // each chain bundle + the dispatch + body-pull tools.
    "mcp__hacker-bob__bob_resolve_body",
    "mcp__hacker-bob__bob_prepare_node",
    "mcp__hacker-bob__bob_http_scan",          // evaluator-web
    "mcp__hacker-bob__bob_foundry_run",        // evaluator-evm
    "mcp__hacker-bob__bob_anchor_run",         // evaluator-svm
    "mcp__hacker-bob__bob_aptos_run",          // evaluator-move (aptos)
    "mcp__hacker-bob__bob_sui_run",            // evaluator-move (sui)
    "mcp__hacker-bob__bob_substrate_run",      // evaluator-substrate
    "mcp__hacker-bob__bob_cosmwasm_run",       // evaluator-cosmwasm
    "mcp__hacker-bob__bob_browser_session_start", // browser
    "mcp__hacker-bob__bob_repo_check",         // repo
    "mcp__hacker-bob__bob_repo_docker_run",    // repo
  ];
  for (const tool of expected) {
    assert.ok(
      toolsLine.includes(tool),
      `expected evaluator-spawn frontmatter tools line to include ${tool}`,
    );
  }
  assert.equal(
    toolsLine.includes("mcp__hacker-bob__bob_finalize_node"),
    false,
    "evaluator-spawn must not self-finalize; orchestrator owns bob_finalize_node",
  );
});
