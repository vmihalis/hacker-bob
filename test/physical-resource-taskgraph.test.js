"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const {
  appendContract,
  normalizeContract,
} = require("../mcp/lib/contracts.js");
const {
  selectNextExecutableNodes,
} = require("../mcp/lib/graph-scheduler.js");
const {
  materializeTaskGraph,
} = require("../mcp/lib/task-graph-materializer.js");
const {
  TASK_GRAPH_NODE_ID_PREFIX,
  appendHypothesisProposal,
} = require("../mcp/lib/task-graph-events.js");
const { hashCanonicalJson } = require("../mcp/lib/verification-contracts.js");

const digest = (label) => hashCanonicalJson({ label });

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-physical-resource-taskgraph-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function contractInput(binding = null) {
  const value = {
    contract_id: "physical-reader-contract",
    severity_floor: "high",
    invariants: [{ id: "instrument_identity", statement: "The enrolled reader identity remains exact." }],
    witnesses: [{
      id: "inventory_receipt",
      kind: "tool_output_match",
      predicate: { tool: "bob_http_scan", match: { path: "$.status", equals: 200 } },
    }],
    production_paths: [{
      description: "Exercise the registered producer while the physical provider surface is integrated.",
      tool_call_pattern: [{ tool: "bob_http_scan" }],
    }],
  };
  if (binding) value.physical_resource_bundle = binding;
  return value;
}

function resourceBinding(label = "one") {
  return {
    version: 1,
    resource_bundle_ref: `resource-bundle:${label}`,
    resource_bundle_digest: digest(`bundle-${label}`),
  };
}

test("Contract hashing binds a compact physical resource-bundle reference without changing legacy hashes", () => {
  const legacy = normalizeContract(contractInput());
  const legacyAgain = normalizeContract(contractInput());
  const physical = normalizeContract(contractInput(resourceBinding("one")));
  const drifted = normalizeContract(contractInput(resourceBinding("two")));
  assert.equal(legacy.contract_hash, legacyAgain.contract_hash);
  assert.equal(Object.prototype.hasOwnProperty.call(legacy, "physical_resource_bundle"), false);
  assert.notEqual(physical.contract_hash, legacy.contract_hash);
  assert.notEqual(physical.contract_hash, drifted.contract_hash);
  assert.deepEqual(physical.physical_resource_bundle, resourceBinding("one"));
  assert.throws(
    () => normalizeContract(contractInput({ ...resourceBinding("one"), extra: true })),
    /unknown fields: extra/,
  );
});

test("TaskGraph carries the exact hash-bound resource binding and scheduling defaults to no-reservation credit", () => {
  withTempHome(() => {
    const domain = "physical-resource-taskgraph.example";
    const proposalId = "physical-reader-one";
    const nodeId = `${TASK_GRAPH_NODE_ID_PREFIX}H-${proposalId}`;
    appendHypothesisProposal({
      target_domain: domain,
      ts: "2026-07-18T00:00:00.000Z",
      hypothesis_statement: "The authorized reader can inventory the enrolled test medium.",
      surface_refs: ["surface:physical-reader"],
      proposal_id: proposalId,
    });
    materializeTaskGraph(domain, { write: true });
    const attached = appendContract({
      target_domain: domain,
      node_id: nodeId,
      contract: contractInput(resourceBinding("one")),
      ts: "2026-07-18T00:00:01.000Z",
    });
    assert.ok(JSON.stringify(attached.event.payload).length < 2_048);
    const document = materializeTaskGraph(domain, { write: false }).document;
    const node = document.nodes.find((entry) => entry.node_id === nodeId);
    assert.deepEqual(node.physical_resource_bundle, resourceBinding("one"));
    const selection = selectNextExecutableNodes(domain, {}, 1, { document });
    assert.equal(selection.selected.length, 0);
    assert.equal(selection.skipped.length, 1);
    assert.deepEqual(selection.skipped[0].physical_resource_bundle, resourceBinding("one"));
    assert.equal(selection.skipped[0].contract_hash, node.contract_hash);
    assert.equal(selection.skipped[0].physical_reservation_state, "not_held");
    assert.equal(selection.considered_count, 1);
    assert.equal(selection.source_graph_hash, document.hashes.graph_hash);
    assert.throws(
      () => selectNextExecutableNodes(domain, {}, 1, {
        document,
        physicalResourceReservationEligibilityPort: Object.freeze({ version: 1 }),
        sessionNucleusHash: digest("nucleus"),
      }),
      /private/i,
    );
  });
});

test("legacy TaskGraph candidates omit the resource field byte-for-byte", () => {
  withTempHome(() => {
    const domain = "legacy-resource-taskgraph.example";
    const proposalId = "legacy-one";
    const nodeId = `${TASK_GRAPH_NODE_ID_PREFIX}H-${proposalId}`;
    appendHypothesisProposal({
      target_domain: domain,
      ts: "2026-07-18T00:00:00.000Z",
      hypothesis_statement: "Legacy hypothesis remains unchanged.",
      surface_refs: ["surface:legacy"],
      proposal_id: proposalId,
    });
    materializeTaskGraph(domain, { write: true });
    appendContract({
      target_domain: domain,
      node_id: nodeId,
      contract: contractInput(),
      ts: "2026-07-18T00:00:01.000Z",
    });
    const document = materializeTaskGraph(domain, { write: false }).document;
    const node = document.nodes.find((entry) => entry.node_id === nodeId);
    assert.equal(Object.prototype.hasOwnProperty.call(node, "physical_resource_bundle"), false);
    const candidate = selectNextExecutableNodes(domain, {}, 1, { document }).selected[0];
    assert.equal(Object.prototype.hasOwnProperty.call(candidate, "physical_resource_bundle"), false);
    assert.equal(JSON.stringify(candidate), JSON.stringify({
      node_id: nodeId,
      kind: "hypothesis",
      state: "contracted",
      priority: "medium",
      severity_floor: null,
      tier: 1,
      ts_first: "2026-07-18T00:00:00.000Z",
      ts_last: "2026-07-18T00:00:01.000Z",
    }));
  });
});
