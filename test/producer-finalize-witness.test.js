"use strict";

// Producer finalize witness — the producer-engine WRITE path.
//
// When bob_finalize_node finalizes a kind === "producer" node whose Contract
// passes the mechanical verifier, the SERVER mints the producer output: it
// appends a producer_run 'produced' row and emits surface.observed for a
// surface-producing producer. The witness (buildProducerOutputContract) is
// satisfied ONLY by attested numeric counts / a run-bound surface.observed —
// NEVER a file_exists / agent-scratch check. An empty-AND-input-untouched run
// fails the witness (the silent-loss cure): the node goes executed → failed
// with no produced row and no surface emission, even though the mechanical
// verifier passed.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const finalizeNode = require("../mcp/tools/finalize-node.js");
const {
  appendFrontierEvent,
  readFrontierEvents,
} = require("../mcp/core/frontier/frontier-events.js");
const {
  appendNodeTransition,
} = require("../mcp/core/waves/task-graph-events.js");
const {
  appendContract,
} = require("../mcp/core/contract/index.js");
const {
  materializeTaskGraph,
} = require("../mcp/core/waves/task-graph-materializer.js");
const {
  producerRunSet,
} = require("../mcp/core/producer-run-ledger.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-producer-finalize-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    process.env.HOME = previousHome;
    try { fs.rmSync(home, { recursive: true, force: true }); } catch {}
  }
}

// Drive a producer node to `dispatched` with a known prep_token. bob_prepare_node
// cannot be used on a producer node (its pack derivation is scoped to the
// dispatchable evaluator kinds), so the contracted → ready → dispatched promotion
// is emitted directly — exactly as bob_prepare_node would — minting a fixed
// prep_token_hash the finalize call cross-checks.
function seedDispatchedProducer(domain, producerKey, prepToken) {
  appendFrontierEvent({
    target_domain: domain,
    kind: "observation.recorded",
    ts: "2026-06-01T00:00:00.000Z",
    payload: {
      observation_kind: "producer_proposed",
      producer_key: producerKey,
      producer_id: producerKey,
    },
  });
  materializeTaskGraph(domain, { write: true });
  const doc = materializeTaskGraph(domain, { write: false }).document;
  const node = doc.nodes.find((n) => n.kind === "producer");
  assert.ok(node, "expected a materialized producer node");
  const nodeId = node.node_id;

  // A trivially-mechanical-passing Contract: evidence_ref_kind_present fires on
  // any evidence_ref of kind repo_file, so the mechanical verifier passes
  // independently of the producer-output witness.
  appendContract({
    target_domain: domain,
    node_id: nodeId,
    ts: "2026-06-01T00:01:00.000Z",
    contract: {
      contract_id: "C-producer",
      severity_floor: "low",
      invariants: [{ id: "I1", statement: "Producer emits output." }],
      witnesses: [{ id: "W1", kind: "evidence_ref_kind_present", predicate: { kind: "repo_file" } }],
      production_paths: [{
        description: "Run the recon producer.",
        tool_call_pattern: [{ tool: "bob_http_scan" }],
      }],
    },
  });
  appendNodeTransition({
    target_domain: domain,
    node_id: nodeId,
    from_state: "contracted",
    to_state: "ready",
    ts: "2026-06-01T00:02:00.000Z",
  });
  appendNodeTransition({
    target_domain: domain,
    node_id: nodeId,
    from_state: "ready",
    to_state: "dispatched",
    prep_token_hash: prepToken,
    ts: "2026-06-01T00:03:00.000Z",
  });
  materializeTaskGraph(domain, { write: true });
  return nodeId;
}

test("producer finalize: a surface-producing run satisfies the witness, mints a produced row + surface.observed", () => {
  withTempHome(() => {
    const domain = "producer-pass.example.com";
    const prepToken = "producer-pass-token-aaaaaaaaaaaaaaaaaaaaaaaa";
    const nodeId = seedDispatchedProducer(domain, "web_assembly", prepToken);

    const result = JSON.parse(finalizeNode.handler({
      target_domain: domain,
      node_id: nodeId,
      prep_token: prepToken,
      agent_output: {
        // Mechanical verifier passes (repo_file evidence present) ...
        evidence_refs: [{ kind: "repo_file", file_path: "recon/assembly.json" }],
        // ... and the producer attests a real surface, satisfying the witness.
        producer_output: {
          surfaces_observed: [
            { surface_id: "surface:web-home", surface_type: "web" },
          ],
        },
      },
    }));

    assert.equal(result.to_state, "finalized",
      `expected finalized; got ${JSON.stringify(result.failure_reason || result)}`);

    // The SERVER minted a terminal produced producer_run row.
    assert.ok(producerRunSet(domain).has("web_assembly"),
      "expected a terminal producer_run row for web_assembly");

    // The SERVER minted surface.observed for the surface-producing producer.
    const observed = readFrontierEvents(domain).filter(
      (e) => e.kind === "surface.observed"
        && e.payload && e.payload.producer_key === "web_assembly",
    );
    assert.equal(observed.length, 1, "expected exactly one minted surface.observed");
    assert.equal(observed[0].payload.surface_type, "web");
  });
});

test("producer finalize: an empty AND input-untouched run FAILS the witness (no fake pass, no produced row)", () => {
  withTempHome(() => {
    const domain = "producer-empty.example.com";
    const prepToken = "producer-empty-token-bbbbbbbbbbbbbbbbbbbbbbbb";
    const nodeId = seedDispatchedProducer(domain, "web_assembly", prepToken);

    const result = JSON.parse(finalizeNode.handler({
      target_domain: domain,
      node_id: nodeId,
      prep_token: prepToken,
      agent_output: {
        // Mechanical verifier STILL passes (repo_file evidence present) ...
        evidence_refs: [{ kind: "repo_file", file_path: "recon/assembly.json" }],
        // ... but the attested run is empty AND input-untouched: no surface,
        // zero output items, zero input items. Membership is never file_exists.
        producer_output: {
          surfaces_observed: [],
          producer_run: { output_artifact: { item_count: 0 } },
          input_consumed: { input_item_count: 0 },
        },
      },
    }));

    assert.equal(result.to_state, "failed", "empty producer run must fail the witness");
    assert.equal(result.failure_reason.reason, "producer_output_empty");
    // The mechanical verifier DID pass — the producer-output witness is the gate.
    assert.equal(result.mechanical_verdict.satisfied, true);

    // No PRODUCED producer_run row was minted (no silent fake pass). The
    // witness-empty finalize is terminal-on-first: it writes exactly one terminal
    // BLOCKED row directly, so the producer joins the terminal run set in a single
    // pass (a producer node can never re-execute) and the recon floor stops
    // re-proposing it — never a non-terminal strike that the floor would re-dispatch.
    const producerRunRows = readFrontierEvents(domain).filter(
      (e) => e.kind === "observation.recorded"
        && e.payload && e.payload.observation_kind === "producer_run"
        && e.payload.producer_key === "web_assembly",
    );
    assert.equal(producerRunRows.filter((e) => e.payload.status === "produced").length, 0,
      "no produced row may exist for an empty producer run (no silent fake pass)");
    assert.equal(producerRunRows.filter((e) => e.payload.status === "blocked").length, 1,
      "a witness-empty finalize writes exactly one terminal blocked row");
    assert.equal(producerRunSet(domain).has("web_assembly"), true,
      "the witness-empty producer is terminal in the run set after a single finalize");
    // No surface.observed was minted by the producer engine.
    const observed = readFrontierEvents(domain).filter(
      (e) => e.kind === "surface.observed"
        && e.payload && e.payload.producer_key === "web_assembly",
    );
    assert.equal(observed.length, 0, "no surface.observed may be minted on witness failure");
  });
});
