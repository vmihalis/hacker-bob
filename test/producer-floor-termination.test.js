"use strict";

// Producer-floor termination guarantees. Two distinct closure paths drive every
// reachable producer to a terminal producer_run row so a later coverage floor
// stops re-dispatching it and the recon-producer drain stays finite:
//
//   TERMINAL-ON-FIRST — a witness-empty finalize. The producer executed and
//   emitted nothing, and a producer node can never re-execute, so the finalize
//   writes the terminal blocked row DIRECTLY in a single pass — never a strike
//   toward a threshold. This is the leg the live system actually takes when a
//   producer run is empty; it cannot accrue three strikes because the failed node
//   is reconciled by neither reconciler and never re-executes.
//
//   STRIKE-TALLY — the transient retryable legs. The orphan-executed reconciler
//   closes a finalize lost across the turn barrier (a node stuck 'executed' with
//   no terminal row) and the stale-dispatch reconciler closes a node stuck
//   'proposed'/'dispatched'; each grants grace ticks then accrues a STRUCTURAL
//   strike per pass, auto-blocking at STUCK_PRODUCER_DISPATCH_THRESHOLD. These are
//   transient faults that must keep ticking toward the threshold, never
//   terminal-on-first. A producer that only suffers transient tool faults is never
//   auto-closed, because the strike counter ignores transient failures.
//
// Leg (h) of the coherence gate asserts a future advisory producer keyed on a
// fluctuating per-instance id is rejected.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  recordProducerRun,
  producerStrikeTally,
  producerRunSet,
  STUCK_PRODUCER_DISPATCH_THRESHOLD,
} = require("../mcp/lib/producer-run-ledger.js");
const {
  appendFrontierEvent,
  readFrontierEvents,
} = require("../mcp/lib/frontier-events.js");
const { appendNodeTransition } = require("../mcp/lib/task-graph-events.js");
const { appendContract } = require("../mcp/lib/contracts.js");
const { materializeTaskGraph } = require("../mcp/lib/task-graph-materializer.js");
const finalizeNode = require("../mcp/lib/tools/finalize-node.js");
const { evaluateSchedulerPrecondition } = require("../mcp/lib/scheduler-preconditions.js");
const {
  reconcileOrphanExecutedProducers,
  reconcileStaleDispatchProducers,
  planOrphanReconcile,
  planProducerFloor,
  ORPHAN_EXECUTED_RECONCILE_PASS_THRESHOLD,
  STALE_DISPATCH_RECONCILE_PASS_THRESHOLD,
} = require("../mcp/lib/tools/materialize-producer-floor.js");
const { PRODUCER_PACKS } = require("../mcp/lib/producer-packs.js");
const { checkLegH } = require("../scripts/check-producer-coherence.js");

// Drive a producer node to `dispatched` with a known prep_token — the same path
// producer-finalize-witness.test.js uses so the witness-empty finalize this file
// asserts on is the REAL finalize path, not an injected ledger row. bob_prepare_node
// cannot run on a producer node (its pack derivation is scoped to dispatchable
// evaluator kinds), so the contracted -> ready -> dispatched promotion is emitted
// directly, minting the prep_token_hash the finalize call cross-checks.
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

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-producer-floor-term-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    process.env.HOME = previousHome;
    try { fs.rmSync(home, { recursive: true, force: true }); } catch {}
  }
}

// Direct audit read of producer_run rows for one producer_key at one status.
// readProducerRunRows is internal to the ledger, so reconstruct its filter over
// the frontier-event stream the ledger writes to — the assertions hang on this
// audit-direct evidence rather than a derived helper.
function strikeRows(domain, key, status) {
  return readFrontierEvents(domain).filter((event) => (
    event.kind === "observation.recorded"
    && event.payload
    && event.payload.observation_kind === "producer_run"
    && event.payload.producer_key === key
    && event.payload.status === status
  ));
}

test("three structural strikes auto-block; the blocked producer joins the terminal run set", () => {
  withTempHome(() => {
    assert.equal(STUCK_PRODUCER_DISPATCH_THRESHOLD, 3,
      "the auto-block threshold this test pins is three structural strikes");
    const domain = "floor-term-struct.example.com";
    const key = "web_host_family";

    const r1 = recordProducerRun(domain, {
      producer_key: key, status: "failed_retryable", failure_class: "structural",
    });
    assert.equal(producerStrikeTally(domain, key), 1);
    assert.equal(r1.auto_blocked, null);
    assert.equal(producerRunSet(domain).has(key), false);

    const r2 = recordProducerRun(domain, {
      producer_key: key, status: "failed_retryable", failure_class: "structural",
    });
    assert.equal(producerStrikeTally(domain, key), 2);
    assert.equal(r2.auto_blocked, null);
    assert.equal(producerRunSet(domain).has(key), false);

    const r3 = recordProducerRun(domain, {
      producer_key: key, status: "failed_retryable", failure_class: "structural",
    });
    assert.equal(producerStrikeTally(domain, key), 3);
    assert.ok(r3.auto_blocked, "the third structural strike must mint the terminal block");
    assert.equal(producerRunSet(domain).has(key), true);

    assert.equal(strikeRows(domain, key, "blocked").length, 1,
      "exactly one terminal blocked row is written — the row the floor prunes");
  });
});

test("transient faults never strike: three transient failures then a produced run; the tally stays zero", () => {
  withTempHome(() => {
    const domain = "floor-term-transient.example.com";
    const key = "web_urls";

    for (let attempt = 0; attempt < 3; attempt += 1) {
      const r = recordProducerRun(domain, {
        producer_key: key, status: "failed_retryable", failure_class: "transient",
      });
      assert.equal(producerStrikeTally(domain, key), 0,
        "a transient fault never increments the strike tally");
      assert.equal(r.auto_blocked, null, "a transient fault never auto-blocks");
      assert.equal(producerRunSet(domain).has(key), false);
    }

    const produced = recordProducerRun(domain, { producer_key: key, status: "produced" });
    assert.equal(produced.auto_blocked, null);
    assert.equal(producerRunSet(domain).has(key), true,
      "a produced run lands the key in the terminal set");

    assert.equal(strikeRows(domain, key, "blocked").length, 0,
      "no block row was ever written despite three transient failures");
    assert.equal(strikeRows(domain, key, "produced").length, 1,
      "the run genuinely reached produced exactly once");
  });
});

test("auto-block fires at exactly the third structural strike, and a fourth strike is idempotent", () => {
  withTempHome(() => {
    const domain = "floor-term-exact.example.com";
    const key = "web_nuclei";

    const s1 = recordProducerRun(domain, {
      producer_key: key, status: "failed_retryable", failure_class: "structural",
    });
    assert.equal(s1.auto_blocked, null, "the first structural strike does not block");
    assert.equal(producerRunSet(domain).has(key), false);

    const s2 = recordProducerRun(domain, {
      producer_key: key, status: "failed_retryable", failure_class: "structural",
    });
    assert.equal(s2.auto_blocked, null, "the second structural strike does not block");
    assert.equal(producerRunSet(domain).has(key), false);

    const s3 = recordProducerRun(domain, {
      producer_key: key, status: "failed_retryable", failure_class: "structural",
    });
    assert.ok(s3.auto_blocked, "the third structural strike blocks");
    assert.equal(producerRunSet(domain).has(key), true);

    const s4 = recordProducerRun(domain, {
      producer_key: key, status: "failed_retryable", failure_class: "structural",
    });
    assert.equal(s4.auto_blocked, null,
      "a fourth strike on an already-terminal producer does not block again");
    assert.equal(producerStrikeTally(domain, key), 4,
      "the append-only strike counter keeps climbing");
    assert.equal(strikeRows(domain, key, "blocked").length, 1,
      "still exactly one block row — the threshold is not off by one to four");
  });
});

test("orphan-executed reconciler: K-grace ticks first, then structural strikes auto-block at the threshold", () => {
  withTempHome(() => {
    const K = ORPHAN_EXECUTED_RECONCILE_PASS_THRESHOLD;
    assert.equal(K, 2, "this test pins the K-grace at two passes");
    const domain = "orphan-exec.example.com";
    const key = "web_urls";
    const nodeId = "TG-producer-x";
    // A single producer node stuck 'executed' with no terminal producer_run row —
    // a finalize lost across the turn barrier. Inject it directly so the reconciler
    // exercises the orphan path deterministically.
    const nodes = [{ node_id: nodeId, kind: "producer", state: "executed" }];
    const map = new Map([[nodeId, key]]);

    // Pass 1 (index < K): a non-striking transient tick — a legitimate in-flight
    // finalize, never a strike.
    const p1 = reconcileOrphanExecutedProducers(domain, { nodes, nodeIdToProducerKey: map });
    assert.deepEqual(p1.ticked, [key], "pass 1 ticks the orphan");
    assert.deepEqual(p1.struck, [], "pass 1 never strikes");
    assert.equal(producerStrikeTally(domain, key), 0, "no structural strike before pass K");
    assert.equal(producerRunSet(domain).has(key), false);

    // Pass 2 (index === K): the first structural strike.
    const p2 = reconcileOrphanExecutedProducers(domain, { nodes, nodeIdToProducerKey: map });
    assert.deepEqual(p2.struck, [key], "pass K strikes structurally");
    assert.equal(producerStrikeTally(domain, key), 1);
    assert.equal(producerRunSet(domain).has(key), false);

    // Pass 3: the second structural strike — still not terminal.
    reconcileOrphanExecutedProducers(domain, { nodes, nodeIdToProducerKey: map });
    assert.equal(producerStrikeTally(domain, key), 2);
    assert.equal(producerRunSet(domain).has(key), false);

    // Pass 4 (= K+2): the third structural strike auto-blocks; the key turns
    // terminal and joins the run set.
    const p4 = reconcileOrphanExecutedProducers(domain, { nodes, nodeIdToProducerKey: map });
    assert.equal(producerStrikeTally(domain, key), 3);
    assert.deepEqual(p4.auto_blocked, [key], "the third structural strike mints the terminal block");
    assert.equal(producerRunSet(domain).has(key), true, "the blocked producer joins the terminal run set");
    assert.equal(strikeRows(domain, key, "blocked").length, 1, "exactly one terminal blocked row");

    // Pass 5: terminal ⇒ the reconciler skips it — bounded, no further rows.
    const p5 = reconcileOrphanExecutedProducers(domain, { nodes, nodeIdToProducerKey: map });
    assert.deepEqual(p5.ticked, [], "a terminal key is never ticked again");
    assert.deepEqual(p5.struck, [], "a terminal key is never struck again");
    assert.equal(producerStrikeTally(domain, key), 3, "the strike tally is bounded once terminal");
  });
});

test("orphan-executed reconciler: a producer with a terminal produced row is never ticked or struck", () => {
  withTempHome(() => {
    const domain = "orphan-produced.example.com";
    const key = "web_host_family";
    const nodeId = "TG-producer-y";
    // The producer already delivered — its key is terminal in the run set.
    recordProducerRun(domain, { producer_key: key, status: "produced" });
    assert.equal(producerRunSet(domain).has(key), true);

    const nodes = [{ node_id: nodeId, kind: "producer", state: "executed" }];
    const map = new Map([[nodeId, key]]);
    const r = reconcileOrphanExecutedProducers(domain, { nodes, nodeIdToProducerKey: map });
    assert.deepEqual(r.ticked, [], "a terminal-produced key is never ticked");
    assert.deepEqual(r.struck, [], "a terminal-produced key is never struck");
    assert.equal(producerStrikeTally(domain, key), 0, "no strike rows written for a produced key");
  });
});

test("planOrphanReconcile: index < K ticks, index >= K strikes, terminal/non-executed skipped (pure split)", () => {
  const K = ORPHAN_EXECUTED_RECONCILE_PASS_THRESHOLD;
  const nodes = [
    { node_id: "TG-producer-a", kind: "producer", state: "executed" },
    { node_id: "TG-producer-b", kind: "producer", state: "executed" },
    { node_id: "TG-producer-c", kind: "producer", state: "executed" },
    // a non-executed producer node is never reconciled
    { node_id: "TG-producer-d", kind: "producer", state: "proposed" },
    // a non-producer node is ignored entirely
    { node_id: "TG-S-1", kind: "surface", state: "executed" },
  ];
  const map = new Map([
    ["TG-producer-a", "pk-a"],
    ["TG-producer-b", "pk-b"],
    ["TG-producer-c", "pk-c"],
    ["TG-producer-d", "pk-d"],
  ]);
  // pk-a fresh (index 1 < K ⇒ tick); pk-b at K-1 priors (index K ⇒ strike);
  // pk-c already terminal ⇒ skipped entirely.
  const orphanCountsByKey = new Map([
    ["pk-a", 0],
    ["pk-b", K - 1],
  ]);
  const plan = planOrphanReconcile({
    producerNodes: nodes,
    nodeIdToProducerKey: map,
    terminalRunSet: new Set(["pk-c"]),
    orphanCountsByKey,
    passThreshold: K,
  });
  assert.deepEqual(plan.ticks.map((t) => t.producer_key), ["pk-a"], "index below K ⇒ tick");
  assert.deepEqual(plan.strikes.map((s) => s.producer_key), ["pk-b"], "index at/above K ⇒ strike");
});

test("a witness-empty finalize is terminal-on-first: the producer blocks in ONE pass, never re-proposes, and the drain converges", () => {
  withTempHome(() => {
    const domain = "witness-empty-terminal.example.com";
    // The terminal web_assembly synthesizer is the producer under test: it is ready
    // once its eight upstream recon artifact kinds exist and, being a leaf
    // (web_surface is consumed by nothing), blocking it drains the whole floor.
    const key = "web_assembly";
    const prepToken = "witness-empty-token-cccccccccccccccccccccccc";

    // Mark the four upstream web producers terminal so their produces[] unlock
    // exactly web_assembly's eight inputs — the floor's real view when the
    // synthesizer is the next producer to run. One 'produced' terminal row each:
    // this is producer SETUP, NOT the forbidden strike-injection path.
    for (const upstream of ["web_host_family", "web_urls", "web_nuclei", "web_js_jwt"]) {
      recordProducerRun(domain, { producer_key: upstream, status: "produced" });
    }
    const upstreamKinds = [
      "live_hosts", "family_live", "subdomains", "all_urls",
      "nuclei_results", "js_endpoints", "js_secrets", "jwt_candidates",
    ];

    // Stand the producer up on the REAL dispatch path so the finalize below is the
    // genuine witness-empty finalize, not an injected ledger row.
    const nodeId = seedDispatchedProducer(domain, key, prepToken);

    // BEFORE the finalize the floor re-proposes the ready synthesizer — and the
    // real seed_producers_drained precondition is UNSATISFIED. Pre-fix this state
    // is a fixpoint that can never be reached: the witness-empty failed node could
    // only accrue one strike (re-executes never come), so the floor re-proposed it
    // forever and the drain never converged.
    const before = planProducerFloor({
      packs: PRODUCER_PACKS,
      producerRunSet: producerRunSet(domain),
      availableArtifactKinds: upstreamKinds,
    });
    assert.equal(before.ready.some((p) => p.producer_id === key), true,
      "an un-terminal ready producer is re-proposed every floor pass");
    const drainBefore = evaluateSchedulerPrecondition("seed_producers_drained", { target_domain: domain });
    assert.equal(drainBefore.satisfied, false,
      "before the witness-empty finalize the synthesizer is ready ⇒ the drain has not converged");

    // The REAL finalize path: a dispatched producer node finalized with an
    // empty-AND-input-untouched attested run fails the output witness (the
    // mechanical verifier still passes on the repo_file evidence).
    const result = JSON.parse(finalizeNode.handler({
      target_domain: domain,
      node_id: nodeId,
      prep_token: prepToken,
      agent_output: {
        evidence_refs: [{ kind: "repo_file", file_path: "recon/assembly.json" }],
        producer_output: {
          surfaces_observed: [],
          producer_run: { output_artifact: { item_count: 0 } },
          input_consumed: { input_item_count: 0 },
        },
      },
    }));
    assert.equal(result.to_state, "failed",
      `a witness-empty producer run must fail the witness; got ${JSON.stringify(result.failure_reason || result)}`);
    assert.equal(result.failure_reason.reason, "producer_output_empty");
    assert.equal(result.mechanical_verdict.satisfied, true,
      "the mechanical verifier passes — the producer-output witness is the gate");

    // Terminal in ONE finalize — NOT after three strikes. The blocked row is
    // written DIRECTLY; no failed_retryable strike row exists for this key.
    assert.equal(producerRunSet(domain).has(key), true,
      "a witness-empty finalize blocks the producer in a single pass");
    assert.equal(strikeRows(domain, key, "blocked").length, 1,
      "exactly one terminal blocked row — written directly at finalize");
    assert.equal(strikeRows(domain, key, "failed_retryable").length, 0,
      "no structural strike row exists — the witness-empty leg is terminal-on-first, never a strike tally");

    // The floor no longer re-proposes it ⇒ the drain reaches a fixpoint.
    const after = planProducerFloor({
      packs: PRODUCER_PACKS,
      producerRunSet: producerRunSet(domain),
      availableArtifactKinds: upstreamKinds,
    });
    assert.equal(after.ready.some((p) => p.producer_id === key), false,
      "a witness-empty-blocked producer is excluded from re-proposal");

    // The real seed_producers_drained precondition now CONVERGES: the synthesizer
    // is terminal, its web_surface unlocks no further producer, and every upstream
    // is already terminal ⇒ no producer remains ready.
    const drainAfter = evaluateSchedulerPrecondition("seed_producers_drained", { target_domain: domain });
    assert.equal(drainAfter.satisfied, true,
      "seed_producers_drained converges once the witness-empty producer is terminal-blocked");
    assert.equal(drainAfter.ready_count, 0, "no producer remains ready after the terminal block");
  });
});

test("a mechanical-verifier-failed producer finalize is terminal-on-first: it blocks in ONE finalize, never re-proposes, and the drain converges", () => {
  withTempHome(() => {
    const domain = "mech-verifier-failed-terminal.example.com";
    // web_assembly is the terminal leaf synthesizer — the same producer the
    // witness-empty case drives — but here the MECHANICAL verifier itself fails
    // (the Contract's repo_file evidence witness is unmet), so the finalize takes
    // the mechanical_verifier_failed exit, NOT the producer-output-witness exit.
    const key = "web_assembly";
    const prepToken = "mech-failed-token-dddddddddddddddddddddddd";

    // Same producer SETUP as the witness-empty case: the four upstream producers
    // terminal so web_assembly's eight inputs are unlocked and it is the next ready
    // leaf. One 'produced' terminal row each — producer SETUP, not strike-injection.
    for (const upstream of ["web_host_family", "web_urls", "web_nuclei", "web_js_jwt"]) {
      recordProducerRun(domain, { producer_key: upstream, status: "produced" });
    }
    const upstreamKinds = [
      "live_hosts", "family_live", "subdomains", "all_urls",
      "nuclei_results", "js_endpoints", "js_secrets", "jwt_candidates",
    ];

    // Stand the producer up on the REAL dispatch path so the finalize below is the
    // genuine mechanical-verifier-failed finalize, not an injected ledger row.
    const nodeId = seedDispatchedProducer(domain, key, prepToken);

    // Before the finalize the ready leaf is re-proposed and the drain is unsatisfied.
    const before = planProducerFloor({
      packs: PRODUCER_PACKS,
      producerRunSet: producerRunSet(domain),
      availableArtifactKinds: upstreamKinds,
    });
    assert.equal(before.ready.some((p) => p.producer_id === key), true,
      "an un-terminal ready producer is re-proposed every floor pass");
    const drainBefore = evaluateSchedulerPrecondition("seed_producers_drained", { target_domain: domain });
    assert.equal(drainBefore.satisfied, false,
      "before the finalize the ready synthesizer keeps the drain from converging");

    // The REAL finalize path: the agent_output is non-empty (clears the empty gate)
    // but carries NO repo_file evidence, so the Contract's evidence_ref_kind_present
    // witness is unmet and the MECHANICAL verifier fails — the finalize takes the
    // mechanical_verifier_failed exit before it ever reaches the producer-output gate.
    const result = JSON.parse(finalizeNode.handler({
      target_domain: domain,
      node_id: nodeId,
      prep_token: prepToken,
      agent_output: {
        evidence_refs: [{ kind: "http_response", detail: "not a repo_file" }],
      },
    }));
    assert.equal(result.to_state, "failed",
      `the mechanical verifier must fail; got ${JSON.stringify(result.failure_reason || result)}`);
    assert.equal(result.failure_reason.reason, "mechanical_verifier_failed");
    assert.equal(result.mechanical_verdict.satisfied, false,
      "this is the mechanical-verifier exit — the verdict is unsatisfied (distinct from the witness-empty leg)");

    // Terminal in ONE finalize — the blocked row is written DIRECTLY, keyed by the
    // producer_key, with the mechanical_verifier_failed block_reason; no strike row.
    assert.equal(producerRunSet(domain).has(key), true,
      "a mechanical-verifier-failed producer finalize blocks the producer in a single pass");
    const blockedRows = strikeRows(domain, key, "blocked");
    assert.equal(blockedRows.length, 1, "exactly one terminal blocked row — written directly at finalize");
    assert.equal(blockedRows[0].payload.block_reason, "mechanical_verifier_failed",
      "the block row records the mechanical_verifier_failed reason");
    assert.equal(strikeRows(domain, key, "failed_retryable").length, 0,
      "no structural strike row exists — the mechanical-verifier-failed producer leg is terminal-on-first");

    // The floor no longer re-proposes it ⇒ the drain reaches a fixpoint.
    const after = planProducerFloor({
      packs: PRODUCER_PACKS,
      producerRunSet: producerRunSet(domain),
      availableArtifactKinds: upstreamKinds,
    });
    assert.equal(after.ready.some((p) => p.producer_id === key), false,
      "a terminal-blocked producer is excluded from re-proposal");
    const drainAfter = evaluateSchedulerPrecondition("seed_producers_drained", { target_domain: domain });
    assert.equal(drainAfter.satisfied, true,
      "seed_producers_drained converges once the mechanical-verifier-failed producer is terminal-blocked");
    assert.equal(drainAfter.ready_count, 0, "no producer remains ready after the terminal block");
  });
});

test("a producer_unresolved producer finalize is terminal-on-first: it blocks in ONE finalize, is never floor-proposed, and the drain converges", () => {
  withTempHome(() => {
    const domain = "producer-unresolved-terminal.example.com";
    // A producer node whose producer_key resolves via its producer_proposed event
    // but whose base id is OUTSIDE PRODUCER_PACKS — the producer_unresolved exit. The
    // mechanical verifier PASSES (repo_file evidence present) so the finalize reaches
    // the kind === "producer" output gate, where the unresolved-pack branch fires.
    // The bogus key is not a PRODUCER_PACKS member, so the run-set-driven floor never
    // proposes it; the terminal block keeps the producer_run ledger honest and the
    // key idempotently terminal in ONE finalize.
    const key = "web_bogus_unresolved";
    const prepToken = "producer-unresolved-token-eeeeeeeeeeeeeeeeeeee";

    // Stand the producer up on the REAL dispatch path so the finalize below is the
    // genuine producer_unresolved finalize, not an injected ledger row.
    const nodeId = seedDispatchedProducer(domain, key, prepToken);

    // The bogus key is outside PRODUCER_PACKS, so the floor (which iterates
    // PRODUCER_PACKS) never proposes it — before or after the finalize.
    const before = planProducerFloor({
      packs: PRODUCER_PACKS,
      producerRunSet: producerRunSet(domain),
      availableArtifactKinds: [],
    });
    assert.equal(before.ready.some((p) => p.producer_id === key), false,
      "an unresolved producer key is never a member of the PRODUCER_PACKS floor");

    const result = JSON.parse(finalizeNode.handler({
      target_domain: domain,
      node_id: nodeId,
      prep_token: prepToken,
      agent_output: {
        // repo_file evidence ⇒ the mechanical verifier PASSES, so the finalize
        // reaches the producer output gate and takes the producer_unresolved exit.
        evidence_refs: [{ kind: "repo_file", file_path: "recon/bogus.json" }],
      },
    }));
    assert.equal(result.to_state, "failed",
      `an unresolved producer must fail; got ${JSON.stringify(result.failure_reason || result)}`);
    assert.equal(result.failure_reason.reason, "producer_unresolved");
    assert.equal(result.mechanical_verdict.satisfied, true,
      "the mechanical verifier PASSED — producer_unresolved is a second, additive gate");

    // Terminal in ONE finalize — the blocked row is written DIRECTLY, keyed by the
    // resolved producer_key, with the producer_unresolved block_reason; no strike row.
    assert.equal(producerRunSet(domain).has(key), true,
      "a producer_unresolved finalize blocks the producer in a single pass");
    const blockedRows = strikeRows(domain, key, "blocked");
    assert.equal(blockedRows.length, 1, "exactly one terminal blocked row — written directly at finalize");
    assert.equal(blockedRows[0].payload.block_reason, "producer_unresolved",
      "the block row records the producer_unresolved reason");
    assert.equal(strikeRows(domain, key, "failed_retryable").length, 0,
      "no structural strike row exists — the producer_unresolved leg is terminal-on-first");

    // Still never floor-proposed, and the floor is at its fixpoint.
    const after = planProducerFloor({
      packs: PRODUCER_PACKS,
      producerRunSet: producerRunSet(domain),
      availableArtifactKinds: [],
    });
    assert.equal(after.ready.some((p) => p.producer_id === key), false,
      "a terminal-blocked unresolved producer is still never floor-proposed");
    const drainAfter = evaluateSchedulerPrecondition("seed_producers_drained", { target_domain: domain });
    assert.equal(drainAfter.satisfied, true,
      "seed_producers_drained converges — no real producer is ready and the unresolved key is terminal");
    assert.equal(drainAfter.ready_count, 0, "no producer remains ready after the terminal block");
  });
});

test("the strike-tally legs stay retryable: a single structural strike does NOT block, and only the threshold-th does", () => {
  withTempHome(() => {
    // The transient orphan-executed / stale-dispatch reconcilers must keep TICKING
    // toward STUCK_PRODUCER_DISPATCH_THRESHOLD — they are NOT terminal-on-first like
    // the witness-empty finalize. One structural strike leaves the producer
    // retryable; the threshold-th strike is what auto-blocks it.
    const domain = "strike-tally-retryable.example.com";
    const key = "web_urls";

    const first = recordProducerRun(domain, {
      producer_key: key, status: "failed_retryable", failure_class: "structural",
      reason: "orphan_executed_unreconciled",
    });
    assert.equal(first.auto_blocked, null, "a single structural strike must NOT block (the legs are retryable)");
    assert.equal(producerRunSet(domain).has(key), false,
      "one strike leaves the producer non-terminal — the threshold still governs the transient legs");
    assert.equal(producerStrikeTally(domain, key), 1);

    let last = null;
    for (let strike = 2; strike <= STUCK_PRODUCER_DISPATCH_THRESHOLD; strike += 1) {
      last = recordProducerRun(domain, {
        producer_key: key, status: "failed_retryable", failure_class: "structural",
        reason: "orphan_executed_unreconciled",
      });
    }
    assert.ok(last && last.auto_blocked,
      "only the threshold-th structural strike auto-blocks the transient legs");
    assert.equal(producerRunSet(domain).has(key), true);
    assert.equal(strikeRows(domain, key, "blocked").length, 1, "exactly one terminal blocked row");
  });
});

test("a stuck proposed/dispatched producer converges to blocked via the stale-dispatch reconciler", () => {
  withTempHome(() => {
    const T = STALE_DISPATCH_RECONCILE_PASS_THRESHOLD;
    assert.ok(Number.isInteger(T) && T >= 1, "the stale-dispatch grace threshold is a positive integer");
    const domain = "stale-dispatch.example.com";
    const key = "web_urls";

    // A 'dispatched' producer node whose worker never returned an executed
    // transition: no terminal producer_run row, stuck pre-executed.
    const nodes = [{ node_id: "TG-producer-stuck", kind: "producer", state: "dispatched" }];
    const map = new Map([["TG-producer-stuck", key]]);

    // Grace ticks for the first (T-1) passes, then structural strikes; the
    // STUCK_PRODUCER_DISPATCH_THRESHOLD-th strike auto-blocks. Total passes to a
    // terminal block = (T-1) grace + the strike threshold.
    const passesToBlock = (T - 1) + STUCK_PRODUCER_DISPATCH_THRESHOLD;
    let blocked = false;
    for (let pass = 0; pass < passesToBlock; pass += 1) {
      const r = reconcileStaleDispatchProducers(domain, { nodes, nodeIdToProducerKey: map });
      if (r.auto_blocked.length) blocked = true;
    }

    assert.equal(blocked, true, "a perpetually-stuck dispatched producer eventually auto-blocks");
    assert.equal(producerRunSet(domain).has(key), true,
      "the blocked stale producer joins the terminal run set");
    assert.equal(strikeRows(domain, key, "blocked").length, 1, "exactly one terminal blocked row");

    // Bounded: a terminal key is never ticked or struck again.
    const after = reconcileStaleDispatchProducers(domain, { nodes, nodeIdToProducerKey: map });
    assert.deepEqual(after.ticked, [], "a terminal key is never ticked again");
    assert.deepEqual(after.struck, [], "a terminal key is never struck again");
  });
});

test("the stale-dispatch reconciler grants grace before any strike, and skips executed/terminal nodes", () => {
  withTempHome(() => {
    const domain = "stale-dispatch-grace.example.com";
    const key = "web_nuclei";
    const nodes = [{ node_id: "TG-producer-fresh", kind: "producer", state: "proposed" }];
    const map = new Map([["TG-producer-fresh", key]]);

    // The first pass is a non-striking grace tick — a producer still legitimately
    // awaiting dispatch is never struck on sight.
    const first = reconcileStaleDispatchProducers(domain, { nodes, nodeIdToProducerKey: map });
    assert.deepEqual(first.ticked, [key], "the first encounter is a grace tick");
    assert.deepEqual(first.struck, [], "no strike on the first pass");
    assert.equal(producerStrikeTally(domain, key), 0, "grace ticks never strike");

    // An 'executed' node belongs to the orphan-executed reconciler, not this one.
    const executedNodes = [{ node_id: "TG-producer-exec", kind: "producer", state: "executed" }];
    const executedMap = new Map([["TG-producer-exec", "web_js_jwt"]]);
    const exec = reconcileStaleDispatchProducers(domain, { nodes: executedNodes, nodeIdToProducerKey: executedMap });
    assert.deepEqual(exec.ticked, [], "an executed node is not a stale-dispatch node");
    assert.deepEqual(exec.struck, [], "an executed node is left to the orphan-executed reconciler");
  });
});

test("producer-coherence leg (h): real registry vacuously green; a synthetic fluctuating-key advisory is rejected", () => {
  // Every pack today is advisory:false, so leg (h) is vacuously green.
  assert.deepEqual(checkLegH(), [], "no advisory producer exists today ⇒ leg (h) is vacuously green");
  // A future advisory producer keyed on a fluctuating per-instance id (an identity
  // self-edge: produces ∩ consumes non-empty) MUST be rejected.
  const violations = checkLegH({
    syn: {
      producer_id: "adv_fluct",
      advisory: true,
      produces: ["sc_surface"],
      trigger: { kind: "derived", consumes: ["sc_surface"] },
    },
  });
  assert.equal(violations.length, 1, "exactly one violation");
  assert.equal(violations[0].kind, "advisory_producer_fluctuating_key");
  assert.equal(violations[0].producer_id, "adv_fluct");
});
