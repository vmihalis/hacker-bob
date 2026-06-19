"use strict";

// Plane X Cycle X.1 — TaskGraph event-ledger wrappers + proposal tools.
//
// X.1 ships:
//   - FRONTIER_EVENT_KINDS += "node.transitioned"  (the ONE new top-level
//     kind permitted by X-P8).
//   - mcp/lib/task-graph-events.js with the frozen state-transition table
//     (Do step 4) and three wrappers (Do step 2):
//       appendNodeTransition, appendTransitionProposal,
//       appendHypothesisProposal.
//   - bob_propose_hypothesis + bob_propose_transition tools (Do step 3).
//
// Do step 5 specifies three test families: causality on append, out-of-
// order refused, prose-cap fires on oversize. The tests below cover all
// three plus the proposal-tool roundtrip and the state-transition table
// (so a future cycle that edits the table is forced to update tests).

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  FRONTIER_EVENT_KINDS,
  appendFrontierEvent,
  readFrontierEvents,
} = require("../mcp/lib/frontier-events.js");
const {
  NODE_STATE_TRANSITIONS,
  NODE_STATE_VALUES,
  TASK_GRAPH_NODE_ID_PREFIX,
  TRANSITION_KIND_VALUES,
  appendHypothesisProposal,
  appendNodeTransition,
  appendTransitionProposal,
  assertNodeTransitionAllowed,
  isAllowedNodeTransition,
  readHypothesisProposals,
  readNodeTransitions,
  readTransitionProposals,
} = require("../mcp/lib/task-graph-events.js");
const {
  materializeFrontier,
} = require("../mcp/lib/frontier-materializer.js");
const { TOOL_HANDLERS } = require("../mcp/lib/tool-registry.js");

// X.3 Do step 3: bob_propose_transition validates both endpoints exist in
// surface-index. Tests that exercise the tool roundtrip seed both endpoint
// surfaces with surface.observed events and force a materialization so
// surface-index.json carries them before the handler runs.
function seedMaterializedSurface(domain, surfaceId) {
  appendFrontierEvent({
    target_domain: domain,
    kind: "surface.observed",
    ts: "2026-05-31T00:00:00.000Z",
    surface_id: surfaceId,
    payload: { title: surfaceId },
  });
  materializeFrontier(domain, { write: true });
}

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-task-graph-events-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

// ─── New top-level kind is registered ────────────────────────────────────

test("FRONTIER_EVENT_KINDS contains exactly one new top-level kind for X.1", () => {
  assert.ok(FRONTIER_EVENT_KINDS.includes("node.transitioned"));
  // X-P8 budgets ONE new top-level kind per cycle; cycle X.1 adds exactly
  // this one. The proposal events ride on the existing observation.recorded
  // bucket. If a future change adds another node.* top-level kind, the
  // budget is owed a separate cycle review.
  const nodeKinds = FRONTIER_EVENT_KINDS.filter((kind) => kind.startsWith("node."));
  assert.deepEqual(nodeKinds, ["node.transitioned"]);
});

// ─── State-transition table is frozen at Do step 4 ───────────────────────

test("NODE_STATE_VALUES matches the X.1 vocabulary", () => {
  assert.deepEqual(NODE_STATE_VALUES.slice().sort(), [
    "abandoned",
    "contracted",
    "dispatched",
    "executed",
    "failed",
    "finalized",
    "proposed",
    "ready",
    "verified",
  ]);
});

test("NODE_STATE_TRANSITIONS matches the X.1 table + X.8 re-contract path", () => {
  // The table is intentionally narrow; copy it verbatim from the spec so
  // any drift surfaces as a test failure rather than a silent runtime change.
  // X.8 adds `failed → contracted` for the retry-with-recall workflow:
  // when the operator re-contracts a failed node with a refined Contract,
  // the brief inlines the prior failure payload via the `prior_attempt`
  // slice.
  const expected = {
    proposed: ["contracted", "abandoned"],
    contracted: ["ready", "abandoned"],
    ready: ["dispatched", "abandoned"],
    dispatched: ["executed", "failed"],
    executed: ["verified", "failed"],
    verified: ["finalized", "failed"],
    finalized: [],
    failed: ["contracted"],
    abandoned: [],
  };
  for (const state of Object.keys(expected)) {
    assert.deepEqual(
      NODE_STATE_TRANSITIONS[state].slice(),
      expected[state],
      `transitions for ${state} drifted from the X.1/X.8 state table`,
    );
  }
});

test("isAllowedNodeTransition accepts in-table pairs and refuses everything else", () => {
  assert.equal(isAllowedNodeTransition("proposed", "contracted"), true);
  assert.equal(isAllowedNodeTransition("contracted", "ready"), true);
  assert.equal(isAllowedNodeTransition("ready", "dispatched"), true);
  assert.equal(isAllowedNodeTransition("dispatched", "executed"), true);
  assert.equal(isAllowedNodeTransition("dispatched", "failed"), true);
  assert.equal(isAllowedNodeTransition("verified", "finalized"), true);
  // X.8 retry-with-recall: failed → contracted is the re-contract path.
  assert.equal(isAllowedNodeTransition("failed", "contracted"), true);

  // Out-of-order
  assert.equal(isAllowedNodeTransition("proposed", "ready"), false);
  assert.equal(isAllowedNodeTransition("dispatched", "ready"), false);
  // Skipping verified → finalized via executed → finalized
  assert.equal(isAllowedNodeTransition("executed", "finalized"), false);
  // Truly terminal states have no successors
  assert.equal(isAllowedNodeTransition("finalized", "verified"), false);
  assert.equal(isAllowedNodeTransition("abandoned", "proposed"), false);
  // failed → dispatched (skipping contracted) is still refused.
  assert.equal(isAllowedNodeTransition("failed", "dispatched"), false);
  assert.equal(isAllowedNodeTransition("failed", "ready"), false);
});

test("assertNodeTransitionAllowed throws a structured invalid_node_transition error", () => {
  let caught = null;
  try {
    assertNodeTransitionAllowed("proposed", "ready");
  } catch (error) {
    caught = error;
  }
  assert.ok(caught, "should throw");
  assert.equal(caught.code, "invalid_node_transition");
  assert.equal(caught.details.from_state, "proposed");
  assert.equal(caught.details.to_state, "ready");
  assert.deepEqual(caught.details.allowed_from_state, ["contracted", "abandoned"]);
});

// ─── appendNodeTransition: causality (Do step 5) ─────────────────────────

test("appendNodeTransition emits node.transitioned with the canonical payload", () => {
  withTempHome(() => {
    const domain = "x1.example.com";
    const event = appendNodeTransition({
      target_domain: domain,
      node_id: `${TASK_GRAPH_NODE_ID_PREFIX}hyp-001`,
      from_state: "proposed",
      to_state: "contracted",
      contract_hash: "deadbeef",
      ts: "2026-05-31T00:00:00.000Z",
    });

    assert.equal(event.kind, "node.transitioned");
    assert.equal(event.payload.node_id, "TG-hyp-001");
    assert.equal(event.payload.from_state, "proposed");
    assert.equal(event.payload.to_state, "contracted");
    assert.equal(event.payload.contract_hash, "deadbeef");
    // Optional fields stay omitted when not provided.
    assert.equal(event.payload.prep_token, undefined);
    assert.equal(event.payload.output_hash, undefined);
    assert.equal(event.payload.failure_reason, undefined);
    assert.equal(event.payload.edge_added_to, undefined);
    // Event id and hash bind the payload.
    assert.match(event.event_id, /^FE-/);
    assert.match(event.event_hash, /^[0-9a-f]{64}$/);

    // Reader projection finds the same event.
    const transitions = readNodeTransitions(domain);
    assert.equal(transitions.length, 1);
    assert.equal(transitions[0].event_id, event.event_id);
  });
});

test("appendNodeTransition refuses out-of-order transitions at append time", () => {
  withTempHome(() => {
    const domain = "x1-out-of-order.example.com";
    let caught = null;
    try {
      appendNodeTransition({
        target_domain: domain,
        node_id: `${TASK_GRAPH_NODE_ID_PREFIX}n1`,
        from_state: "proposed",
        // proposed → ready is NOT in the frozen table; proposed must first
        // be contracted (or abandoned).
        to_state: "ready",
      });
    } catch (error) {
      caught = error;
    }
    assert.ok(caught, "must reject out-of-order transition");
    assert.equal(caught.code, "invalid_node_transition");
    assert.match(caught.message, /invalid_node_transition/);
    // The append never persisted the event.
    assert.equal(readNodeTransitions(domain).length, 0);
  });
});

test("appendNodeTransition refuses a TaskGraph node id without the TG- prefix", () => {
  withTempHome(() => {
    assert.throws(
      () =>
        appendNodeTransition({
          target_domain: "x1-id-prefix.example.com",
          node_id: "surface:not-a-tg-id",
          from_state: "proposed",
          to_state: "contracted",
        }),
      /node_id must match TG-/,
    );
  });
});

test("appendNodeTransition carries edge_added_to[] when ready/finalize unblocks downstream", () => {
  withTempHome(() => {
    const domain = "x1-edges.example.com";
    const event = appendNodeTransition({
      target_domain: domain,
      node_id: `${TASK_GRAPH_NODE_ID_PREFIX}root`,
      from_state: "verified",
      to_state: "finalized",
      output_hash: "sha256:beef",
      edge_added_to: [
        `${TASK_GRAPH_NODE_ID_PREFIX}child-a`,
        `${TASK_GRAPH_NODE_ID_PREFIX}child-b`,
      ],
    });
    assert.deepEqual(event.payload.edge_added_to, ["TG-child-a", "TG-child-b"]);
  });
});

// ─── appendTransitionProposal: prose cap + enum guard ────────────────────

test("appendTransitionProposal emits observation.recorded with payload.kind transition_proposed", () => {
  withTempHome(() => {
    const domain = "x1-tp.example.com";
    const event = appendTransitionProposal({
      target_domain: domain,
      from_surface: "surface:web-auth",
      to_surface: "surface:evm-vault",
      kind: "identity_propagation",
      trust_assumption: "JWT sub equals msg.sender on the vault contract.",
      evidence_refs: ["http_record:R7"],
    });
    assert.equal(event.kind, "observation.recorded");
    assert.equal(event.payload.kind, "transition_proposed");
    assert.equal(event.payload.from_surface, "surface:web-auth");
    assert.equal(event.payload.to_surface, "surface:evm-vault");
    assert.equal(event.payload.transition_kind, "identity_propagation");
    assert.match(event.payload.trust_assumption, /JWT sub equals msg.sender/);
    assert.deepEqual(event.payload.evidence_refs, ["http_record:R7"]);

    const proposals = readTransitionProposals(domain);
    assert.equal(proposals.length, 1);
    assert.equal(proposals[0].event_id, event.event_id);
  });
});

test("appendTransitionProposal refuses an out-of-enum transition kind", () => {
  withTempHome(() => {
    assert.throws(
      () =>
        appendTransitionProposal({
          target_domain: "x1-tp-bad.example.com",
          from_surface: "surface:a",
          to_surface: "surface:b",
          // Not in the X-D3 enum.
          kind: "magic_handoff",
          trust_assumption: "ok",
        }),
      /kind must be one of/,
    );
  });
});

test("appendTransitionProposal refuses identical from_surface and to_surface", () => {
  withTempHome(() => {
    assert.throws(
      () =>
        appendTransitionProposal({
          target_domain: "x1-tp-loop.example.com",
          from_surface: "surface:a",
          to_surface: "surface:a",
          kind: "identity_propagation",
          trust_assumption: "ok",
        }),
      /must differ/,
    );
  });
});

test("appendTransitionProposal fires prose_too_long on oversize trust_assumption (513 chars)", () => {
  withTempHome(() => {
    let caught = null;
    try {
      appendTransitionProposal({
        target_domain: "x1-tp-prose.example.com",
        from_surface: "surface:a",
        to_surface: "surface:b",
        kind: "trust_handoff",
        // 513 chars — one over the 512 cap.
        trust_assumption: "x".repeat(513),
      });
    } catch (error) {
      caught = error;
    }
    assert.ok(caught, "must reject oversize prose");
    assert.equal(caught.code, "prose_too_long");
    assert.equal(caught.details.field, "trust_assumption");
    assert.equal(caught.details.length, 513);
    assert.equal(caught.details.max_chars, 512);
  });
});

test("appendTransitionProposal accepts trust_assumption at exactly the 512-char cap", () => {
  withTempHome(() => {
    const event = appendTransitionProposal({
      target_domain: "x1-tp-exact.example.com",
      from_surface: "surface:a",
      to_surface: "surface:b",
      kind: "value_movement",
      trust_assumption: "x".repeat(512),
    });
    assert.equal(event.payload.trust_assumption.length, 512);
  });
});

// ─── appendHypothesisProposal: prose cap + surface_refs guard ────────────

test("appendHypothesisProposal emits observation.recorded with payload.kind hypothesis_proposed", () => {
  withTempHome(() => {
    const domain = "x1-hp.example.com";
    const event = appendHypothesisProposal({
      target_domain: domain,
      hypothesis_statement: "Token rebalance routes can be replayed within the gas-relayer window.",
      surface_refs: ["surface:relayer-rebalance"],
      suggested_contract: {
        invariants: [{ id: "I-1", statement: "Each relayed tx executes at most once." }],
      },
    });
    assert.equal(event.kind, "observation.recorded");
    assert.equal(event.payload.kind, "hypothesis_proposed");
    assert.deepEqual(event.payload.surface_refs, ["surface:relayer-rebalance"]);
    assert.equal(
      event.payload.hypothesis_statement,
      "Token rebalance routes can be replayed within the gas-relayer window.",
    );
    assert.ok(event.payload.suggested_contract);

    const proposals = readHypothesisProposals(domain);
    assert.equal(proposals.length, 1);
    assert.equal(proposals[0].event_id, event.event_id);
  });
});

test("appendHypothesisProposal fires prose_too_long on oversize statement", () => {
  withTempHome(() => {
    let caught = null;
    try {
      appendHypothesisProposal({
        target_domain: "x1-hp-prose.example.com",
        hypothesis_statement: "x".repeat(600),
        surface_refs: ["surface:a"],
      });
    } catch (error) {
      caught = error;
    }
    assert.ok(caught, "must reject oversize prose");
    assert.equal(caught.code, "prose_too_long");
    assert.equal(caught.details.field, "hypothesis_statement");
    assert.equal(caught.details.length, 600);
    assert.equal(caught.details.max_chars, 512);
  });
});

test("appendHypothesisProposal refuses an empty surface_refs array", () => {
  withTempHome(() => {
    assert.throws(
      () =>
        appendHypothesisProposal({
          target_domain: "x1-hp-empty.example.com",
          hypothesis_statement: "y",
          surface_refs: [],
        }),
      /surface_refs must contain at least one/,
    );
  });
});

// ─── Causality: append order is preserved + reader filters by kind ───────

test("ledger preserves append order across mixed proposal + transition writes", () => {
  withTempHome(() => {
    const domain = "x1-causality.example.com";
    const a = appendHypothesisProposal({
      target_domain: domain,
      hypothesis_statement: "Hypothesis A.",
      surface_refs: ["surface:a"],
      ts: "2026-05-31T00:00:01.000Z",
    });
    const b = appendTransitionProposal({
      target_domain: domain,
      from_surface: "surface:a",
      to_surface: "surface:b",
      kind: "identity_propagation",
      trust_assumption: "Carrying identity across two surfaces.",
      ts: "2026-05-31T00:00:02.000Z",
    });
    const c = appendNodeTransition({
      target_domain: domain,
      node_id: "TG-node-1",
      from_state: "proposed",
      to_state: "contracted",
      contract_hash: "hash-1",
      ts: "2026-05-31T00:00:03.000Z",
    });

    const events = readFrontierEvents(domain);
    assert.equal(events.length, 3);
    assert.equal(events[0].event_id, a.event_id);
    assert.equal(events[1].event_id, b.event_id);
    assert.equal(events[2].event_id, c.event_id);

    // Each reader projects only its kind.
    assert.equal(readHypothesisProposals(domain).length, 1);
    assert.equal(readTransitionProposals(domain).length, 1);
    assert.equal(readNodeTransitions(domain).length, 1);
  });
});

// ─── Proposal tools (bob_propose_hypothesis / bob_propose_transition) ────

test("bob_propose_hypothesis tool roundtrips an event and reports the payload kind", () => {
  withTempHome(() => {
    const handler = TOOL_HANDLERS.bob_propose_hypothesis;
    assert.ok(typeof handler === "function", "tool registered");
    const raw = handler({
      target_domain: "x1-tool-hp.example.com",
      hypothesis_statement: "Refund-flow accepts cross-tenant tokens.",
      surface_refs: ["surface:refund-flow"],
    });
    const result = JSON.parse(raw);
    assert.equal(result.appended, true);
    assert.equal(result.kind, "observation.recorded");
    assert.equal(result.payload_kind, "hypothesis_proposed");
    assert.equal(result.target_domain, "x1-tool-hp.example.com");
    assert.match(result.event_id, /^FE-/);
  });
});

test("bob_propose_transition tool roundtrips an event and reports the payload kind", () => {
  withTempHome(() => {
    const domain = "x1-tool-tp.example.com";
    // X.3 endpoint-existence gate: seed both surfaces before proposing.
    seedMaterializedSurface(domain, "surface:auth");
    seedMaterializedSurface(domain, "surface:vault");
    const handler = TOOL_HANDLERS.bob_propose_transition;
    assert.ok(typeof handler === "function", "tool registered");
    const raw = handler({
      target_domain: domain,
      from_surface: "surface:auth",
      to_surface: "surface:vault",
      kind: TRANSITION_KIND_VALUES[0],
      trust_assumption: "Auth response identity is trusted by the on-chain vault.",
    });
    const result = JSON.parse(raw);
    assert.equal(result.appended, true);
    assert.equal(result.kind, "observation.recorded");
    assert.equal(result.payload_kind, "transition_proposed");
    assert.equal(result.target_domain, domain);
  });
});

test("bob_propose_hypothesis tool surfaces the prose_too_long failure as a thrown error", () => {
  withTempHome(() => {
    const handler = TOOL_HANDLERS.bob_propose_hypothesis;
    let caught = null;
    try {
      handler({
        target_domain: "x1-tool-cap.example.com",
        hypothesis_statement: "x".repeat(1024),
        surface_refs: ["surface:a"],
      });
    } catch (error) {
      caught = error;
    }
    assert.ok(caught, "must reject oversize prose");
    assert.equal(caught.code, "prose_too_long");
  });
});

test("bob_propose_transition tool surfaces the prose_too_long failure as a thrown error", () => {
  withTempHome(() => {
    const domain = "x1-tool-cap-tp.example.com";
    // X.3 endpoint-existence gate: seed both surfaces so the prose-cap error
    // (not the endpoint-existence error) fires in this test.
    seedMaterializedSurface(domain, "surface:a");
    seedMaterializedSurface(domain, "surface:b");
    const handler = TOOL_HANDLERS.bob_propose_transition;
    let caught = null;
    try {
      handler({
        target_domain: domain,
        from_surface: "surface:a",
        to_surface: "surface:b",
        kind: "trust_handoff",
        trust_assumption: "x".repeat(1024),
      });
    } catch (error) {
      caught = error;
    }
    assert.ok(caught, "must reject oversize prose");
    assert.equal(caught.code, "prose_too_long");
  });
});
