"use strict";

// Plane X Cycle X.3 — Transition surface kind + surface-index extension.
//
// X.3 ships:
//   - mcp/lib/constants.js gains SURFACE_KIND_VALUES (closed enum:
//     surface, transition, hypothesis, claim) — the SoT shared by the
//     task-graph materializer (X.2) and the surface-index materializer
//     (X-P6 "transitions persist as kind: 'transition' in surface-index").
//   - mcp/lib/frontier-materializer.js folds transition_proposed events
//     into a first-class transitions[] section of surface-index.json.
//     Per X-P6 each entry carries kind: "transition".
//   - mcp/lib/tools/propose-transition.js validates both from_surface and
//     to_surface exist in the session's surface-index before allowing the
//     append (Do step 3). Refusal surfaces a structured unknown_surface
//     error.
//
// Per Do step 5 (Review) the tests must demonstrate:
//   1. SURFACE_KIND_VALUES is closed at 4 (matches the X.2 node-kind enum).
//   2. transition payload shape (already X.1, re-asserted here for X.3 lock).
//   3. bob_propose_transition refuses unknown endpoints with structured error.
//   4. bob_propose_transition succeeds when both endpoints are seeded.
//   5. Materializer folds transition_proposed → surface-index transitions[]
//      with kind: "transition" + deterministic transition_id.
//   6. Re-materialization with the same event log produces byte-identical
//      surface_index_hash (the X.3 fold preserves materializer determinism).

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  SURFACE_KIND_VALUES,
} = require("../mcp/lib/constants.js");
const {
  TASK_GRAPH_NODE_KIND_VALUES,
} = require("../mcp/lib/task-graph-materializer.js");
const {
  appendFrontierEvent,
  readFrontierEvents,
} = require("../mcp/lib/frontier-events.js");
const {
  appendTransitionProposal,
  TRANSITION_KIND_VALUES,
} = require("../mcp/lib/task-graph-events.js");
const {
  materializeFrontier,
} = require("../mcp/lib/frontier-materializer.js");
const {
  surfaceIndexPath,
} = require("../mcp/lib/paths.js");
const { TOOL_HANDLERS } = require("../mcp/lib/tool-registry.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-x3-transition-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function seedSurface(domain, surfaceId, payload = {}) {
  appendFrontierEvent({
    target_domain: domain,
    kind: "surface.observed",
    ts: "2026-05-31T00:00:00.000Z",
    surface_id: surfaceId,
    payload: { title: surfaceId, ...payload },
  });
  materializeFrontier(domain, { write: true });
}

// ─── Do step 1: SURFACE_KIND_VALUES is the closed enum (constants.js) ─────

test("SURFACE_KIND_VALUES is the closed enum of node + surface kinds", () => {
  assert.deepEqual(SURFACE_KIND_VALUES.slice().sort(), [
    "claim",
    "hypothesis",
    "surface",
    "transition",
  ]);
  assert.ok(SURFACE_KIND_VALUES.includes("transition"), "X.3 step 1: transition is first-class");
});

test("X.2 task-graph node-kind enum aliases the X.3 SURFACE_KIND_VALUES SoT", () => {
  // The materializer alias preserves back-compat re-export but the SoT is
  // SURFACE_KIND_VALUES in constants.js. Both arrays carry the same 4 kinds.
  assert.deepEqual(
    TASK_GRAPH_NODE_KIND_VALUES.slice().sort(),
    SURFACE_KIND_VALUES.slice().sort(),
  );
});

// ─── Do step 2: transition payload shape (X.1 lock in X.3 fold) ──────────

test("transition_proposed payload carries from/to/kind/trust_assumption per X.3 step 2", () => {
  withTempHome(() => {
    const domain = "x3-payload.example.com";
    seedSurface(domain, "surface:auth");
    seedSurface(domain, "surface:vault");
    const event = appendTransitionProposal({
      target_domain: domain,
      from_surface: "surface:auth",
      to_surface: "surface:vault",
      kind: "identity_propagation",
      trust_assumption: "JWT.sub recovered server-side is trusted on-chain.",
      evidence_refs: ["http_record:R7", "evm_call:T9"],
    });
    assert.equal(event.kind, "observation.recorded");
    assert.equal(event.payload.kind, "transition_proposed");
    assert.equal(event.payload.from_surface, "surface:auth");
    assert.equal(event.payload.to_surface, "surface:vault");
    assert.equal(event.payload.transition_kind, "identity_propagation");
    assert.match(event.payload.trust_assumption, /JWT\.sub/);
    assert.deepEqual(event.payload.evidence_refs, ["http_record:R7", "evm_call:T9"]);
  });
});

// ─── Do step 3: bob_propose_transition validates both endpoints exist ─────

test("bob_propose_transition refuses when from_surface is not in surface-index", () => {
  withTempHome(() => {
    const domain = "x3-missing-from.example.com";
    // Only the to_surface is seeded.
    seedSurface(domain, "surface:vault");
    const handler = TOOL_HANDLERS.bob_propose_transition;
    let caught = null;
    try {
      handler({
        target_domain: domain,
        from_surface: "surface:never-observed-auth",
        to_surface: "surface:vault",
        kind: "identity_propagation",
        trust_assumption: "Trust me.",
      });
    } catch (error) {
      caught = error;
    }
    assert.ok(caught, "must reject unknown from_surface");
    assert.equal(caught.code, "unknown_surface");
    assert.equal(caught.details.field, "from_surface");
    assert.equal(caught.details.surface_id, "surface:never-observed-auth");
    // No event was appended.
    const events = readFrontierEvents(domain).filter((e) => e.kind === "observation.recorded");
    assert.equal(events.length, 0);
  });
});

test("bob_propose_transition refuses when to_surface is not in surface-index", () => {
  withTempHome(() => {
    const domain = "x3-missing-to.example.com";
    seedSurface(domain, "surface:auth");
    const handler = TOOL_HANDLERS.bob_propose_transition;
    let caught = null;
    try {
      handler({
        target_domain: domain,
        from_surface: "surface:auth",
        to_surface: "surface:never-observed-vault",
        kind: "value_movement",
        trust_assumption: "ok",
      });
    } catch (error) {
      caught = error;
    }
    assert.ok(caught, "must reject unknown to_surface");
    assert.equal(caught.code, "unknown_surface");
    assert.equal(caught.details.field, "to_surface");
    assert.equal(caught.details.surface_id, "surface:never-observed-vault");
  });
});

test("bob_propose_transition succeeds when both endpoints are seeded", () => {
  withTempHome(() => {
    const domain = "x3-happy.example.com";
    seedSurface(domain, "surface:auth");
    seedSurface(domain, "surface:vault");
    const handler = TOOL_HANDLERS.bob_propose_transition;
    const raw = handler({
      target_domain: domain,
      from_surface: "surface:auth",
      to_surface: "surface:vault",
      kind: "identity_propagation",
      trust_assumption: "JWT.sub is recovered server-side and trusted on-chain.",
      evidence_refs: ["http_record:R7"],
      proposal_id: "TP-jwt-to-vault",
    });
    const result = JSON.parse(raw);
    assert.equal(result.appended, true);
    assert.equal(result.payload_kind, "transition_proposed");
    assert.match(result.event_id, /^FE-/);
  });
});

// ─── Do step 4: materializer folds with kind: "transition" in surface-index ─

test("materializer folds transition_proposed into surface-index.json with kind: transition", () => {
  withTempHome(() => {
    const domain = "x3-fold.example.com";
    seedSurface(domain, "surface:web-auth");
    seedSurface(domain, "surface:evm-vault");
    appendTransitionProposal({
      target_domain: domain,
      from_surface: "surface:web-auth",
      to_surface: "surface:evm-vault",
      kind: "identity_propagation",
      trust_assumption: "JWT.sub equals msg.sender on the vault.",
      evidence_refs: ["http_record:R7"],
      proposal_id: "TP-jwt-to-vault",
      ts: "2026-05-31T01:00:00.000Z",
    });
    const result = materializeFrontier(domain, { write: true });
    const surfaceIndex = result.surface_index;
    assert.ok(Array.isArray(surfaceIndex.transitions), "surface-index.json carries transitions[]");
    assert.equal(surfaceIndex.transition_count, 1);
    assert.equal(surfaceIndex.transitions.length, 1);
    const transition = surfaceIndex.transitions[0];
    assert.equal(transition.kind, "transition", "kind discriminator per X-P6");
    assert.equal(transition.transition_id, "transition:TP-jwt-to-vault");
    assert.equal(transition.from_surface, "surface:web-auth");
    assert.equal(transition.to_surface, "surface:evm-vault");
    assert.equal(transition.transition_kind, "identity_propagation");
    assert.match(transition.trust_assumption, /JWT\.sub/);
    assert.deepEqual(transition.evidence_refs, ["http_record:R7"]);
    assert.ok(SURFACE_KIND_VALUES.includes(transition.kind), "kind is in the closed enum");
  });
});

test("materializer derives a stable transition_id from (from, to, kind) when proposal_id is absent", () => {
  withTempHome(() => {
    const domain = "x3-stable-id.example.com";
    seedSurface(domain, "surface:a");
    seedSurface(domain, "surface:b");
    appendTransitionProposal({
      target_domain: domain,
      from_surface: "surface:a",
      to_surface: "surface:b",
      kind: "trust_handoff",
      trust_assumption: "ok",
      ts: "2026-05-31T01:00:00.000Z",
    });
    const result = materializeFrontier(domain, { write: false });
    const transitions = result.surface_index.transitions;
    assert.equal(transitions.length, 1);
    // Synthetic id derived from from::to::kind so a repeated proposal folds
    // into the same entry (idempotent re-proposal).
    assert.equal(transitions[0].transition_id, "transition:surface:a::surface:b::trust_handoff");
  });
});

test("materializer folds two distinct transitions (different kinds) into two entries", () => {
  withTempHome(() => {
    const domain = "x3-two-kinds.example.com";
    seedSurface(domain, "surface:auth");
    seedSurface(domain, "surface:vault");
    appendTransitionProposal({
      target_domain: domain,
      from_surface: "surface:auth",
      to_surface: "surface:vault",
      kind: "identity_propagation",
      trust_assumption: "JWT.sub equals msg.sender.",
      ts: "2026-05-31T01:00:00.000Z",
    });
    appendTransitionProposal({
      target_domain: domain,
      from_surface: "surface:auth",
      to_surface: "surface:vault",
      kind: "value_movement",
      trust_assumption: "Auth response gates the vault deposit endpoint.",
      ts: "2026-05-31T01:00:01.000Z",
    });
    const result = materializeFrontier(domain, { write: false });
    assert.equal(result.surface_index.transition_count, 2);
    const kinds = result.surface_index.transitions.map((t) => t.transition_kind).sort();
    assert.deepEqual(kinds, ["identity_propagation", "value_movement"]);
  });
});

// ─── Determinism: same event log → same surface_index_hash across re-folds ─

test("materializer is byte-identical across re-materializations with the same event log", () => {
  withTempHome(() => {
    const domain = "x3-determinism.example.com";
    seedSurface(domain, "surface:auth");
    seedSurface(domain, "surface:vault");
    appendTransitionProposal({
      target_domain: domain,
      from_surface: "surface:auth",
      to_surface: "surface:vault",
      kind: "identity_propagation",
      trust_assumption: "JWT.sub equals msg.sender on the vault.",
      ts: "2026-05-31T01:00:00.000Z",
    });
    const r1 = materializeFrontier(domain, { write: false });
    const r2 = materializeFrontier(domain, { write: false });
    const r3 = materializeFrontier(domain, { write: false });
    assert.equal(r1.surface_index.surface_index_hash, r2.surface_index.surface_index_hash);
    assert.equal(r2.surface_index.surface_index_hash, r3.surface_index.surface_index_hash);
    // The hash binds the new transition_count + transitions[] fields too.
    assert.equal(r1.surface_index.transition_count, 1);
  });
});

// ─── Transition fold does NOT regress the surfaces[] section ──────────────

test("materializer leaves surfaces[] intact when transitions[] grows", () => {
  withTempHome(() => {
    const domain = "x3-coexist.example.com";
    seedSurface(domain, "surface:auth", { surface_type: "web" });
    seedSurface(domain, "surface:vault", { surface_type: "smart_contract" });
    appendTransitionProposal({
      target_domain: domain,
      from_surface: "surface:auth",
      to_surface: "surface:vault",
      kind: "identity_propagation",
      trust_assumption: "ok",
      ts: "2026-05-31T01:00:00.000Z",
    });
    const result = materializeFrontier(domain, { write: false });
    assert.equal(result.surface_index.surface_count, 2);
    assert.equal(result.surface_index.transition_count, 1);
    const surfaceIds = result.surface_index.surfaces.map((s) => s.surface_id).sort();
    assert.deepEqual(surfaceIds, ["surface:auth", "surface:vault"]);
    // The surfaces[] entries are NOT misclassified as transitions; they keep
    // the wave-scheduler-facing surface_type (web/smart_contract) and do not
    // gain a synthetic kind: "transition".
    for (const surface of result.surface_index.surfaces) {
      assert.notEqual(surface.kind, "transition");
    }
  });
});

// ─── Materializer skips malformed transition events (defensive fold) ──────

test("materializer skips transition_proposed events with missing endpoints (defensive fold)", () => {
  withTempHome(() => {
    const domain = "x3-defensive.example.com";
    seedSurface(domain, "surface:auth");
    // Inject a malformed transition_proposed observation directly (bypassing
    // appendTransitionProposal so we can exercise the defensive fold). The
    // materializer should ignore it rather than crash.
    appendFrontierEvent({
      target_domain: domain,
      kind: "observation.recorded",
      ts: "2026-05-31T01:00:00.000Z",
      payload: {
        kind: "transition_proposed",
        // from_surface omitted.
        to_surface: "surface:auth",
        transition_kind: "trust_handoff",
        trust_assumption: "ok",
      },
    });
    const result = materializeFrontier(domain, { write: false });
    assert.equal(result.surface_index.transition_count, 0);
    assert.equal(result.surface_index.transitions.length, 0);
  });
});

// ─── Re-proposal updates trust_assumption + accumulates evidence_refs ─────

test("repeat propose-transition with same (from,to,kind) folds into one entry and merges evidence_refs", () => {
  withTempHome(() => {
    const domain = "x3-merge.example.com";
    seedSurface(domain, "surface:auth");
    seedSurface(domain, "surface:vault");
    appendTransitionProposal({
      target_domain: domain,
      from_surface: "surface:auth",
      to_surface: "surface:vault",
      kind: "identity_propagation",
      trust_assumption: "first wording",
      evidence_refs: ["http_record:R7"],
      ts: "2026-05-31T01:00:00.000Z",
    });
    appendTransitionProposal({
      target_domain: domain,
      from_surface: "surface:auth",
      to_surface: "surface:vault",
      kind: "identity_propagation",
      trust_assumption: "refined wording",
      evidence_refs: ["evm_call:T9"],
      ts: "2026-05-31T01:00:01.000Z",
    });
    const result = materializeFrontier(domain, { write: false });
    assert.equal(result.surface_index.transition_count, 1);
    const transition = result.surface_index.transitions[0];
    // Most-recent trust_assumption wins (last-write-wins per refinement).
    assert.equal(transition.trust_assumption, "refined wording");
    // evidence_refs accumulate across re-proposals.
    assert.deepEqual(transition.evidence_refs.slice().sort(), ["evm_call:T9", "http_record:R7"]);
    // Both source events are tracked.
    assert.equal(transition.source_event_ids.length, 2);
  });
});
