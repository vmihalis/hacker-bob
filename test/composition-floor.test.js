"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  planCompositionFloor,
  handler: materializeProducerFloor,
} = require("../mcp/tools/materialize-producer-floor.js");
const { appendFrontierEvent, readFrontierEvents } = require("../mcp/core/frontier/frontier-events.js");
const {
  readTransitionProposals,
  TRANSITION_KIND_VALUES,
} = require("../mcp/core/waves/task-graph-events.js");
const { transitionSurfaceId: exportedTransitionSurfaceId } = require("../mcp/core/frontier/frontier-materializer.js");

function transitionSurfaceId(payload, eventId) {
  if (typeof exportedTransitionSurfaceId === "function") {
    return exportedTransitionSurfaceId(payload, eventId);
  }
  const proposalId = typeof payload.proposal_id === "string" ? payload.proposal_id.trim() : "";
  if (proposalId) return `transition:${proposalId}`;
  const from = typeof payload.from_surface === "string" ? payload.from_surface.trim() : "";
  const to = typeof payload.to_surface === "string" ? payload.to_surface.trim() : "";
  const kind = typeof payload.transition_kind === "string" ? payload.transition_kind.trim() : "";
  if (from && to && kind) return `transition:${from}::${to}::${kind}`;
  return `transition:event:${eventId}`;
}

const transitionKeyOf = ({ from, to }) => transitionSurfaceId({
  from_surface: from,
  to_surface: to,
  transition_kind: "identity_propagation",
}, null);

let domainCounter = 0;

function uniqueDomain(label) {
  domainCounter += 1;
  return `composition-floor-${label}-${process.pid}-${domainCounter}.example.com`;
}

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-composition-floor-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    process.env.HOME = previousHome;
    try { fs.rmSync(home, { recursive: true, force: true }); } catch {}
  }
}

function leakedFact({ fingerprint, surface, claim }) {
  return {
    kind: "observation.recorded",
    payload: {
      observation_kind: "leaked_identifier",
      identifier_class: "object_id",
      identifier_fingerprint: fingerprint,
      surface_id: surface,
      claim_id: claim,
    },
  };
}

function appendLeakedFact(domain, { fingerprint, surface, claim }) {
  return appendFrontierEvent({
    target_domain: domain,
    kind: "observation.recorded",
    payload: {
      observation_kind: "leaked_identifier",
      identifier_class: "object_id",
      identifier_fingerprint: fingerprint,
      surface_id: surface,
      claim_id: claim,
    },
    surface_id: surface,
    claim_id: claim,
    actor: "orchestrator",
  });
}

test("shared leaked identifier proposes exactly one deduped transition edge", () => {
  const fingerprint = "a".repeat(64);
  const facts = [
    leakedFact({ fingerprint, surface: "surface:a", claim: "claim:a" }),
    leakedFact({ fingerprint, surface: "surface:b", claim: "claim:b" }),
  ];

  const plan = planCompositionFloor({
    leakedIdentifierFacts: facts,
    surfaceIds: new Set(["surface:a", "surface:b"]),
    existingTransitionKeys: new Set(),
    transitionKeyOf,
  });
  assert.equal(plan.blocked_prereqs.length, 0);
  assert.equal(plan.propose.length, 1);
  assert.equal(plan.propose[0].from_surface, "surface:a");
  assert.equal(plan.propose[0].to_surface, "surface:b");
  assert.equal(plan.propose[0].kind, "identity_propagation");

  const forward = transitionKeyOf({ from: "surface:a", to: "surface:b" });
  const forwardDedupe = planCompositionFloor({
    leakedIdentifierFacts: facts,
    surfaceIds: new Set(["surface:a", "surface:b"]),
    existingTransitionKeys: new Set([forward]),
    transitionKeyOf,
  });
  assert.equal(forwardDedupe.propose.length, 0);

  const reverse = transitionKeyOf({ from: "surface:b", to: "surface:a" });
  const reverseDedupe = planCompositionFloor({
    leakedIdentifierFacts: facts,
    surfaceIds: new Set(["surface:a", "surface:b"]),
    existingTransitionKeys: new Set([reverse]),
    transitionKeyOf,
  });
  assert.equal(reverseDedupe.propose.length, 0);
});

test("shared identifier fans out all unordered surface pairs and reaches a fixpoint", () => {
  const fingerprint = "b".repeat(64);
  const surfaces = ["surface:a", "surface:b", "surface:c", "surface:d"];
  const facts = surfaces.map((surface, index) => leakedFact({
    fingerprint,
    surface,
    claim: `claim:${index}`,
  }));

  const plan = planCompositionFloor({
    leakedIdentifierFacts: facts,
    surfaceIds: new Set(surfaces),
    existingTransitionKeys: new Set(),
    transitionKeyOf,
  });
  assert.equal(plan.propose.length, 6);

  const existing = new Set(plan.propose.map((proposal) => transitionKeyOf({
    from: proposal.from_surface,
    to: proposal.to_surface,
  })));
  const fixpoint = planCompositionFloor({
    leakedIdentifierFacts: facts,
    surfaceIds: new Set(surfaces),
    existingTransitionKeys: existing,
    transitionKeyOf,
  });
  assert.equal(fixpoint.propose.length, 0);
});

test("composition floor is vacuous without shared leaked identifiers", () => {
  const empty = planCompositionFloor({
    leakedIdentifierFacts: [],
    surfaceIds: new Set(),
    existingTransitionKeys: new Set(),
    transitionKeyOf,
  });
  assert.equal(empty.propose.length, 0);

  const singletonOnly = planCompositionFloor({
    leakedIdentifierFacts: [
      leakedFact({ fingerprint: "c".repeat(64), surface: "surface:a", claim: "claim:a" }),
      leakedFact({ fingerprint: "d".repeat(64), surface: "surface:b", claim: "claim:b" }),
    ],
    surfaceIds: new Set(["surface:a", "surface:b"]),
    existingTransitionKeys: new Set(),
    transitionKeyOf,
  });
  assert.equal(singletonOnly.propose.length, 0);
});

test("materialize producer floor appends and folds a shared leaked-identifier transition once", () => {
  withTempHome(() => {
    const domain = uniqueDomain("handler");
    const fingerprint = "e".repeat(64);
    appendLeakedFact(domain, { fingerprint, surface: "surface:x", claim: "claim:x" });
    appendLeakedFact(domain, { fingerprint, surface: "surface:y", claim: "claim:y" });
    assert.equal(readFrontierEvents(domain).filter((event) => (
      event.payload && event.payload.observation_kind === "leaked_identifier"
    )).length, 2);

    materializeProducerFloor({ target_domain: domain });
    const first = readTransitionProposals(domain).filter((event) => (
      event.payload.transition_kind === "identity_propagation"
    ));
    assert.equal(first.length, 1);
    assert.equal(first[0].payload.from_surface, "surface:x");
    assert.equal(first[0].payload.to_surface, "surface:y");

    materializeProducerFloor({ target_domain: domain });
    const second = readTransitionProposals(domain).filter((event) => (
      event.payload.transition_kind === "identity_propagation"
    ));
    assert.equal(second.length, 1);
  });
});

test("identity_propagation prereq is satisfied and planner is exported", () => {
  assert.equal(TRANSITION_KIND_VALUES.includes("identity_propagation"), true);
  assert.equal(typeof planCompositionFloor, "function");
});
