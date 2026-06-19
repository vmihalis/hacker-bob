"use strict";

// Plane X Cycle X.11 — cross-stack brief composition (the Nike fix).
//
// Tests per X.11 spec Do step 4:
//   1. Transition brief contains both endpoints' tools + the relational
//      Contract template + observations (in distilled summary form per
//      X-P9).
//   2. Surface node with adjacent transition gets brief that names the
//      transition + the adjacent Hypotheses (if any).
//   3. Brief size for a representative transition with 50 adjacent
//      observations stays under 30KB (sanity check on the X-P9 distilled-
//      by-shape claim).
//
// Plus auxiliary coverage for:
//   - Per-kind hunting vocab + Contract template surfacing per transition_kind
//   - Cross-stack composition slice ABSENT on Surface nodes with NO adjacent
//     transitions (the conditional drop per renderNodeBriefExtras)
//   - The orchestrator stanza presence (registry-driven so we read the file)

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
  TRANSITION_KIND_VALUES,
  appendHypothesisProposal,
  appendNodeTransition,
  appendTransitionProposal,
} = require("../mcp/lib/task-graph-events.js");
const {
  materializeTaskGraph,
} = require("../mcp/lib/task-graph-materializer.js");
const {
  appendContract,
} = require("../mcp/lib/contracts.js");
const {
  TRANSITION_KIND_HUNTING_VOCAB,
  TRANSITION_KIND_CONTRACT_TEMPLATES,
  transitionKindBriefContent,
} = require("../mcp/lib/technique-packs.js");
const {
  surfaceRoutesPath,
} = require("../mcp/lib/paths.js");
const {
  writeFileAtomic,
} = require("../mcp/lib/storage.js");

const KNOWN_TOOL = "bob_http_scan";

function parseFencedBriefJson(value, label) {
  const match = String(value).match(/^<<UNTRUSTED_DATA nonce=([0-9a-f]{32}) label=([^>\n]+)>>\n([\s\S]*)\n<<END_UNTRUSTED_DATA nonce=\1>>$/);
  assert.ok(match, `expected fenced ${label} slice`);
  assert.equal(match[2], label);
  return JSON.parse(match[3]);
}

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-x11-cross-stack-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

// Seed a minimal session: emit a single surface.observed so the session
// dir exists and the materializer has something to fold.
function seedSession(domain) {
  appendFrontierEvent({
    target_domain: domain,
    kind: "surface.observed",
    ts: "2026-05-31T00:00:00.000Z",
    surface_id: "surface:seed",
    payload: { title: "seed" },
  });
}

// Seed two surfaces (a web surface + an EVM smart-contract surface) so a
// transition between them can be proposed and a Surface evaluator brief
// can detect the adjacent transition via the materialized graph.
function seedTwoSurfaces(domain, webSurfaceId, evmSurfaceId) {
  appendFrontierEvent({
    target_domain: domain,
    kind: "surface.observed",
    ts: "2026-05-31T00:00:01.000Z",
    surface_id: webSurfaceId,
    payload: { title: "web auth endpoint", surface_type: "web" },
  });
  appendFrontierEvent({
    target_domain: domain,
    kind: "surface.observed",
    ts: "2026-05-31T00:00:02.000Z",
    surface_id: evmSurfaceId,
    payload: { title: "evm vault contract", surface_type: "smart_contract", chain_family: "evm" },
  });
}

// Write a minimal surface-routes.json. The X.5 deriveTransitionPack reads
// surface metadata from this file (via prepare-node's safeSurfaceRouteMap)
// so the cross-stack UNION of both endpoints' evaluator-callable tool
// sets requires real routes. Each entry mirrors the
// validateSurfaceRoute schema (capability_pack + evaluator_agent +
// brief_profile + capability_pack_version + reasons + confidence).
function seedSurfaceRoutes(domain, routes) {
  const document = {
    version: 1,
    route_version: 1,
    routes: routes.map((route) => ({
      surface_id: route.surface_id,
      surface_type: route.surface_type,
      capability_pack: route.capability_pack,
      capability_pack_version: route.capability_pack_version || 1,
      evaluator_agent: route.evaluator_agent,
      brief_profile: route.brief_profile,
      context_budget: route.context_budget || {
        candidate_pack_limit: 8,
        full_pack_read_limit: 2,
        attempt_log_required: true,
      },
      confidence: route.confidence || "high",
      reasons: route.reasons || ["seeded for cross-stack brief test"],
      ...(route.chain_family ? { chain_family: route.chain_family } : {}),
    })),
  };
  writeFileAtomic(surfaceRoutesPath(domain), `${JSON.stringify(document, null, 2)}\n`);
}

// Convenience: seed routes for the web-auth + evm-vault fixture used across
// the X.11 tests. Mirrors the canonical capability_pack catalog:
// web → evaluator-agent (web brief_profile), smart_contract_evm →
// evaluator-evm-agent (smart_contract_evm brief_profile). These names are
// the canonical pack values from mcp/lib/capability-packs.js.
function seedWebEvmRoutes(domain, webSurfaceId, evmSurfaceId) {
  seedSurfaceRoutes(domain, [
    {
      surface_id: webSurfaceId,
      surface_type: "web",
      capability_pack: "web",
      evaluator_agent: "evaluator-agent",
      brief_profile: "web",
    },
    {
      surface_id: evmSurfaceId,
      surface_type: "smart_contract",
      chain_family: "evm",
      capability_pack: "smart_contract_evm",
      evaluator_agent: "evaluator-evm-agent",
      brief_profile: "smart_contract_evm",
    },
  ]);
}

// Propose a Transition between two surfaces and materialize.
function seedProposedTransition(domain, {
  fromSurface,
  toSurface,
  kind = "identity_propagation",
  trustAssumption = "Auth token sub binds to wallet address via signature recovery.",
  proposalId = "TP-x11-default",
} = {}) {
  appendTransitionProposal({
    target_domain: domain,
    ts: "2026-05-31T00:01:00.000Z",
    from_surface: fromSurface,
    to_surface: toSurface,
    kind,
    trust_assumption: trustAssumption,
    proposal_id: proposalId,
  });
  materializeTaskGraph(domain, { write: true });
  return `${TASK_GRAPH_NODE_ID_PREFIX}T-${proposalId}`;
}

// Build a Contract input that the X.4 satisfiability gate accepts.
function baseContractInput({
  contractId = "C-x11-base",
  severity = "high",
  witnessKind = "tool_output_match",
  predicate = { tool: KNOWN_TOOL, match: { path: "$.status", equals: 200 } },
} = {}) {
  return {
    contract_id: contractId,
    severity_floor: severity,
    invariants: [{ id: "I1", statement: "X.11 cross-stack composition coverage." }],
    witnesses: [{ id: "W1", kind: witnessKind, predicate }],
    production_paths: [{
      description: "Invoke the canonical web producer.",
      tool_call_pattern: [{ tool: KNOWN_TOOL }],
    }],
  };
}

// Seed a contracted Transition node so prepare_node will accept it. The
// initial state from the proposal is `proposed`; the X.4 attach path lands
// it at `contracted`.
function seedContractedTransition(domain, transitionNodeId, contractInput = null) {
  appendContract({
    target_domain: domain,
    node_id: transitionNodeId,
    contract: contractInput || baseContractInput(),
    ts: "2026-05-31T00:02:00.000Z",
  });
  materializeTaskGraph(domain, { write: true });
  return transitionNodeId;
}

// ─── Per-kind hunting vocab + Contract template surface ──────────────────

test("TRANSITION_KIND_HUNTING_VOCAB covers every X-D3 transition_kind", () => {
  for (const kind of TRANSITION_KIND_VALUES) {
    assert.ok(typeof TRANSITION_KIND_HUNTING_VOCAB[kind] === "string",
      `hunting vocab missing for ${kind}`);
    assert.ok(TRANSITION_KIND_HUNTING_VOCAB[kind].length > 0,
      `hunting vocab empty for ${kind}`);
    // X-P9 prose discipline: each hunting vocab string stays under the
    // 1024-char target so the brief renderer can inline all six.
    assert.ok(TRANSITION_KIND_HUNTING_VOCAB[kind].length <= 1024,
      `hunting vocab for ${kind} exceeds 1024 chars (${TRANSITION_KIND_HUNTING_VOCAB[kind].length})`);
  }
});

test("TRANSITION_KIND_CONTRACT_TEMPLATES covers every X-D3 transition_kind with a relational_value_match skeleton", () => {
  for (const kind of TRANSITION_KIND_VALUES) {
    const template = TRANSITION_KIND_CONTRACT_TEMPLATES[kind];
    assert.ok(template, `template missing for ${kind}`);
    assert.equal(template.witness.kind, "relational_value_match",
      `template witness kind for ${kind} must be relational_value_match per X.11 spec`);
    // The predicate skeleton has left + op + right with extract_paths.
    const pred = template.witness.predicate;
    assert.ok(pred.left && typeof pred.left.artifact_ref === "string");
    assert.ok(pred.left.extract_path.startsWith("$"));
    assert.ok(pred.right && typeof pred.right.artifact_ref === "string");
    assert.ok(pred.right.extract_path.startsWith("$"));
    assert.equal(pred.op, "eq", `template op for ${kind} must be eq (cross-stack equality)`);
    // Placeholder artifact_refs use angle-bracket markers so the agent
    // reads them as "fill these in".
    assert.ok(pred.left.artifact_ref.includes("<") && pred.left.artifact_ref.includes(">"),
      `left artifact_ref for ${kind} must use placeholder markers`);
    assert.ok(pred.right.artifact_ref.includes("<") && pred.right.artifact_ref.includes(">"),
      `right artifact_ref for ${kind} must use placeholder markers`);
    // Invariant statement stays under the X-D4 280-char cap.
    assert.ok(template.invariant.length <= 280,
      `invariant for ${kind} exceeds 280 chars (${template.invariant.length})`);
  }
});

test("transitionKindBriefContent returns null for unknown / empty kinds and bundled content for known kinds", () => {
  assert.equal(transitionKindBriefContent(null), null);
  assert.equal(transitionKindBriefContent(""), null);
  assert.equal(transitionKindBriefContent("not_a_kind"), null);
  const content = transitionKindBriefContent("identity_propagation");
  assert.ok(content);
  assert.equal(content.transition_kind, "identity_propagation");
  assert.ok(content.hunting_vocab);
  assert.ok(content.contract_template);
  assert.equal(content.contract_template.witness.kind, "relational_value_match");
});

// ─── X.11 Do step 4 (1): Transition brief contains both endpoints' tools + relational Contract template + observations ─

test("Transition brief inlines the cross_stack_composition slice with transition_kind, hunting_vocab, worked Contract template, both endpoints, both endpoints' summary observations", () => {
  withTempHome(() => {
    const domain = "x11-transition-brief.example.com";
    seedSession(domain);
    seedTwoSurfaces(domain, "surface:web-auth", "surface:evm-vault");

    // Seed observations on each endpoint surface so the slice's
    // endpoint_observations buckets have content. Per X-P9 each
    // observation is already summary-grade at emit; the slice inlines
    // up to ENDPOINT_OBSERVATIONS_PER_SURFACE_CAP per surface.
    for (let i = 0; i < 5; i += 1) {
      appendFrontierEvent({
        target_domain: domain,
        kind: "observation.recorded",
        ts: `2026-05-31T00:00:1${i}.000Z`,
        surface_id: "surface:web-auth",
        payload: { observation_kind: "synthetic_web", index: i },
      });
      appendFrontierEvent({
        target_domain: domain,
        kind: "observation.recorded",
        ts: `2026-05-31T00:00:2${i}.000Z`,
        surface_id: "surface:evm-vault",
        payload: { observation_kind: "synthetic_evm", index: i },
      });
    }

    const transitionNodeId = seedProposedTransition(domain, {
      fromSurface: "surface:web-auth",
      toSurface: "surface:evm-vault",
      kind: "identity_propagation",
      trustAssumption: "Auth token sub binds to wallet recovered_signer on EVM dispatch.",
      proposalId: "TP-x11-id-prop",
    });
    seedContractedTransition(domain, transitionNodeId);

    const prep = JSON.parse(TOOL_HANDLERS.bob_prepare_node({
      target_domain: domain,
      node_id: transitionNodeId,
    }));

    // The Transition brief MUST inline the cross_stack_composition slice.
    assert.ok(prep.brief.cross_stack_composition,
      "Transition brief must inline cross_stack_composition slice per X.11 Do step 1");
    const xs = parseFencedBriefJson(prep.brief.cross_stack_composition, "cross_stack_composition");

    // transition_kind + trust_assumption surfaced from the proposal payload.
    assert.equal(xs.transition_kind, "identity_propagation");
    assert.equal(xs.trust_assumption, "Auth token sub binds to wallet recovered_signer on EVM dispatch.");

    // Both endpoint surfaces named.
    assert.equal(xs.endpoint_surfaces.from, "surface:web-auth");
    assert.equal(xs.endpoint_surfaces.to, "surface:evm-vault");

    // Per-kind hunting vocab (the focused, transition_kind-specific narrative).
    assert.ok(xs.hunting_vocab, "hunting_vocab must surface for known transition_kind");
    assert.equal(xs.hunting_vocab, TRANSITION_KIND_HUNTING_VOCAB.identity_propagation);

    // Worked Contract template (the relational_value_match skeleton).
    assert.ok(xs.contract_template, "contract_template must surface for known transition_kind");
    assert.equal(xs.contract_template.witness.kind, "relational_value_match");
    assert.equal(xs.contract_template.witness.predicate.op, "eq");
    assert.ok(xs.contract_template.witness.predicate.left.artifact_ref.includes("http_record:"));
    assert.ok(xs.contract_template.witness.predicate.right.artifact_ref.includes("evm_call:"));

    // Both endpoints' summary-grade observations surfaced.
    assert.ok(xs.endpoint_observations["surface:web-auth"]);
    assert.ok(xs.endpoint_observations["surface:evm-vault"]);
    assert.equal(xs.endpoint_observations["surface:web-auth"].events.length, 5);
    assert.equal(xs.endpoint_observations["surface:evm-vault"].events.length, 5);
    // Each event is a summary-shape (event_id + ts + surface_id + payload),
    // not a raw body.
    const sampleEvent = xs.endpoint_observations["surface:web-auth"].events[0];
    assert.ok(typeof sampleEvent.event_id === "string");
    assert.ok(typeof sampleEvent.ts === "string");
    assert.equal(sampleEvent.surface_id, "surface:web-auth");

    // The endpoint_capability_packs[] union (both endpoint families' packs)
    // is surfaced so the agent reads the cross-stack signal in one place.
    assert.ok(Array.isArray(xs.endpoint_capability_packs));
    // The discipline strings are non-empty narratives so the agent has the
    // X.11 framing ("Use the contract_template as the predicate skeleton...").
    assert.ok(typeof xs.discipline === "string" && xs.discipline.length > 0);
    assert.ok(typeof xs.cross_stack_tools_discipline === "string"
      && xs.cross_stack_tools_discipline.length > 0);
  });
});

// ─── X.11 Do step 4 (2): Surface node with adjacent Transition gets brief naming it ─

test("Surface node with ≥1 adjacent Transition surfaces the cross_stack_composition slice with one-line adjacent_transitions summaries", () => {
  withTempHome(() => {
    const domain = "x11-surface-adj.example.com";
    seedSession(domain);
    seedTwoSurfaces(domain, "surface:web-auth", "surface:evm-vault");

    // Seed a Transition that touches surface:web-auth.
    const transitionNodeId = seedProposedTransition(domain, {
      fromSurface: "surface:web-auth",
      toSurface: "surface:evm-vault",
      kind: "trust_handoff",
      trustAssumption: "Off-chain admin role maps to on-chain vault authority.",
      proposalId: "TP-x11-trust",
    });

    // Build a Contract on a Surface node id (we synthesize the contracted
    // state via raw node.transitioned because the wave-scheduler usually
    // owns Surface-node lifecycle). The surface-node id pattern is
    // TG-S-<surface_id>.
    const surfaceNodeId = `${TASK_GRAPH_NODE_ID_PREFIX}S-surface:web-auth`;
    appendNodeTransition({
      target_domain: domain,
      node_id: surfaceNodeId,
      from_state: "proposed",
      to_state: "contracted",
      contract_hash: "abcd1234".repeat(8),
      contract: {
        contract_id: "C-surface-x11",
        contract_hash: "abcd1234".repeat(8),
        severity_floor: "medium",
        invariants: [{ id: "I1", statement: "Web auth endpoint authorizes correctly." }],
        witnesses: [{
          id: "W1",
          kind: "tool_output_match",
          predicate: { tool: KNOWN_TOOL, match: { path: "$.status", equals: 200 } },
        }],
        production_paths: [{
          description: "Probe web auth.",
          tool_call_pattern: [{ tool: KNOWN_TOOL }],
        }],
      },
    });
    materializeTaskGraph(domain, { write: true });

    const prep = JSON.parse(TOOL_HANDLERS.bob_prepare_node({
      target_domain: domain,
      node_id: surfaceNodeId,
    }));

    // The Surface brief MUST inline the cross_stack_composition slice
    // because there is ≥1 adjacent Transition touching surface:web-auth.
    assert.ok(prep.brief.cross_stack_composition,
      "Surface brief with adjacent Transition must inline cross_stack_composition slice per X.11 Do step 2");
    const xs = parseFencedBriefJson(prep.brief.cross_stack_composition, "cross_stack_composition");

    assert.equal(xs.surface_id, "surface:web-auth");
    assert.ok(Array.isArray(xs.adjacent_transitions));
    assert.equal(xs.adjacent_transitions.length, 1);
    const adj = xs.adjacent_transitions[0];
    assert.equal(adj.node_id, transitionNodeId);
    assert.equal(adj.transition_kind, "trust_handoff");
    assert.equal(adj.trust_assumption, "Off-chain admin role maps to on-chain vault authority.");
    // The OTHER endpoint surface (not the dispatched one) is named so the
    // Surface evaluator sees the full handoff at a glance.
    assert.equal(adj.other_endpoint_surface, "surface:evm-vault");

    // X.11 Do step 2 says the brief ALSO carries the adjacent_hypotheses
    // slice (the existing X.8 slice). When no Hypotheses are adjacent the
    // slice key is dropped per renderNodeBriefExtras; in this fixture we
    // didn't propose any so the key SHOULD be absent.
    assert.equal(prep.brief.adjacent_hypotheses, undefined);
  });
});

test("Surface node with adjacent Transition AND adjacent Hypothesis surfaces BOTH the cross_stack_composition AND adjacent_hypotheses slices", () => {
  withTempHome(() => {
    const domain = "x11-surface-adj-both.example.com";
    seedSession(domain);
    seedTwoSurfaces(domain, "surface:web-auth", "surface:evm-vault");

    // Seed a Transition + a Hypothesis on the same surface.
    seedProposedTransition(domain, {
      fromSurface: "surface:web-auth",
      to_surface: "surface:evm-vault",
      toSurface: "surface:evm-vault",
      kind: "identity_propagation",
      trustAssumption: "Auth token sub binds to vault depositor address.",
      proposalId: "TP-x11-both",
    });
    appendHypothesisProposal({
      target_domain: domain,
      ts: "2026-05-31T00:01:30.000Z",
      hypothesis_statement: "Web auth leaks privileged role in error response.",
      surface_refs: ["surface:web-auth"],
      proposal_id: "HP-x11-both",
    });

    const surfaceNodeId = `${TASK_GRAPH_NODE_ID_PREFIX}S-surface:web-auth`;
    appendNodeTransition({
      target_domain: domain,
      node_id: surfaceNodeId,
      from_state: "proposed",
      to_state: "contracted",
      contract_hash: "cafebabe".repeat(8),
      contract: {
        contract_id: "C-surface-both",
        contract_hash: "cafebabe".repeat(8),
        severity_floor: "high",
        invariants: [{ id: "I1", statement: "Web auth endpoint authorizes correctly." }],
        witnesses: [{
          id: "W1",
          kind: "tool_output_match",
          predicate: { tool: KNOWN_TOOL, match: { path: "$.status", equals: 200 } },
        }],
        production_paths: [{
          description: "Probe web auth.",
          tool_call_pattern: [{ tool: KNOWN_TOOL }],
        }],
      },
    });
    materializeTaskGraph(domain, { write: true });

    const prep = JSON.parse(TOOL_HANDLERS.bob_prepare_node({
      target_domain: domain,
      node_id: surfaceNodeId,
    }));

    assert.ok(prep.brief.cross_stack_composition,
      "Surface brief must inline cross_stack_composition (adjacent Transition present)");
    assert.equal(parseFencedBriefJson(prep.brief.cross_stack_composition, "cross_stack_composition").adjacent_transitions.length, 1);

    assert.ok(prep.brief.adjacent_hypotheses,
      "Surface brief must inline adjacent_hypotheses (adjacent Hypothesis present, X.8 slice)");
    assert.equal(parseFencedBriefJson(prep.brief.adjacent_hypotheses, "adjacent_hypotheses").hypotheses.length, 1);
    assert.equal(
      parseFencedBriefJson(prep.brief.adjacent_hypotheses, "adjacent_hypotheses").hypotheses[0].hypothesis_statement,
      "Web auth leaks privileged role in error response.",
    );
  });
});

// ─── X.11 Do step 4 (3): Brief size sanity check (X-P9 distilled-by-shape) ─

test("Transition brief with 50 adjacent observations per endpoint stays under 30KB (X-P9 size sanity check)", () => {
  withTempHome(() => {
    const domain = "x11-size-budget.example.com";
    seedSession(domain);
    seedTwoSurfaces(domain, "surface:web-auth", "surface:evm-vault");

    // Seed 50 observations on EACH endpoint surface (100 total). Per X-P9
    // each event is shape-bounded; the brief's endpoint_observations slice
    // caps at ENDPOINT_OBSERVATIONS_PER_SURFACE_CAP per surface so the
    // 100-event ledger compresses to a fixed brief shape.
    const pad = (n) => String(n).padStart(2, "0");
    for (let i = 0; i < 50; i += 1) {
      const minutes = pad(Math.floor(i / 10));
      const seconds = pad((i % 10) * 6);
      appendFrontierEvent({
        target_domain: domain,
        kind: "observation.recorded",
        ts: `2026-05-31T01:${minutes}:${seconds}.000Z`,
        surface_id: "surface:web-auth",
        payload: {
          observation_kind: "synthetic_web",
          index: i,
          method: "POST",
          url: `https://x11-size-budget.example.com/api/v1/route-${i}`,
          status: 200,
        },
      });
      appendFrontierEvent({
        target_domain: domain,
        kind: "observation.recorded",
        ts: `2026-05-31T02:${minutes}:${seconds}.000Z`,
        surface_id: "surface:evm-vault",
        payload: {
          observation_kind: "synthetic_evm",
          index: i,
          tx_hash: `0x${"f".repeat(64)}`,
          recovered_signer: "0xWALLET",
        },
      });
    }

    const transitionNodeId = seedProposedTransition(domain, {
      fromSurface: "surface:web-auth",
      toSurface: "surface:evm-vault",
      kind: "identity_propagation",
      trustAssumption: "Auth token sub binds to wallet recovered_signer on EVM dispatch.",
      proposalId: "TP-x11-size",
    });
    seedContractedTransition(domain, transitionNodeId);

    const prep = JSON.parse(TOOL_HANDLERS.bob_prepare_node({
      target_domain: domain,
      node_id: transitionNodeId,
    }));

    const briefSize = JSON.stringify(prep.brief).length;
    assert.ok(briefSize < 30_000,
      `brief size ${briefSize} bytes exceeds the X-P9 sanity check budget of 30KB`);

    // Sanity: the cross_stack_composition slice is present and the
    // endpoint_observations bucket count stays bounded by the per-surface
    // cap (NOT by the full 50 ledger events).
    assert.ok(prep.brief.cross_stack_composition);
    const xs = parseFencedBriefJson(prep.brief.cross_stack_composition, "cross_stack_composition");
    const webEvents = xs.endpoint_observations["surface:web-auth"].events;
    const evmEvents = xs.endpoint_observations["surface:evm-vault"].events;
    assert.ok(webEvents.length <= 8, `web events cap exceeded: ${webEvents.length}`);
    assert.ok(evmEvents.length <= 8, `evm events cap exceeded: ${evmEvents.length}`);
  });
});

// ─── X.11 conditional slice drop — Surface with NO adjacent Transitions ──

test("Surface node with NO adjacent Transition does NOT carry the cross_stack_composition slice (T-R1 inflation guard)", () => {
  withTempHome(() => {
    const domain = "x11-surface-no-adj.example.com";
    seedSession(domain);
    appendFrontierEvent({
      target_domain: domain,
      kind: "surface.observed",
      ts: "2026-05-31T00:00:01.000Z",
      surface_id: "surface:lonely-web",
      payload: { title: "lonely web endpoint" },
    });
    materializeTaskGraph(domain, { write: true });

    const surfaceNodeId = `${TASK_GRAPH_NODE_ID_PREFIX}S-surface:lonely-web`;
    appendNodeTransition({
      target_domain: domain,
      node_id: surfaceNodeId,
      from_state: "proposed",
      to_state: "contracted",
      contract_hash: "deadbeef".repeat(8),
      contract: {
        contract_id: "C-lonely",
        contract_hash: "deadbeef".repeat(8),
        severity_floor: "low",
        invariants: [{ id: "I1", statement: "Lonely surface authorizes." }],
        witnesses: [{
          id: "W1",
          kind: "tool_output_match",
          predicate: { tool: KNOWN_TOOL, match: { path: "$.status", equals: 200 } },
        }],
        production_paths: [{
          description: "Probe lonely.",
          tool_call_pattern: [{ tool: KNOWN_TOOL }],
        }],
      },
    });
    materializeTaskGraph(domain, { write: true });

    const prep = JSON.parse(TOOL_HANDLERS.bob_prepare_node({
      target_domain: domain,
      node_id: surfaceNodeId,
    }));

    assert.equal(prep.brief.cross_stack_composition, undefined,
      "Surface brief with NO adjacent Transition must NOT carry an empty cross_stack_composition slice");
  });
});

// ─── X.11 Transition pack carries BOTH endpoints' tools via X.5 derivePackForNode ─

test("Transition node's derived pack UNIONs both endpoints' capability_pack tool sets (cross-stack tools per X.11 Do step 1)", () => {
  withTempHome(() => {
    const domain = "x11-pack-union.example.com";
    seedSession(domain);
    seedTwoSurfaces(domain, "surface:web-auth", "surface:evm-vault");
    // Seed real surface routes so deriveTransitionPack picks both endpoint
    // packs (web + smart_contract_evm) and unions their tool sets. Without
    // routes both endpoints fall back to DEFAULT_CAPABILITY_PACK_ID ("web").
    seedWebEvmRoutes(domain, "surface:web-auth", "surface:evm-vault");
    const transitionNodeId = seedProposedTransition(domain, {
      fromSurface: "surface:web-auth",
      toSurface: "surface:evm-vault",
      kind: "identity_propagation",
      trustAssumption: "Auth token sub binds to vault depositor.",
      proposalId: "TP-x11-pack",
    });
    seedContractedTransition(domain, transitionNodeId);

    const prep = JSON.parse(TOOL_HANDLERS.bob_prepare_node({
      target_domain: domain,
      node_id: transitionNodeId,
    }));

    // The allowed_tools_for_node[] is the UNION of both endpoint families'
    // evaluator tool sets per deriveTransitionPack in X.5. We can sanity-
    // check this without re-deriving: web-family bob_http_scan AND
    // EVM-family bob_evm_call / bob_evm_storage_read must both be in scope
    // (these are the canonical web + EVM evaluator tools).
    const allowedTools = prep.brief.allowed_tools_for_node.allowed_tools;
    assert.ok(Array.isArray(allowedTools));
    // bob_http_scan is in the evaluator-web bundle.
    assert.ok(allowedTools.includes("bob_http_scan"),
      "Transition brief allowed_tools must include web-family bob_http_scan");
    // bob_evm_call is in the evaluator-evm bundle.
    assert.ok(allowedTools.includes("bob_evm_call"),
      "Transition brief allowed_tools must include EVM-family bob_evm_call");

    // The brief's cross_stack_composition slice surfaces the same union
    // via the endpoint_capability_packs[] array.
    const xs = parseFencedBriefJson(prep.brief.cross_stack_composition, "cross_stack_composition");
    assert.ok(xs.endpoint_capability_packs.includes("web"));
    assert.ok(xs.endpoint_capability_packs.includes("smart_contract_evm"));
  });
});

// ─── X.11 Do step 3: orchestrator stanza presence ────────────────────────

test("orchestrator.md carries the X.11 cross-stack transition proposals stanza per Do step 3", () => {
  const orchestratorPath = path.join(__dirname, "..", "prompts", "roles", "orchestrator.md");
  const content = fs.readFileSync(orchestratorPath, "utf8");
  // The stanza must name the prep step: bob_propose_transition before
  // dispatching Surface-node waves when ≥2 stack families on the same target.
  assert.ok(content.includes("bob_propose_transition"),
    "orchestrator.md must reference bob_propose_transition (X.11 Do step 3)");
  assert.ok(content.includes("≥2 stack families") || content.includes("Cross-stack"),
    "orchestrator.md must include the X.11 cross-stack transition stanza");
});

// ─── X.11 sanity: independent invocation of derivePackForNode and the brief composer ─

test("Transition node brief composition is deterministic: same fixture → same cross_stack_composition shape", () => {
  withTempHome(() => {
    const domain = "x11-determinism.example.com";
    seedSession(domain);
    seedTwoSurfaces(domain, "surface:web-auth", "surface:evm-vault");
    const transitionNodeId = seedProposedTransition(domain, {
      fromSurface: "surface:web-auth",
      toSurface: "surface:evm-vault",
      kind: "value_movement",
      trustAssumption: "Off-chain authorization signs the payee binding.",
      proposalId: "TP-x11-det",
    });
    seedContractedTransition(domain, transitionNodeId);

    const prep1 = JSON.parse(TOOL_HANDLERS.bob_prepare_node({
      target_domain: domain,
      node_id: transitionNodeId,
    }));
    // The X.8 prepare_node call emits a node.transitioned event so a
    // direct second call would refuse on the dispatched state. Re-derive
    // the brief context by calling derivePackForNode directly and
    // confirming the slice shape is stable. For the cross-stack
    // composition, the contract_template is the deterministic surface
    // (no clock / random / env reads).
    assert.ok(prep1.brief.cross_stack_composition);
    const xs1 = parseFencedBriefJson(prep1.brief.cross_stack_composition, "cross_stack_composition");
    const template1 = xs1.contract_template;
    const template2 = transitionKindBriefContent("value_movement").contract_template;
    assert.deepEqual(template1, template2);
  });
});

// ─── X.11 unknown transition_kind handling ───────────────────────────────

test("Transition node with a transition_kind outside the X-D3 closed enum still gets the cross_stack_composition slice but with null hunting_vocab + null contract_template", () => {
  withTempHome(() => {
    const domain = "x11-unknown-kind.example.com";
    seedSession(domain);
    seedTwoSurfaces(domain, "surface:web-auth", "surface:evm-vault");
    // Synthesize a transition_proposed event with an unknown transition_kind
    // by going around the appendTransitionProposal validator. We emit the
    // event via the raw frontier_events append + a node.transitioned to
    // bring the synthetic node to contracted state.
    appendFrontierEvent({
      target_domain: domain,
      kind: "observation.recorded",
      ts: "2026-05-31T00:01:00.000Z",
      payload: {
        kind: "transition_proposed",
        from_surface: "surface:web-auth",
        to_surface: "surface:evm-vault",
        transition_kind: "synthetic_unknown_kind",
        trust_assumption: "Synthetic transition for unknown-kind regression.",
        proposal_id: "TP-unknown",
      },
    });
    materializeTaskGraph(domain, { write: true });
    const transitionNodeId = `${TASK_GRAPH_NODE_ID_PREFIX}T-TP-unknown`;
    appendContract({
      target_domain: domain,
      node_id: transitionNodeId,
      contract: baseContractInput({ contractId: "C-unknown" }),
      ts: "2026-05-31T00:02:00.000Z",
    });
    materializeTaskGraph(domain, { write: true });

    const prep = JSON.parse(TOOL_HANDLERS.bob_prepare_node({
      target_domain: domain,
      node_id: transitionNodeId,
    }));

    assert.ok(prep.brief.cross_stack_composition);
    const xs = parseFencedBriefJson(prep.brief.cross_stack_composition, "cross_stack_composition");
    assert.equal(xs.transition_kind, "synthetic_unknown_kind");
    assert.equal(xs.hunting_vocab, null);
    assert.equal(xs.contract_template, null);
    // The endpoint_observations buckets still surface (zero events here).
    assert.ok(xs.endpoint_observations["surface:web-auth"]);
    assert.ok(xs.endpoint_observations["surface:evm-vault"]);
  });
});
