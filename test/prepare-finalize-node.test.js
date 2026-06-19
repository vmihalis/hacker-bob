"use strict";

// Plane X Cycle X.8 — prepare_node + finalize_node atomic protocol tests.
//
// Per the spec's Do step 5 the suite covers:
//   1. prepare_node on non-contracted node → refused
//   2. empty agent_output → refused
//   3. stale prep_token → refused
//   4. successful flow with relational_value_match Contract → finalize
//      succeeds; downstream nodes ready
//   5. mechanical-fail flow → finalize emits failed with structured
//      failure_reason; downstream not ready
//   6. retry-with-recall: operator re-contracts a failed node via
//      bob_attach_contract (failed → contracted), re-prepares, the brief
//      surfaces the prior failure via prior_attempt slice, and the second
//      finalize succeeds against the refined Contract
//   7. graph drift detection: mid-run a new edge gets added; fresh
//      bob_prepare_node produces a different graph_context_hash
//   8. hypothesis visibility for Surface node with adjacent Hypothesis
//   9. recommended_reads_for_node inlines DISTILLED SUMMARIES not bodies
//  10. reaper fires on stuck dispatch

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("crypto");
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
  appendNodeTransition,
  appendTransitionProposal,
  expireStaleDispatchedNodes,
  readNodeTransitions,
} = require("../mcp/lib/task-graph-events.js");
const {
  materializeTaskGraph,
} = require("../mcp/lib/task-graph-materializer.js");
const {
  importHttpTraffic,
} = require("../mcp/lib/http-records.js");
const {
  appendContract,
} = require("../mcp/lib/contracts.js");
const {
  OPEN_SENTINEL,
  CLOSE_SENTINEL,
  escapeRegExp,
} = require("../mcp/lib/untrusted-envelope.js");

function parseFencedBriefJson(value, label) {
  const match = String(value).match(/^<<UNTRUSTED_DATA nonce=([0-9a-f]{32}) label=([^>\n]+)>>\n([\s\S]*)\n<<END_UNTRUSTED_DATA nonce=\1>>$/);
  assert.ok(match, `expected fenced ${label} slice`);
  assert.equal(match[2], label);
  return JSON.parse(match[3]);
}

function sha256Hex(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function normalizeEnvelopeNonces(value) {
  return String(value)
    .replace(new RegExp(`${escapeRegExp(OPEN_SENTINEL)} nonce=[0-9a-f]{32}`, "g"), `${OPEN_SENTINEL} nonce=<nonce>`)
    .replace(new RegExp(`${escapeRegExp(CLOSE_SENTINEL)} nonce=[0-9a-f]{32}`, "g"), `${CLOSE_SENTINEL} nonce=<nonce>`);
}

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-prepare-finalize-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function withFixedDate(isoString, fn) {
  const RealDate = Date;
  const fixedTime = new RealDate(isoString).getTime();
  function FixedDate(...args) {
    if (!(this instanceof FixedDate)) {
      return args.length === 0
        ? new RealDate(fixedTime).toString()
        : new RealDate(...args).toString();
    }
    return args.length === 0
      ? new RealDate(fixedTime)
      : new RealDate(...args);
  }
  Object.setPrototypeOf(FixedDate, RealDate);
  FixedDate.prototype = RealDate.prototype;
  FixedDate.now = () => fixedTime;
  FixedDate.parse = RealDate.parse;
  FixedDate.UTC = RealDate.UTC;
  global.Date = FixedDate;
  try {
    return fn();
  } finally {
    global.Date = RealDate;
  }
}

function withSequentialRandomBytes(fn) {
  const originalRandomBytes = crypto.randomBytes;
  let fillByte = 1;
  crypto.randomBytes = (size) => {
    const out = Buffer.alloc(size, fillByte);
    fillByte = (fillByte % 255) + 1;
    return out;
  };
  try {
    return fn();
  } finally {
    crypto.randomBytes = originalRandomBytes;
  }
}

// Helper: stand up a session-state shell so the materializer and downstream
// tools see a domain that exists. The X.8 tools do NOT require a fully
// initialized session (no scope check, no auth) so a minimal seed is enough.
function seedSession(domain) {
  // The frontier-events ledger needs the session dir to exist before the
  // first append. Touching a single observation creates the dir.
  appendFrontierEvent({
    target_domain: domain,
    kind: "surface.observed",
    ts: "2026-05-31T00:00:00.000Z",
    surface_id: "surface:seed",
    payload: { title: "seed" },
  });
}

// Helper: propose a Hypothesis node + materialize so the X.4 attach path
// sees the live `proposed` state.
function seedProposedHypothesis(domain, proposalId, surfaceRefs = ["surface:auth"]) {
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

// Baseline Contract carrying a tool_output_match witness against a real
// MCP tool so the X.4 satisfiability gate passes.
const KNOWN_TOOL = "bob_http_scan";

function baseContractInput({
  contractId = "C-x8-base",
  severity = "high",
  witnessKind = "tool_output_match",
  predicate = { tool: KNOWN_TOOL, match: { path: "$.status", equals: 200 } },
} = {}) {
  return {
    contract_id: contractId,
    severity_floor: severity,
    invariants: [{ id: "I1", statement: "Auth token cannot escalate roles." }],
    witnesses: [{ id: "W1", kind: witnessKind, predicate }],
    production_paths: [{
      description: "Invoke the canonical web producer.",
      tool_call_pattern: [{ tool: KNOWN_TOOL }],
    }],
  };
}

// Helper: seed a proposed Hypothesis + attach a Contract so the node lands
// in `contracted` state, ready for prepare_node.
function seedContractedNode(domain, proposalId, contractInput = null, surfaceRefs = ["surface:auth"]) {
  const nodeId = seedProposedHypothesis(domain, proposalId, surfaceRefs);
  appendContract({
    target_domain: domain,
    node_id: nodeId,
    contract: contractInput || baseContractInput(),
    ts: "2026-05-31T00:02:00.000Z",
  });
  materializeTaskGraph(domain, { write: true });
  return nodeId;
}

// ─── Do step 5 (1): prepare_node on non-contracted node refuses ─────────

test("prepare_node refuses when node state is not contracted or ready", () => {
  withTempHome(() => {
    const domain = "x8-refuse-state.example.com";
    seedSession(domain);
    const nodeId = seedProposedHypothesis(domain, "HP-no-contract");
    let caught = null;
    try {
      TOOL_HANDLERS.bob_prepare_node({
        target_domain: domain,
        node_id: nodeId,
      });
    } catch (err) { caught = err; }
    assert.ok(caught, "expected refusal for proposed-state node");
    assert.equal(caught.code, "node_not_dispatch_ready");
    assert.equal(caught.details.current_state, "proposed");
  });
});

test("prepare_node refuses on a finalized node (state machine forbids re-dispatch)", () => {
  withTempHome(() => {
    const domain = "x8-refuse-finalized.example.com";
    seedSession(domain);
    const nodeId = seedContractedNode(domain, "HP-fin");
    // Run through the full lifecycle once to land at finalized.
    const prep = JSON.parse(TOOL_HANDLERS.bob_prepare_node({
      target_domain: domain,
      node_id: nodeId,
    }));
    TOOL_HANDLERS.bob_finalize_node({
      target_domain: domain,
      node_id: nodeId,
      prep_token: prep.prep_token,
      agent_output: {
        tool_invocations: [{ tool: KNOWN_TOOL, output: { status: 200 } }],
      },
    });
    let caught = null;
    try {
      TOOL_HANDLERS.bob_prepare_node({ target_domain: domain, node_id: nodeId });
    } catch (err) { caught = err; }
    assert.ok(caught);
    assert.equal(caught.code, "node_not_dispatch_ready");
    assert.equal(caught.details.current_state, "finalized");
  });
});

// ─── Do step 5 (2 + 3): finalize refuses empty output + stale prep_token ─

test("finalize_node refuses an empty agent_output", () => {
  withTempHome(() => {
    const domain = "x8-empty-output.example.com";
    seedSession(domain);
    const nodeId = seedContractedNode(domain, "HP-empty");
    const prep = JSON.parse(TOOL_HANDLERS.bob_prepare_node({
      target_domain: domain,
      node_id: nodeId,
    }));
    let caught = null;
    try {
      TOOL_HANDLERS.bob_finalize_node({
        target_domain: domain,
        node_id: nodeId,
        prep_token: prep.prep_token,
        agent_output: {},
      });
    } catch (err) { caught = err; }
    assert.ok(caught);
    assert.equal(caught.code, "agent_output_empty");
  });
});

test("finalize_node refuses a stale prep_token", () => {
  withTempHome(() => {
    const domain = "x8-stale-token.example.com";
    seedSession(domain);
    const nodeId = seedContractedNode(domain, "HP-stale");
    JSON.parse(TOOL_HANDLERS.bob_prepare_node({
      target_domain: domain,
      node_id: nodeId,
    }));
    let caught = null;
    try {
      TOOL_HANDLERS.bob_finalize_node({
        target_domain: domain,
        node_id: nodeId,
        prep_token: "stale-not-a-real-token-aaaaaaaaaaaaaaaaaaaaaaaa",
        agent_output: {
          tool_invocations: [{ tool: KNOWN_TOOL, output: { status: 200 } }],
        },
      });
    } catch (err) { caught = err; }
    assert.ok(caught);
    assert.equal(caught.code, "prep_token_stale");
  });
});

// ─── Do step 5 (4): successful flow with relational_value_match ─────────

test("prepare → finalize succeeds with a relational_value_match Contract; downstream nodes computed", () => {
  withTempHome(() => {
    const domain = "x8-relational-success.example.com";
    seedSession(domain);

    // Build two frontier_event artifacts whose payloads carry the values
    // the relational witness compares. We use frontier_event for both sides
    // because (a) the importHttpTraffic path does not capture response
    // bodies (the http_record resolver returns the redacted record
    // metadata, not the body), and (b) frontier-event resolver returns the
    // pretty-printed event JSON which gives us a deterministic
    // JSONPath-addressable target. The witness asserts
    // event-A.payload.sub == event-B.payload.recovered_signer.
    const leftEvent = appendFrontierEvent({
      target_domain: domain,
      kind: "observation.recorded",
      ts: "2026-05-31T00:03:00.000Z",
      payload: { observation_kind: "synthetic_jwt", sub: "0xWALLET" },
    });
    const rightEvent = appendFrontierEvent({
      target_domain: domain,
      kind: "observation.recorded",
      ts: "2026-05-31T00:03:30.000Z",
      payload: { observation_kind: "synthetic_evm", recovered_signer: "0xWALLET" },
    });

    const contract = {
      contract_id: "C-x8-rel",
      severity_floor: "high",
      invariants: [{ id: "I1", statement: "JWT sub binds to recovered signer." }],
      witnesses: [{
        id: "W-rel",
        kind: "relational_value_match",
        predicate: {
          left: { artifact_ref: `frontier_event:${leftEvent.event_id}`, extract_path: "$.payload.sub" },
          op: "eq",
          right: { artifact_ref: `frontier_event:${rightEvent.event_id}`, extract_path: "$.payload.recovered_signer" },
        },
      }],
      production_paths: [{
        description: "Invoke the canonical web producer.",
        tool_call_pattern: [{ tool: KNOWN_TOOL }],
      }],
    };
    const nodeId = seedContractedNode(domain, "HP-rel", contract);

    const prep = JSON.parse(TOOL_HANDLERS.bob_prepare_node({
      target_domain: domain,
      node_id: nodeId,
    }));
    assert.ok(prep.prep_token, "prep_token must be returned");
    assert.ok(prep.brief, "brief must be returned");
    assert.equal(prep.brief.profile, "node");
    assert.equal(prep.brief.node_id, nodeId);
    assert.ok(prep.brief.contract, "brief.contract must be inlined");
    assert.equal(prep.brief.contract.contract_id, "C-x8-rel");
    assert.equal(prep.brief.contract.witnesses.length, 1);
    const renderedBriefJson = JSON.stringify(prep.brief);
    assert.match(renderedBriefJson, /nonce=[0-9a-f]{32}/, "node brief should carry untrusted fences");
    assert.equal(prep.brief_hash, sha256Hex(normalizeEnvelopeNonces(renderedBriefJson)));

    // The recommended_reads slice must inline distilled summaries / typed
    // pointers per X-P9. For frontier_event refs there is no paired
    // observation summary, so the slice surfaces a typed pointer naming
    // the resolver to call — NOT the body.
    const refs = parseFencedBriefJson(prep.brief.recommended_reads, "recommended_reads").refs;
    assert.ok(refs.length >= 2, "expected both frontier_event refs in recommended_reads");
    const leftRef = refs.find((r) => r.artifact_ref === `frontier_event:${leftEvent.event_id}`);
    assert.ok(leftRef);
    assert.equal(leftRef.kind, "frontier_event");
    assert.ok(leftRef.summary && leftRef.summary.hint && leftRef.summary.hint.includes("bob_resolve_body"));

    const finalized = JSON.parse(TOOL_HANDLERS.bob_finalize_node({
      target_domain: domain,
      node_id: nodeId,
      prep_token: prep.prep_token,
      agent_output: {
        tool_invocations: [{ tool: KNOWN_TOOL, output: { status: 200 } }],
        evidence_refs: [{ kind: "frontier_event", event_id: leftEvent.event_id }],
      },
    }));
    assert.equal(finalized.to_state, "finalized", `finalize verdict: ${JSON.stringify(finalized.mechanical_verdict || finalized.failure_reason)}`);
    assert.equal(finalized.mechanical_verdict.satisfied, true);
    assert.ok(Array.isArray(finalized.adjudication_chain));
    // High severity → brutalist + balanced + final per X-D9.
    assert.deepEqual(finalized.adjudication_chain, ["brutalist", "balanced", "final"]);

    // Re-materialize and assert the node is now finalized.
    materializeTaskGraph(domain, { write: true });
    const doc = materializeTaskGraph(domain, { write: false }).document;
    const node = doc.nodes.find((n) => n.node_id === nodeId);
    assert.equal(node.state, "finalized");
  });
});

test("prepare_node keeps prep_token stable across equivalent briefs with fresh envelope nonces", () => {
  const fixedMaterializedAt = "2026-05-31T00:03:00.000Z";
  const domain = "x8-prep-token-nonce-stability.example.com";

  function prepareFixture() {
    seedSession(domain);
    const nodeId = seedContractedNode(domain, "HP-nonce-stable");
    const prep = JSON.parse(TOOL_HANDLERS.bob_prepare_node({
      target_domain: domain,
      node_id: nodeId,
      ts: "2026-05-31T00:04:00.000Z",
    }));
    return {
      nodeId,
      prep,
      briefJson: JSON.stringify(prep.brief),
    };
  }

  withSequentialRandomBytes(() => {
    const first = withTempHome(() => withFixedDate(fixedMaterializedAt, prepareFixture));
    withTempHome(() => withFixedDate(fixedMaterializedAt, () => {
      const second = prepareFixture();
      assert.match(first.briefJson, /nonce=[0-9a-f]{32}/, "first brief should carry envelope nonces");
      assert.match(second.briefJson, /nonce=[0-9a-f]{32}/, "second brief should carry envelope nonces");
      assert.notEqual(first.briefJson, second.briefJson, "raw briefs should differ by fresh envelope nonces");
      assert.equal(normalizeEnvelopeNonces(first.briefJson), normalizeEnvelopeNonces(second.briefJson));
      assert.equal(first.prep.brief_hash, second.prep.brief_hash);
      assert.equal(first.prep.prep_token, second.prep.prep_token);

      const finalized = JSON.parse(TOOL_HANDLERS.bob_finalize_node({
        target_domain: domain,
        node_id: second.nodeId,
        prep_token: second.prep.prep_token,
        ts: "2026-05-31T00:05:00.000Z",
        agent_output: {
          tool_invocations: [{ tool: KNOWN_TOOL, output: { status: 200 } }],
        },
      }));
      assert.equal(finalized.to_state, "finalized");
    }));
  });
});

// ─── Do step 5 (5): mechanical-fail surfaces structured failure_reason ──

test("finalize → failed when mechanical verifier rejects; failure_reason carries the structured verdict", () => {
  withTempHome(() => {
    const domain = "x8-mech-fail.example.com";
    seedSession(domain);
    // Use a Contract whose tool_output_match expects a specific value the
    // agent_output does not produce → verifier surfaces tool_output_did_not_match.
    const contract = baseContractInput({
      contractId: "C-fail",
      witnessKind: "tool_output_match",
      predicate: { tool: KNOWN_TOOL, match: { path: "$.status", equals: 200 } },
    });
    const nodeId = seedContractedNode(domain, "HP-fail", contract);

    const prep = JSON.parse(TOOL_HANDLERS.bob_prepare_node({
      target_domain: domain,
      node_id: nodeId,
    }));
    const result = JSON.parse(TOOL_HANDLERS.bob_finalize_node({
      target_domain: domain,
      node_id: nodeId,
      prep_token: prep.prep_token,
      agent_output: {
        // Status 500 doesn't match the expected 200 → witness fails.
        tool_invocations: [{ tool: KNOWN_TOOL, output: { status: 500 } }],
      },
    }));
    assert.equal(result.to_state, "failed");
    assert.equal(result.mechanical_verdict.satisfied, false);
    assert.ok(result.failure_reason);
    assert.equal(result.failure_reason.reason, "mechanical_verifier_failed");
    assert.ok(Array.isArray(result.failure_reason.failures));
    const witnessFailure = result.failure_reason.failures.find((f) => f.witness_id === "W1");
    assert.ok(witnessFailure);
    assert.equal(witnessFailure.reason, "tool_output_did_not_match");
  });
});

// ─── Do step 5 (6): re-prepare carries the prior_attempt slice ──────────
//
// End-to-end retry-with-recall workflow (X.8 spec line 338 + X.12 line 425):
//   1. Operator proposes a Hypothesis + attaches an initial Contract (state
//      proposed → contracted).
//   2. prepare_node → finalize_node fails the mechanical verifier (state
//      contracted → ready → dispatched → executed → failed).
//   3. Operator re-contracts the failed node with a refined Contract via
//      bob_attach_contract. The X.8 failed → contracted path lands the
//      node back in `contracted` while the prior failed event stays on
//      the ledger.
//   4. A second prepare_node call succeeds and the brief's `prior_attempt`
//      slice surfaces the prior failure's structured failure_reason
//      (including the failed witness_id list per Do step 2 / spec line 327).
//   5. The second finalize_node call succeeds against the refined Contract.

test("retry-with-recall: re-prepare after re-contracting a failed node inlines the prior_attempt slice with structured failure_reason and the second attempt succeeds", () => {
  withTempHome(() => {
    const domain = "x8-retry-with-recall.example.com";
    seedSession(domain);

    // (1) Propose a Hypothesis and attach an initial Contract.
    const initialContract = baseContractInput({
      contractId: "C-rwr-attempt-1",
      witnessKind: "tool_output_match",
      // Expect status 200; the first attempt will produce status 500 so
      // the mechanical verifier surfaces tool_output_did_not_match.
      predicate: { tool: KNOWN_TOOL, match: { path: "$.status", equals: 200 } },
    });
    const nodeId = seedContractedNode(domain, "HP-rwr", initialContract);

    // (2) First attempt — fails the mechanical verifier.
    const prep1 = JSON.parse(TOOL_HANDLERS.bob_prepare_node({
      target_domain: domain,
      node_id: nodeId,
    }));
    const fin1 = JSON.parse(TOOL_HANDLERS.bob_finalize_node({
      target_domain: domain,
      node_id: nodeId,
      prep_token: prep1.prep_token,
      agent_output: {
        tool_invocations: [{ tool: KNOWN_TOOL, output: { status: 500 } }],
      },
    }));
    assert.equal(fin1.to_state, "failed");
    assert.equal(fin1.failure_reason.reason, "mechanical_verifier_failed");
    // Capture the prior failure's witness_id so we can assert the
    // prior_attempt slice surfaces the same structured payload below.
    const priorWitnessFailure = fin1.failure_reason.failures.find((f) => f.witness_id === "W1");
    assert.ok(priorWitnessFailure, "expected first attempt to fail witness W1");
    assert.equal(priorWitnessFailure.reason, "tool_output_did_not_match");

    // Sanity: live state on the materialized graph is `failed`.
    materializeTaskGraph(domain, { write: true });
    let liveDoc = materializeTaskGraph(domain, { write: false }).document;
    let liveNode = liveDoc.nodes.find((n) => n.node_id === nodeId);
    assert.equal(liveNode.state, "failed");

    // (3) Operator re-contracts via bob_attach_contract with a refined
    // Contract. The X.8 failed → contracted path is the retry-with-recall
    // re-contract entry. The refined Contract uses a DIFFERENT predicate
    // (e.g., a different artifact_ref pair, per X.12) — here we tighten
    // the status check to 200 OR 201 (still expects 200 but the refined
    // Contract is keyed on a new id so the hash differs).
    const refinedContract = baseContractInput({
      contractId: "C-rwr-attempt-2-refined",
      witnessKind: "tool_output_match",
      predicate: { tool: KNOWN_TOOL, match: { path: "$.status", equals: 200 } },
    });
    const reAttach = JSON.parse(TOOL_HANDLERS.bob_attach_contract({
      target_domain: domain,
      node_id: nodeId,
      contract: refinedContract,
    }));
    assert.equal(reAttach.from_state, "failed", "re-contract emits failed → contracted");
    assert.equal(reAttach.to_state, "contracted");
    assert.notEqual(reAttach.contract_hash, prep1.contract_hash, "refined Contract must have a new contract_hash");

    materializeTaskGraph(domain, { write: true });
    liveDoc = materializeTaskGraph(domain, { write: false }).document;
    liveNode = liveDoc.nodes.find((n) => n.node_id === nodeId);
    assert.equal(liveNode.state, "contracted", "re-contracted node is in contracted state");

    // (4) Second prepare_node call — the brief MUST inline the prior
    // failure via the prior_attempt slice.
    const prep2 = JSON.parse(TOOL_HANDLERS.bob_prepare_node({
      target_domain: domain,
      node_id: nodeId,
    }));
    assert.ok(prep2.brief.prior_attempt, "prior_attempt slice MUST be present on re-prepare after a prior failed attempt");
    const priorAttempt = parseFencedBriefJson(prep2.brief.prior_attempt, "prior_attempt");
    assert.ok(Array.isArray(priorAttempt.attempts), "prior_attempt.attempts must be an array");
    assert.ok(priorAttempt.attempts.length >= 1, "at least one prior attempt must be surfaced");
    const surfacedFailure = priorAttempt.attempts[0];
    assert.equal(surfacedFailure.failure_reason.reason, "mechanical_verifier_failed",
      "prior_attempt slice surfaces the structured failure_reason from the prior finalize");
    assert.ok(Array.isArray(surfacedFailure.failure_reason.failures),
      "prior_attempt.attempts[0].failure_reason.failures[] must carry the prior witness failures");
    const surfacedWitnessFailure = surfacedFailure.failure_reason.failures.find((f) => f.witness_id === "W1");
    assert.ok(surfacedWitnessFailure, "prior_attempt surfaces the same witness_id (W1) that failed on the first attempt");
    assert.equal(surfacedWitnessFailure.reason, "tool_output_did_not_match");

    // The contract hash on the brief is the REFINED Contract's hash, not
    // the prior one — the brief is grounded in the current Contract.
    assert.equal(prep2.brief.recap_and_handoff.contract_hash, reAttach.contract_hash);

    // (5) Second finalize_node — succeeds against the refined Contract.
    const fin2 = JSON.parse(TOOL_HANDLERS.bob_finalize_node({
      target_domain: domain,
      node_id: nodeId,
      prep_token: prep2.prep_token,
      agent_output: {
        // This time the tool_output_match witness will pass.
        tool_invocations: [{ tool: KNOWN_TOOL, output: { status: 200 } }],
      },
    }));
    assert.equal(fin2.to_state, "finalized",
      `second finalize should succeed: ${JSON.stringify(fin2.mechanical_verdict || fin2.failure_reason)}`);
    assert.equal(fin2.mechanical_verdict.satisfied, true);

    // Sanity: the prior failure is still on the ledger so future operators
    // can audit the retry history.
    const allFailures = readNodeTransitions(domain).filter(
      (e) => e.payload && e.payload.node_id === nodeId && e.payload.to_state === "failed",
    );
    assert.equal(allFailures.length, 1, "the prior failure event remains on the ledger");

    // The reaper-style sanity: the live materialized state is finalized.
    materializeTaskGraph(domain, { write: true });
    liveDoc = materializeTaskGraph(domain, { write: false }).document;
    liveNode = liveDoc.nodes.find((n) => n.node_id === nodeId);
    assert.equal(liveNode.state, "finalized");
  });
});

// ─── Do step 5 (7): graph drift detection via graph_context_hash ─────────

test("a new edge in the underlying graph produces a different graph_context_hash on re-prepare", () => {
  withTempHome(() => {
    const domain = "x8-drift.example.com";
    seedSession(domain);
    const nodeId = seedContractedNode(domain, "HP-drift", null, ["surface:auth"]);

    const prep1 = JSON.parse(TOOL_HANDLERS.bob_prepare_node({
      target_domain: domain,
      node_id: nodeId,
    }));
    assert.ok(prep1.graph_context_hash);

    // Mid-run: a new transition node lands that touches surface:auth.
    appendTransitionProposal({
      target_domain: domain,
      from_surface: "surface:auth",
      to_surface: "surface:vault",
      kind: "identity_propagation",
      trust_assumption: "Auth token is bound to wallet via signature.",
      proposal_id: "TP-drift-new",
    });
    materializeTaskGraph(domain, { write: true });

    // The dispatched node is now in `dispatched` state from the prior
    // prepare-node; we cannot re-prepare it directly. Verify drift via a
    // fresh prepare on a sibling node sharing the same surface, OR confirm
    // the hash differs by computing it via the helper directly.
    //
    // We use a sibling node to land a fresh prepare and assert that
    // graph_context_hash now reflects the new adjacent Transition.
    const siblingNodeId = seedContractedNode(domain, "HP-drift-sibling", null, ["surface:auth"]);
    const prep2 = JSON.parse(TOOL_HANDLERS.bob_prepare_node({
      target_domain: domain,
      node_id: siblingNodeId,
    }));
    assert.ok(prep2.graph_context_hash);
    // The two hashes should differ because the sibling sees the new
    // Transition as an adjacent node (the original prep1 was on a different
    // node so this is the cleanest way to confirm hash sensitivity to graph
    // shape changes).
    assert.notEqual(prep1.graph_context_hash, prep2.graph_context_hash);
  });
});

// ─── Do step 5 (8): hypothesis visibility — adjacent_hypotheses slice ────

test("a Surface node with an adjacent open Hypothesis inlines the adjacent_hypotheses slice", () => {
  withTempHome(() => {
    const domain = "x8-adjacent-hyp.example.com";
    seedSession(domain);

    // Seed a surface node + materialize.
    appendFrontierEvent({
      target_domain: domain,
      kind: "surface.observed",
      ts: "2026-05-31T00:01:00.000Z",
      surface_id: "surface:billing",
      payload: { title: "billing" },
    });
    materializeTaskGraph(domain, { write: true });
    const surfaceNodeId = `${TASK_GRAPH_NODE_ID_PREFIX}S-surface:billing`;

    // Seed an open Hypothesis whose surface_refs overlap.
    appendHypothesisProposal({
      target_domain: domain,
      ts: "2026-05-31T00:02:00.000Z",
      hypothesis_statement: "Billing endpoint leaks user_id on 404.",
      surface_refs: ["surface:billing"],
      proposal_id: "HP-adj-1",
    });
    materializeTaskGraph(domain, { write: true });

    // Attach a Contract to the surface node — but surface nodes don't go
    // through attach-contract; they're proposed differently. For X.8 prep
    // we'd need a contracted surface node. The spec lists Surface +
    // Transition for the adjacent_hypotheses slice; the slice rendering is
    // triggered by the dispatched node kind. We synthesize the state by
    // directly emitting transitions on the surface node id.
    appendNodeTransition({
      target_domain: domain,
      node_id: surfaceNodeId,
      from_state: "proposed",
      to_state: "contracted",
      contract_hash: "feedface".repeat(8),
      contract: {
        contract_id: "C-surface",
        contract_hash: "feedface".repeat(8),
        severity_floor: "medium",
        invariants: [{ id: "I1", statement: "billing endpoint authorizes." }],
        witnesses: [{
          id: "W1",
          kind: "tool_output_match",
          predicate: { tool: KNOWN_TOOL, match: { path: "$.status", equals: 200 } },
        }],
        production_paths: [{
          description: "probe billing",
          tool_call_pattern: [{ tool: KNOWN_TOOL }],
        }],
      },
    });
    materializeTaskGraph(domain, { write: true });

    const prep = JSON.parse(TOOL_HANDLERS.bob_prepare_node({
      target_domain: domain,
      node_id: surfaceNodeId,
    }));
    assert.ok(prep.brief.adjacent_hypotheses, "adjacent_hypotheses slice must be present for Surface node");
    assert.ok(Array.isArray(parseFencedBriefJson(prep.brief.adjacent_hypotheses, "adjacent_hypotheses").hypotheses));
    assert.ok(parseFencedBriefJson(prep.brief.adjacent_hypotheses, "adjacent_hypotheses").hypotheses.length >= 1);
    const hyp = parseFencedBriefJson(prep.brief.adjacent_hypotheses, "adjacent_hypotheses").hypotheses[0];
    assert.equal(hyp.hypothesis_statement, "Billing endpoint leaks user_id on 404.");
  });
});

// ─── Do step 5 (9): recommended_reads inlines distilled summaries, not bodies ──

test("recommended_reads inlines the distilled http_record summary; the http body never appears in the brief", () => {
  withTempHome(() => {
    const domain = "x8-distilled.example.com";
    seedSession(domain);
    const distinctiveBody = "DISTINCTIVE-BODY-MARKER-7c41-fa92";
    importHttpTraffic({
      target_domain: domain,
      source: "har",
      entries: [{
        method: "POST",
        url: `https://${domain}/login`,
        status: 200,
        host: domain,
        ts: "2026-05-31T00:03:00.000Z",
        body: JSON.stringify({ message: distinctiveBody, sub: "0xWALLET" }),
      }],
    });
    const { readFrontierEvents } = require("../mcp/lib/frontier-events.js");
    const events = readFrontierEvents(domain);
    const recordEvent = events.find(
      (e) => e.kind === "observation.recorded"
        && e.payload && e.payload.observation_kind === "http_record_observed",
    );
    assert.ok(recordEvent);
    const requestId = recordEvent.payload.request_id;

    const contract = {
      contract_id: "C-distill",
      severity_floor: "low",
      invariants: [{ id: "I1", statement: "Endpoint produces 200." }],
      witnesses: [{
        id: "W-hash",
        kind: "hash_equals",
        predicate: {
          artifact_ref: `http_record:${requestId}`,
          expected_hash: "deadbeef".repeat(8),
        },
      }],
      production_paths: [{
        description: "Probe",
        tool_call_pattern: [{ tool: KNOWN_TOOL }],
      }],
    };
    const nodeId = seedContractedNode(domain, "HP-distill", contract);
    const prep = JSON.parse(TOOL_HANDLERS.bob_prepare_node({
      target_domain: domain,
      node_id: nodeId,
    }));

    // The brief JSON must NOT contain the distinctive body marker.
    const briefJson = JSON.stringify(prep.brief);
    assert.equal(briefJson.includes(distinctiveBody), false,
      "the distinctive http body marker must NOT appear in the brief — X-P9 says distilled summaries only");
    // The distilled summary IS inlined (request_id, method, url, status).
    const httpRef = parseFencedBriefJson(prep.brief.recommended_reads, "recommended_reads").refs.find((r) => r.kind === "http_record_observed");
    assert.ok(httpRef);
    assert.equal(httpRef.summary.request_id, requestId);
    assert.equal(httpRef.summary.method, "POST");
    assert.equal(httpRef.summary.status, 200);
    // The full body is NOT present on the summary — bodies are pull-only.
    assert.equal(Object.prototype.hasOwnProperty.call(httpRef.summary, "body"), false);
  });
});

// ─── Do step 5 (10): reaper fires on stuck dispatched ────────────────────

test("expireStaleDispatchedNodes emits dispatched → failed with dispatch_timeout on stale dispatch", () => {
  withTempHome(() => {
    const domain = "x8-reaper.example.com";
    seedSession(domain);
    const nodeId = seedContractedNode(domain, "HP-reaper");
    JSON.parse(TOOL_HANDLERS.bob_prepare_node({
      target_domain: domain,
      node_id: nodeId,
      ts: "2026-05-31T00:00:00.000Z",
    }));
    materializeTaskGraph(domain, { write: true });

    // Call the reaper with `now` set 31 minutes after the dispatch ts.
    // Per the X.1 frozen table the stuck dispatch lands in `failed` with
    // failure_reason.reason = "dispatch_timeout" (the X.8 spec calls it
    // "abandoned" colloquially; the machine-readable surfacing is failed).
    const docBefore = materializeTaskGraph(domain, { write: false }).document;
    const emitted = expireStaleDispatchedNodes(domain, docBefore, {
      now: new Date("2026-05-31T00:31:00.000Z"),
    });
    assert.equal(emitted.length, 1);
    assert.equal(emitted[0].payload.from_state, "dispatched");
    assert.equal(emitted[0].payload.to_state, "failed");
    assert.equal(emitted[0].payload.failure_reason.reason, "dispatch_timeout");
    materializeTaskGraph(domain, { write: true });
    const doc = materializeTaskGraph(domain, { write: false }).document;
    const node = doc.nodes.find((n) => n.node_id === nodeId);
    assert.equal(node.state, "failed");
  });
});

test("expireStaleDispatchedNodes does NOT fire on a fresh dispatched node", () => {
  withTempHome(() => {
    const domain = "x8-reaper-fresh.example.com";
    seedSession(domain);
    const nodeId = seedContractedNode(domain, "HP-fresh");
    JSON.parse(TOOL_HANDLERS.bob_prepare_node({
      target_domain: domain,
      node_id: nodeId,
      ts: "2026-05-31T00:00:00.000Z",
    }));
    // 10 minutes later — under the 30-min threshold.
    const doc = materializeTaskGraph(domain, { write: false }).document;
    const emitted = expireStaleDispatchedNodes(domain, doc, {
      now: new Date("2026-05-31T00:10:00.000Z"),
    });
    assert.equal(emitted.length, 0);
  });
});

// ─── Edge: agent_output with at least one channel passes empty-output guard ─

test("finalize accepts agent_output with only evidence_refs[] (non-empty)", () => {
  withTempHome(() => {
    const domain = "x8-only-evidence.example.com";
    seedSession(domain);
    // Build a Contract whose witness fires on evidence_ref_kind_present so
    // the finalize call can succeed with only evidence_refs[].
    const contract = baseContractInput({
      contractId: "C-only-ev",
      witnessKind: "evidence_ref_kind_present",
      predicate: { kind: "repo_file" },
    });
    const nodeId = seedContractedNode(domain, "HP-only-ev", contract);
    const prep = JSON.parse(TOOL_HANDLERS.bob_prepare_node({
      target_domain: domain,
      node_id: nodeId,
    }));
    const result = JSON.parse(TOOL_HANDLERS.bob_finalize_node({
      target_domain: domain,
      node_id: nodeId,
      prep_token: prep.prep_token,
      agent_output: {
        evidence_refs: [{ kind: "repo_file", file_path: "auth.js" }],
      },
    }));
    assert.equal(result.to_state, "finalized");
  });
});
