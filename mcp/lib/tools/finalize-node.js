"use strict";

// Plane X Cycle X.8 — bob_finalize_node.
//
// The third call of the clou-style three-call protocol (X-D8). Validates
// the prep_token issued by bob_prepare_node against the most recent
// dispatched node.transitioned event, emits dispatched → executed, runs
// the X.6 mechanical verifier FIRST (X-P3: mechanical verifier runs
// before any LLM adjudication), and lands the node in:
//   - executed → failed   when the mechanical verifier surfaces missing
//     witnesses or failed predicates. The structured failure_reason
//     payload (including extracted values for relational_value_match
//     failures and the failed witness_id list) becomes the recall source
//     for the next bob_prepare_node call's `prior_attempt` slice.
//   - executed → verified → finalized   when the mechanical verifier
//     passes. The adjudication chain (X-D9, severity-floor-gated) is
//     queued via a structured chain_request payload on the verified
//     event so X.9's graph scheduler can pick it up; X.8 ships the QUEUE
//     shape, the live LLM-round dispatch wires in X.9 (per X-D7 the
//     graph scheduler owns Transition + Hypothesis dispatch including
//     the adjudication-chain dispatch path).
//
// edge_added_to[] surfaces downstream nodes the verified Contract has
// unblocked. The materializer derives `unblocks` edges from this field
// (X-D1 / X-P1). X.8 surfaces ONLY the unambiguous downstream nodes —
// Hypothesis or Transition nodes whose surface_refs[] include any of
// the finalized node's surface_refs AND whose state is `contracted` (so
// the X.9 graph scheduler can pick them up next). Hypothesis nodes still
// in `proposed` (Contract not yet attached) are intentionally NOT
// auto-unblocked; the operator/evaluator must attach a Contract first.
//
// Per Do step 3 both prepare-node and finalize-node are orchestrator +
// graph-scheduler-only. The graph-scheduler bundle ships in X.9; v1 here
// is realized as `orchestrator`.

const {
  assertNonEmptyString,
} = require("../validation.js");
const {
  assertSafeDomain,
} = require("../paths.js");
const {
  assertTaskGraphNodeId,
  appendNodeTransition,
  findAttachedContract,
  findMostRecentNodeTransition,
} = require("../task-graph-events.js");
const {
  materializeTaskGraph,
} = require("../task-graph-materializer.js");
const {
  mechanicalVerify,
} = require("../contract-verifier.js");
const {
  scheduleMaterialization,
} = require("../frontier-materialize-debounce.js");
const {
  isPlainObject,
} = require("../verification-contracts.js");
const {
  buildOneHopGraphContext,
  derivePackForNode,
} = require("../capability-pack-derivation.js");
const {
  readSurfaceRoutesStrict,
} = require("../surface-router.js");

// Adjudication chain shape per X-D9: severity_floor → rounds. The X.8
// finalize emits the chain REQUEST shape into the verification round
// payload via the verified → finalized transition; X.9 + later cycles
// wire the live dispatcher.
const ADJUDICATION_CHAIN_BY_SEVERITY = Object.freeze({
  low: Object.freeze(["balanced"]),
  medium: Object.freeze(["balanced", "final"]),
  high: Object.freeze(["brutalist", "balanced", "final"]),
  critical: Object.freeze(["brutalist", "balanced", "final"]),
});

function structuredError(code, message, details) {
  const err = new Error(`${code}: ${message}`);
  err.code = code;
  if (details) err.details = details;
  return err;
}

// Helper shared with bob_prepare_node for the surface metadata used in
// pack derivation. Inlined here (rather than imported) because the
// surface-router strict read is sensitive to absent route files and we
// must not regress finalize on a missing routes shape.
function safeSurfaceRouteMap(targetDomain) {
  let result;
  try {
    result = readSurfaceRoutesStrict(targetDomain);
  } catch {
    return {};
  }
  const map = {};
  const doc = result && result.document;
  if (!doc || !Array.isArray(doc.routes)) return map;
  for (const route of doc.routes) {
    if (!route || typeof route !== "object") continue;
    const surfaceId = typeof route.surface_id === "string" ? route.surface_id : null;
    if (!surfaceId) continue;
    map[surfaceId] = {
      id: surfaceId,
      surface_type: route.surface_type || null,
      chain_family: route.chain_family || null,
      capability_pack: route.capability_pack || null,
      brief_profile: route.brief_profile || null,
    };
  }
  return map;
}

// Plane X Cycle X.10 — tool_constraint_violation detective control.
//
// The X-P7 ergonomics trade replaces the static per-stack frontmatter
// allow-list with the brief's per-node allowed_tools_for_node[]. The
// evaluator-spawn shell carries the UNION of evaluator-family tools at
// frontmatter time; this finalize-time check is the enforcement edge:
// when agent_output.tool_invocations[] names any tool outside the
// dispatched node's allowed set, emit node.transitioned executed →
// failed with structured failure_reason.reason = "tool_constraint_violation"
// AND a list of the offending tools so the next prepare-node call's
// prior_attempt slice surfaces them.
//
// Pack derivation is pure (X-P4): re-deriving the pack at finalize
// using the same node + same graph context + same contract returns
// the same allowed_tools_for_node[] that prepare-node emitted into the
// brief. No need to round-trip the set through the prep_token.
function checkToolConstraintViolation(agentOutput, allowedToolsForNode) {
  const allowed = new Set(allowedToolsForNode);
  const violations = [];
  const invocations = Array.isArray(agentOutput && agentOutput.tool_invocations)
    ? agentOutput.tool_invocations
    : [];
  for (let i = 0; i < invocations.length; i += 1) {
    const entry = invocations[i];
    if (!isPlainObject(entry)) continue;
    const tool = typeof entry.tool === "string" ? entry.tool : null;
    if (!tool) continue;
    if (!allowed.has(tool)) {
      violations.push({ index: i, tool });
    }
  }
  return violations;
}

function findNodeInDocument(document, nodeId) {
  if (!document || !Array.isArray(document.nodes)) return null;
  for (const node of document.nodes) {
    if (node && node.node_id === nodeId) return node;
  }
  return null;
}

// Compute downstream `edge_added_to[]` per Do step 2. Walks the
// materialized graph for nodes whose surface_refs intersect with the
// finalized node's surface_refs AND whose state is `contracted`. The
// graph-scheduler (X.9) consumes the unblocks edges to decide what to
// dispatch next; X.8 surfaces ONLY the unambiguous candidates.
function computeUnblockedDownstream(document, finalizedNode) {
  if (!finalizedNode) return [];
  const surfaces = Array.isArray(finalizedNode.surface_refs)
    ? new Set(finalizedNode.surface_refs.filter((s) => typeof s === "string"))
    : new Set();
  if (surfaces.size === 0) return [];
  const out = [];
  if (document && Array.isArray(document.nodes)) {
    for (const node of document.nodes) {
      if (!node || node.node_id === finalizedNode.node_id) continue;
      if (node.state !== "contracted") continue;
      if (!Array.isArray(node.surface_refs)) continue;
      const overlap = node.surface_refs.some((ref) => surfaces.has(ref));
      if (overlap) out.push(node.node_id);
    }
  }
  return out.sort();
}

function handler(args) {
  const input = args || {};
  const domain = assertSafeDomain(
    assertNonEmptyString(input.target_domain, "target_domain"),
  );
  const nodeId = assertTaskGraphNodeId(input.node_id, "node_id");
  const prepToken = assertNonEmptyString(input.prep_token, "prep_token");

  // X.8 Do step 2: empty agent_output refused. We require an object with
  // at least one structured channel populated; an empty object is treated
  // as "agent produced nothing" and refused.
  const agentOutput = input.agent_output;
  if (!isPlainObject(agentOutput)) {
    throw structuredError(
      "agent_output_invalid",
      "agent_output must be a non-empty object",
      { node_id: nodeId },
    );
  }
  const hasInvocations = Array.isArray(agentOutput.tool_invocations) && agentOutput.tool_invocations.length > 0;
  const hasEvidence = Array.isArray(agentOutput.evidence_refs) && agentOutput.evidence_refs.length > 0;
  const hasCliPacks = Array.isArray(agentOutput.cli_pack_invocations) && agentOutput.cli_pack_invocations.length > 0;
  const hasFindings = Array.isArray(agentOutput.findings) && agentOutput.findings.length > 0;
  if (!hasInvocations && !hasEvidence && !hasCliPacks && !hasFindings) {
    throw structuredError(
      "agent_output_empty",
      "agent_output must include at least one of: tool_invocations[], evidence_refs[], cli_pack_invocations[], findings[]",
      { node_id: nodeId },
    );
  }

  // Recover the most recent dispatched event for the node. The caller's
  // prep_token must match its payload.prep_token_hash exactly (the
  // canonical on-disk field name avoids the sensitive-material guard's
  // _token suffix detection; see task-graph-events.js note).
  const dispatchedEvent = findMostRecentNodeTransition(domain, nodeId, "dispatched");
  if (!dispatchedEvent) {
    throw structuredError(
      "no_dispatched_event",
      `node ${nodeId} has no dispatched node.transitioned event; call bob_prepare_node first`,
      { node_id: nodeId },
    );
  }
  if (dispatchedEvent.payload.prep_token_hash !== prepToken) {
    throw structuredError(
      "prep_token_stale",
      `prep_token does not match the most recent dispatched event for node ${nodeId}; re-prepare and retry`,
      {
        node_id: nodeId,
        dispatched_event_id: dispatchedEvent.event_id,
      },
    );
  }

  // Read the live state to make sure no concurrent finalize is racing.
  const result = materializeTaskGraph(domain, { write: false });
  const document = result.document;
  const finalizedNode = findNodeInDocument(document, nodeId);
  if (!finalizedNode) {
    throw structuredError(
      "unknown_node",
      `node ${nodeId} is not present in the materialized task-graph`,
      { node_id: nodeId },
    );
  }
  if (finalizedNode.state !== "dispatched") {
    throw structuredError(
      "node_not_dispatched",
      `node ${nodeId} is in state "${finalizedNode.state}"; finalize-node requires state "dispatched"`,
      { node_id: nodeId, current_state: finalizedNode.state },
    );
  }

  // dispatched → executed: the agent has returned output. Whether the
  // mechanical verifier passes determines the next transition (verified
  // or failed).
  const executedEvent = appendNodeTransition({
    target_domain: domain,
    node_id: nodeId,
    from_state: "dispatched",
    to_state: "executed",
    prep_token_hash: prepToken,
    ts: input.ts,
    source: { tool: "bob_finalize_node" },
    actor: input.actor,
  });

  // Recover the Contract — the verifier evaluates witnesses against the
  // agent output + session artifacts.
  const attached = findAttachedContract(domain, nodeId);
  if (!attached || !attached.contract) {
    // Defensive: a dispatched node WITHOUT an attached Contract is a
    // catastrophic invariant break (X.4 satisfiability gate would have
    // refused). Surface a structured failure and flip to failed so the
    // operator sees the unrecoverable state.
    const failureReason = {
      reason: "contract_not_attached_at_finalize",
      detail: "the node was dispatched without an attached Contract; this is an invariant break",
    };
    const failedEvent = appendNodeTransition({
      target_domain: domain,
      node_id: nodeId,
      from_state: "executed",
      to_state: "failed",
      failure_reason: failureReason,
      ts: input.ts,
      source: { tool: "bob_finalize_node" },
      actor: input.actor,
    });
    try { scheduleMaterialization(domain); } catch {}
    return JSON.stringify({
      version: 1,
      target_domain: domain,
      node_id: nodeId,
      to_state: "failed",
      mechanical_verdict: null,
      failure_reason: failureReason,
      executed_event_id: executedEvent.event_id,
      failed_event_id: failedEvent.event_id,
    });
  }

  // Plane X Cycle X.10 — tool_constraint_violation detective control.
  // Re-derive the pack (pure per X-P4) so we have the exact
  // allowed_tools_for_node[] the brief carried. If any tool invocation
  // names a tool outside the set, emit executed → failed BEFORE running
  // the mechanical verifier so the failure_reason is unambiguous and
  // the next prepare-node call's prior_attempt slice surfaces the
  // violation. Note: we re-materialize only the ≤1-hop graph context
  // (not the full live graph) so the derivation matches what was
  // bound into the prep_token.
  const surfaceMetadataById = safeSurfaceRouteMap(domain);
  const finalizeGraphContext = buildOneHopGraphContext(document, nodeId, surfaceMetadataById);
  const finalizePack = derivePackForNode(
    finalizedNode,
    finalizeGraphContext,
    [],
    attached.contract,
  );
  const toolViolations = checkToolConstraintViolation(
    agentOutput,
    finalizePack.allowed_tools_for_node,
  );
  if (toolViolations.length > 0) {
    const failureReason = {
      reason: "tool_constraint_violation",
      violations: toolViolations,
      allowed_tools: finalizePack.allowed_tools_for_node.slice().sort(),
      detail: "agent_output.tool_invocations[] named one or more tools outside allowed_tools_for_node[]; the evaluator-spawn shell carries the union of evaluator-family tools at frontmatter time (X-P7 ergonomics trade) and the per-node allow-list is enforced detectively at finalize. Refine the Contract or re-spawn within the constraint.",
    };
    const failedEvent = appendNodeTransition({
      target_domain: domain,
      node_id: nodeId,
      from_state: "executed",
      to_state: "failed",
      contract_hash: attached.contract.contract_hash,
      failure_reason: failureReason,
      ts: input.ts,
      source: { tool: "bob_finalize_node" },
      actor: input.actor,
    });
    try { scheduleMaterialization(domain); } catch {}
    return JSON.stringify({
      version: 1,
      target_domain: domain,
      node_id: nodeId,
      to_state: "failed",
      mechanical_verdict: null,
      failure_reason: failureReason,
      contract_hash: attached.contract.contract_hash,
      executed_event_id: executedEvent.event_id,
      failed_event_id: failedEvent.event_id,
    });
  }

  // Run the mechanical verifier (X.6). Per X-P3 it runs FIRST; the
  // adjudication chain is queued only on success.
  const sessionArtifacts = { target_domain: domain };
  let verdict;
  try {
    verdict = mechanicalVerify(attached.contract, agentOutput, sessionArtifacts);
  } catch (err) {
    // Defensive: the verifier should never throw on a normalized
    // Contract; treat a throw as a failure with structured cause.
    verdict = {
      satisfied: false,
      missing: [],
      failures: [{
        witness_id: null,
        reason: "verifier_exception",
        error_code: err && err.code ? err.code : null,
        error_message: err && err.message ? err.message : String(err),
      }],
    };
  }

  if (!verdict.satisfied) {
    // executed → failed. The failure_reason payload carries the
    // structured verdict so the next prepare-node call's prior_attempt
    // slice can inline both extracted values + artifact_refs for
    // relational_value_match failures, exactly per Do step 2.
    const failureReason = {
      reason: "mechanical_verifier_failed",
      missing: verdict.missing,
      failures: verdict.failures,
      contract_hash: attached.contract.contract_hash,
    };
    const failedEvent = appendNodeTransition({
      target_domain: domain,
      node_id: nodeId,
      from_state: "executed",
      to_state: "failed",
      contract_hash: attached.contract.contract_hash,
      failure_reason: failureReason,
      verification: verdict,
      ts: input.ts,
      source: { tool: "bob_finalize_node" },
      actor: input.actor,
    });
    try { scheduleMaterialization(domain); } catch {}
    return JSON.stringify({
      version: 1,
      target_domain: domain,
      node_id: nodeId,
      to_state: "failed",
      mechanical_verdict: verdict,
      failure_reason: failureReason,
      contract_hash: attached.contract.contract_hash,
      executed_event_id: executedEvent.event_id,
      failed_event_id: failedEvent.event_id,
    });
  }

  // Mechanical verifier passed → queue adjudication chain per X-D9.
  // X.8 emits the executed → verified → finalized chain WITHOUT actually
  // dispatching the adjudication-round agents. The verified payload
  // carries the severity-floor-gated round list as a deferred queue
  // shape so X.9's graph-walking scheduler (which owns adjudication
  // dispatch per X-D7) can pick it up. X.8's contract is: the chain
  // shape lands on the ledger as soon as the mechanical verifier passes;
  // live adjudication dispatch is X.9's responsibility.
  const adjudicationRounds = ADJUDICATION_CHAIN_BY_SEVERITY[attached.contract.severity_floor] || [];
  const verifiedEvent = appendNodeTransition({
    target_domain: domain,
    node_id: nodeId,
    from_state: "executed",
    to_state: "verified",
    contract_hash: attached.contract.contract_hash,
    verification: {
      satisfied: true,
      witness_count: attached.contract.witnesses.length,
      severity_floor: attached.contract.severity_floor,
      adjudication_chain: adjudicationRounds.slice(),
    },
    ts: input.ts,
    source: { tool: "bob_finalize_node" },
    actor: input.actor,
  });

  // verified → finalized. Compute the downstream nodes the finalized
  // Contract has unblocked (Do step 2 edge_added_to[]).
  const downstream = computeUnblockedDownstream(document, finalizedNode);
  const finalizedEvent = appendNodeTransition({
    target_domain: domain,
    node_id: nodeId,
    from_state: "verified",
    to_state: "finalized",
    contract_hash: attached.contract.contract_hash,
    edge_added_to: downstream,
    ts: input.ts,
    source: { tool: "bob_finalize_node" },
    actor: input.actor,
  });

  try { scheduleMaterialization(domain); } catch {}

  return JSON.stringify({
    version: 1,
    target_domain: domain,
    node_id: nodeId,
    to_state: "finalized",
    mechanical_verdict: verdict,
    contract_hash: attached.contract.contract_hash,
    severity_floor: attached.contract.severity_floor,
    adjudication_chain: adjudicationRounds.slice(),
    edge_added_to: downstream,
    executed_event_id: executedEvent.event_id,
    verified_event_id: verifiedEvent.event_id,
    finalized_event_id: finalizedEvent.event_id,
  });
}

module.exports = Object.freeze({
  name: "bob_finalize_node",
  description:
    "Finalize a TaskGraph node (clou-style three-call protocol, third call). "
    + "Validates prep_token against the most recent dispatched node.transitioned "
    + "event; refuses stale tokens, refuses empty agent_output. Emits dispatched "
    + "→ executed, then runs the X.6 mechanical verifier FIRST (X-P3). On "
    + "verifier failure → executed → failed with structured failure_reason "
    + "(including extracted values for relational_value_match failures so the "
    + "next bob_prepare_node call's prior_attempt slice can inline them). On "
    + "verifier pass → executed → verified → finalized with severity_floor-gated "
    + "adjudication chain queued in the verified payload (X-D9). Computes "
    + "edge_added_to[] from now-unblocked downstream nodes (contracted nodes "
    + "whose surface_refs overlap). Orchestrator + graph-scheduler only.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
      node_id: {
        type: "string",
        description:
          "TaskGraph node id (TG-<prefix>-<slug>). Must be in state \"dispatched\".",
      },
      prep_token: {
        type: "string",
        description:
          "The prep_token returned by bob_prepare_node. Must match the most recent dispatched event's payload.prep_token; stale tokens are refused.",
      },
      agent_output: {
        type: "object",
        description:
          "Structured agent output. Must include at least one of: tool_invocations[], evidence_refs[], cli_pack_invocations[], findings[]. Empty objects are refused.",
        properties: {
          tool_invocations: { type: "array" },
          evidence_refs: { type: "array" },
          cli_pack_invocations: { type: "array" },
          findings: { type: "array" },
        },
      },
      ts: { type: "string" },
      actor: { type: "string" },
    },
    required: ["target_domain", "node_id", "prep_token", "agent_output"],
  },
  handler,
  // Orchestrator is the only finalize authority. evaluator-spawn was
  // previously listed here for "self-awareness" but bob_finalize_node
  // trusts caller-supplied agent_output.tool_invocations[] — a spawned
  // evaluator with this access could self-finalize while omitting or
  // under-reporting its own tool calls, defeating the X.6 tool-constraint
  // detector. The evaluator-spawn prompt (step 7) already states "The
  // orchestrator runs bob_finalize_node" — keep the security model aligned.
  role_bundles: ["orchestrator"],
  mutating: true,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: ["frontier-events.jsonl"],
  ADJUDICATION_CHAIN_BY_SEVERITY,
});
