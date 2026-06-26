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
  readCellProposals,
} = require("../task-graph-events.js");
const {
  materializeTaskGraph,
  cellNodeId,
} = require("../task-graph-materializer.js");
const {
  logCellCoverage,
} = require("../coverage.js");
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
const {
  readCompositionVerifiedSummary,
} = require("../composition-live-verifier.js");
const {
  isBindLeaf,
} = require("../cross-stack-differential-verifier.js");

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
  // readSurfaceRoutesStrict is now tolerant: it QUARANTINES stale/duplicate routes (it used to throw,
  // which the catch above turned into a silent empty {} — losing ALL routes). The valid routes survive
  // in doc.routes; the quarantined ones are omitted from this metadata map. Surface a diagnostic so a
  // fully- or partially-corrupt routing artifact is not silently indistinguishable from "no routes were
  // set up". This map only enriches one-hop graph context, so we degrade gracefully (no throw) — unlike
  // getContextBudget/findRoutedSurface, where a wrong/missing route must hard-fail the operation.
  if (Array.isArray(result.malformed_routes) && result.malformed_routes.length > 0) {
    const quarantinedIds = result.malformed_routes
      .map((m) => (m && m.surface_id) || `routes[${m && m.index}]`)
      .join(", ");
    process.stderr.write(
      `WARNING: surface-routes.json has ${result.malformed_routes.length} quarantined route(s) [${quarantinedIds}] omitted from the surface metadata map; re-run bob_route_surfaces to regenerate (${doc.routes.length} valid route(s) retained).\n`,
    );
  }
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
// materializer folds these into `unblocks` edges as an audit/telemetry
// trace of which contracted nodes this finalization unblocked; X.8 surfaces
// ONLY the unambiguous candidates. Dispatch order itself is driven by the
// coverage-pruned cell floor and node state (the stigmergic wavefront READ in
// the cell-floor producer), not by walking these post-hoc edges.
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

// Resolve a surface_ref's stack family from the route-metadata map already built
// in handler() via safeSurfaceRouteMap. web vs smart_contract are distinct stacks;
// an absent/unknown surface_type collapses to null (NOT a third stack) so a
// missing-metadata surface NEVER manufactures a spurious distinct stack.
function surfaceStackFamily(surfaceRef, surfaceMetadataById) {
  const meta = surfaceMetadataById && surfaceMetadataById[surfaceRef];
  const surfaceType = meta && typeof meta.surface_type === "string" ? meta.surface_type.trim() : "";
  if (surfaceType === "web" || surfaceType === "smart_contract" || surfaceType === "code_module") {
    return surfaceType;
  }
  return null;
}

// surfacesSpanDistinctStacks — true iff the node's surface_refs resolve (via the
// route-metadata map) to >=2 DISTINCT stack families. A web<->web "nesting"
// transition (both surfaces web) returns false. This is the POSITIVE detector for an
// EXPLICITLY distinct-stack span; the fail-closed leg below (surfacesProvenSameStack)
// is what catches a genuinely cross-stack transition whose route metadata is too poor
// to resolve here.
function surfacesSpanDistinctStacks(surfaceRefs, surfaceMetadataById) {
  if (!Array.isArray(surfaceRefs)) return false;
  const families = new Set();
  for (const ref of surfaceRefs) {
    if (typeof ref !== "string") continue;
    const family = surfaceStackFamily(ref, surfaceMetadataById);
    if (family) families.add(family);
  }
  return families.size >= 2;
}

// surfacesProvenSameStack — the FAIL-CLOSED inversion of the distinct-stack heuristic.
// True ONLY when a multi-surface transition can be PROVEN same-stack: EVERY surface has
// KNOWN route metadata AND they all share ONE family. ANY surface with absent/unknown
// metadata returns false — we CANNOT prove same-stack, so the transition must produce a
// bound cross-stack verified_pass rather than escape the gate on missing metadata. A
// degenerate (<2 surfaces) transition is trivially same-stack (not multi-surface).
function surfacesProvenSameStack(surfaceRefs, surfaceMetadataById) {
  if (!Array.isArray(surfaceRefs) || surfaceRefs.length < 2) return true;
  const families = new Set();
  for (const ref of surfaceRefs) {
    const family = surfaceStackFamily(ref, surfaceMetadataById);
    if (family == null) return false; // ANY unknown-metadata surface -> NOT proven same-stack
    families.add(family);
  }
  return families.size === 1; // all known and identical family
}

// anyWitnessOrLeafIsBindShaped — a Contract whose evidence carries a bind leaf
// (positive_run_ref + control_run_ref, the cross-stack-differential-verifier
// shape) is an explicit cross-stack claim. Today Contracts carry no leaf array,
// so this scans the OPTIONAL cross_stack_verification.path_hash declaration as
// the primary marker and any witness predicate object that is itself bind-shaped
// (a defensive, forward-compatible read — absent in every existing Contract).
function anyWitnessOrLeafIsBindShaped(contract) {
  if (!contract || typeof contract !== "object") return false;
  const witnesses = Array.isArray(contract.witnesses) ? contract.witnesses : [];
  for (const witness of witnesses) {
    if (witness && typeof witness === "object" && isBindLeaf(witness.predicate)) {
      return true;
    }
  }
  return false;
}

// claimsCrossStackMechanism — the PRECISE, additive, FAIL-CLOSED trigger predicate for
// the finalize cross-stack gate. Fires when ALL hold:
//   (1) the node is a Transition node (kind === "transition") — a Hypothesis
//       (even a cross-stack-SHAPED relational_value_match witness) NEVER triggers.
//   (2) surface_refs is an array of length >= 2 — a single-surface transition
//       (degenerate) never triggers.
//   (3) a cross-stack claim: surface_refs span >= 2 distinct stacks, OR
//       contract.cross_stack_verification.required === true, OR a bind-shaped witness
//       predicate, OR — FAIL-CLOSED — a multi-surface transition we CANNOT PROVE is
//       same-stack (poor/unknown route metadata). Inverting the trigger from "can I
//       PROVE distinct" to "can I PROVE same-stack" closes the hole where a genuinely
//       cross-stack transition with absent route metadata and no explicit marker
//       escaped the gate (surfacesSpanDistinctStacks fails open on unknown metadata).
// A two-surface SAME-stack transition with COMPLETE metadata (web<->web nesting) is
// surfacesProvenSameStack -> NOT a cross-stack claim and finalizes EXACTLY as today.
function claimsCrossStackMechanism(node, contract, surfaceMetadataById) {
  if (!node || node.kind !== "transition") return false;
  if (!Array.isArray(node.surface_refs) || node.surface_refs.length < 2) return false;
  if (surfacesSpanDistinctStacks(node.surface_refs, surfaceMetadataById)) return true;
  if (contract && contract.cross_stack_verification && contract.cross_stack_verification.required === true) {
    return true;
  }
  if (anyWitnessOrLeafIsBindShaped(contract)) return true;
  // FAIL-CLOSED: a multi-surface transition we cannot PROVE is same-stack must produce a
  // bound cross-stack verified_pass — missing/unknown route metadata no longer lets it
  // escape the gate. A genuine web<->web nesting transition with COMPLETE metadata is
  // surfacesProvenSameStack===true here and still finalizes as before (no regression).
  if (!surfacesProvenSameStack(node.surface_refs, surfaceMetadataById)) return true;
  return false;
}

// crossStackDeclaredPathHash — the path_hash the transition's cross-stack
// mechanism is bound to. Only the EXPLICIT cross_stack_verification.path_hash is
// authoritative; without it the gate refuses (an unbound cross-stack claim cannot
// name the verified_pass it would be satisfied by). Returns null when undeclared.
function crossStackDeclaredPathHash(contract) {
  if (contract && contract.cross_stack_verification
    && typeof contract.cross_stack_verification.path_hash === "string"
    && contract.cross_stack_verification.path_hash) {
    return contract.cross_stack_verification.path_hash;
  }
  return null;
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

  // Cross-stack mechanism gate (ADDITIVE — runs AFTER the mechanical verifier
  // passes, BEFORE the executed → verified append). The structural mechanical
  // verifier proves the witnesses resolve; it does NOT prove a cross-stack
  // composition path's mechanism was executed and flipped. A Transition node
  // that CLAIMS a cross-stack mechanism (claimsCrossStackMechanism: kind ===
  // "transition", surface_refs span >= 2 distinct stacks / cross_stack_
  // verification.required / a bind-shaped witness) requires a bound cross-stack
  // verified_pass — the path_hash declared on the Contract must be a member of
  // the audit-graded composition-verified.jsonl verified_path_hashes[], which
  // is RE-RESOLVED (bind rows RE-MAC-verified, the flip RE-adjudicated) at read
  // time. The agent cannot Write-forge that ledger. An ordinary transition (web
  // <-> web nesting, single-surface, or no cross-stack marker) does NOT trigger
  // this gate and finalizes EXACTLY as before; the object-auth guard re-execute
  // path is never a kind === "transition" finalize and is untouched.
  if (claimsCrossStackMechanism(finalizedNode, attached.contract, surfaceMetadataById)) {
    const declaredPathHash = crossStackDeclaredPathHash(attached.contract);
    let bound = false;
    if (declaredPathHash) {
      try {
        const summary = readCompositionVerifiedSummary(domain);
        // HIGH-3: a cross-stack mechanism requires has_bind_leaf && is_cross_stack
        // membership — a guard-only or same-stack-family verified_pass can no longer
        // satisfy this gate by plain path_hash membership.
        const crossStackSet = Array.isArray(summary.verified_cross_stack_path_hashes)
          ? summary.verified_cross_stack_path_hashes
          : [];
        if (crossStackSet.includes(declaredPathHash)) {
          // HIGH-2: reconcile the bound path's surface_refs against THIS node's
          // surface_refs — a verified_pass minted for a different node's surfaces must
          // not arm this node's gate by plain membership. Bound surface_refs are
          // ["invariant:<finding>:<contract>", "offensive:<surface_id>"]; require the
          // bound offensive surface_id to be one of the node's surface_refs (the node's
          // surface_refs are raw surface ids, no offensive:/invariant: prefix). An empty
          // bound-surface set (a legacy row) falls back to membership alone.
          const refsMap = summary.verified_cross_stack_path_surface_refs;
          const boundSurfaceRefs = refsMap && Array.isArray(refsMap[declaredPathHash])
            ? refsMap[declaredPathHash]
            : [];
          const nodeSurfaces = new Set(
            Array.isArray(finalizedNode.surface_refs)
              ? finalizedNode.surface_refs.filter((s) => typeof s === "string")
              : [],
          );
          if (boundSurfaceRefs.length === 0) {
            bound = true; // legacy row without surface_refs: membership alone
          } else {
            for (const ref of boundSurfaceRefs) {
              if (typeof ref !== "string") continue;
              if (ref.startsWith("offensive:") && nodeSurfaces.has(ref.slice("offensive:".length))) {
                bound = true;
                break;
              }
            }
          }
        }
      } catch {
        bound = false; // fail-closed on an unreadable ledger
      }
    }
    if (!bound) {
      const failureReason = {
        reason: "cross_stack_mechanism_unverified",
        contract_hash: attached.contract.contract_hash,
        surface_refs: Array.isArray(finalizedNode.surface_refs)
          ? finalizedNode.surface_refs.slice()
          : [],
        declared_path_hash: declaredPathHash,
        detail: "this transition claims a cross-stack mechanism (surface_refs span >= 2 stacks / a bind leaf / cross_stack_verification.required); run bob_verify_composition_path binding the positive executed row and its flipping control to mint a verified_pass to composition-verified.jsonl keyed by this path_hash before finalizing.",
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
        // NOT null: the mechanical verifier DID pass; this is a second, additive gate.
        mechanical_verdict: verdict,
        failure_reason: failureReason,
        contract_hash: attached.contract.contract_hash,
        executed_event_id: executedEvent.event_id,
        failed_event_id: failedEvent.event_id,
      });
    }
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

  // Cell coverage reconcile: a finalized CELL writes measurable coverage. The cell reached
  // finalized only because its coverage witness verified (mechanicalVerify
  // passed the cell_coverage evidence-ref witness), so the probe evidence is
  // present — coverage stays falsifiable. Recover the cell's identity from its
  // cell_proposed event and pull the evidence summary from the verified
  // evidence ref. Best-effort: a coverage-write hiccup must not unwind the
  // finalized transition.
  if (finalizedNode && finalizedNode.kind === "cell") {
    try {
      const payload = readCellProposals(domain)
        .map((ev) => ev && ev.payload)
        .find((p) => p && typeof p.cell_key === "string"
          && cellNodeId({ cellKey: p.cell_key }) === nodeId);
      if (payload) {
        const evidenceRefs = Array.isArray(agentOutput && agentOutput.evidence_refs)
          ? agentOutput.evidence_refs
          : [];
        const cov = evidenceRefs.find(
          (r) => r && (r.kind === "cell_coverage" || r === "cell_coverage"),
        );
        const evidenceSummary = (cov && typeof cov === "object" && typeof cov.summary === "string" && cov.summary)
          || `cell ${payload.bug_class} probed and verified (graph-dispatched)`;
        logCellCoverage({
          target_domain: domain,
          surface_id: payload.surface_id,
          bug_class: payload.bug_class,
          auth_profile: payload.auth_profile,
          status: "tested",
          evidence_summary: evidenceSummary,
        });
      }
    } catch {
      // Coverage reconcile is best-effort; the finalized transition stands.
    }
  }

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
