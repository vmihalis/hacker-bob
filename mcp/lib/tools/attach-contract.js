"use strict";

// chain+evaluator-shared justified: chain-builder needs graph mutation/query authority via the chain bundle (rev 4.1 defect 3 absorption); single-spawner topology preserved per Y.9 chain-bundle audit
//
// Plane X Cycle X.4 — bob_attach_contract.
//
// Attaches a normalized Contract to a TaskGraph node and emits the
// `node.transitioned proposed → contracted` event. Per X-D11 the
// pre-dispatch satisfiability gate fires here: a Contract whose
// witness predicates reference tools the node cannot produce, or
// artifact_ref prefixes outside the X-D12 closed set, is refused with a
// structured `contract_unsatisfiable` error so the operator never burns
// a run on an un-realizable Contract.
//
// Allowed bundles per X-D10: orchestrator + evaluator + operator. The
// v1 bundle taxonomy realizes operator as `orchestrator` (the only
// bundle wired to the operator-facing slash command at this point in
// the plane), so the role_bundles array is the dedup'd pair
// [orchestrator, evaluator-shared].
//
// X.4 ships the STRUCTURAL satisfiability check (every referenced tool
// must exist in TOOL_HANDLERS; every artifact_ref prefix must be in the
// X-D12 closed set). X.5's bob_prepare_node call extends this with the
// per-node `allowed_tools_for_node[]` from derivePackForNode; the
// attach-contract tool accepts an optional `allowed_tools_for_node[]`
// argument so future cycles (and the X.5 self-test) can preflight a
// Contract against a synthesized per-node pack without re-implementing
// the structural check.

const {
  APPEND_CONTRACT_LEGAL_FROM_STATES,
  appendContract,
  normalizeContract,
  assertContractSatisfiable,
  INVARIANT_STATEMENT_MAX_CHARS,
  WITNESS_KIND_VALUES,
} = require("../contracts.js");
const {
  assertTaskGraphNodeId,
} = require("../task-graph-events.js");
const {
  assertNonEmptyString,
  normalizeStringArray,
} = require("../validation.js");
const {
  materializeTaskGraph,
} = require("../task-graph-materializer.js");
const {
  scheduleMaterialization,
} = require("../frontier-materialize-debounce.js");

// Find the node in the materialized task-graph and return its state, or
// null when the node has not yet been observed. The materializer is the
// authoritative view of node lifecycle per X-P1; we never read the
// frontier-events ledger directly here.
function lookupNodeState(targetDomain, nodeId) {
  const result = materializeTaskGraph(targetDomain, { write: false });
  const document = result.document;
  for (const node of document.nodes) {
    if (node.node_id === nodeId) {
      return { state: node.state, kind: node.kind };
    }
  }
  return null;
}

function structuredError(code, message, details) {
  const err = new Error(`${code}: ${message}`);
  err.code = code;
  if (details) err.details = details;
  return err;
}

function handler(args) {
  const input = args || {};
  const targetDomain = assertNonEmptyString(input.target_domain, "target_domain");
  const nodeId = assertTaskGraphNodeId(input.node_id, "node_id");

  // Node-existence + state check (Do step 3). The materializer is the
  // SoT; if the node hasn't been folded yet, refuse with unknown_node
  // so the caller knows to materialize first.
  const existing = lookupNodeState(targetDomain, nodeId);
  if (!existing) {
    throw structuredError(
      "unknown_node",
      `node ${nodeId} is not present in the materialized task-graph; propose it before attaching a contract`,
      { node_id: nodeId },
    );
  }
  if (!APPEND_CONTRACT_LEGAL_FROM_STATES.includes(existing.state)) {
    // The attach path requires the node in state `proposed`, OR `failed`
    // (the re-contract entry per X.8) so the operator can attach a refined
    // Contract to a failed node without first abandoning it. All other
    // states (contracted, ready, dispatched, executed, verified, finalized,
    // abandoned) refuse with the structured node_not_proposed code so the
    // operator-facing UI can render a clear domain-specific message
    // instead of bubbling the lower-level invalid_node_transition error.
    throw structuredError(
      "node_not_proposed",
      `node ${nodeId} is in state "${existing.state}"; attach-contract requires one of [${APPEND_CONTRACT_LEGAL_FROM_STATES.join(", ")}]`,
      {
        node_id: nodeId,
        current_state: existing.state,
        legal_from_states: APPEND_CONTRACT_LEGAL_FROM_STATES.slice(),
      },
    );
  }

  const allowedToolsForNode = input.allowed_tools_for_node == null
    ? null
    : normalizeStringArray(input.allowed_tools_for_node, "allowed_tools_for_node");

  // normalizeContract throws on schema violations; the structured
  // errors (prose_too_long, extract_path_unsafe, etc) bubble through
  // the MCP envelope so the caller sees the field-specific failure.
  const normalized = normalizeContract(input.contract);

  // X.5 (a later cycle) wires derivePackForNode here; X.4 falls back to
  // the universal registry-membership check via assertContractSatisfiable
  // unless the caller has supplied allowed_tools_for_node.
  assertContractSatisfiable(normalized, {
    allowed_tools_for_node: allowedToolsForNode || undefined,
  });

  const { event, contract } = appendContract({
    target_domain: targetDomain,
    node_id: nodeId,
    contract: input.contract,
    allowed_tools_for_node: allowedToolsForNode || undefined,
    ts: input.ts,
    source: input.source,
    actor: input.actor,
  });

  // Best-effort debounced materialization so the materialized view sees
  // the new contracted state without an explicit follow-up call.
  try {
    scheduleMaterialization(targetDomain);
  } catch {
    // Materialization is best-effort; never regress the append.
  }

  return JSON.stringify({
    version: 1,
    attached: true,
    target_domain: targetDomain,
    node_id: nodeId,
    contract_id: contract.contract_id,
    contract_hash: contract.contract_hash,
    severity_floor: contract.severity_floor,
    event_id: event.event_id,
    event_hash: event.event_hash,
    from_state: event.payload.from_state,
    to_state: event.payload.to_state,
  });
}

module.exports = Object.freeze({
  name: "bob_attach_contract",
  description:
    "Attach a hash-bound Contract to a TaskGraph node and transition the "
    + "node to \"contracted\". The default path is proposed → contracted; "
    + "the X.8 re-contract path also allows failed → contracted (operator "
    + "re-contracts a failed node with a refined Contract; prior failure "
    + "events stay on the ledger so the next bob_prepare_node call's "
    + "`prior_attempt` brief slice surfaces the structured failure payload). "
    + "Validates the Contract schema (≥1 invariant + ≥1 witness + ≥1 "
    + `production_path per X-P2; invariant statements capped at ${INVARIANT_STATEMENT_MAX_CHARS} chars), `
    + "hashes the canonical form with the per-Contract severity_floor bound "
    + "in (X-D9), and runs the pre-dispatch satisfiability check (X-D11): "
    + "every production_paths[].tool_call_pattern[].tool must exist in the "
    + "MCP tool registry, every tool_output_match witness must reference a "
    + "tool present in production_paths, and every relational_value_match / "
    + "hash_equals predicate must use an artifact_ref prefix in the X-D12 "
    + "closed set. Mismatch → structured contract_unsatisfiable refusal.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
      node_id: {
        type: "string",
        description:
          "TaskGraph node id (TG-<prefix>-<slug>). Must already be in the materialized graph with state \"proposed\" (default path) or \"failed\" (X.8 re-contract path).",
      },
      contract: {
        type: "object",
        description:
          "Contract payload per X-D4 (contract_id, severity_floor, invariants[], witnesses[], production_paths[]). "
          + `Witness kinds are restricted to the closed set: ${WITNESS_KIND_VALUES.join(", ")}.`,
        properties: {
          contract_id: { type: "string" },
          severity_floor: {
            type: "string",
            enum: ["low", "medium", "high", "critical"],
          },
          invariants: {
            type: "array",
            minItems: 1,
            items: {
              type: "object",
              properties: {
                id: { type: "string" },
                statement: { type: "string", maxLength: INVARIANT_STATEMENT_MAX_CHARS },
              },
              required: ["id", "statement"],
            },
          },
          witnesses: {
            type: "array",
            minItems: 1,
            items: {
              type: "object",
              properties: {
                id: { type: "string" },
                kind: { type: "string", enum: [...WITNESS_KIND_VALUES] },
                predicate: { type: "object", additionalProperties: true },
              },
              required: ["id", "kind", "predicate"],
            },
          },
          production_paths: {
            type: "array",
            minItems: 1,
            items: {
              type: "object",
              properties: {
                description: { type: "string" },
                tool_call_pattern: {
                  type: "array",
                  minItems: 1,
                  items: {
                    type: "object",
                    properties: {
                      tool: { type: "string" },
                      args_match: { type: "object" },
                    },
                    required: ["tool"],
                  },
                },
              },
              required: ["description", "tool_call_pattern"],
            },
          },
        },
        required: ["contract_id", "severity_floor", "invariants", "witnesses", "production_paths"],
      },
      allowed_tools_for_node: {
        type: "array",
        items: { type: "string" },
        description:
          "Optional per-node allowed-tools set from X.5's derivePackForNode. "
          + "When supplied, every production_paths[].tool_call_pattern[].tool must "
          + "appear in this set; mismatch → contract_unsatisfiable.tool_outside_pack. "
          + "When omitted, the structural fallback (TOOL_HANDLERS membership) applies.",
      },
      ts: { type: "string" },
      source: { type: "object" },
      actor: { type: "string" },
    },
    required: ["target_domain", "node_id", "contract"],
  },
  handler,
  // X-D10: Contract attachment is allowed for orchestrator + evaluator +
  // operator. In v1 the operator bundle is realized as orchestrator (the
  // bundle wired to the operator-facing slash command), so the dedup'd
  // pair is [orchestrator, evaluator-shared]. Y.11 (rev 4.1 defect 3)
  // extends with "chain" so chain-builder can attach Contracts to
  // chain-proposed Hypothesis nodes via the graph apparatus. The chain
  // bundle grants tool access, not dispatch authority — Y-P8
  // single-spawner topology is preserved by the Y.9 chain-bundle audit +
  // single-spawner check.
  role_bundles: ["orchestrator", "evaluator-shared", "chain"],
  mutating: true,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: ["frontier-events.jsonl"],
});
