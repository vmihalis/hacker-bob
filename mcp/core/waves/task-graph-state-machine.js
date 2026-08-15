"use strict";

// Pure TaskGraph identity and state-machine primitives.  This module owns no
// storage and imports neither the event writer nor the materializer, allowing
// both sides of the atomic compare-and-append boundary to use the same rules
// without closing a CommonJS require cycle.

const {
  hashCanonicalJson,
} = require("../verification/verification-contracts.js");

const TASK_GRAPH_NODE_ID_PREFIX = "TG-";

const NODE_STATE_VALUES = Object.freeze([
  "proposed",
  "contracted",
  "ready",
  "dispatched",
  "executed",
  "verified",
  "finalized",
  "failed",
  "abandoned",
]);

const NODE_STATE_TRANSITIONS = Object.freeze({
  proposed: Object.freeze(["contracted", "abandoned"]),
  contracted: Object.freeze(["ready", "abandoned"]),
  ready: Object.freeze(["dispatched", "abandoned"]),
  dispatched: Object.freeze(["executed", "failed"]),
  executed: Object.freeze(["verified", "failed"]),
  verified: Object.freeze(["finalized", "failed"]),
  finalized: Object.freeze([]),
  failed: Object.freeze(["contracted"]),
  abandoned: Object.freeze([]),
});

function shortHash(input) {
  return hashCanonicalJson({ v: String(input) }).slice(0, 16);
}

function surfaceNodeId(surfaceId) {
  if (typeof surfaceId !== "string" || !surfaceId.trim()) return null;
  return `${TASK_GRAPH_NODE_ID_PREFIX}S-${surfaceId.trim()}`;
}

function hypothesisNodeId({ proposalId, eventId }) {
  if (typeof proposalId === "string" && proposalId.trim()) {
    return `${TASK_GRAPH_NODE_ID_PREFIX}H-${proposalId.trim()}`;
  }
  return `${TASK_GRAPH_NODE_ID_PREFIX}H-${shortHash(eventId)}`;
}

function transitionNodeId({ proposalId, eventId }) {
  if (typeof proposalId === "string" && proposalId.trim()) {
    return `${TASK_GRAPH_NODE_ID_PREFIX}T-${proposalId.trim()}`;
  }
  return `${TASK_GRAPH_NODE_ID_PREFIX}T-${shortHash(eventId)}`;
}

function claimNodeId(claimId) {
  if (typeof claimId !== "string" || !claimId.trim()) return null;
  return `${TASK_GRAPH_NODE_ID_PREFIX}C-${claimId.trim()}`;
}

function cellNodeId({ cellKey, proposalId, eventId }) {
  if (typeof proposalId === "string" && proposalId.trim()) {
    return `${TASK_GRAPH_NODE_ID_PREFIX}cell-${proposalId.trim()}`;
  }
  if (typeof cellKey === "string" && cellKey.trim()) {
    return `${TASK_GRAPH_NODE_ID_PREFIX}cell-${shortHash(cellKey)}`;
  }
  return `${TASK_GRAPH_NODE_ID_PREFIX}cell-${shortHash(eventId)}`;
}

function producerNodeId({ producerKey, proposalId, eventId }) {
  if (typeof proposalId === "string" && proposalId.trim()) {
    return `${TASK_GRAPH_NODE_ID_PREFIX}producer-${proposalId.trim()}`;
  }
  if (typeof producerKey === "string" && producerKey.trim()) {
    return `${TASK_GRAPH_NODE_ID_PREFIX}producer-${shortHash(producerKey)}`;
  }
  return `${TASK_GRAPH_NODE_ID_PREFIX}producer-${shortHash(eventId)}`;
}

function isAllowedNodeTransition(fromState, toState) {
  const successors = NODE_STATE_TRANSITIONS[fromState];
  return Array.isArray(successors) && successors.includes(toState);
}

function proposalNodeId(event) {
  if (!event || typeof event !== "object" || Array.isArray(event)) return null;
  if (event.kind === "surface.observed") return surfaceNodeId(event.surface_id);
  if (event.kind === "claim.candidate.linked") {
    const claimId = event.claim_id
      || (event.payload && typeof event.payload.claim_id === "string"
        ? event.payload.claim_id
        : null);
    return claimNodeId(claimId);
  }
  if (event.kind !== "observation.recorded" || !event.payload
      || typeof event.payload !== "object" || Array.isArray(event.payload)) {
    return null;
  }
  const payload = event.payload;
  if (payload.kind === "hypothesis_proposed") {
    return hypothesisNodeId({ proposalId: payload.proposal_id, eventId: event.event_id });
  }
  if (payload.kind === "transition_proposed") {
    return transitionNodeId({ proposalId: payload.proposal_id, eventId: event.event_id });
  }
  if (payload.kind === "cell_proposed") {
    return cellNodeId({
      cellKey: payload.cell_key,
      proposalId: payload.proposal_id,
      eventId: event.event_id,
    });
  }
  const observationKind = typeof payload.observation_kind === "string"
    && payload.observation_kind.trim()
    ? payload.observation_kind.trim()
    : (typeof payload.kind === "string" ? payload.kind.trim() : "");
  if (observationKind === "producer_proposed") {
    return producerNodeId({
      producerKey: payload.producer_key || payload.producer_id,
      proposalId: payload.proposal_id,
      eventId: event.event_id,
    });
  }
  return null;
}

function projectLiveTaskGraphNodeState(events, nodeId) {
  if (!Array.isArray(events)) throw new Error("TaskGraph state projection requires events[]");
  let state = null;
  for (const event of events) {
    if (state == null && proposalNodeId(event) === nodeId) state = "proposed";
    if (state == null || !event || event.kind !== "node.transitioned"
        || !event.payload || event.payload.node_id !== nodeId) continue;
    const fromState = event.payload.from_state;
    const toState = event.payload.to_state;
    if (state === fromState && NODE_STATE_VALUES.includes(fromState)
        && NODE_STATE_VALUES.includes(toState)
        && isAllowedNodeTransition(fromState, toState)) {
      state = toState;
    }
  }
  return state;
}

module.exports = Object.freeze({
  NODE_STATE_TRANSITIONS,
  NODE_STATE_VALUES,
  TASK_GRAPH_NODE_ID_PREFIX,
  cellNodeId,
  claimNodeId,
  hypothesisNodeId,
  isAllowedNodeTransition,
  producerNodeId,
  projectLiveTaskGraphNodeState,
  proposalNodeId,
  surfaceNodeId,
  transitionNodeId,
});
