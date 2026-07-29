"use strict";

// Plane X Cycle X.1 — TaskGraph event-ledger wrappers.
//
// Per X-P1 the TaskGraph is the dispatch authority for Transition and
// Hypothesis nodes (Surface and Claim continue to dispatch through the
// wave-scheduler unchanged per X-D7). Per X-P8 the ledger gains ONE new
// top-level frontier event kind (`node.transitioned`); proposal events
// reuse the existing `observation.recorded` framework with typed
// `payload.kind` values.
//
// This module is the only sanctioned writer for the three kinds of
// TaskGraph events:
//
//   1. appendNodeTransition           → kind: "node.transitioned"
//   2. appendTransitionProposal       → kind: "observation.recorded" with
//                                       payload.kind: "transition_proposed"
//   3. appendHypothesisProposal       → kind: "observation.recorded" with
//                                       payload.kind: "hypothesis_proposed"
//
// All three honor X-P9 (storage-distilled emission): payloads are
// natively summary-grade (IDs, hashes, structured failure_reason, prose
// bounded at ≤512 chars). Bodies do not live in these events.

const {
  appendFrontierEvent,
  appendTaskGraphTransitionEvent,
  readFrontierEvents,
} = require("./frontier-events.js");
const {
  assertEnumValue,
  assertNonEmptyString,
  normalizeOptionalText,
  normalizeStringArray,
} = require("./validation.js");
const {
  normalizeId,
  normalizeOptionalId,
  normalizeOptionalObject,
} = require("./fabric-common.js");
const {
  NODE_STATE_TRANSITIONS,
  NODE_STATE_VALUES,
  TASK_GRAPH_NODE_ID_PREFIX,
  isAllowedNodeTransition,
  projectLiveTaskGraphNodeState,
} = require("./task-graph-state-machine.js");

// Plane X Target Vocabulary: state ∈ {proposed, contracted, ready,
// dispatched, executed, verified, finalized, failed, abandoned}.

// X-D3 closed enum of transition surface kinds. Imported here so the
// proposal-tool input schema and the wrapper both share one source of
// truth. The X.3 cycle wires this enum into the surface-index "transition"
// surface kind; X.1 references it from the proposal wrapper so a caller
// cannot record an undefined transition kind even before X.3 ships.
const TRANSITION_KIND_VALUES = Object.freeze([
  "identity_propagation",
  "value_movement",
  "trust_handoff",
  "state_dependency",
  "oracle_dependency",
  "message_passing",
]);

// Per X-P9 the spec caps two text fields at append-time so brief renderers
// can inline them without a render-time budget. Hard cap is 512 chars; over
// the cap surfaces a structured `prose_too_long` error.
const TRANSITION_TRUST_ASSUMPTION_MAX_CHARS = 512;
const HYPOTHESIS_STATEMENT_MAX_CHARS = 512;

// Composition-experiment vocabulary. A path-composition experiment confirms a
// composed cross-surface path only when EVERY leaf is bound to a replayable
// frontier event. The result is binary: `pass` (every leaf resolved to a real
// validated observation) or `fail` (at least one leaf was refused because its
// evidence_ref did not bind to a real event). There is no third "partial"
// outcome — an unbound leaf means the path cannot be confirmed at all.
const COMPOSITION_EXPERIMENT_RESULT_KINDS = Object.freeze(["pass", "fail"]);

// Every leaf's `evidence_ref` must be a `frontier_event:<event_id>` binding.
// The text after the colon is the frontier event_id the harness resolves
// against readFrontierEvents(domain); a bare string that merely "looks like"
// evidence (an opaque hash, a URL, a free-form note) does not match and so
// cannot bind a leaf. The id charset mirrors normalizeId's accepted shape so a
// ref that passes this pattern can be looked up verbatim.
const EVIDENCE_BINDING_REF_PATTERN = /^frontier_event:[A-Za-z0-9_-]+$/;

// Node identifiers in the TaskGraph plane carry a `TG-` prefix. The
// pre-flight sweep noted that mcp/lib/surface-graph.js uses generic
// `node_id` strings for an unrelated surface-adjacency graph; the prefix
// disambiguates which graph a given id belongs to in tool descriptions,
// in agent reasoning, and in any cross-tool join.
const TASK_GRAPH_NODE_ID_PATTERN = /^TG-[A-Za-z0-9][A-Za-z0-9._:-]{0,128}$/;
const SHA256_DIGEST_PATTERN = /^[a-f0-9]{64}$/u;
const PHYSICAL_RESERVATION_REF_PATTERN = /^reservation:[A-Za-z0-9][A-Za-z0-9._:-]{0,190}$/u;

// Safe, compact proof that a physical node reached `dispatched` only while an
// exact broker-held reservation was live. This is evidence/binding metadata,
// never a reservation credential: it deliberately excludes raw fences,
// allocation bodies, device handles, and callbacks.
const PHYSICAL_RESOURCE_DISPATCH_BINDING_FIELDS = Object.freeze([
  "source_graph_hash",
  "session_nucleus_hash",
  "resource_bundle_digest",
  "reservation_ref",
  "receipt_digest",
  "allocation_plan_digest",
  "eligibility_digest",
]);

function assertTaskGraphNodeId(value, fieldName = "node_id") {
  const text = assertNonEmptyString(value, fieldName);
  if (!TASK_GRAPH_NODE_ID_PATTERN.test(text)) {
    throw new Error(
      `${fieldName} must match ${TASK_GRAPH_NODE_ID_PREFIX}<id> (received: ${text})`,
    );
  }
  return text;
}

function normalizePhysicalResourceDispatchBinding(
  input,
  fieldName = "physical_resource_dispatch",
) {
  if (input == null || typeof input !== "object" || Array.isArray(input)) {
    throw new Error(`${fieldName} must be an object`);
  }
  const prototype = Object.getPrototypeOf(input);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new Error(`${fieldName} must be a plain object`);
  }
  const keys = Reflect.ownKeys(input);
  if (keys.some((key) => typeof key !== "string")) {
    throw new Error(`${fieldName} cannot contain symbol fields`);
  }
  const allowed = new Set(PHYSICAL_RESOURCE_DISPATCH_BINDING_FIELDS);
  const unknown = keys.filter((key) => !allowed.has(key)).sort();
  const missing = PHYSICAL_RESOURCE_DISPATCH_BINDING_FIELDS
    .filter((key) => !Object.prototype.hasOwnProperty.call(input, key));
  if (unknown.length > 0) {
    throw new Error(`${fieldName} has unknown fields: ${unknown.join(", ")}`);
  }
  if (missing.length > 0) {
    throw new Error(`${fieldName} is missing fields: ${missing.join(", ")}`);
  }
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(input, key);
    if (!descriptor || !("value" in descriptor) || descriptor.enumerable !== true) {
      throw new Error(`${fieldName}.${key} must be an enumerable data field`);
    }
  }
  const reservationRef = input.reservation_ref;
  if (typeof reservationRef !== "string"
      || !PHYSICAL_RESERVATION_REF_PATTERN.test(reservationRef)) {
    throw new Error(`${fieldName}.reservation_ref must be a namespaced reservation reference`);
  }
  const out = {
    source_graph_hash: input.source_graph_hash,
    session_nucleus_hash: input.session_nucleus_hash,
    resource_bundle_digest: input.resource_bundle_digest,
    reservation_ref: reservationRef,
    receipt_digest: input.receipt_digest,
    allocation_plan_digest: input.allocation_plan_digest,
    eligibility_digest: input.eligibility_digest,
  };
  for (const field of PHYSICAL_RESOURCE_DISPATCH_BINDING_FIELDS) {
    if (field === "reservation_ref") continue;
    if (typeof out[field] !== "string" || !SHA256_DIGEST_PATTERN.test(out[field])) {
      throw new Error(`${fieldName}.${field} must be a lowercase SHA-256 digest`);
    }
  }
  return Object.freeze(out);
}

function assertSurfaceRef(value, fieldName) {
  // Surface refs are arbitrary strings minted by surface discovery (e.g.
  // "surface:billing-profile"). They are not TaskGraph node ids and they
  // intentionally do NOT carry the TG- prefix.
  return normalizeId(value, fieldName);
}

function assertNodeTransitionAllowed(fromState, toState) {
  if (!isAllowedNodeTransition(fromState, toState)) {
    const err = new Error(
      `invalid_node_transition: ${fromState} -> ${toState} is not in the frozen state-transition table`,
    );
    err.code = "invalid_node_transition";
    err.details = {
      from_state: fromState,
      to_state: toState,
      allowed_from_state: NODE_STATE_TRANSITIONS[fromState]
        ? NODE_STATE_TRANSITIONS[fromState].slice()
        : [],
    };
    throw err;
  }
}

// Resolve the live TaskGraph state from the exact ledger snapshot read while
// frontier-events.js holds the session lock.  The pure state projector is
// shared with the materializer and owns no I/O, so this atomic validation does
// not introduce a reverse dependency or CommonJS require cycle.
function assertLiveNodeTransition({ event, existing_events: existingEvents }) {
  const payload = event && event.payload ? event.payload : {};
  const nodeId = payload.node_id;
  const fromState = payload.from_state;
  const toState = payload.to_state;
  const liveState = projectLiveTaskGraphNodeState(existingEvents, nodeId);
  if (liveState == null) {
    const err = new Error(
      `node_not_proposed: node ${nodeId} has no live TaskGraph proposal`,
    );
    err.code = "node_not_proposed";
    err.details = {
      node_id: nodeId,
      current_state: null,
      asserted_from_state: fromState,
      asserted_to_state: toState,
    };
    throw err;
  }
  if (liveState !== fromState) {
    const err = new Error(
      `stale_node_transition: node ${nodeId} is in state "${liveState}", not asserted from_state "${fromState}"`,
    );
    err.code = "stale_node_transition";
    err.details = {
      node_id: nodeId,
      current_state: liveState,
      asserted_from_state: fromState,
      asserted_to_state: toState,
    };
    throw err;
  }
  return true;
}

function assertProseUnderCap(value, fieldName, maxChars) {
  if (typeof value !== "string") {
    throw new Error(`${fieldName} must be a string`);
  }
  // Cap is applied to the trimmed value because trailing whitespace
  // (especially the trailing newline that lots of editors append) is not
  // semantically meaningful and would otherwise lead to confusing
  // off-by-one prose-cap violations for human authors.
  const trimmed = value.trim();
  if (!trimmed) {
    throw new Error(`${fieldName} must be a non-empty string`);
  }
  if (trimmed.length > maxChars) {
    const err = new Error(
      `prose_too_long: ${fieldName} length ${trimmed.length} exceeds cap ${maxChars}`,
    );
    err.code = "prose_too_long";
    err.details = {
      field: fieldName,
      length: trimmed.length,
      max_chars: maxChars,
    };
    throw err;
  }
  return trimmed;
}

// Append a node-state-machine transition. Caller passes the full
// from_state → to_state pair so the frozen table can refuse out-of-order
// transitions without first reading the ledger. Payload structure is the
// X-D1 schema: {node_id, from_state, to_state, contract_hash?, contract?,
// prep_token?, output_hash?, failure_reason?, edge_added_to[]}.
//
// Cycle X.8 extends the payload with TWO inline-only fields:
//   - `contract` — the FULL normalized Contract content carried on the
//     proposed → contracted event so the X.8 prepare_node brief renderer
//     can inline the Contract slice without a separate persistence layer.
//     The Contract is summary-grade per X-P9 (invariants ≤ 280 chars each,
//     witness predicates structured, production paths description-bounded)
//     so inlining keeps the event under the X-P9 2KB hard cap.
//   - `verification` — the mechanical verifier verdict carried on the
//     executed → verified | failed events. The verdict is already
//     structured (X.6 output shape) and bounded by the witness count.
// Plane-PH adds `physical_resource_dispatch` on ready → dispatched only: a
// closed digest/reference projection proving the broker-held reservation that
// authorized preparation. It contains no credential, fence, allocation body,
// callback, or device handle.
function appendNodeTransition(input, options = {}) {
  if (input == null || typeof input !== "object" || Array.isArray(input)) {
    throw new Error("appendNodeTransition input must be an object");
  }
  const nodeId = assertTaskGraphNodeId(input.node_id, "node_id");
  const fromState = assertEnumValue(input.from_state, NODE_STATE_VALUES, "from_state");
  const toState = assertEnumValue(input.to_state, NODE_STATE_VALUES, "to_state");
  assertNodeTransitionAllowed(fromState, toState);

  const contractHash = normalizeOptionalText(input.contract_hash, "contract_hash");
  // The prep_token is a sha256 hash of (node_id || contract_hash || brief_hash
  // || materialized_at || graph_context_hash). It is NOT an auth credential
  // (no bearer / cookie / API key) — it is a session-scoped binding hash that
  // the finalize_node call cross-checks against the most recent dispatched
  // event. We persist it under the `prep_token_hash` payload key so the
  // sensitive-material guard does not flag it as a forbidden token-shaped
  // field. The X.8 tool surfaces `prep_token` in its public API; the storage
  // layer normalizes to `prep_token_hash` so the on-disk shape is unambiguous.
  const prepTokenHash = normalizeOptionalText(
    input.prep_token_hash != null ? input.prep_token_hash : input.prep_token,
    "prep_token_hash",
  );
  const outputHash = normalizeOptionalText(input.output_hash, "output_hash");
  const failureReason = normalizeOptionalObject(input.failure_reason, "failure_reason");
  const edgeAddedTo = normalizeStringArray(input.edge_added_to, "edge_added_to")
    .map((edge) => assertTaskGraphNodeId(edge, "edge_added_to[]"));
  const contractPayload = normalizeOptionalObject(input.contract, "contract");
  const verification = normalizeOptionalObject(input.verification, "verification");
  const physicalResourceDispatch = input.physical_resource_dispatch == null
    ? null
    : normalizePhysicalResourceDispatchBinding(
      input.physical_resource_dispatch,
      "physical_resource_dispatch",
    );
  if (physicalResourceDispatch && toState !== "dispatched") {
    throw new Error("physical_resource_dispatch is valid only on a transition to dispatched");
  }
  if (physicalResourceDispatch && !SHA256_DIGEST_PATTERN.test(prepTokenHash || "")) {
    throw new Error(
      "a physical_resource_dispatch requires an exact lowercase SHA-256 prep_token_hash",
    );
  }
  // X.9 Do step 1: the graph-scheduler sorts by priority + queue_policy.
  // The X.2 materializer already folds `payload.priority` and
  // `payload.severity_floor` from node.transitioned events, so the
  // writer accepts both as optional inputs. Both are surface-level
  // discriminators (not bound into the contract_hash); the operator
  // can re-prioritize an open node via a state transition that carries
  // the new priority. Values are trimmed but otherwise opaque to the
  // wrapper (validation against the closed enum lives in the X.9
  // scheduler which interprets them).
  const priority = normalizeOptionalText(input.priority, "priority");
  const severityFloor = normalizeOptionalText(input.severity_floor, "severity_floor");

  const payload = {
    node_id: nodeId,
    from_state: fromState,
    to_state: toState,
  };
  if (contractHash) payload.contract_hash = contractHash;
  if (contractPayload) payload.contract = contractPayload;
  if (prepTokenHash) payload.prep_token_hash = prepTokenHash;
  if (outputHash) payload.output_hash = outputHash;
  if (failureReason) payload.failure_reason = failureReason;
  if (verification) payload.verification = verification;
  if (physicalResourceDispatch) payload.physical_resource_dispatch = physicalResourceDispatch;
  if (priority) payload.priority = priority;
  if (severityFloor) payload.severity_floor = severityFloor;
  if (edgeAddedTo.length > 0) payload.edge_added_to = edgeAddedTo;

  const source = normalizeOptionalObject(input.source, "source");
  const actor = normalizeOptionalText(input.actor, "actor");

  return appendTaskGraphTransitionEvent({
    target_domain: input.target_domain,
    kind: "node.transitioned",
    ts: input.ts,
    payload,
    source: source || undefined,
    actor: actor || undefined,
    // node.transitioned events do not have a surface_id, frontier_item_id,
    // task_id, or claim_id. The materializer (X.2) joins via payload.node_id
    // → node.surface_refs[] folded from the proposal event.
  }, assertLiveNodeTransition, options);
}

// Find the most recent node.transitioned event for `nodeId` that carries
// an inlined Contract payload (proposed → contracted emits one). Returns
// `null` when the node has never been contracted. Used by X.8's
// prepare_node to recover the Contract content for the brief renderer
// without persisting a separate contracts.jsonl — the Contract IS the
// payload of the contracting event.
function findAttachedContract(targetDomain, nodeId) {
  const events = readNodeTransitions(targetDomain);
  for (let i = events.length - 1; i >= 0; i -= 1) {
    const event = events[i];
    if (!event || !event.payload) continue;
    if (event.payload.node_id !== nodeId) continue;
    if (event.payload.to_state !== "contracted") continue;
    if (event.payload.contract && typeof event.payload.contract === "object") {
      return {
        contract: event.payload.contract,
        contract_hash: event.payload.contract_hash || event.payload.contract.contract_hash,
        event_id: event.event_id,
        ts: event.ts,
      };
    }
  }
  return null;
}

// Find the most recent node.transitioned event for `nodeId` matching the
// given `to_state`. Used by X.8's prepare_node + finalize_node to recover
// prior failure payloads (for the prior_attempt slice) and to validate
// prep_tokens against the most recent dispatched event. Returns null when
// no matching event exists.
function findMostRecentNodeTransition(targetDomain, nodeId, toState) {
  const events = readNodeTransitions(targetDomain);
  for (let i = events.length - 1; i >= 0; i -= 1) {
    const event = events[i];
    if (!event || !event.payload) continue;
    if (event.payload.node_id !== nodeId) continue;
    if (toState != null && event.payload.to_state !== toState) continue;
    return event;
  }
  return null;
}

// X.8 reaper: a stuck `dispatched` node whose most-recent dispatched event
// is older than `staleAfterMs` (default 30 minutes per the X.8 spec) is
// expired into the `failed` terminal state with `failure_reason.reason =
// "dispatch_timeout"`. The X.1 frozen state-transition table allows
// `dispatched → failed` directly (the table forbids `dispatched →
// abandoned`); the X.8 spec calls the result "abandoned" colloquially —
// the canonical machine-readable surfacing is `failed` with the
// dispatch_timeout failure_reason. The X.2 summary view surfaces these
// in `failed_nodes[]` alongside mechanical-verifier failures so the
// operator triage path is uniform.
//
// Idempotent: nodes whose CURRENT live state is not `dispatched` are
// skipped (terminal failed/finalized/abandoned nodes are not re-failed).
//
// The caller MUST pass a materialized task-graph document (typically from
// materializeTaskGraph(targetDomain, { write: false })). The reaper does
// not materialize internally — pushing materialization out of this module
// keeps the require graph cycle-free (the materializer requires
// task-graph-events.js at top scope; the reverse dependency would close a
// cycle the test/session-state-store.test.js closure check refuses).
const DEFAULT_STALE_DISPATCH_MS = 30 * 60 * 1000;

function expireStaleDispatchedNodes(targetDomain, materializedDocument, options = {}) {
  const staleAfterMs = Number.isFinite(options.staleAfterMs)
    ? options.staleAfterMs
    : DEFAULT_STALE_DISPATCH_MS;
  const now = options.now instanceof Date ? options.now : new Date();
  const nowMs = now.getTime();
  if (!materializedDocument || !Array.isArray(materializedDocument.nodes)) {
    throw new Error("expireStaleDispatchedNodes requires a materialized task-graph document with nodes[]");
  }
  const emitted = [];
  for (const node of materializedDocument.nodes) {
    if (!node || node.state !== "dispatched") continue;
    const lastDispatched = findMostRecentNodeTransition(targetDomain, node.node_id, "dispatched");
    if (!lastDispatched) continue;
    const tsMs = Date.parse(lastDispatched.ts);
    if (!Number.isFinite(tsMs)) continue;
    if (nowMs - tsMs < staleAfterMs) continue;
    const failureReason = {
      reason: "dispatch_timeout",
      stale_after_ms: staleAfterMs,
      dispatched_at: lastDispatched.ts,
      elapsed_ms: nowMs - tsMs,
    };
    if (node.physical_resource_dispatch != null) {
      const physical = normalizePhysicalResourceDispatchBinding(
        node.physical_resource_dispatch,
        "stale_dispatched_node.physical_resource_dispatch",
      );
      const prepTokenHash = lastDispatched.payload.prep_token_hash;
      if (!SHA256_DIGEST_PATTERN.test(prepTokenHash || "")) {
        throw new Error(
          "a stale physical dispatch requires an exact lowercase SHA-256 prep_token_hash",
        );
      }
      Object.assign(failureReason, {
        reservation_ref: physical.reservation_ref,
        receipt_digest: physical.receipt_digest,
        allocation_plan_digest: physical.allocation_plan_digest,
        eligibility_digest: physical.eligibility_digest,
        resource_bundle_digest: physical.resource_bundle_digest,
        source_graph_hash: physical.source_graph_hash,
        session_nucleus_hash: physical.session_nucleus_hash,
        prep_token_hash: prepTokenHash,
      });
    }
    const event = appendNodeTransition({
      target_domain: targetDomain,
      node_id: node.node_id,
      from_state: "dispatched",
      to_state: "failed",
      contract_hash: node.contract_hash || undefined,
      failure_reason: failureReason,
      ts: now.toISOString(),
      source: { tool: "expireStaleDispatchedNodes" },
    });
    emitted.push(event);
  }
  return emitted;
}

// Append a transition-proposed observation. Reuses observation.recorded
// per X-D1 / X-P8. trust_assumption is the only free-form prose field;
// capped at TRANSITION_TRUST_ASSUMPTION_MAX_CHARS (X.1 step 2) so the
// storage-distilled emission discipline (X-P9) holds at append time.
function appendTransitionProposal(input, options = {}) {
  if (input == null || typeof input !== "object" || Array.isArray(input)) {
    throw new Error("appendTransitionProposal input must be an object");
  }
  const fromSurface = assertSurfaceRef(input.from_surface, "from_surface");
  const toSurface = assertSurfaceRef(input.to_surface, "to_surface");
  if (fromSurface === toSurface) {
    throw new Error("from_surface and to_surface must differ");
  }
  const transitionKind = assertEnumValue(input.kind, TRANSITION_KIND_VALUES, "kind");
  const trustAssumption = assertProseUnderCap(
    input.trust_assumption,
    "trust_assumption",
    TRANSITION_TRUST_ASSUMPTION_MAX_CHARS,
  );
  const evidenceRefs = normalizeStringArray(input.evidence_refs, "evidence_refs");
  const proposalId = normalizeOptionalId(input.proposal_id, "proposal_id");

  const payload = {
    kind: "transition_proposed",
    from_surface: fromSurface,
    to_surface: toSurface,
    transition_kind: transitionKind,
    trust_assumption: trustAssumption,
  };
  if (evidenceRefs.length > 0) payload.evidence_refs = evidenceRefs;
  if (proposalId) payload.proposal_id = proposalId;

  const source = normalizeOptionalObject(input.source, "source");
  const actor = normalizeOptionalText(input.actor, "actor");

  return appendFrontierEvent({
    target_domain: input.target_domain,
    kind: "observation.recorded",
    ts: input.ts,
    payload,
    source: source || undefined,
    actor: actor || undefined,
  }, options);
}

// Append a hypothesis-proposed observation. hypothesis_statement is the
// only free-form prose field; capped at HYPOTHESIS_STATEMENT_MAX_CHARS so
// briefs that inline it (X.8 adjacent_hypotheses slice; X.11 cross-stack
// composition) stay summary-grade by construction per X-P9.
function appendHypothesisProposal(input, options = {}) {
  if (input == null || typeof input !== "object" || Array.isArray(input)) {
    throw new Error("appendHypothesisProposal input must be an object");
  }
  const hypothesisStatement = assertProseUnderCap(
    input.hypothesis_statement,
    "hypothesis_statement",
    HYPOTHESIS_STATEMENT_MAX_CHARS,
  );
  const surfaceRefs = normalizeStringArray(input.surface_refs, "surface_refs")
    .map((ref) => assertSurfaceRef(ref, "surface_refs[]"));
  if (surfaceRefs.length === 0) {
    throw new Error("surface_refs must contain at least one surface_id");
  }
  const suggestedContract = normalizeOptionalObject(input.suggested_contract, "suggested_contract");
  const proposalId = normalizeOptionalId(input.proposal_id, "proposal_id");

  const payload = {
    kind: "hypothesis_proposed",
    hypothesis_statement: hypothesisStatement,
    surface_refs: surfaceRefs,
  };
  if (suggestedContract) payload.suggested_contract = suggestedContract;
  if (proposalId) payload.proposal_id = proposalId;

  const source = normalizeOptionalObject(input.source, "source");
  const actor = normalizeOptionalText(input.actor, "actor");

  return appendFrontierEvent({
    target_domain: input.target_domain,
    kind: "observation.recorded",
    ts: input.ts,
    payload,
    source: source || undefined,
    actor: actor || undefined,
  }, options);
}

// Append a cell_proposed observation.recorded event — one coverage cell
// (a (surface x bug_class x auth_role) obligation, or for OSS a
// (harness x sanitizer x input_class) obligation) emitted from a
// deriveChildFanoutPlan child. The cell keys on the REAL parent surface_id
// (never a synthetic id); the cell_key is carried verbatim in the payload for
// 1:1 coverage reconciliation. Single-spawner: the orchestrator appends; no
// worker spawn. Mirrors appendHypothesisProposal (same observation.recorded
// top-level kind — no new frontier-event-kind budget spent).
function appendCellProposal(input, options = {}) {
  if (input == null || typeof input !== "object" || Array.isArray(input)) {
    throw new Error("appendCellProposal input must be an object");
  }
  const surfaceId = assertSurfaceRef(input.surface_id, "surface_id");
  const bugClass = assertNonEmptyString(input.bug_class, "bug_class");
  const cellKey = assertNonEmptyString(input.cell_key, "cell_key");
  const authProfile = normalizeOptionalText(input.auth_profile, "auth_profile") || "";
  // A2: a transition-cell rides the SAME cell_proposed payload but is grounded in
  // an EDGE — both endpoint surfaces. When present, the materializer attaches
  // both as surface_refs (instead of the single surface_id); absent keeps the
  // surface-cell path byte-identical.
  const fromSurface = input.from_surface == null ? "" : assertSurfaceRef(input.from_surface, "from_surface");
  const toSurface = input.to_surface == null ? "" : assertSurfaceRef(input.to_surface, "to_surface");
  const techniquePackIds = normalizeStringArray(input.technique_pack_ids, "technique_pack_ids");
  const capabilityPackIds = normalizeStringArray(input.capability_pack_ids, "capability_pack_ids");
  const planningKey = normalizeOptionalText(input.planning_key, "planning_key") || "";
  const proposalId = normalizeOptionalId(input.proposal_id, "proposal_id");
  // E2 depth re-probe: a residual-flagged covered cell is re-proposed as a
  // Tier-2 cell. tier=2 (the only non-default) sorts the node after all Tier-1
  // breadth cells (C1). Absent/1 keeps the surface-cell path byte-identical.
  const tier = Number.isInteger(input.tier) && input.tier > 1 ? input.tier : null;

  const payload = {
    kind: "cell_proposed",
    surface_id: surfaceId,
    cell_key: cellKey,
    bug_class: bugClass,
    auth_profile: authProfile,
    technique_pack_ids: techniquePackIds,
    capability_pack_ids: capabilityPackIds,
  };
  if (planningKey) payload.planning_key = planningKey;
  if (proposalId) payload.proposal_id = proposalId;
  if (fromSurface) payload.from_surface = fromSurface;
  if (toSurface) payload.to_surface = toSurface;
  if (tier) payload.tier = tier;

  const source = normalizeOptionalObject(input.source, "source");
  const actor = normalizeOptionalText(input.actor, "actor");

  return appendFrontierEvent({
    target_domain: input.target_domain,
    kind: "observation.recorded",
    ts: input.ts,
    payload,
    source: source || undefined,
    actor: actor || undefined,
  }, options);
}

// Reader helpers. The materializer (X.2) will subsume most of these but
// during X.1 the proposal-tool tests need a lightweight projection that
// returns only the TaskGraph-flavored events without re-decoding every
// observation.recorded payload by hand.
function readNodeTransitions(targetDomain) {
  return readFrontierEvents(targetDomain)
    .filter((event) => event.kind === "node.transitioned");
}

function readTransitionProposals(targetDomain) {
  return readFrontierEvents(targetDomain)
    .filter((event) => (
      event.kind === "observation.recorded"
      && event.payload
      && event.payload.kind === "transition_proposed"
    ));
}

function readHypothesisProposals(targetDomain) {
  return readFrontierEvents(targetDomain)
    .filter((event) => (
      event.kind === "observation.recorded"
      && event.payload
      && event.payload.kind === "hypothesis_proposed"
    ));
}

function readCellProposals(targetDomain) {
  return readFrontierEvents(targetDomain)
    .filter((event) => (
      event.kind === "observation.recorded"
      && event.payload
      && event.payload.kind === "cell_proposed"
    ));
}

module.exports = {
  COMPOSITION_EXPERIMENT_RESULT_KINDS,
  DEFAULT_STALE_DISPATCH_MS,
  EVIDENCE_BINDING_REF_PATTERN,
  HYPOTHESIS_STATEMENT_MAX_CHARS,
  NODE_STATE_TRANSITIONS,
  NODE_STATE_VALUES,
  PHYSICAL_RESOURCE_DISPATCH_BINDING_FIELDS,
  TASK_GRAPH_NODE_ID_PATTERN,
  TASK_GRAPH_NODE_ID_PREFIX,
  TRANSITION_KIND_VALUES,
  TRANSITION_TRUST_ASSUMPTION_MAX_CHARS,
  appendCellProposal,
  appendHypothesisProposal,
  appendNodeTransition,
  appendTransitionProposal,
  assertLiveNodeTransition,
  assertNodeTransitionAllowed,
  assertTaskGraphNodeId,
  expireStaleDispatchedNodes,
  findAttachedContract,
  findMostRecentNodeTransition,
  isAllowedNodeTransition,
  normalizePhysicalResourceDispatchBinding,
  readCellProposals,
  readHypothesisProposals,
  readNodeTransitions,
  readTransitionProposals,
};
