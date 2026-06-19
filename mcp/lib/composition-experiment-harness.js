"use strict";

// Path-composition experiment harness.
//
// A composed cross-surface path is a hypothesis: "these leaf observations, in
// this order, compose into a confirmable attack path." This harness REFUSES to
// confirm a path unless every leaf is bound to a replayable frontier event.
// The binding is the whole point — a path whose leaves are only described in
// prose (or bound to refs that do not resolve) cannot be replayed, so it cannot
// be confirmed. Confirmation here means: every leaf's `evidence_ref`
//
//   (i)   matches EVIDENCE_BINDING_REF_PATTERN (a `frontier_event:<id>` ref),
//   (ii)  resolves to a real frontier event whose event_id exists in the
//         session ledger (readFrontierEvents), and
//   (iii) that resolved event is a typed-replay observation (the canonical
//         observation.recorded kind) whose payload is SHAPED for independent
//         replay: a decisive observation (edge_type + request + response +
//         verdict), a negative control whose request/response DIFFER from the
//         positive and whose verdict is the OPPOSITE (a discriminating, declared
//         flip), and a replay_hash over the whole decisive tuple. Binding to
//         another kind, an untyped payload, a non-discriminating control, or a
//         tampered hash is refused.
//
// This is an OFFLINE shape gate, not a live verifier: the harness never executes
// a request. A "pass" therefore means the path's evidence is replay-shaped,
// discriminating, and tamper-evident — a NECESSARY precondition carried as
// `verification_required: true`, which a live verifier must still confirm by
// re-executing each leaf. It does not by itself prove the exploit.
//
// If ANY leaf fails any of (i)(ii)(iii) the result is "fail" and the offending
// leaves are returned in `refused_leaves[]`. Only a path whose every leaf
// resolves and validates yields "pass". Each run is appended to the MCP-owned,
// capped composition-results.jsonl under withSessionLock.

const {
  readFrontierEvents,
} = require("./frontier-events.js");
const {
  COMPOSITION_EXPERIMENT_RESULT_KINDS,
  EVIDENCE_BINDING_REF_PATTERN,
} = require("./task-graph-events.js");
const {
  assertSafeDomain,
  compositionResultsJsonlPath,
} = require("./paths.js");
const {
  appendJsonlLine,
  withSessionLock,
} = require("./storage.js");
const {
  hashCanonicalJson,
} = require("./verification-contracts.js");

const COMPOSITION_RESULTS_VERSION = 1;
// Cap mirrors the other session-scoped *.jsonl writers: the ledger is a rolling
// audit trail of experiment outcomes, not an unbounded archive. trimJsonlFile
// keeps the most recent records.
const COMPOSITION_RESULTS_MAX_RECORDS = 2000;
const EVIDENCE_REF_PREFIX = "frontier_event:";

// Refusal reasons are a closed vocabulary so the orchestrator can branch on the
// cause without parsing prose. Each maps to exactly one of the (i)(ii)(iii)
// gates above.
const REFUSAL_MALFORMED_REF = "malformed_evidence_ref";
const REFUSAL_UNRESOLVED_EVENT = "unresolved_frontier_event";
const REFUSAL_INVALID_PAYLOAD = "invalid_observation_payload";
const REFUSAL_NO_DECISIVE_FLIP = "no_decisive_control_flip";
const REFUSAL_NONDISCRIMINATING_CONTROL = "nondiscriminating_control";
const REFUSAL_REPLAY_MISMATCH = "replay_hash_mismatch";

// Only the canonical typed-observation kind may carry replay evidence; other
// frontier streams (surface.observed, session.seeded, …) cannot launder an
// exploit-shaped payload into a confirmation.
const REPLAY_OBSERVATION_KIND = "observation.recorded";
const EDGE_TYPE_VALUES = Object.freeze(["reachability", "guard", "sink"]);
const REPLAY_VERDICT_VALUES = Object.freeze(["confirmed", "denied"]);

function isNonEmptyValue(value) {
  if (value == null) return false;
  if (typeof value === "string") return value.length > 0;
  if (Array.isArray(value)) return value.length > 0;
  if (typeof value === "object") return Object.keys(value).length > 0;
  return true;
}

// Typed-replay predicate — an OFFLINE artifact-shape gate, NOT a live verifier.
// It does not execute requests; it validates that the resolved observation is
// SHAPED for independent replay and is internally tamper-evident:
//   - a decisive observation (edge_type + request + response + verdict),
//   - a negative control whose request/response actually DIFFER from the
//     positive (a real discriminating control, not the same input with the
//     verdict relabelled) and whose verdict is the OPPOSITE (a declared flip),
//   - a replay_hash that recomputes from the WHOLE decisive tuple
//     {edge_type, request, response, verdict, negative_control}, so the flip
//     claim — not just the positive half — is hash-bound.
// A pass therefore means the evidence is replay-shaped, discriminating, and
// tamper-evident — a NECESSARY precondition a live verifier must still confirm
// by re-executing both requests. It does NOT by itself prove the exploit; the
// harness has no way to run an HTTP/contract call. Returns null on pass, else
// the refusal reason.
function replayObservationRefusal(payload) {
  if (payload == null || typeof payload !== "object" || Array.isArray(payload)) {
    return REFUSAL_INVALID_PAYLOAD;
  }
  const { edge_type, request, response, verdict, negative_control, replay_hash } = payload;
  if (!EDGE_TYPE_VALUES.includes(edge_type)) return REFUSAL_INVALID_PAYLOAD;
  if (!isNonEmptyValue(request) || !isNonEmptyValue(response)) return REFUSAL_INVALID_PAYLOAD;
  if (!REPLAY_VERDICT_VALUES.includes(verdict)) return REFUSAL_INVALID_PAYLOAD;
  if (negative_control == null || typeof negative_control !== "object" || Array.isArray(negative_control)) {
    return REFUSAL_INVALID_PAYLOAD;
  }
  if (!isNonEmptyValue(negative_control.request) || !isNonEmptyValue(negative_control.response)) {
    return REFUSAL_INVALID_PAYLOAD;
  }
  if (!REPLAY_VERDICT_VALUES.includes(negative_control.verdict)) return REFUSAL_INVALID_PAYLOAD;
  // The decisive control must FLIP the verdict; an equal verdict is a bound but
  // benign observation (no genuine guard-fail / reachability / sensitivity).
  if (verdict === negative_control.verdict) return REFUSAL_NO_DECISIVE_FLIP;
  // The control must be a DIFFERENT input. Same request+response with only the
  // verdict relabelled is a physically impossible flip (identical input cannot
  // yield opposite outcomes) — refuse it rather than confirm a fabricated flip.
  if (hashCanonicalJson(request) === hashCanonicalJson(negative_control.request)
    && hashCanonicalJson(response) === hashCanonicalJson(negative_control.response)) {
    return REFUSAL_NONDISCRIMINATING_CONTROL;
  }
  // The replay_hash binds the WHOLE decisive tuple so the entire claim (both
  // observations and the flip) is tamper-evident and a live verifier can
  // recompute it after re-executing both requests; a missing or mismatched hash
  // is unreplayable evidence.
  if (typeof replay_hash !== "string"
    || replay_hash !== hashCanonicalJson({ edge_type, request, response, verdict, negative_control })) {
    return REFUSAL_REPLAY_MISMATCH;
  }
  return null;
}

// Build a one-pass index from event_id → event so each leaf resolves in O(1)
// regardless of leaf count or ledger size.
function indexEventsById(events) {
  const index = new Map();
  for (const event of events) {
    if (event && typeof event.event_id === "string") {
      index.set(event.event_id, event);
    }
  }
  return index;
}

// Evaluate a single leaf against the three binding gates. Returns null when the
// leaf is bound (passes all gates) or a structured refusal record otherwise.
function evaluateLeaf(leaf, index, position) {
  const base = { index: position };
  if (leaf == null || typeof leaf !== "object" || Array.isArray(leaf)) {
    return { ...base, evidence_ref: null, reason: REFUSAL_MALFORMED_REF };
  }
  const evidenceRef = leaf.evidence_ref;
  base.evidence_ref = typeof evidenceRef === "string" ? evidenceRef : null;
  if (typeof leaf.edge_id === "string" && leaf.edge_id.trim()) {
    base.edge_id = leaf.edge_id.trim();
  }

  // (i) The ref must be a well-formed frontier_event binding.
  if (typeof evidenceRef !== "string" || !EVIDENCE_BINDING_REF_PATTERN.test(evidenceRef)) {
    return { ...base, reason: REFUSAL_MALFORMED_REF };
  }

  // (ii) The bound event_id must resolve to a real event in the ledger.
  const eventId = evidenceRef.slice(EVIDENCE_REF_PREFIX.length);
  const event = index.get(eventId);
  if (!event) {
    return { ...base, resolved_event_id: eventId, reason: REFUSAL_UNRESOLVED_EVENT };
  }

  // (iii) The resolved event must be a typed-replay observation: the canonical
  // observation.recorded kind whose payload passes replayObservationRefusal
  // (decisive request/response + a discriminating, verdict-flipping negative
  // control, full-tuple replay_hash). Binding to another kind or a non-typed
  // payload is refused. This is a SHAPE gate, not a live verification.
  const resolvedKind = typeof event.kind === "string" ? event.kind : null;
  if (event.kind !== REPLAY_OBSERVATION_KIND) {
    return { ...base, resolved_event_id: eventId, resolved_kind: resolvedKind, reason: REFUSAL_INVALID_PAYLOAD };
  }
  const replayRefusal = replayObservationRefusal(event.payload);
  if (replayRefusal) {
    return { ...base, resolved_event_id: eventId, resolved_kind: resolvedKind, reason: replayRefusal };
  }

  return null;
}

// Run a path-composition experiment. `path` is an ordered list of leaf edges,
// each carrying an `evidence_ref`. The experiment passes only when every leaf
// binds to a typed-replay observation that is replay-shaped, discriminating, and
// tamper-evident; otherwise it refuses (fail) and reports each unbound leaf. A
// pass carries `verification_required: true` — it is an offline precondition a
// live verifier must still confirm by re-executing each leaf's request; the
// harness does not execute anything.
function runPathCompositionExperiment(domain, { path } = {}) {
  const targetDomain = assertSafeDomain(domain);
  if (!Array.isArray(path)) {
    throw new Error("path must be an array of leaf edges");
  }
  if (path.length === 0) {
    // A path with no leaves composes nothing; there is nothing to confirm.
    throw new Error("path must contain at least one leaf edge");
  }

  // Resolve every leaf against the frontier ledger and record the result under
  // one held session lock, so the recorded pass/fail reflects a single
  // point-in-time snapshot a concurrent frontier append cannot tear.
  const record = withSessionLock(targetDomain, () => {
    const index = indexEventsById(readFrontierEvents(targetDomain));

    const refusedLeaves = [];
    const boundEventIds = [];
    path.forEach((leaf, position) => {
      const refusal = evaluateLeaf(leaf, index, position);
      if (refusal) {
        refusedLeaves.push(refusal);
      } else {
        boundEventIds.push(leaf.evidence_ref.slice(EVIDENCE_REF_PREFIX.length));
      }
    });

    const built = {
      version: COMPOSITION_RESULTS_VERSION,
      target_domain: targetDomain,
      ts: new Date().toISOString(),
      result: refusedLeaves.length === 0
        ? COMPOSITION_EXPERIMENT_RESULT_KINDS[0] // "pass"
        : COMPOSITION_EXPERIMENT_RESULT_KINDS[1], // "fail"
      // A pass is an offline shape/replay precondition, NOT a verified exploit:
      // a live verifier must still re-execute each leaf's request to confirm.
      verification_required: refusedLeaves.length === 0,
      leaf_count: path.length,
      bound_leaf_count: boundEventIds.length,
      refused_leaf_count: refusedLeaves.length,
      // The ordered list of event_ids the confirmed path replays through. On a
      // refusal this is the prefix that did bind; the path is still "fail".
      bound_event_ids: boundEventIds,
      // Hash of the ordered ref sequence so two runs of the same path are
      // recognizable in the ledger without inlining every ref.
      path_hash: hashCanonicalJson(
        path.map((leaf) => (leaf && typeof leaf === "object" ? leaf.evidence_ref ?? null : null)),
      ),
    };
    if (refusedLeaves.length > 0) {
      built.refused_leaves = refusedLeaves;
    }
    appendJsonlLine(compositionResultsJsonlPath(targetDomain), built, {
      maxRecords: COMPOSITION_RESULTS_MAX_RECORDS,
    });
    return built;
  });

  const out = {
    target_domain: targetDomain,
    result: record.result,
    verification_required: record.verification_required,
    leaf_count: record.leaf_count,
    bound_leaf_count: record.bound_leaf_count,
    refused_leaf_count: record.refused_leaf_count,
    bound_event_ids: record.bound_event_ids,
    path_hash: record.path_hash,
  };
  if (record.refused_leaves) {
    out.refused_leaves = record.refused_leaves;
  }
  return out;
}

module.exports = {
  COMPOSITION_RESULTS_MAX_RECORDS,
  COMPOSITION_RESULTS_VERSION,
  EDGE_TYPE_VALUES,
  REPLAY_VERDICT_VALUES,
  REPLAY_OBSERVATION_KIND,
  REFUSAL_INVALID_PAYLOAD,
  REFUSAL_MALFORMED_REF,
  REFUSAL_NO_DECISIVE_FLIP,
  REFUSAL_NONDISCRIMINATING_CONTROL,
  REFUSAL_REPLAY_MISMATCH,
  REFUSAL_UNRESOLVED_EVENT,
  runPathCompositionExperiment,
};
