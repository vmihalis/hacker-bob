"use strict";

// Plane X Cycle X.6 — mechanical Contract DSL verifier.
//
// `mechanicalVerify(contract, agent_output, session_artifacts)` evaluates
// every witness in the normalized Contract against the agent's reported
// output and the on-disk session artifacts. Returns a structured verdict:
//
//   {
//     satisfied: boolean,                                // true iff every witness evaluates to true
//     missing:   [witness_id, ...],                      // witnesses whose required input is absent
//     failures:  [{witness_id, reason, ...payload}, ...] // structured failure payloads
//   }
//
// Per X-P3 the verifier runs FIRST; the LLM adjudication chain (X-D9)
// only runs when `satisfied === true`. The shape of the failure payload
// is load-bearing for X.8's `prior_attempt` brief slice — the structured
// `reason` + `extracted_payload` lets the next prepare-node call surface
// exactly what was tried and why it didn't hold.
//
// Per Do step 2 the verifier shares the per-prefix body resolvers from
// X.7 (`body-resolvers/index.js`) so the on-disk path is the single
// source of truth. The verifier does NOT dispatch to `bob_resolve_body`
// — it is server-side code, the resolvers are server-side helpers, the
// MCP tool layer is for evaluator-facing calls only.
//
// Per Do step 4 clou's anti-patterns (recursion-theater,
// receiver-blindness, silent-completion) are precluded by construction:
// every witness kind requires a concrete runtime artifact (a tool
// invocation, a file on disk, a frontier event with a verifiable kind, a
// CLI pack id present in the invocation telemetry, a relational value
// pair). Pure-AST shape pinning is not expressible in the closed 7-kind
// vocabulary, so the verifier cannot pass a Contract by hashing the
// agent's claim about its own behavior.

const fs = require("fs");
const path = require("path");
const {
  resolveArtifactBody,
} = require("./body-resolvers/index.js");
const {
  JSONPATH_SELECTOR_RE,
  WITNESS_KIND_VALUES,
} = require("./contracts.js");
const {
  sessionDir,
} = require("./paths.js");
const {
  FRONTIER_EVENT_KINDS,
} = require("./frontier-events.js");

// ─── Internal helpers ────────────────────────────────────────────────────

function isPlainObject(value) {
  return value != null && typeof value === "object" && !Array.isArray(value);
}

// Wrapper around the X.7 per-prefix resolver registry. Returns the
// resolver's full body envelope (`{body, content_hash, body_size_bytes}`)
// or null when the ref is unresolvable (artifact does not exist on
// disk). Throws structured errors on malformed refs / unknown prefixes;
// the caller catches those and surfaces them as `missing_artifact` /
// `malformed_artifact_ref` failures (witness_id-attributed), never as
// process-level exceptions — a malformed predicate would have been
// refused at `bob_attach_contract` (X-D11), so reaching this code path
// with a malformed ref means the predicate has drifted post-attach
// (which itself is a verifier failure, not a verifier crash).
//
// The `session_artifacts` argument is the X.6 verifier's binding to the
// session — currently a `{target_domain}` envelope so the resolvers
// route to the right on-disk session root. Future cycles may carry pre-
// resolved bodies inline (e.g. for sandboxed verification); the shape
// is left open via `session_artifacts.bodies_by_ref` for that use case.
function resolveArtifactBodyInternal(artifactRef, sessionArtifacts) {
  if (isPlainObject(sessionArtifacts) && isPlainObject(sessionArtifacts.bodies_by_ref)) {
    const preResolved = sessionArtifacts.bodies_by_ref[artifactRef];
    if (preResolved !== undefined) return preResolved || null;
  }
  if (!isPlainObject(sessionArtifacts) || typeof sessionArtifacts.target_domain !== "string") {
    return null;
  }
  try {
    return resolveArtifactBody(sessionArtifacts.target_domain, artifactRef);
  } catch (err) {
    // Re-throw structured errors so the witness-level evaluator can
    // surface a failure_reason that names the cause. The caller wraps
    // these into the verifier verdict.
    throw err;
  }
}

// ─── Restricted JSONPath extractor ───────────────────────────────────────
//
// Mirrors the X.4 closed selector subset:
//   $.field
//   $.field.nested
//   $.array[N]            (N a non-negative integer)
//   $.array[*].field      (wildcard with a continuation)
//   $.array[N].field[*]   (mixed selectors)
//
// Returns an array of values that match the selector. The array shape is
// uniform (even for a single-value selector) so the relational evaluator
// can compose against arrays without special-casing. An empty result
// array means "extract yielded no value" which the caller surfaces as
// `extract_yielded_no_value` per Do step 3.

const TOKEN_RE = /\.([A-Za-z_][A-Za-z0-9_]*)|\[(\d+|\*)\]/g;

function extractByJsonPath(rootValue, extractPath) {
  if (typeof extractPath !== "string" || !JSONPATH_SELECTOR_RE.test(extractPath)) {
    // Defensive: predicate normalization at attach time should have
    // refused this already. Reaching here means a Contract was edited
    // out-of-band; surface as no-value so the witness fails with
    // extract_yielded_no_value rather than crashing the verifier.
    return [];
  }
  // Walk the tokens left-to-right, threading a working list of "current"
  // values through each step. A wildcard fan-out at any step grows the
  // list; a missing key at any step prunes the corresponding value.
  let current = [rootValue];
  TOKEN_RE.lastIndex = 0;
  let match;
  while ((match = TOKEN_RE.exec(extractPath)) !== null) {
    const next = [];
    const fieldName = match[1];
    const arrayIndex = match[2];
    for (const value of current) {
      if (value == null) continue;
      if (fieldName != null) {
        if (isPlainObject(value) && Object.prototype.hasOwnProperty.call(value, fieldName)) {
          next.push(value[fieldName]);
        }
      } else if (arrayIndex === "*") {
        if (Array.isArray(value)) {
          for (const entry of value) next.push(entry);
        }
      } else {
        if (Array.isArray(value)) {
          const idx = Number(arrayIndex);
          if (Number.isInteger(idx) && idx >= 0 && idx < value.length) {
            next.push(value[idx]);
          }
        }
      }
    }
    current = next;
  }
  return current;
}

// Parse a resolver body string into a JSON value when possible; fall back
// to the raw string so JSONPath-against-text still has something
// addressable (e.g. for plain-text command stdout the body envelope is a
// JSON object whose `stdout` field carries the raw text — but the parser
// should accept both shapes gracefully).
function parseResolvedBody(envelope) {
  if (envelope == null) return null;
  const raw = envelope.body;
  if (typeof raw !== "string") return raw;
  try {
    return JSON.parse(raw);
  } catch {
    return raw;
  }
}

// ─── Per-witness evaluators ──────────────────────────────────────────────
//
// Each evaluator returns one of three shapes:
//   {ok: true}                                                       → witness satisfied
//   {ok: false, kind: "missing", reason}                             → input not present
//   {ok: false, kind: "failed",  reason, ...payload}                 → input present but predicate failed
//
// The verifier's top-level loop classifies "missing" into `missing[]`
// and "failed" into `failures[]` so the caller can distinguish "agent
// didn't produce the artifact" from "agent produced the artifact and it
// disagrees with the Contract" — relevant for the X.8 brief renderer
// (a missing artifact often means a stale recommended_read; a failed
// predicate means the agent's hypothesis was wrong).

function evaluateToolOutputMatch(predicate, witness, agentOutput) {
  const tool = predicate.tool;
  const invocations = collectToolInvocations(agentOutput);
  const matching = invocations.filter((inv) => inv && inv.tool === tool);
  if (matching.length === 0) {
    return {
      ok: false,
      kind: "missing",
      reason: "tool_not_invoked",
      tool,
    };
  }
  // The `match` matcher is a structured shape; v1 supports a single
  // form `{path, equals}` matching X.4's positive test fixture
  // (`{path: "$.status", equals: 200}`). Any invocation whose
  // recorded `output` extracts to the expected value satisfies the
  // witness. Other matcher shapes are reserved for future cycles; this
  // evaluator returns a structured failure naming the unsupported shape
  // so a future extension surfaces clearly.
  const matchSpec = predicate.match;
  if (!isPlainObject(matchSpec) || typeof matchSpec.path !== "string") {
    return {
      ok: false,
      kind: "failed",
      reason: "match_spec_unsupported",
      match: matchSpec,
    };
  }
  for (const inv of matching) {
    const extracted = extractByJsonPath(inv.output, matchSpec.path);
    if (extracted.length === 0) continue;
    if (Object.prototype.hasOwnProperty.call(matchSpec, "equals")) {
      const expected = matchSpec.equals;
      if (extracted.some((value) => deepEqual(value, expected))) {
        return { ok: true };
      }
    } else {
      // No `equals` means "extracted any value at all" satisfies the
      // witness. This is the "tool emitted a value at $.path" mode.
      return { ok: true };
    }
  }
  return {
    ok: false,
    kind: "failed",
    reason: "tool_output_did_not_match",
    tool,
    expected: matchSpec,
    observed_invocations: matching.length,
  };
}

function evaluateFileExists(predicate, witness, agentOutput, sessionArtifacts) {
  const requestedPath = predicate.path;
  const underSession = predicate.under_session !== false; // default: under session root
  let resolvedPath;
  if (underSession) {
    if (!isPlainObject(sessionArtifacts) || typeof sessionArtifacts.target_domain !== "string") {
      return {
        ok: false,
        kind: "missing",
        reason: "session_artifacts_missing_target_domain",
        path: requestedPath,
      };
    }
    resolvedPath = path.join(sessionDir(sessionArtifacts.target_domain), requestedPath);
  } else {
    if (!path.isAbsolute(requestedPath)) {
      return {
        ok: false,
        kind: "failed",
        reason: "absolute_path_required_when_under_session_false",
        path: requestedPath,
      };
    }
    resolvedPath = requestedPath;
  }
  let exists;
  try {
    exists = fs.existsSync(resolvedPath);
  } catch {
    exists = false;
  }
  if (!exists) {
    return {
      ok: false,
      kind: "missing",
      reason: "file_not_found",
      path: requestedPath,
      resolved_path: resolvedPath,
    };
  }
  return { ok: true };
}

function evaluateHashEquals(predicate, witness, agentOutput, sessionArtifacts) {
  const artifactRef = predicate.artifact_ref;
  let envelope;
  try {
    envelope = resolveArtifactBodyInternal(artifactRef, sessionArtifacts);
  } catch (err) {
    return {
      ok: false,
      kind: "failed",
      reason: err && err.code ? err.code : "body_resolution_failed",
      artifact_ref: artifactRef,
    };
  }
  if (envelope == null) {
    return {
      ok: false,
      kind: "missing",
      reason: "missing_artifact",
      artifact_ref: artifactRef,
    };
  }
  const observed = (envelope.content_hash || "").toLowerCase();
  const expected = (predicate.expected_hash || "").toLowerCase();
  if (observed && observed === expected) {
    return { ok: true };
  }
  return {
    ok: false,
    kind: "failed",
    reason: "hash_did_not_match",
    artifact_ref: artifactRef,
    expected_hash: expected,
    observed_hash: observed,
  };
}

function evaluateEvidenceRefKindPresent(predicate, witness, agentOutput) {
  const expectedKind = predicate.kind;
  const refs = collectEvidenceRefs(agentOutput);
  for (const ref of refs) {
    if (ref && typeof ref === "object" && ref.kind === expectedKind) {
      return { ok: true };
    }
    if (typeof ref === "string" && ref === expectedKind) {
      return { ok: true };
    }
  }
  return {
    ok: false,
    kind: "missing",
    reason: "evidence_ref_kind_not_present",
    expected_kind: expectedKind,
    observed_kinds: Array.from(new Set(
      refs.map((ref) => (ref && typeof ref === "object" ? ref.kind : ref))
        .filter((kind) => typeof kind === "string"),
    )).sort(),
  };
}

function evaluateFrontierEventEmitted(predicate, witness, agentOutput, sessionArtifacts) {
  if (!FRONTIER_EVENT_KINDS.includes(predicate.kind)) {
    // Predicate normalization at attach refuses this; defensive check.
    return {
      ok: false,
      kind: "failed",
      reason: "frontier_event_kind_unknown",
      requested_kind: predicate.kind,
    };
  }
  // Prefer pre-resolved events on the session_artifacts envelope (X.8
  // can pass `events_since_dispatch` to scope the read); fall back to
  // reading the on-disk ledger when no scope is provided.
  let events = isPlainObject(sessionArtifacts) && Array.isArray(sessionArtifacts.events)
    ? sessionArtifacts.events
    : null;
  if (events == null) {
    if (!isPlainObject(sessionArtifacts) || typeof sessionArtifacts.target_domain !== "string") {
      return {
        ok: false,
        kind: "missing",
        reason: "session_artifacts_missing_target_domain",
        requested_kind: predicate.kind,
      };
    }
    try {
      // Lazy require to avoid module-load cycle (frontier-events transitively
      // imports contracts via task-graph helpers).
      const { readFrontierEvents } = require("./frontier-events.js");
      events = readFrontierEvents(sessionArtifacts.target_domain);
    } catch {
      events = [];
    }
  }
  for (const event of events) {
    if (!event || event.kind !== predicate.kind) continue;
    if (predicate.payload_kind != null) {
      const payloadKind = event.payload && event.payload.observation_kind;
      if (payloadKind !== predicate.payload_kind) continue;
    }
    return { ok: true };
  }
  return {
    ok: false,
    kind: "missing",
    reason: "frontier_event_not_emitted",
    requested_kind: predicate.kind,
    requested_payload_kind: predicate.payload_kind || null,
  };
}

function evaluateCliPackInvoked(predicate, witness, agentOutput) {
  const expectedPack = predicate.cli_pack;
  const packs = collectCliPackInvocations(agentOutput);
  if (packs.has(expectedPack)) {
    return { ok: true };
  }
  return {
    ok: false,
    kind: "missing",
    reason: "cli_pack_not_invoked",
    expected_cli_pack: expectedPack,
    observed_cli_packs: Array.from(packs).sort(),
  };
}

function evaluateRelationalValueMatch(predicate, witness, agentOutput, sessionArtifacts) {
  const leftRef = predicate.left.artifact_ref;
  const rightRef = predicate.right.artifact_ref;

  let leftEnvelope;
  try {
    leftEnvelope = resolveArtifactBodyInternal(leftRef, sessionArtifacts);
  } catch (err) {
    return {
      ok: false,
      kind: "failed",
      reason: err && err.code ? err.code : "body_resolution_failed",
      left_artifact_ref: leftRef,
      right_artifact_ref: rightRef,
    };
  }
  let rightEnvelope;
  try {
    rightEnvelope = resolveArtifactBodyInternal(rightRef, sessionArtifacts);
  } catch (err) {
    return {
      ok: false,
      kind: "failed",
      reason: err && err.code ? err.code : "body_resolution_failed",
      left_artifact_ref: leftRef,
      right_artifact_ref: rightRef,
    };
  }
  // missing_artifact per Do step 3 — the verifier reports which side is
  // unresolvable so the brief renderer can surface "left missing" vs
  // "right missing" in the prior_attempt slice.
  if (leftEnvelope == null || rightEnvelope == null) {
    return {
      ok: false,
      kind: "missing",
      reason: "missing_artifact",
      left_artifact_ref: leftRef,
      right_artifact_ref: rightRef,
      left_present: leftEnvelope != null,
      right_present: rightEnvelope != null,
    };
  }

  const leftRoot = parseResolvedBody(leftEnvelope);
  const rightRoot = parseResolvedBody(rightEnvelope);
  const leftValues = extractByJsonPath(leftRoot, predicate.left.extract_path);
  const rightValues = extractByJsonPath(rightRoot, predicate.right.extract_path);

  if (leftValues.length === 0 || rightValues.length === 0) {
    return {
      ok: false,
      kind: "failed",
      reason: "extract_yielded_no_value",
      left_artifact_ref: leftRef,
      right_artifact_ref: rightRef,
      left_extract_path: predicate.left.extract_path,
      right_extract_path: predicate.right.extract_path,
      left_yielded_count: leftValues.length,
      right_yielded_count: rightValues.length,
    };
  }

  const op = predicate.op;
  const holds = relationalOpHolds(op, leftValues, rightValues);
  if (holds) {
    return { ok: true };
  }
  // Surface BOTH extracted scalar values + BOTH artifact_refs per Do
  // step 3 so the X.8 prior_attempt slice can inline the structured
  // failure payload verbatim. For wildcard fan-outs we surface the
  // first value pair (the most addressable representation) and a count
  // so the brief can show "tested N×M pairs, none held".
  return {
    ok: false,
    kind: "failed",
    reason: "relation_did_not_hold",
    left_artifact_ref: leftRef,
    right_artifact_ref: rightRef,
    left_extract_path: predicate.left.extract_path,
    right_extract_path: predicate.right.extract_path,
    op,
    left_value: leftValues[0],
    right_value: rightValues[0],
    left_value_count: leftValues.length,
    right_value_count: rightValues.length,
  };
}

// ─── Relational op evaluator ─────────────────────────────────────────────

function relationalOpHolds(op, leftValues, rightValues) {
  switch (op) {
    case "eq":
      for (const lv of leftValues) {
        for (const rv of rightValues) {
          if (deepEqual(lv, rv)) return true;
        }
      }
      return false;
    case "neq":
      // "neq" holds when at least one pair is unequal — useful for
      // assertions like "the recovered signer is NOT the zero address".
      for (const lv of leftValues) {
        for (const rv of rightValues) {
          if (!deepEqual(lv, rv)) return true;
        }
      }
      return false;
    case "subset_of": {
      // Every left value must appear in the right values set.
      for (const lv of leftValues) {
        let found = false;
        for (const rv of rightValues) {
          if (deepEqual(lv, rv)) { found = true; break; }
        }
        if (!found) return false;
      }
      return true;
    }
    case "contains": {
      // Any left value (string or array) must contain any right value.
      for (const lv of leftValues) {
        for (const rv of rightValues) {
          if (typeof lv === "string" && typeof rv === "string" && lv.includes(rv)) return true;
          if (Array.isArray(lv) && lv.some((entry) => deepEqual(entry, rv))) return true;
        }
      }
      return false;
    }
    default:
      return false;
  }
}

function deepEqual(a, b) {
  if (a === b) return true;
  if (a == null || b == null) return false;
  if (typeof a !== typeof b) return false;
  if (typeof a !== "object") return false;
  const aIsArr = Array.isArray(a);
  const bIsArr = Array.isArray(b);
  if (aIsArr !== bIsArr) return false;
  if (aIsArr) {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i += 1) {
      if (!deepEqual(a[i], b[i])) return false;
    }
    return true;
  }
  const aKeys = Object.keys(a).sort();
  const bKeys = Object.keys(b).sort();
  if (aKeys.length !== bKeys.length) return false;
  for (let i = 0; i < aKeys.length; i += 1) {
    if (aKeys[i] !== bKeys[i]) return false;
    if (!deepEqual(a[aKeys[i]], b[aKeys[i]])) return false;
  }
  return true;
}

// ─── Agent output normalizers ────────────────────────────────────────────
//
// The agent_output shape is loose at this layer because the X.8
// finalize-node tool will normalize it before passing it in (per the
// X.8 Do step "rejects empty agent_output"). Here we accept a few
// conventional shapes:
//   {tool_invocations: [{tool, args?, output?}, ...]}
//   {evidence_refs:    [{kind, ...} | "kind_string", ...]}
//   {cli_pack_invocations: [pack_id, ...]}
//
// Future cycles may extend the agent_output schema; the collectors here
// are tolerant of missing arrays (treated as empty) so adding a new
// channel doesn't retroactively break older Contracts.

function collectToolInvocations(agentOutput) {
  if (!isPlainObject(agentOutput)) return [];
  const tools = agentOutput.tool_invocations;
  return Array.isArray(tools) ? tools : [];
}

function collectEvidenceRefs(agentOutput) {
  if (!isPlainObject(agentOutput)) return [];
  const refs = agentOutput.evidence_refs;
  return Array.isArray(refs) ? refs : [];
}

function collectCliPackInvocations(agentOutput) {
  const out = new Set();
  if (!isPlainObject(agentOutput)) return out;
  const direct = agentOutput.cli_pack_invocations;
  if (Array.isArray(direct)) {
    for (const entry of direct) {
      if (typeof entry === "string" && entry) out.add(entry);
    }
  }
  // Tool invocations may also carry a `cli_pack` tag (the X.8 finalize
  // path can stamp the pack id when a Bash invocation matches a pack);
  // fold those in so a Contract that requires `cli_pack_invoked` doesn't
  // require the agent to also list the pack id separately.
  for (const inv of collectToolInvocations(agentOutput)) {
    if (inv && typeof inv.cli_pack === "string" && inv.cli_pack) {
      out.add(inv.cli_pack);
    }
  }
  return out;
}

// ─── Dispatcher table (one entry per witness kind) ───────────────────────

const EVALUATORS = Object.freeze({
  tool_output_match: evaluateToolOutputMatch,
  file_exists: evaluateFileExists,
  hash_equals: evaluateHashEquals,
  evidence_ref_kind_present: evaluateEvidenceRefKindPresent,
  frontier_event_emitted: evaluateFrontierEventEmitted,
  cli_pack_invoked: evaluateCliPackInvoked,
  relational_value_match: evaluateRelationalValueMatch,
});

// Compile-time sanity: every X-D4 witness kind has a registered
// evaluator. A future cycle that adds a witness kind without a matching
// evaluator entry here would throw at module-load time so the gap
// surfaces in CI before the verifier silently passes the new kind.
for (const kind of WITNESS_KIND_VALUES) {
  if (typeof EVALUATORS[kind] !== "function") {
    throw new Error(`contract-verifier: missing evaluator for witness kind "${kind}"`);
  }
}

// ─── Top-level entry point ───────────────────────────────────────────────

function mechanicalVerify(contract, agentOutput, sessionArtifacts) {
  if (!isPlainObject(contract) || !Array.isArray(contract.witnesses)) {
    throw new Error("mechanicalVerify expects a normalized contract with witnesses[]");
  }

  const missing = [];
  const failures = [];

  for (const witness of contract.witnesses) {
    if (!witness || typeof witness !== "object") continue;
    const evaluator = EVALUATORS[witness.kind];
    if (typeof evaluator !== "function") {
      // Defensive — should never happen since attach time refuses
      // unknown kinds. Surface as a structured failure so the verdict
      // still describes what went wrong.
      failures.push({
        witness_id: witness.id,
        reason: "witness_kind_unknown",
        kind: witness.kind,
      });
      continue;
    }
    let outcome;
    try {
      outcome = evaluator(witness.predicate, witness, agentOutput, sessionArtifacts);
    } catch (err) {
      // Predicate normalization at attach refuses malformed predicates
      // (X-D11); reaching this code with a thrown evaluator means the
      // resolver / extractor crashed on an unforeseen input. Surface as
      // a structured failure rather than crashing the verifier.
      failures.push({
        witness_id: witness.id,
        reason: "evaluator_threw",
        error_code: err && err.code ? err.code : null,
        error_message: err && err.message ? err.message : String(err),
      });
      continue;
    }
    if (outcome && outcome.ok === true) continue;
    const payload = outcome && typeof outcome === "object" ? outcome : {};
    const { ok: _ok, kind: classification, ...details } = payload;
    if (classification === "missing") {
      missing.push(witness.id);
      failures.push({
        witness_id: witness.id,
        ...details,
      });
    } else {
      failures.push({
        witness_id: witness.id,
        ...details,
      });
    }
  }

  return {
    satisfied: failures.length === 0,
    missing,
    failures,
  };
}

module.exports = {
  EVALUATORS,
  extractByJsonPath,
  mechanicalVerify,
  resolveArtifactBodyInternal,
};
