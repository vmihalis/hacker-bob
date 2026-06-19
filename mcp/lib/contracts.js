"use strict";

// Plane X Cycle X.4 — Contract schema + attach with pre-dispatch
// satisfiability check.
//
// Per X-P2 every TaskGraph node carries a Contract before dispatch with
// ≥1 invariant + ≥1 expected witness + ≥1 production_path. The Contract
// is hash-bound; severity_floor is PER-CONTRACT and folded into
// `contract_hash` (X-D4) so a Contract referenced by a node can never
// silently degrade its adjudication chain by re-keying severity in place.
//
// Per X-D11 the satisfiability gate (`assertContractSatisfiable`) refuses
// attachment when a witness predicate references a tool, artifact_ref
// prefix, or capability the node's derived pack cannot produce. The X.4
// shape of the gate is structural — it verifies (a) every
// production_paths[].tool_call_pattern[].tool exists in the MCP tool
// registry and (b) every relational_value_match predicate's artifact_ref
// prefix is in the X-D12 closed set — and accepts an OPTIONAL
// `allowed_tools_for_node[]` from the caller (X.5's derivePackForNode
// supplies the per-node set in a later cycle; X.4 falls back to the
// universal registry-membership check so attach refusal still fires on
// witness predicates that name a tool that does not exist).
//
// Per X-P9 (storage-distilled emission) Contract payloads ARE the brief-
// inlinable form: invariant statements ≤ 280 chars (Do step 4),
// predicates are structured, no free-form prose hides in the witnesses.
// The X.8 `bob_prepare_node` brief inlines the full Contract as a
// `contract` slice; no body resolution is needed.

// tool-registry.js loads every tool module via tools/index.js; some of those
// tool modules (e.g. attach-contract.js) require this module. To avoid an
// import cycle at module-load time, we lazy-require the registry inside
// assertContractSatisfiable. The first call materializes the TOOL_HANDLERS
// reference; subsequent calls reuse the cached binding.
let _toolHandlersCache = null;
function getToolHandlers() {
  if (_toolHandlersCache == null) {
    _toolHandlersCache = require("./tool-registry.js").TOOL_HANDLERS;
  }
  return _toolHandlersCache;
}
const {
  FRONTIER_EVENT_KINDS,
} = require("./frontier-events.js");
const {
  appendNodeTransition,
  assertTaskGraphNodeId,
} = require("./task-graph-events.js");
const {
  assertEnumValue,
  assertNonEmptyString,
  normalizeOptionalText,
  normalizeStringArray,
} = require("./validation.js");
const {
  hashCanonicalJson,
  isPlainObject,
} = require("./verification-contracts.js");
const {
  normalizeOptionalObject,
} = require("./fabric-common.js");
const {
  SEVERITY_VALUES,
} = require("./constants.js");

// ─── Frozen vocabulary (X-D4, X-D12) ─────────────────────────────────────

// X-D4: 7 closed witness kinds. The Contract DSL evaluator (X.6) ships
// one evaluator per kind; any addition would require a separate cycle.
const WITNESS_KIND_VALUES = Object.freeze([
  "tool_output_match",
  "file_exists",
  "hash_equals",
  "evidence_ref_kind_present",
  "frontier_event_emitted",
  "cli_pack_invoked",
  "relational_value_match",
]);

// X-D12: closed set of artifact_ref prefixes. `bob_resolve_body` (X.7)
// registers a resolver per prefix; predicates referencing prefixes
// outside this set are refused at attach time so the X.6 verifier and
// the X.8 prepare_node brief renderer never see an unresolvable ref.
const ARTIFACT_REF_PREFIX_VALUES = Object.freeze([
  "http_record",
  "evm_call",
  "repo_check",
  "repo_command_run",
  "finding",
  "evidence_pack",
  "frontier_event",
]);

// X-D9: severity_floor maps to a per-Contract adjudication chain. The
// floor is the most stringent severity the verifier is allowed to
// recommend; bound into contract_hash so re-keying severity in place
// changes the hash (and therefore the node's contract_hash). Mirrors
// SEVERITY_VALUES from constants.js minus "info" because info-only
// invariants don't need an adjudication round.
const SEVERITY_FLOOR_VALUES = Object.freeze(
  SEVERITY_VALUES.filter((s) => s !== "info"),
);

// Do step 4: invariant statement prose bound. 280 is the Twitter-style
// hard cap the spec freezes; an invariant that needs more prose either
// belongs in `description` (free-form, NOT brief-inlined) or should be
// split into two invariants.
const INVARIANT_STATEMENT_MAX_CHARS = 280;

// Production-path description bound. Mirrors the X-P9 prose discipline
// applied to trust_assumption + hypothesis_statement in X.1. Production
// paths are brief-inlined in the X.8 prepare_node `contract` slice so
// keeping them short is load-bearing for brief size.
const PRODUCTION_PATH_DESCRIPTION_MAX_CHARS = 280;

// Restricted JSONPath selector subset (X.4 Do step 2). Supports:
//   $.field
//   $.field.nested
//   $.array[N]            (N a non-negative integer)
//   $.array[*].field      (wildcard with a continuation)
//   $.array[N].field[*]   (mixed selectors)
// Explicitly NOT supported: filter expressions ?(...),
// function calls length(), recursive descent .., scripts (), unions [a,b],
// slices [a:b]. Anything containing those tokens is refused so the X.6
// verifier never has to defend against an extract_path that could exfil
// a side effect.
const JSONPATH_SELECTOR_RE = /^\$(?:\.[A-Za-z_][A-Za-z0-9_]*|\[(?:\d+|\*)\])+$/;

// X-D12 artifact_ref shape: <prefix>:<ref_id>. ref_id is the resolver's
// canonical lookup key (e.g. http_record:R7 → traffic.jsonl record R7).
// Permit a generous alphanumeric + dash + underscore + dot + colon ref
// body so resolvers can use compound keys (e.g. evm_call:tx:0xabc...)
// without escaping; refuse path separators and shell metacharacters.
const ARTIFACT_REF_RE = /^([A-Za-z_][A-Za-z0-9_]*):([A-Za-z0-9._:-]{1,200})$/;

// Allowed comparison ops for relational_value_match (X-D4 sub-schema).
const RELATIONAL_MATCH_OP_VALUES = Object.freeze([
  "eq",
  "neq",
  "subset_of",
  "contains",
]);

// ─── Internal helpers ────────────────────────────────────────────────────

function isShortText(value) {
  return typeof value === "string" && value.length > 0;
}

function assertStringWithCap(value, fieldName, maxChars) {
  const text = assertNonEmptyString(value, fieldName);
  if (text.length > maxChars) {
    const err = new Error(
      `prose_too_long: ${fieldName} length ${text.length} exceeds cap ${maxChars}`,
    );
    err.code = "prose_too_long";
    err.details = {
      field: fieldName,
      length: text.length,
      max_chars: maxChars,
    };
    throw err;
  }
  return text;
}

function assertJsonPathSelector(value, fieldName) {
  const text = assertNonEmptyString(value, fieldName);
  if (!JSONPATH_SELECTOR_RE.test(text)) {
    const err = new Error(
      `extract_path_unsafe: ${fieldName} "${text}" is outside the restricted JSONPath subset ($.field, $.field.nested, $.array[N], $.array[*].field)`,
    );
    err.code = "extract_path_unsafe";
    err.details = {
      field: fieldName,
      extract_path: text,
    };
    throw err;
  }
  return text;
}

function assertArtifactRef(value, fieldName) {
  const text = assertNonEmptyString(value, fieldName);
  const match = ARTIFACT_REF_RE.exec(text);
  if (!match) {
    const err = new Error(
      `artifact_ref_malformed: ${fieldName} "${text}" does not match <prefix>:<ref_id>`,
    );
    err.code = "artifact_ref_malformed";
    err.details = { field: fieldName, artifact_ref: text };
    throw err;
  }
  const [, prefix] = match;
  if (!ARTIFACT_REF_PREFIX_VALUES.includes(prefix)) {
    const err = new Error(
      `artifact_ref_unknown_prefix: ${fieldName} prefix "${prefix}" is not in the X-D12 closed set (${ARTIFACT_REF_PREFIX_VALUES.join(", ")})`,
    );
    err.code = "artifact_ref_unknown_prefix";
    err.details = {
      field: fieldName,
      artifact_ref: text,
      prefix,
      allowed_prefixes: ARTIFACT_REF_PREFIX_VALUES.slice(),
    };
    throw err;
  }
  return text;
}

function artifactRefPrefix(ref) {
  if (typeof ref !== "string") return null;
  const idx = ref.indexOf(":");
  if (idx <= 0) return null;
  return ref.slice(0, idx);
}

// ─── Predicate normalizers (one per witness kind) ────────────────────────
//
// Every predicate normalizer returns a frozen, validated predicate. The
// returned object is folded into the canonical Contract so its hash is
// stable across formally-equivalent inputs (key-order changes do not
// change the hash because hashCanonicalJson sorts object keys).

function normalizeToolOutputMatchPredicate(predicate, fieldName) {
  if (!isPlainObject(predicate)) {
    throw new Error(`${fieldName}.predicate must be an object`);
  }
  const tool = assertNonEmptyString(predicate.tool, `${fieldName}.predicate.tool`);
  // `match` is a structured matcher (e.g. {path: "$.status", equals: 200}).
  // The verifier (X.6) interprets it; the schema layer enforces only its
  // presence + object shape so the verifier can evolve match grammar
  // without rev-locking the Contract schema.
  if (!isPlainObject(predicate.match)) {
    throw new Error(`${fieldName}.predicate.match must be an object`);
  }
  return Object.freeze({
    tool,
    match: predicate.match,
  });
}

function normalizeFileExistsPredicate(predicate, fieldName) {
  if (!isPlainObject(predicate)) {
    throw new Error(`${fieldName}.predicate must be an object`);
  }
  const path = assertNonEmptyString(predicate.path, `${fieldName}.predicate.path`);
  const out = { path };
  if (predicate.under_session != null) {
    if (typeof predicate.under_session !== "boolean") {
      throw new Error(`${fieldName}.predicate.under_session must be boolean`);
    }
    out.under_session = predicate.under_session;
  }
  return Object.freeze(out);
}

function normalizeHashEqualsPredicate(predicate, fieldName) {
  if (!isPlainObject(predicate)) {
    throw new Error(`${fieldName}.predicate must be an object`);
  }
  const artifactRef = assertArtifactRef(predicate.artifact_ref, `${fieldName}.predicate.artifact_ref`);
  const expectedHash = assertNonEmptyString(predicate.expected_hash, `${fieldName}.predicate.expected_hash`);
  if (!/^[a-f0-9]{32,128}$/i.test(expectedHash)) {
    throw new Error(
      `${fieldName}.predicate.expected_hash must be a lowercase hex digest (32..128 chars)`,
    );
  }
  return Object.freeze({
    artifact_ref: artifactRef,
    expected_hash: expectedHash.toLowerCase(),
  });
}

function normalizeEvidenceRefKindPresentPredicate(predicate, fieldName) {
  if (!isPlainObject(predicate)) {
    throw new Error(`${fieldName}.predicate must be an object`);
  }
  const kind = assertNonEmptyString(predicate.kind, `${fieldName}.predicate.kind`);
  // The evidence-ref kind universe is open across plane O / T evidence
  // emitters; we do not lock it here. The verifier (X.6) refuses kinds
  // not produced by any registered evidence emitter at evaluation time;
  // X.4 only enforces structural well-formedness.
  return Object.freeze({ kind });
}

function normalizeFrontierEventEmittedPredicate(predicate, fieldName) {
  if (!isPlainObject(predicate)) {
    throw new Error(`${fieldName}.predicate must be an object`);
  }
  const kind = assertNonEmptyString(predicate.kind, `${fieldName}.predicate.kind`);
  if (!FRONTIER_EVENT_KINDS.includes(kind)) {
    throw new Error(
      `${fieldName}.predicate.kind "${kind}" is not in FRONTIER_EVENT_KINDS (${FRONTIER_EVENT_KINDS.join(", ")})`,
    );
  }
  const out = { kind };
  if (predicate.payload_kind != null) {
    out.payload_kind = assertNonEmptyString(
      predicate.payload_kind,
      `${fieldName}.predicate.payload_kind`,
    );
  }
  return Object.freeze(out);
}

function normalizeCliPackInvokedPredicate(predicate, fieldName) {
  if (!isPlainObject(predicate)) {
    throw new Error(`${fieldName}.predicate must be an object`);
  }
  const cliPack = assertNonEmptyString(predicate.cli_pack, `${fieldName}.predicate.cli_pack`);
  return Object.freeze({ cli_pack: cliPack });
}

function normalizeRelationalValueMatchPredicate(predicate, fieldName) {
  if (!isPlainObject(predicate)) {
    throw new Error(`${fieldName}.predicate must be an object`);
  }
  const left = predicate.left;
  const right = predicate.right;
  if (!isPlainObject(left)) {
    throw new Error(`${fieldName}.predicate.left must be an object`);
  }
  if (!isPlainObject(right)) {
    throw new Error(`${fieldName}.predicate.right must be an object`);
  }
  const leftRef = assertArtifactRef(left.artifact_ref, `${fieldName}.predicate.left.artifact_ref`);
  const leftPath = assertJsonPathSelector(left.extract_path, `${fieldName}.predicate.left.extract_path`);
  const rightRef = assertArtifactRef(right.artifact_ref, `${fieldName}.predicate.right.artifact_ref`);
  const rightPath = assertJsonPathSelector(right.extract_path, `${fieldName}.predicate.right.extract_path`);
  const op = assertEnumValue(predicate.op, RELATIONAL_MATCH_OP_VALUES, `${fieldName}.predicate.op`);
  return Object.freeze({
    left: Object.freeze({
      artifact_ref: leftRef,
      extract_path: leftPath,
    }),
    op,
    right: Object.freeze({
      artifact_ref: rightRef,
      extract_path: rightPath,
    }),
  });
}

const PREDICATE_NORMALIZERS = Object.freeze({
  tool_output_match: normalizeToolOutputMatchPredicate,
  file_exists: normalizeFileExistsPredicate,
  hash_equals: normalizeHashEqualsPredicate,
  evidence_ref_kind_present: normalizeEvidenceRefKindPresentPredicate,
  frontier_event_emitted: normalizeFrontierEventEmittedPredicate,
  cli_pack_invoked: normalizeCliPackInvokedPredicate,
  relational_value_match: normalizeRelationalValueMatchPredicate,
});

// ─── Top-level shape normalizers ────────────────────────────────────────

function normalizeInvariant(raw, index) {
  if (!isPlainObject(raw)) {
    throw new Error(`invariants[${index}] must be an object`);
  }
  const id = assertNonEmptyString(raw.id, `invariants[${index}].id`);
  const statement = assertStringWithCap(
    raw.statement,
    `invariants[${index}].statement`,
    INVARIANT_STATEMENT_MAX_CHARS,
  );
  return Object.freeze({ id, statement });
}

function normalizeWitness(raw, index) {
  if (!isPlainObject(raw)) {
    throw new Error(`witnesses[${index}] must be an object`);
  }
  const id = assertNonEmptyString(raw.id, `witnesses[${index}].id`);
  const kind = assertEnumValue(raw.kind, WITNESS_KIND_VALUES, `witnesses[${index}].kind`);
  const normalize = PREDICATE_NORMALIZERS[kind];
  const predicate = normalize(raw.predicate, `witnesses[${index}]`);
  return Object.freeze({ id, kind, predicate });
}

function normalizeProductionPath(raw, index) {
  if (!isPlainObject(raw)) {
    throw new Error(`production_paths[${index}] must be an object`);
  }
  const description = assertStringWithCap(
    raw.description,
    `production_paths[${index}].description`,
    PRODUCTION_PATH_DESCRIPTION_MAX_CHARS,
  );
  const toolCallPattern = raw.tool_call_pattern;
  if (!Array.isArray(toolCallPattern) || toolCallPattern.length === 0) {
    throw new Error(`production_paths[${index}].tool_call_pattern must be a non-empty array`);
  }
  const normalizedPattern = toolCallPattern.map((entry, i) => {
    if (!isPlainObject(entry)) {
      throw new Error(`production_paths[${index}].tool_call_pattern[${i}] must be an object`);
    }
    const tool = assertNonEmptyString(
      entry.tool,
      `production_paths[${index}].tool_call_pattern[${i}].tool`,
    );
    // args_match is an optional structured matcher carried verbatim into
    // the verifier; the schema layer requires only an object shape.
    let argsMatch = null;
    if (entry.args_match != null) {
      if (!isPlainObject(entry.args_match)) {
        throw new Error(
          `production_paths[${index}].tool_call_pattern[${i}].args_match must be an object`,
        );
      }
      argsMatch = entry.args_match;
    }
    const out = { tool };
    if (argsMatch) out.args_match = argsMatch;
    return Object.freeze(out);
  });
  return Object.freeze({
    description,
    tool_call_pattern: Object.freeze(normalizedPattern),
  });
}

// ─── Top-level Contract normalizer + hash ────────────────────────────────

function normalizeContract(input) {
  if (!isPlainObject(input)) {
    throw new Error("contract must be an object");
  }
  const contractId = assertNonEmptyString(input.contract_id, "contract_id");
  const severityFloor = assertEnumValue(
    input.severity_floor,
    SEVERITY_FLOOR_VALUES,
    "severity_floor",
  );

  const invariantsRaw = input.invariants;
  if (!Array.isArray(invariantsRaw) || invariantsRaw.length === 0) {
    throw new Error("invariants must be a non-empty array (Contract requires ≥1 invariant per X-P2)");
  }
  const invariants = invariantsRaw.map(normalizeInvariant);

  const witnessesRaw = input.witnesses;
  if (!Array.isArray(witnessesRaw) || witnessesRaw.length === 0) {
    throw new Error("witnesses must be a non-empty array (Contract requires ≥1 witness per X-P2)");
  }
  const witnesses = witnessesRaw.map(normalizeWitness);

  const productionPathsRaw = input.production_paths;
  if (!Array.isArray(productionPathsRaw) || productionPathsRaw.length === 0) {
    throw new Error(
      "production_paths must be a non-empty array (Contract requires ≥1 production_path per X-P2)",
    );
  }
  const productionPaths = productionPathsRaw.map(normalizeProductionPath);

  // Refuse duplicate invariant / witness ids: stable internal references
  // (the X.6 verifier returns witness_ids verbatim in failure payloads).
  const invariantIds = new Set();
  for (const inv of invariants) {
    if (invariantIds.has(inv.id)) {
      throw new Error(`duplicate invariant id: ${inv.id}`);
    }
    invariantIds.add(inv.id);
  }
  const witnessIds = new Set();
  for (const w of witnesses) {
    if (witnessIds.has(w.id)) {
      throw new Error(`duplicate witness id: ${w.id}`);
    }
    witnessIds.add(w.id);
  }

  // contract_hash binds the per-Contract severity_floor (X-D9 / X-D4).
  // Re-keying severity in place therefore CHANGES the hash, which means
  // the X.2 materializer surfaces a contract_hash mismatch and the
  // attach must be re-emitted. This is the X-D4 anti-pattern guard.
  const hashable = {
    contract_id: contractId,
    severity_floor: severityFloor,
    invariants: invariants.map((i) => ({ id: i.id, statement: i.statement })),
    witnesses: witnesses.map((w) => ({ id: w.id, kind: w.kind, predicate: w.predicate })),
    production_paths: productionPaths.map((p) => ({
      description: p.description,
      tool_call_pattern: p.tool_call_pattern.map((tcp) => {
        const out = { tool: tcp.tool };
        if (tcp.args_match != null) out.args_match = tcp.args_match;
        return out;
      }),
    })),
  };
  const contractHash = hashCanonicalJson(hashable);

  return Object.freeze({
    contract_id: contractId,
    contract_hash: contractHash,
    severity_floor: severityFloor,
    invariants: Object.freeze(invariants),
    witnesses: Object.freeze(witnesses),
    production_paths: Object.freeze(productionPaths),
  });
}

// ─── Satisfiability gate (X-D11) ─────────────────────────────────────────
//
// `assertContractSatisfiable(contract, options)`:
//   - options.allowed_tools_for_node[] — optional set from X.5's
//     derivePackForNode. When provided, EVERY tool referenced by a
//     production_paths[].tool_call_pattern[].tool MUST be in this set;
//     a mismatch surfaces contract_unsatisfiable.tool_outside_pack.
//   - When NOT provided, the gate falls back to the universal
//     registry-membership check: every referenced tool must exist in
//     TOOL_HANDLERS so a Contract cannot bind to a typo or a tool
//     scheduled for removal. The fallback is the X.4-shipped path; X.5
//     swaps in the per-node check via the options arg.
//
// The gate ALWAYS validates witness predicate satisfiability against the
// X-D12 closed prefix set + JSONPath subset. That guard is invariant
// across X.4 vs X.5: predicates the verifier could not resolve must
// never be persisted, regardless of which derivation backs the per-node
// allowed_tools_for_node[] set.

function assertContractSatisfiable(contract, options = {}) {
  if (!isPlainObject(contract) || typeof contract.contract_hash !== "string") {
    throw new Error("assertContractSatisfiable expects a normalized contract");
  }
  const allowedTools = Array.isArray(options.allowed_tools_for_node)
    ? new Set(options.allowed_tools_for_node)
    : null;

  // Walk production_paths first because a missing tool there is the most
  // common cause of contract_unsatisfiable.
  const seenTools = new Set();
  const unknownTools = [];
  const outsidePack = [];
  for (let i = 0; i < contract.production_paths.length; i += 1) {
    const path = contract.production_paths[i];
    for (let j = 0; j < path.tool_call_pattern.length; j += 1) {
      const tool = path.tool_call_pattern[j].tool;
      seenTools.add(tool);
      const inRegistry = Object.prototype.hasOwnProperty.call(getToolHandlers(), tool);
      if (!inRegistry) {
        unknownTools.push({
          production_path_index: i,
          tool_call_pattern_index: j,
          tool,
        });
      }
      if (allowedTools && !allowedTools.has(tool)) {
        outsidePack.push({
          production_path_index: i,
          tool_call_pattern_index: j,
          tool,
        });
      }
    }
  }
  if (unknownTools.length > 0) {
    const err = new Error(
      `contract_unsatisfiable: production_paths reference ${unknownTools.length} tool(s) absent from the MCP tool registry`,
    );
    err.code = "contract_unsatisfiable";
    err.reason = "tool_not_in_registry";
    err.details = {
      reason: "tool_not_in_registry",
      contract_id: contract.contract_id,
      contract_hash: contract.contract_hash,
      unknown_tools: unknownTools,
    };
    throw err;
  }
  if (outsidePack.length > 0) {
    const err = new Error(
      `contract_unsatisfiable: production_paths reference ${outsidePack.length} tool(s) outside the node's derived pack`,
    );
    err.code = "contract_unsatisfiable";
    err.reason = "tool_outside_pack";
    err.details = {
      reason: "tool_outside_pack",
      contract_id: contract.contract_id,
      contract_hash: contract.contract_hash,
      tools_outside_pack: outsidePack,
      allowed_tools_for_node: Array.from(allowedTools).sort(),
    };
    throw err;
  }

  // Witness-level satisfiability. Two cross-checks:
  //   1. tool_output_match witness MUST reference a tool that also appears
  //      in production_paths (closed correspondence: an expected witness
  //      whose producer is not in any production path is a Contract bug,
  //      not a runtime miss).
  //   2. cli_pack_invoked witness predicates reference an open
  //      cli_pack universe; X.5 ships the closed cli pack set, so X.4
  //      only structural-checks predicate shape (already done in
  //      normalizeContract). No additional witness-level enforcement at
  //      X.4 beyond predicate normalization.
  const toolOutputMismatch = [];
  for (let i = 0; i < contract.witnesses.length; i += 1) {
    const witness = contract.witnesses[i];
    if (witness.kind !== "tool_output_match") continue;
    const tool = witness.predicate.tool;
    if (!seenTools.has(tool)) {
      toolOutputMismatch.push({
        witness_index: i,
        witness_id: witness.id,
        tool,
      });
    }
  }
  if (toolOutputMismatch.length > 0) {
    const err = new Error(
      `contract_unsatisfiable: ${toolOutputMismatch.length} tool_output_match witness(es) reference tools absent from production_paths`,
    );
    err.code = "contract_unsatisfiable";
    err.reason = "tool_output_match_not_in_production_paths";
    err.details = {
      reason: "tool_output_match_not_in_production_paths",
      contract_id: contract.contract_id,
      contract_hash: contract.contract_hash,
      mismatches: toolOutputMismatch,
    };
    throw err;
  }

  return true;
}

// Collect the artifact_ref values surfaced by a Contract's predicates.
// X.5's derivePackForNode uses this to derive `recommended_reads_for_node[]`;
// X.8's prepare_node brief inlines distilled summaries for each ref. The
// result deduplicates and preserves insertion order (left-then-right per
// predicate) so the brief is deterministic.
function collectContractArtifactRefs(contract) {
  if (!isPlainObject(contract) || !Array.isArray(contract.witnesses)) return [];
  const seen = new Set();
  const out = [];
  const push = (ref) => {
    if (typeof ref !== "string" || !ref.trim()) return;
    if (seen.has(ref)) return;
    seen.add(ref);
    out.push(ref);
  };
  for (const witness of contract.witnesses) {
    const pred = witness.predicate;
    if (!isPlainObject(pred)) continue;
    if (witness.kind === "relational_value_match") {
      if (isPlainObject(pred.left)) push(pred.left.artifact_ref);
      if (isPlainObject(pred.right)) push(pred.right.artifact_ref);
    }
    if (witness.kind === "hash_equals") {
      push(pred.artifact_ref);
    }
  }
  return out;
}

// Look up the current state of a TaskGraph node in the materialized
// view. Returns the node's state when present, null otherwise. The
// caller passes the lookup function in so contracts.js doesn't have to
// transitively pull in the materializer (which itself pulls in
// frontier-events) at module-load time; the default lookup uses
// task-graph-materializer.materializeTaskGraph.
let _materializeTaskGraphCache = null;
function defaultLookupNodeState(targetDomain, nodeId) {
  if (_materializeTaskGraphCache == null) {
    _materializeTaskGraphCache = require("./task-graph-materializer.js").materializeTaskGraph;
  }
  const result = _materializeTaskGraphCache(targetDomain, { write: false });
  for (const node of result.document.nodes) {
    if (node.node_id === nodeId) {
      return { state: node.state, kind: node.kind };
    }
  }
  return null;
}

// ─── Append helper (`appendContract`) ────────────────────────────────────
//
// Single sanctioned writer that ties together the schema + satisfiability
// check + the X.1 node-state-machine transition. Returns the
// node.transitioned event so the X.4 attach-contract tool can echo the
// event_id back to the caller for downstream observability.
//
// Validates against the LIVE node state (via the materialized view) so a
// caller can't bypass the proposed → contracted gate by asserting a
// stale from_state. X.1's appendNodeTransition checks only the frozen
// state-transition table; appendContract layers in the per-attempt
// "node is actually in proposed" check that operators rely on.

// States from which `appendContract` may emit a contracted event.
// `proposed` is the default attach path. `failed` is the X.8 re-contract
// path: the operator attaches a refined Contract to a failed node so the
// next prepare_node call can surface the prior failure via the brief's
// `prior_attempt` slice. Other states
// (contracted/ready/dispatched/executed/verified/finalized/abandoned)
// continue to refuse with `node_not_proposed`.
const APPEND_CONTRACT_LEGAL_FROM_STATES = Object.freeze(["proposed", "failed"]);

function appendContract(input, options = {}) {
  if (!isPlainObject(input)) {
    throw new Error("appendContract input must be an object");
  }
  const nodeId = assertTaskGraphNodeId(input.node_id, "node_id");
  const targetDomain = assertNonEmptyString(input.target_domain, "target_domain");
  const contract = normalizeContract(input.contract);
  assertContractSatisfiable(contract, {
    allowed_tools_for_node: input.allowed_tools_for_node,
  });

  // Live state check. The default lookup folds the materialized graph;
  // tests + the attach-contract tool can pass options.lookup_node_state
  // to short-circuit the read or to inject a fixture. The legal from_states
  // are {proposed, failed} per X.8 — the failed re-contract entry lets
  // the operator attach a refined Contract to a failed node without first
  // abandoning it.
  const lookup = typeof options.lookup_node_state === "function"
    ? options.lookup_node_state
    : defaultLookupNodeState;
  const existing = lookup(targetDomain, nodeId);
  const fromState = existing ? existing.state : "proposed";
  if (existing && !APPEND_CONTRACT_LEGAL_FROM_STATES.includes(fromState)) {
    // Surface the same node_not_proposed code the attach-contract tool
    // emits at the outer layer; callers reading both layers see a
    // consistent code regardless of which guard fired first. The message
    // + details surface the alternative legal states explicitly.
    const err = new Error(
      `node_not_proposed: node ${nodeId} is in state "${fromState}"; appendContract requires one of [${APPEND_CONTRACT_LEGAL_FROM_STATES.join(", ")}]`,
    );
    err.code = "node_not_proposed";
    err.details = {
      node_id: nodeId,
      current_state: fromState,
      legal_from_states: APPEND_CONTRACT_LEGAL_FROM_STATES.slice(),
    };
    throw err;
  }

  const source = normalizeOptionalObject(input.source, "source");
  const actor = normalizeOptionalText(input.actor, "actor");

  // X.8 — inline the FULL normalized Contract content in the node.transitioned
  // payload so the X.8 prepare_node brief renderer can recover the Contract
  // without a separate persistence layer. The Contract is summary-grade per
  // X-P9 (invariants ≤ 280 chars each, predicates structured, production
  // paths description-bounded) so inlining stays comfortably under the
  // X-P9 2KB hard cap on payload bodies.
  //
  // When `fromState === "failed"`, the emitted transition is
  // failed → contracted (the X.8 re-contract path). The prior
  // dispatched/executed/failed event chain stays untouched on the ledger
  // so the prepare_node brief's `prior_attempt` slice can surface the
  // prior structured failure_reason payload verbatim.
  const event = appendNodeTransition({
    target_domain: targetDomain,
    node_id: nodeId,
    from_state: fromState,
    to_state: "contracted",
    contract_hash: contract.contract_hash,
    contract,
    ts: input.ts,
    source: source || undefined,
    actor: actor || undefined,
  }, options);

  return {
    event,
    contract,
    from_state: fromState,
  };
}

module.exports = {
  APPEND_CONTRACT_LEGAL_FROM_STATES,
  ARTIFACT_REF_PREFIX_VALUES,
  ARTIFACT_REF_RE,
  INVARIANT_STATEMENT_MAX_CHARS,
  JSONPATH_SELECTOR_RE,
  PRODUCTION_PATH_DESCRIPTION_MAX_CHARS,
  RELATIONAL_MATCH_OP_VALUES,
  SEVERITY_FLOOR_VALUES,
  WITNESS_KIND_VALUES,
  appendContract,
  artifactRefPrefix,
  assertArtifactRef,
  assertContractSatisfiable,
  assertJsonPathSelector,
  collectContractArtifactRefs,
  normalizeContract,
};
