"use strict";

// Synthetic, MCP-authored coverage Contract for a coverage cell. A cell is a
// self-defining obligation ("probe this (element x bug_class x auth_role) cell
// and record coverage with evidence"), not an operator conjecture — so the
// orchestrator-driven MCP layer mints its Contract rather than asking an
// operator to author one per cell. The Contract is real and normalized: it
// travels the existing proposed->contracted->ready->dispatched->executed->
// verified chain unchanged, and bob_finalize_node's mechanicalVerify grades the
// cell against the witness below (a cell with no recorded coverage evidence
// fails — coverage stays falsifiable, the closure-teeth foundation).
//
// Deterministic: the same cell_key mints the same contract_id, so the contract
// (and its hash) dedupe to one per cell.

const { hashCanonicalJson } = require("../verification/verification-contracts.js");

// The evidence kind the cell evaluator records to prove a DYNAMIC probe. Kept
// in the open evidence-ref kind universe (contracts.js leaves it unlocked). The
// cell's witness requires this ref; an attempt that did not dynamically probe
// records none, so the witness is missing -> mechanicalVerify refuses.
const CELL_COVERAGE_EVIDENCE_KIND = "cell_coverage";

// Closure-teeth evidence bar (the closed set of attempt kinds an evaluator
// classifies a cell probe as). A cell CLOSES only via a dynamic_attempt or an
// evidenced_refutation — both record the cell_coverage dynamic-probe evidence
// ref above. A code_review_only attempt records NO such ref, so the cell's
// witness is missing, mechanicalVerify refuses, and the cell fails verification
// (executed->failed, re-contractable) rather than closing. Coverage is therefore
// never satisfiable by code review alone.
const CELL_ATTEMPT_KIND_VALUES = Object.freeze([
  "dynamic_attempt",
  "evidenced_refutation",
  "code_review_only",
]);
const CELL_COVERING_ATTEMPT_KINDS = Object.freeze(["dynamic_attempt", "evidenced_refutation"]);

function isCellCoveringAttempt(attemptKind) {
  return CELL_COVERING_ATTEMPT_KINDS.includes(attemptKind);
}

// The probe tool whose invocation produces the coverage record. Must be in the
// cell's evaluator-shared allowed_tools_for_node so assertContractSatisfiable
// passes against the per-node pack.
const CELL_PROBE_TOOL = "bob_log_coverage";

const INVARIANT_STATEMENT_CAP = 280;

function cap(value, max) {
  const s = typeof value === "string" ? value : "";
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
}

function buildCellCoverageContract({ surfaceId, bugClass, authProfile, cellKey }) {
  if (typeof cellKey !== "string" || cellKey.length === 0) {
    throw new Error("buildCellCoverageContract: cellKey is required");
  }
  const contractId = `cell-cov-${hashCanonicalJson({ cell_key: cellKey }).slice(0, 16)}`;
  const role = authProfile ? `@${authProfile}` : "@anonymous";
  const statement = cap(
    `Cell ${cap(bugClass || "?", 64)}${role} on ${cap(surfaceId || "?", 96)} was probed and `
    + `coverage recorded with a ${CELL_COVERAGE_EVIDENCE_KIND} evidence ref.`,
    INVARIANT_STATEMENT_CAP,
  );
  return {
    contract_id: contractId,
    severity_floor: "low",
    invariants: [{ id: "coverage", statement }],
    witnesses: [{
      id: "probed",
      kind: "evidence_ref_kind_present",
      predicate: { kind: CELL_COVERAGE_EVIDENCE_KIND },
    }],
    production_paths: [{
      description: "Probe the cell and record coverage with an evidence ref.",
      tool_call_pattern: [{ tool: CELL_PROBE_TOOL }],
    }],
  };
}

module.exports = {
  CELL_COVERAGE_EVIDENCE_KIND,
  CELL_PROBE_TOOL,
  CELL_ATTEMPT_KIND_VALUES,
  CELL_COVERING_ATTEMPT_KINDS,
  isCellCoveringAttempt,
  buildCellCoverageContract,
};
