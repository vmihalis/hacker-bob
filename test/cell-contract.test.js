const test = require("node:test");
const assert = require("node:assert/strict");

const { normalizeContract } = require("../mcp/lib/contracts.js");
const { mechanicalVerify } = require("../mcp/lib/contract-verifier.js");
const {
  buildCellCoverageContract,
  CELL_COVERAGE_EVIDENCE_KIND,
  CELL_ATTEMPT_KIND_VALUES,
  isCellCoveringAttempt,
} = require("../mcp/lib/cell-contract.js");

const CELL = {
  surfaceId: "surface:billing",
  bugClass: "idor",
  authProfile: "admin",
  cellKey: JSON.stringify(["surface:billing", "", "", "idor", "admin"]),
};

test("the synthetic cell contract is well-formed (normalizes + binds a stable hash)", () => {
  const c1 = normalizeContract(buildCellCoverageContract(CELL));
  const c2 = normalizeContract(buildCellCoverageContract(CELL));
  assert.equal(c1.contract_hash, c2.contract_hash, "deterministic from cell_key");
  assert.equal(c1.severity_floor, "low");
  assert.equal(c1.witnesses.length, 1);
  assert.equal(c1.witnesses[0].kind, "evidence_ref_kind_present");
  assert.equal(c1.witnesses[0].predicate.kind, CELL_COVERAGE_EVIDENCE_KIND);
});

test("D2 evidence bar: a cell closes ONLY with a dynamic-probe evidence ref, never code-review-only", () => {
  const contract = normalizeContract(buildCellCoverageContract(CELL));
  // A dynamic probe / evidenced refutation records the cell_coverage ref -> verified.
  const dynamic = mechanicalVerify(contract, { evidence_refs: [{ kind: CELL_COVERAGE_EVIDENCE_KIND }] }, {});
  assert.equal(dynamic.satisfied, true);
  // A code-review-only attempt records NO probe ref (just a prose finding) ->
  // the witness is missing -> mechanicalVerify refuses -> the cell cannot close.
  const codeReview = mechanicalVerify(contract, { evidence_refs: [], findings: [{ note: "looks fixed" }] }, {});
  assert.equal(codeReview.satisfied, false);
  assert.ok(codeReview.missing.length > 0);
});

test("the attempt-kind enum classifies covering vs non-covering attempts", () => {
  assert.deepEqual(
    CELL_ATTEMPT_KIND_VALUES.slice().sort(),
    ["code_review_only", "dynamic_attempt", "evidenced_refutation"],
  );
  assert.equal(isCellCoveringAttempt("dynamic_attempt"), true);
  assert.equal(isCellCoveringAttempt("evidenced_refutation"), true);
  assert.equal(isCellCoveringAttempt("code_review_only"), false);
});
