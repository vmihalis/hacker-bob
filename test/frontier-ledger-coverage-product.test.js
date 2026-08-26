"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const {
  buildClassLatticeCoverageProduct,
  structuralClassForBugClass,
} = require("../mcp/core/frontier/coverage.js");

function planningKey(bugClass, authProfile = "") {
  return JSON.stringify([bugClass, authProfile]);
}

test("frontier-ledger: soft, forged, and unknown class rows do not close coverage", () => {
  const product = buildClassLatticeCoverageProduct({
    target_domain: "frontier-ledger.example.com",
    surface_id: "surface:api",
    expected_cells: [
      {
        surface_id: "surface:api",
        bug_class: "idor",
        auth_profile: "owner",
        planning_key: planningKey("idor", "owner"),
      },
      {
        surface_id: "surface:api",
        bug_class: "race_condition",
        auth_profile: "owner",
        planning_key: planningKey("race_condition", "owner"),
      },
      {
        surface_id: "surface:api",
        bug_class: "observed_invariant_canary_v1",
        auth_profile: "",
        planning_key: planningKey("observed_invariant_canary_v1", ""),
      },
    ],
    coverage_records: [
      {
        surface_id: "surface:api",
        bug_class: "idor",
        auth_profile: "owner",
        status: "promising",
        evidence_summary: "soft candidate only",
        next_step: "needs signed differential",
      },
      {
        surface_id: "surface:api",
        bug_class: "race_condition",
        auth_profile: "owner",
        status: "tested",
        evidence_summary: "forged unknown-class close attempt",
      },
      {
        surface_id: "surface:api",
        bug_class: "observed_invariant_canary_v1",
        auth_profile: "",
        status: "proof_closed",
        evidence_summary: "unsupported coverage status forged into the log",
      },
    ],
  });

  const byClass = new Map(product.rows.map((row) => [row.class_id, row]));
  assert.equal(byClass.get("idor").status, "not_tested", "soft/promising evidence is an explicit untested row");
  assert.equal(byClass.get("race_condition").status, "held", "unknown class holds even when a forged tested row exists");
  assert.equal(byClass.get("observed_invariant_canary_v1").status, "held", "unsupported proof_closed log input is refused");
  assert.equal(product.counts_by_status.tested || 0, 0);
  assert.equal(product.counts_by_status.proof_closed || 0, 0);
  assert.equal(product.gap_count, 3);
  assert.match(product.coverage_product_hash, /^[a-f0-9]{64}$/);
});

test("frontier-ledger: coverage product enumerates tested, blocked, and not-tested lattice rows", () => {
  const product = buildClassLatticeCoverageProduct({
    target_domain: "frontier-ledger.example.com",
    surface_id: "surface:api",
    expected_cells: [
      { surface_id: "surface:api", bug_class: "idor", auth_profile: "owner", planning_key: planningKey("idor", "owner") },
      { surface_id: "surface:api", bug_class: "ssrf", auth_profile: "", planning_key: planningKey("ssrf", "") },
      { surface_id: "surface:api", bug_class: "token_entropy", auth_profile: "", planning_key: planningKey("token_entropy", "") },
    ],
    coverage_records: [
      { surface_id: "surface:api", bug_class: "idor", auth_profile: "owner", status: "tested", evidence_summary: "executed probe" },
      { surface_id: "surface:api", bug_class: "ssrf", auth_profile: "", status: "blocked", evidence_summary: "egress profile unavailable" },
    ],
  });

  const byClass = new Map(product.rows.map((row) => [row.class_id, row]));
  assert.equal(byClass.get("idor").status, "tested");
  assert.equal(byClass.get("ssrf").status, "blocked");
  assert.equal(byClass.get("token_entropy").status, "held");
  assert.equal(structuralClassForBugClass("token_entropy"), "entropy");
  assert.ok(product.coverage_gaps.some((gap) => gap.class_id === "ssrf" && gap.status === "blocked"));
  assert.ok(product.coverage_gaps.some((gap) => gap.class_id === "token_entropy" && gap.status === "held"));
});
