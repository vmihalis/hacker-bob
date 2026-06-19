"use strict";

const {
  assertEnumValue,
} = require("./validation.js");

// Plane T cycle T.4 — `browser_behavior_probe` is the browser-shaped sibling
// of `behavior_probe`. Distinct enum value (not an option/flag on the HTTP
// lens) so the scheduler, brief renderer, and pack-affinity filtering can
// dispatch unambiguously. Order is insertion-stable: it slots next to
// `behavior_probe` so a human reading the enum sees the HTTP/browser pair
// together.
//
// Plane O cycle O.6 — three OSS-shaped lenses extend the enum:
//   `code_surface_scout` — initial enumeration over a repo-bound target.
//      Distinct from `surface_scout` because it triggers the `repo_workflow`
//      brief slice (suppressing the curl-shaped HTTP playbook) under the
//      `profile: "oss"` slice registry.
//   `taint_trace` — call-graph traversal from attacker-controlled input to
//      dangerous sink. Subsumes dependency-audit work (a dep-audit is itself
//      a taint trace from manifest → known CVE → reachable call site).
//   `fuzz_run` — bounded fuzz / ASAN / sanitizer harness inside docker.
//      Distinct lens because it gates the non-dry-run docker path.
// 13 total. Reviewer-B parsimony: dependency_audit and reproduction_in_container
// are intentionally NOT added (audit collapses into taint_trace; in-container
// reproduction reuses existing `reproduction_check`).
const TASK_LENSES = Object.freeze([
  "seed_mapping",
  "surface_scout",
  "behavior_probe",
  "browser_behavior_probe",
  "control_check",
  "claim_development",
  "impact_correlation",
  "reproduction_check",
  "evidence_capture",
  "coverage_closeout",
  "code_surface_scout",
  "taint_trace",
  "fuzz_run",
]);

function normalizeTaskLens(value, fieldName = "lens") {
  return assertEnumValue(value, TASK_LENSES, fieldName);
}

function isTaskLens(value) {
  return TASK_LENSES.includes(value);
}

module.exports = {
  TASK_LENSES,
  isTaskLens,
  normalizeTaskLens,
};
