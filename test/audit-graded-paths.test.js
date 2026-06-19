"use strict";

// Y.3 Stage b — AUDIT_GRADED_PATHS registry. Asserts:
//   * AUDIT_GRADED_PATHS is Object.freeze'd
//   * Scratch artifacts (subdomains.txt, attack_surface.json, etc.) are NOT
//     in the list (Y-R22 — scope intentionally narrow)
//   * isAuditGradedPath correctly classifies known audit-graded basenames,
//     directory prefixes (verification-attempts/), and handoff filename patterns
//   * Non-session paths return false (defensive)

const test = require("node:test");
const assert = require("node:assert/strict");
const os = require("os");
const path = require("path");

const {
  AUDIT_GRADED_PATHS,
  isAuditGradedPath,
  sessionDir,
} = require("../mcp/lib/paths.js");

test("AUDIT_GRADED_PATHS is frozen at the outer + inner levels", () => {
  assert.equal(Object.isFrozen(AUDIT_GRADED_PATHS), true);
  assert.equal(Object.isFrozen(AUDIT_GRADED_PATHS.basenames), true);
  assert.equal(Object.isFrozen(AUDIT_GRADED_PATHS.relative_dirs), true);
  assert.equal(Object.isFrozen(AUDIT_GRADED_PATHS.filename_patterns), true);
});

test("audit-graded basenames include the canonical hash-bound artifacts", () => {
  const required = [
    "report.md",
    "chains.md",
    "evidence-packs.md",
    "proof-bundles.md",
    "proof-bundles.json",
    "grade.md",
    "claim-freeze.json",
    "report-amendments.jsonl",
    "diff-impact.json",
  ];
  for (const name of required) {
    assert.ok(
      AUDIT_GRADED_PATHS.basenames.includes(name),
      `${name} must be in AUDIT_GRADED_PATHS.basenames`,
    );
  }
});

test("scratch artifacts are NOT audit-graded (Y-R22 narrow scope)", () => {
  const scratch = [
    "subdomains.txt",
    "attack_surface.json",
    "family_seeds.txt",
    "surface-discovery-tools.txt",
  ];
  for (const name of scratch) {
    assert.ok(
      !AUDIT_GRADED_PATHS.basenames.includes(name),
      `${name} must NOT be in AUDIT_GRADED_PATHS (scratch remains agent-writable)`,
    );
  }
});

test("isAuditGradedPath classifies report.md as audit-graded under the session dir", () => {
  const domain = "example.com";
  const reportPath = path.join(sessionDir(domain), "report.md");
  assert.equal(isAuditGradedPath(reportPath, domain), true);
});

test("isAuditGradedPath classifies subdomains.txt as NOT audit-graded", () => {
  const domain = "example.com";
  const scratchPath = path.join(sessionDir(domain), "subdomains.txt");
  assert.equal(isAuditGradedPath(scratchPath, domain), false);
});

test("isAuditGradedPath matches handoff-w*-a*.{json,md} filename patterns", () => {
  const domain = "example.com";
  const handoffJson = path.join(sessionDir(domain), "handoff-w1-a3.json");
  const handoffMd = path.join(sessionDir(domain), "handoff-w12-a7.md");
  assert.equal(isAuditGradedPath(handoffJson, domain), true);
  assert.equal(isAuditGradedPath(handoffMd, domain), true);
  // Non-matching shapes (missing wave or agent) must return false.
  assert.equal(isAuditGradedPath(path.join(sessionDir(domain), "handoff-w1.json"), domain), false);
});

test("isAuditGradedPath matches verification-attempts/ directory prefix", () => {
  const domain = "example.com";
  const attemptFile = path.join(sessionDir(domain), "verification-attempts", "att-1.json");
  assert.equal(isAuditGradedPath(attemptFile, domain), true);
});

test("isAuditGradedPath returns false for paths outside the session dir", () => {
  const domain = "example.com";
  const outsidePath = path.join(os.homedir(), "report.md");
  assert.equal(isAuditGradedPath(outsidePath, domain), false);
});

test("isAuditGradedPath returns false for invalid inputs (defensive)", () => {
  assert.equal(isAuditGradedPath(null, "x"), false);
  assert.equal(isAuditGradedPath("/tmp/report.md", null), false);
  assert.equal(isAuditGradedPath("", "x"), false);
});
