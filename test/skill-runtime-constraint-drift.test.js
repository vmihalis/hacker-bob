"use strict";

// Cycle Y.8 — check:skill-runtime-constraint-drift test surface.
//
// Asserts:
//   * BINARY_INTERNAL and BOB_OWNED registries are Object.freeze'd
//     closed lists.
//   * The BINARY_INTERNAL entry cites investigation w0b0v41zw H2
//     (Reviewer-MUST-confirm bullet for Y.8).
//   * Each registry entry fires on its drift fixture and is silent on
//     the curated clean fixture.
//   * The check exits zero against the real rendered Claude surface.
//   * FP rate ≤ 2% on the curated runtime-constraint corpus.

const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("path");

const ROOT = path.join(__dirname, "..");
const FIXTURE_DIR = path.join(ROOT, "test", "fixtures", "skill-parser");

const {
  BINARY_INTERNAL,
  BOB_OWNED,
  evaluateBodyAgainstConstraints,
} = require("../mcp/lib/runtime-constraints.js");
const {
  runCheck,
  checkDocument,
} = require("../scripts/check-skill-runtime-constraint-drift.js");
const { readSkillFile } = require("../scripts/lib/skill-parser.js");

function loadFixture(name) {
  return readSkillFile(path.join(FIXTURE_DIR, name));
}

test("BINARY_INTERNAL + BOB_OWNED are Object.freeze'd closed lists", () => {
  assert.ok(Object.isFrozen(BINARY_INTERNAL), "BINARY_INTERNAL must be frozen");
  assert.ok(Object.isFrozen(BOB_OWNED), "BOB_OWNED must be frozen");
  for (const entry of BINARY_INTERNAL) {
    assert.ok(Object.isFrozen(entry), `entry ${entry.id} must be frozen`);
  }
  for (const entry of BOB_OWNED) {
    assert.ok(Object.isFrozen(entry), `entry ${entry.id} must be frozen`);
  }
});

test("BINARY_INTERNAL — canonical entry cites investigation w0b0v41zw H2 (Reviewer MUST confirm)", () => {
  const subagentEntry = BINARY_INTERNAL.find(
    (entry) => entry.id === "binary_internal_subagent_write_relative_path",
  );
  assert.ok(subagentEntry, "expected binary_internal_subagent_write_relative_path entry");
  assert.match(
    subagentEntry.evidence,
    /investigation w0b0v41zw H2/,
    "evidence MUST cite investigation w0b0v41zw H2 per Y.8 Reviewer bullet",
  );
});

test("BOB_OWNED — every entry cites its hook source", () => {
  for (const entry of BOB_OWNED) {
    assert.match(entry.source, /^\.claude\/hooks\//, `entry ${entry.id} must cite a .claude/hooks/ source`);
    assert.ok(typeof entry.remediation === "string" && entry.remediation.length > 0, `entry ${entry.id} must include remediation`);
  }
});

test("runtime-constraint-violation fixture — BINARY_INTERNAL subagent-write regex fires", () => {
  const document = loadFixture("runtime-constraint-violation.md");
  const violations = checkDocument(document);
  const hit = violations.find((v) => v.constraint_id === "binary_internal_subagent_write_relative_path");
  assert.ok(hit, `expected binary_internal violation, got ${JSON.stringify(violations)}`);
  assert.equal(hit.source_kind, "binary_internal");
});

test("runtime-constraint-bash-guard fixture — BOB_OWNED session-read-guard fires", () => {
  const document = loadFixture("runtime-constraint-bash-guard.md");
  const violations = checkDocument(document);
  const hit = violations.find((v) => v.constraint_id === "bob_owned_session_read_guard_sensitive_files");
  assert.ok(hit, `expected bob_owned session-read-guard violation, got ${JSON.stringify(violations)}`);
  assert.equal(hit.source_kind, "bob_owned");
});

test("runtime-constraint-clean fixture — zero violations", () => {
  const document = loadFixture("runtime-constraint-clean.md");
  const violations = checkDocument(document);
  assert.deepEqual(violations, [], `unexpected violations: ${JSON.stringify(violations, null, 2)}`);
});

test("real rendered Claude surface — exits zero", () => {
  const result = runCheck({ root: ROOT });
  assert.ok(result.files_inspected.length >= 3, "expected to discover ≥3 rendered files");
  assert.deepEqual(
    result.violations,
    [],
    `unexpected runtime-constraint drift in real Claude surface: ${result.violations
      .map((v) => `${v.file}:${v.line} ${v.constraint_id}`)
      .join("\n  ")}`,
  );
});

test("FP rate ≤2% on curated runtime-constraint corpus", () => {
  const cleanFixtures = ["runtime-constraint-clean.md", "clean-skill.md", "non-state-section.md"];
  let falsePositives = 0;
  for (const fixture of cleanFixtures) {
    const document = loadFixture(fixture);
    const violations = checkDocument(document);
    falsePositives += violations.length;
  }
  const fpRate = falsePositives / cleanFixtures.length;
  assert.ok(fpRate <= 0.02, `FP rate ${fpRate} exceeds budget 0.02 (${falsePositives} false positives across ${cleanFixtures.length} clean fixtures)`);
});

test("evaluateBodyAgainstConstraints is pure over its body input", () => {
  const body = "Bash(\"cat ~/hacker-bob-sessions/example.com/auth.json\")";
  const first = evaluateBodyAgainstConstraints(body, { filePath: "x.md" });
  const second = evaluateBodyAgainstConstraints(body, { filePath: "x.md" });
  assert.deepEqual(first, second);
  assert.ok(first.length >= 1);
});
