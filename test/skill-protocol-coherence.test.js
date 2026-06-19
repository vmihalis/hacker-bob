"use strict";

// Cycle Y.8 — check:skill-protocol-coherence test surface.
//
// Asserts:
//   * The shared parser IR (Y-D16) produces the expected state-block
//     shape for the rendered orchestrator SKILL.md.
//   * Each of the three coherence dimensions (D1 structural
//     containment, D2 registry coherence, D3 token-registry coherence)
//     fires on its dedicated fixture and is silent on the curated
//     clean fixtures.
//   * The check exits zero against the real rendered surface
//     (`.claude/skills/**/SKILL.md` + `.claude/agents/**/*.md`).
//   * FP rate against the curated corpus is ≤ 2% (Reviewer gate per
//     Y.8 Operator Discipline bullet).
//   * The generator (`scripts/lib/claude-role-renderer.js` →
//     `injectSchemaRefDirectives`) auto-injects the markers so the
//     check passes without hand-authoring directives.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");

const ROOT = path.join(__dirname, "..");
const FIXTURE_DIR = path.join(ROOT, "test", "fixtures", "skill-parser");

const {
  parseSkillText,
  readSkillFile,
  discoverRoleMarkdownFiles,
  WRITE_TOOL_TOKEN_PATTERN,
  SCHEMA_REF_PATTERN,
} = require("../scripts/lib/skill-parser.js");
const {
  runCheck,
  checkDocument,
} = require("../scripts/check-skill-protocol-coherence.js");

function loadFixture(name) {
  return readSkillFile(path.join(FIXTURE_DIR, name));
}

function violationsForFixture(name) {
  const document = loadFixture(name);
  return checkDocument(document);
}

test("parser IR — STATE blocks open on H2 STATE: heading and close on next H2", () => {
  const text = [
    "## Preamble", // section
    "preamble body", "",
    "## STATE: SETUP",
    "setup body line 1",
    "setup body line 2", "",
    "## STATE: REPORT",
    "report body", "",
    "## Outro", // section
    "outro body",
  ].join("\n");
  const document = parseSkillText(text);
  const stateBlocks = document.blocks.filter((b) => b.kind === "state");
  assert.equal(stateBlocks.length, 2);
  assert.equal(stateBlocks[0].name, "SETUP");
  assert.equal(stateBlocks[1].name, "REPORT");
  assert.ok(stateBlocks[0].body.includes("setup body line 1"));
  assert.ok(!stateBlocks[0].body.includes("report body"));
});

test("parser IR — write-tool tokens inside fenced code blocks tagged in_code_block: true", () => {
  const text = [
    "## STATE: REPORT",
    "Call `bob_compose_report({})`.",
    "```json",
    "{ \"tool\": \"bob_write_chain_attempt\" }",
    "```",
  ].join("\n");
  const document = parseSkillText(text);
  const state = document.blocks.find((b) => b.kind === "state");
  const tokens = state.tokens.write_tools;
  const inline = tokens.find((t) => t.token === "bob_compose_report");
  const fenced = tokens.find((t) => t.token === "bob_write_chain_attempt");
  assert.ok(inline);
  assert.equal(inline.in_code_block, false);
  assert.ok(fenced);
  assert.equal(fenced.in_code_block, true);
});

test("parser IR — schema_ref and precondition directives parsed", () => {
  const text = [
    "## STATE: SETUP",
    "<!-- @schema_ref: bob_compose_report -->",
    "<!-- @precondition: partial_surfaces_drained -->",
  ].join("\n");
  const document = parseSkillText(text);
  const block = document.blocks.find((b) => b.kind === "state");
  assert.equal(block.tokens.schema_refs.length, 1);
  assert.equal(block.tokens.schema_refs[0].token, "bob_compose_report");
  assert.equal(block.tokens.preconditions.length, 1);
  assert.equal(block.tokens.preconditions[0].token, "partial_surfaces_drained");
});

test("D1 structural containment — fires on STATE block missing @schema_ref", () => {
  const violations = violationsForFixture("drift-missing-schema-ref.md");
  const d1 = violations.filter((v) => v.dimension === "D1_structural_containment");
  assert.ok(d1.length >= 1, `expected D1 violation, got ${JSON.stringify(violations)}`);
  assert.equal(d1[0].token, "bob_compose_report");
});

test("D2 registry coherence — fires on stale @schema_ref directive", () => {
  const violations = violationsForFixture("drift-stale-schema-ref.md");
  const d2 = violations.filter((v) => v.dimension === "D2_registry_coherence");
  assert.ok(d2.length >= 1, `expected D2 violation, got ${JSON.stringify(violations)}`);
  assert.equal(d2[0].token, "bob_write_phantom_tool_that_was_retired");
});

test("D3 token registry — fires on unknown write-tool token in STATE block", () => {
  const violations = violationsForFixture("drift-unknown-write-tool.md");
  const d3 = violations.filter((v) => v.dimension === "D3_token_registry");
  assert.ok(d3.length >= 1, `expected D3 violation, got ${JSON.stringify(violations)}`);
  assert.equal(d3[0].token, "bob_write_typo_handoff");
});

test("clean fixture — zero violations across all three dimensions", () => {
  const violations = violationsForFixture("clean-skill.md");
  assert.deepEqual(violations, [], `unexpected violations: ${JSON.stringify(violations, null, 2)}`);
});

test("code-fenced tokens — no D1 violation when the only write-tool occurrence is inside ```", () => {
  const violations = violationsForFixture("code-fenced-write-token.md");
  assert.deepEqual(violations, []);
});

test("non-STATE section — tokens in Hard Rules / asset-map sections do not fire D1", () => {
  const violations = violationsForFixture("non-state-section.md");
  assert.deepEqual(violations, []);
});

test("real rendered Claude surface — exits zero", () => {
  const result = runCheck({ root: ROOT });
  assert.ok(result.files_inspected.length >= 3, "expected to discover ≥3 rendered files");
  assert.deepEqual(
    result.violations,
    [],
    `unexpected drift in real Claude surface: ${result.violations
      .map((v) => `${v.file}:${v.line} ${v.dimension} ${v.token}`)
      .join("\n  ")}`,
  );
});

test("FP rate ≤2% on curated corpus — clean fixtures produce zero false positives", () => {
  // The FP rate predicate: count fixtures whose advertised category is
  // "clean" (TRUE NEGATIVE) and assert the check fires zero violations
  // on them. With three clean fixtures (`clean-skill.md`,
  // `code-fenced-write-token.md`, `non-state-section.md`) and zero
  // unexpected violations, FP rate = 0/3 = 0% ≤ 2%.
  const cleanFixtures = [
    "clean-skill.md",
    "code-fenced-write-token.md",
    "non-state-section.md",
  ];
  let falsePositives = 0;
  for (const fixture of cleanFixtures) {
    const violations = violationsForFixture(fixture);
    if (violations.length > 0) {
      falsePositives += violations.length;
    }
  }
  const fpRate = falsePositives / cleanFixtures.length;
  assert.ok(fpRate <= 0.02, `FP rate ${fpRate} exceeds budget 0.02 (${falsePositives} false positives across ${cleanFixtures.length} clean fixtures)`);
});

test("discoverRoleMarkdownFiles — picks up rendered SKILL.md + agent .md files", () => {
  const files = discoverRoleMarkdownFiles(ROOT);
  const relative = files.map((f) => path.relative(ROOT, f));
  assert.ok(
    relative.includes(path.join(".claude", "skills", "bob-evaluate-runner", "SKILL.md")),
    `expected to find bob-evaluate-runner SKILL.md, got ${relative.join(", ")}`,
  );
  assert.ok(
    relative.some((p) => p.startsWith(path.join(".claude", "agents"))),
    `expected to find .claude/agents/ entries`,
  );
  // The check operates on the rendered surface only — source role
  // markdown under prompts/roles/ is NOT in the discovery set.
  assert.ok(
    !relative.some((p) => p.startsWith(path.join("prompts", "roles"))),
    `prompts/roles/ should NOT be discovered (rendered surface only)`,
  );
});

test("generator auto-injection — re-rendering populates @schema_ref directives in REPORT block", () => {
  const skillPath = path.join(ROOT, ".claude", "skills", "bob-evaluate-runner", "SKILL.md");
  const document = readSkillFile(skillPath);
  const reportBlock = document.blocks.find((b) => b.kind === "state" && b.name === "REPORT");
  assert.ok(reportBlock, "expected REPORT STATE block in rendered SKILL.md");
  const writeTokensOutsideCode = reportBlock.tokens.write_tools
    .filter((t) => !t.in_code_block)
    .map((t) => t.token);
  const schemaRefTokens = reportBlock.tokens.schema_refs.map((r) => r.token);
  for (const writeToken of new Set(writeTokensOutsideCode)) {
    assert.ok(
      schemaRefTokens.includes(writeToken),
      `expected @schema_ref directive for ${writeToken} in REPORT block; got [${schemaRefTokens.join(", ")}]`,
    );
  }
});
