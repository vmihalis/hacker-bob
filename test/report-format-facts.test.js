"use strict";

// Durability guard for the verified `bob_compose_report` format facts.
//
// The reporter role prompt carries a block of facts about bob's OWN report.md
// format — the frozen `SECTION_KINDS` enum, the `SECTION_PROSE_MAX`
// split-not-truncate rule, the auto-filled `section-N` behaviour, and the
// heading/prose safety footgun that mints phantom findings. Those facts were
// derived by reading `mcp/lib/tools/compose-report.js` and
// `mcp/lib/audit-report-parser.js` and confirmed by execution.
//
// Why this file exists: the renderer-parity tests in
// `test/prompt-contracts.test.js` compare each generated artifact against
// renderer output. That is exactly the blind spot that file documents at
// :810-813 — delete the block from the SOURCE, regenerate, and parity still
// passes because renderer output and on-disk file stay in sync, both missing
// it. Parity proves agreement, not presence. These tests assert PRESENCE, in
// the source and in every generated mirror.
//
// Vacuity discipline: every collection walked here has a hardcoded floor, and
// the marker assertion is backed by a mutation control (remove the block from
// the source text and each marker's count must strictly drop), so a passing
// run cannot mean "the loop found nothing to check".

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.join(__dirname, "..");

function read(relativePath) {
  return fs.readFileSync(path.join(ROOT, relativePath), "utf8");
}

function countOccurrences(haystack, needle) {
  return haystack.split(needle).length - 1;
}

// The SOURCE of truth for the reporter role prompt. Editing a generated
// artifact instead of this file is the defect this guard was written after.
const SOURCE = "prompts/roles/reporter.md";

// Every generated artifact the role renderers mirror the reporter prompt into.
// Hardcoded rather than globbed: a glob over a renamed or emptied directory
// would satisfy the loops below vacuously.
const ARTIFACTS = Object.freeze([
  ".claude/agents/report-writer.md",
  "adapters/codex/skills/bob-evaluate/SKILL.md",
  "adapters/kimi/skills/bob-evaluate/SKILL.md",
]);
const ARTIFACT_FLOOR = 3;

// A string that predates the format-facts block and is expected in the
// reporter prompt regardless of it. Its presence proves the test read the file
// it meant to read, so a marker miss below means "absent", not "wrong path".
const SOURCE_POSITIVE_CONTROL = "bob_compose_report";

// One marker per fact the block must keep carrying. Each was absent from the
// reporter prompt before this work landed, so none of them can pass inertly.
const REQUIRED_MARKERS = Object.freeze([
  "SECTION_KINDS",             // frozen eight-value sections[].kind enum
  "PROVENANCE_VALUES",         // frozen sections[].provenance enum
  "SECTION_PROSE_MAX",         // 4096 cap, refused not truncated -> split yourself
  "section-N",                 // auto-filled section_id from the array index
  "HEADING AND PROSE SAFETY",  // the phantom-finding footgun block
  "renderMarkdown",            // the unescaped interpolation surface
  "audit-report-parser.js",    // the parser that turns a stray H2 into a finding
  "buildCvssAnnotations",      // session-state H2, not a compose argument
  "readAmendments",            // append-only amendment ledger, not a compose argument
]);
const MARKER_FLOOR = 9;

// The block is delimited by two lines that occur exactly once in the source.
const BLOCK_START = "SHAPE CONSTRAINTS on `bob_compose_report`";
const BLOCK_END = "- Never read an empty `parser_warnings`";
const BLOCK_BYTE_FLOOR = 4096;
const BLOCK_LINE_FLOOR = 20;

// Symbols the block cites by name, and the file each must still resolve in.
// If compose-report.js is refactored out from under the prose, this goes red
// instead of the prompt quietly documenting a function that no longer exists.
const CITED_SYMBOLS = Object.freeze([
  Object.freeze({ file: "mcp/tools/compose-report.js", symbol: "SECTION_KINDS" }),
  Object.freeze({ file: "mcp/tools/compose-report.js", symbol: "PROVENANCE_VALUES" }),
  Object.freeze({ file: "mcp/tools/compose-report.js", symbol: "SECTION_PROSE_MAX" }),
  Object.freeze({ file: "mcp/tools/compose-report.js", symbol: "function renderMarkdown" }),
  Object.freeze({ file: "mcp/tools/compose-report.js", symbol: "function normalizeSection" }),
  Object.freeze({ file: "mcp/tools/compose-report.js", symbol: "function buildCvssAnnotations" }),
  Object.freeze({ file: "mcp/tools/compose-report.js", symbol: "function readAmendments" }),
  Object.freeze({ file: "mcp/core/audit-report-parser.js", symbol: "warnings.push" }),
  Object.freeze({ file: "mcp/core/io/paths.js", symbol: "function assertSafeDomain" }),
  Object.freeze({ file: "mcp/core/io/validation.js", symbol: "function assertNonEmptyString" }),
]);
const CITED_SYMBOL_FLOOR = 10;

function extractBlock(text) {
  const start = text.indexOf(BLOCK_START);
  assert.notEqual(start, -1, `${SOURCE} lost the format-facts block opener: ${BLOCK_START}`);
  assert.equal(
    countOccurrences(text, BLOCK_START), 1,
    `${BLOCK_START} must occur exactly once so the block boundary is unambiguous`,
  );
  const endAnchor = text.indexOf(BLOCK_END);
  assert.notEqual(endAnchor, -1, `${SOURCE} lost the format-facts block closer: ${BLOCK_END}`);
  assert.equal(
    countOccurrences(text, BLOCK_END), 1,
    `${BLOCK_END} must occur exactly once so the block boundary is unambiguous`,
  );
  assert.ok(endAnchor > start, "the format-facts block closer must follow its opener");
  const endOfLine = text.indexOf("\n", endAnchor);
  return text.slice(start, endOfLine === -1 ? text.length : endOfLine);
}

test("reporter role SOURCE carries the verified bob_compose_report format facts", () => {
  const source = read(SOURCE);

  // Positive control first: prove we read the reporter prompt at all.
  assert.ok(
    source.includes(SOURCE_POSITIVE_CONTROL),
    `${SOURCE} does not contain ${SOURCE_POSITIVE_CONTROL}; the test is reading the wrong file`,
  );

  assert.ok(
    REQUIRED_MARKERS.length >= MARKER_FLOOR,
    `expected at least ${MARKER_FLOOR} markers, have ${REQUIRED_MARKERS.length}`,
  );

  let checked = 0;
  const missing = [];
  for (const marker of REQUIRED_MARKERS) {
    assert.equal(typeof marker, "string");
    assert.ok(marker.length > 0, "an empty marker would match every document");
    if (!source.includes(marker)) missing.push(marker);
    checked += 1;
  }
  assert.deepEqual(missing, [], `${SOURCE} lost format facts`);
  assert.equal(checked, REQUIRED_MARKERS.length);
  assert.ok(checked >= MARKER_FLOOR, `marker floor: checked ${checked}`);
});

test("every generated reporter artifact mirrors the format-facts block byte-identically", () => {
  const source = read(SOURCE);
  const block = extractBlock(source);

  assert.ok(
    block.length >= BLOCK_BYTE_FLOOR,
    `format-facts block collapsed to ${block.length} bytes (floor ${BLOCK_BYTE_FLOOR})`,
  );
  const blockLines = block.split("\n").length;
  assert.ok(
    blockLines >= BLOCK_LINE_FLOOR,
    `format-facts block collapsed to ${blockLines} lines (floor ${BLOCK_LINE_FLOOR})`,
  );

  assert.ok(
    ARTIFACTS.length >= ARTIFACT_FLOOR,
    `expected at least ${ARTIFACT_FLOOR} generated artifacts, have ${ARTIFACTS.length}`,
  );

  let mirrored = 0;
  for (const artifact of ARTIFACTS) {
    const text = read(artifact);
    assert.ok(
      text.includes(SOURCE_POSITIVE_CONTROL),
      `${artifact} does not contain ${SOURCE_POSITIVE_CONTROL}; the test is reading the wrong file`,
    );
    assert.ok(
      text.includes(block),
      `${artifact} does not carry the format-facts block byte-identically; regenerate it from ${SOURCE}`,
    );
    for (const marker of REQUIRED_MARKERS) {
      assert.ok(text.includes(marker), `${artifact} lost format fact: ${marker}`);
    }
    mirrored += 1;
  }
  assert.equal(mirrored, ARTIFACTS.length);
  assert.ok(mirrored >= ARTIFACT_FLOOR, `artifact floor: mirrored ${mirrored}`);
});

test("removing the format-facts block from the source strictly drops every marker (mutation control)", () => {
  // Without this, a marker that happened to appear elsewhere in the prompt
  // would keep the presence test green after the block was deleted. Prove each
  // marker is carried BY the block: excise it and every count must fall.
  const source = read(SOURCE);
  const block = extractBlock(source);
  const mutated = source.replace(block, "");
  assert.ok(mutated.length < source.length, "mutation control failed to excise the block");

  let dropped = 0;
  const survived = [];
  for (const marker of REQUIRED_MARKERS) {
    const before = countOccurrences(source, marker);
    const after = countOccurrences(mutated, marker);
    assert.ok(before > 0, `marker ${marker} is absent from ${SOURCE}`);
    if (!(after < before)) survived.push(`${marker} (${before} -> ${after})`);
    dropped += 1;
  }
  assert.deepEqual(survived, [], "these markers do not depend on the format-facts block");
  assert.equal(dropped, REQUIRED_MARKERS.length);
  assert.ok(dropped >= MARKER_FLOOR, `mutation floor: ${dropped}`);
});

test("the format-facts block cites symbols that still resolve in the code it documents", () => {
  assert.ok(
    CITED_SYMBOLS.length >= CITED_SYMBOL_FLOOR,
    `expected at least ${CITED_SYMBOL_FLOOR} cited symbols, have ${CITED_SYMBOLS.length}`,
  );

  let resolved = 0;
  const unresolved = [];
  for (const entry of CITED_SYMBOLS) {
    const text = read(entry.file);
    assert.ok(text.length > 0, `${entry.file} is empty`);
    if (!text.includes(entry.symbol)) unresolved.push(`${entry.file}: ${entry.symbol}`);
    resolved += 1;
  }
  assert.deepEqual(
    unresolved, [],
    "the reporter prompt documents symbols that no longer exist; re-derive the facts before shipping",
  );
  assert.equal(resolved, CITED_SYMBOLS.length);
  assert.ok(resolved >= CITED_SYMBOL_FLOOR, `cited-symbol floor: ${resolved}`);
});
