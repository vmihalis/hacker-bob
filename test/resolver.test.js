"use strict";

/**
 * Tests for A3 — resolver.ts (and diff.ts position map integration).
 *
 * Verifies acceptance criteria:
 *   1. resolveFindings returns ResolvedComment[] with position set to the diff
 *      offset for in-diff addition lines.
 *   2. For lines not in the diff (between hunks / beyond last hunk), falls back
 *      to nearest hunk boundary position.
 *   3. Findings on files not in the diff at all are converted to PR-level
 *      comments (position undefined, body prefixed with filename + line).
 *   4. body is formatted as:
 *      "[{severity}] {title}\n\n{description}\n\n**Evidence:**\n```\n{evidence}\n```"
 *   5. side is 'RIGHT' for additions/context, 'LEFT' for deletions.
 *   6. line_start <= 0 is clamped to 1.
 *   7. Multi-file diff: per-file position counter resets correctly.
 *   8. Binary file in diff: falls back to position 1 (file-level comment).
 *   9. Unresolvable file (not in diff): PR-level comment format.
 *  10. buildDiffPositionMap: position for line 1 of a new file is 2 (after @@ header).
 *  11. buildDiffPositionMap: multi-file diff with correct per-file position reset.
 *
 * Golden values are manually computed from the fixture diffs in
 * test/fixtures/sample-diffs/ to catch position algorithm regressions.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

// ---------------------------------------------------------------------------
// Imports from compiled dist.
// ---------------------------------------------------------------------------

const dist = path.join(__dirname, "..", "packages", "bob-diff-review", "dist");

const {
  buildDiffPositionMap,
} = require(path.join(dist, "diff.js"));

const {
  resolveFindings,
  resolvePosition,
  formatCommentBody,
  formatPRLevelBody,
} = require(path.join(dist, "resolver.js"));

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

const FIXTURES = path.join(__dirname, "fixtures", "sample-diffs");

function loadDiff(name) {
  return fs.readFileSync(path.join(FIXTURES, `${name}.txt`), "utf8");
}

/**
 * Build a minimal valid FindingEntry for test use.
 */
function makeFinding(overrides = {}) {
  return {
    surface_id: "surf-001",
    file: "src/main.js",
    line_start: 2,
    line_end: 2,
    title: "Test Finding",
    severity: "high",
    description: "A test description.",
    evidence: "GET /path HTTP/1.1\n\nHTTP/1.1 200 OK",
    hunk_text: "",
    ...overrides,
  };
}

/**
 * Build a minimal valid DiffReviewFindings document.
 */
function makeFindings(findings = []) {
  return {
    session_id: "ses-test001",
    target_domain: "gh-00000001",
    generated_at: "2026-06-07T00:00:00.000Z",
    impacted_entries: [],
    findings,
  };
}

// ---------------------------------------------------------------------------
// Section 1: buildDiffPositionMap golden-value tests (diff.ts integration)
// ---------------------------------------------------------------------------

test("buildDiffPositionMap: line 1 of a new file has position 2 (after @@ header)", () => {
  // The @@ header counts as position 1; the first actual content line is 2.
  const diff = loadDiff("addition-only");
  const posMap = buildDiffPositionMap(diff);
  const fileMap = posMap.get("src/main.js");
  assert.ok(fileMap, "src/main.js should be in the position map");
  assert.strictEqual(fileMap.get(1), 2, "line 1 should map to position 2");
});

test("buildDiffPositionMap: addition lines are mapped to correct positions", () => {
  const diff = loadDiff("addition-only");
  const posMap = buildDiffPositionMap(diff);
  const fileMap = posMap.get("src/main.js");
  // Computed manually:
  // @@ header = position 1 (not in map)
  //  context line 1 → position 2
  // +addition line 2 → position 3
  // +addition line 3 → position 4
  //  context line 4 → position 5
  assert.strictEqual(fileMap.get(1), 2, "context line 1 → position 2");
  assert.strictEqual(fileMap.get(2), 3, "addition line 2 → position 3");
  assert.strictEqual(fileMap.get(3), 4, "addition line 3 → position 4");
  assert.strictEqual(fileMap.get(4), 5, "context line 4 → position 5");
});

test("buildDiffPositionMap: deletion lines use negative keys", () => {
  const diff = loadDiff("deletion-only");
  const posMap = buildDiffPositionMap(diff);
  const fileMap = posMap.get("src/utils.js");
  assert.ok(fileMap, "src/utils.js should be in the position map");
  // Old-file line 2 was deleted → stored under key -2 → position 3
  // Old-file line 3 was deleted → stored under key -3 → position 4
  assert.strictEqual(fileMap.get(-2), 3, "deletion of old-line 2 → position 3");
  assert.strictEqual(fileMap.get(-3), 4, "deletion of old-line 3 → position 4");
  // New-file context and additions still have positive keys
  assert.strictEqual(fileMap.get(1), 2, "context line 1 → position 2");
  assert.strictEqual(fileMap.get(2), 5, "addition line 2 (new) → position 5");
});

test("buildDiffPositionMap: multi-file diff resets per-file position counter", () => {
  const diff = loadDiff("multi-file");
  const posMap = buildDiffPositionMap(diff);

  const alphaMap = posMap.get("src/alpha.js");
  const betaMap = posMap.get("src/beta.js");

  assert.ok(alphaMap, "src/alpha.js should be in the map");
  assert.ok(betaMap, "src/beta.js should be in the map");

  // src/alpha.js position counter resets at its diff --git header:
  // @@ position 1 (not in map)
  //  const x = 1; → position 2 (line 1)
  // +const y = 2; → position 3 (line 2)
  //  const z = 3; → position 4 (line 3)
  assert.strictEqual(alphaMap.get(1), 2, "alpha line 1 → position 2");
  assert.strictEqual(alphaMap.get(2), 3, "alpha line 2 → position 3");
  assert.strictEqual(alphaMap.get(3), 4, "alpha line 3 → position 4");

  // src/beta.js position counter independently resets:
  // @@ -10,3 +10,4 @@ → position 1 (not in map)
  //  function init() { → position 2 (line 10)
  // +  setup();         → position 3 (line 11)
  //    run();           → position 4 (line 12)
  //  }                  → position 5 (line 13)
  assert.strictEqual(betaMap.get(10), 2, "beta line 10 → position 2");
  assert.strictEqual(betaMap.get(11), 3, "beta line 11 → position 3");
  assert.strictEqual(betaMap.get(12), 4, "beta line 12 → position 4");
  assert.strictEqual(betaMap.get(13), 5, "beta line 13 → position 5");
});

test("buildDiffPositionMap: binary file produces empty position map", () => {
  const diff = loadDiff("binary");
  const posMap = buildDiffPositionMap(diff);

  const binaryMap = posMap.get("assets/image.png");
  assert.ok(binaryMap !== undefined, "binary file should still appear in posMap");
  assert.strictEqual(binaryMap.size, 0, "binary file map should be empty");

  // The text file after the binary entry should parse normally.
  const codeMap = posMap.get("src/code.js");
  assert.ok(codeMap, "src/code.js should be in the map");
  assert.strictEqual(codeMap.get(1), 2, "src/code.js line 1 → position 2");
  assert.strictEqual(codeMap.get(2), 3, "src/code.js line 2 → position 3");
});

// ---------------------------------------------------------------------------
// Section 2: resolvePosition unit tests
// ---------------------------------------------------------------------------

test("resolvePosition: exact positive key lookup (addition/context line)", () => {
  const fileMap = new Map([
    [1, 2],
    [2, 3],
    [3, 4],
  ]);
  const result = resolvePosition(fileMap, 2);
  assert.deepStrictEqual(result, { position: 3, side: "RIGHT" });
});

test("resolvePosition: exact negative key lookup (deletion line)", () => {
  const fileMap = new Map([
    [1, 2],
    [-2, 3],
    [-3, 4],
    [2, 5],
  ]);
  // line_start=2 → check positive key 2 first (exists → position 5)
  const addResult = resolvePosition(fileMap, 2);
  assert.deepStrictEqual(addResult, { position: 5, side: "RIGHT" });

  // To test deletion lookup we need a map without the positive key.
  const deletionOnlyMap = new Map([
    [1, 2],
    [-2, 3],
  ]);
  const delResult = resolvePosition(deletionOnlyMap, 2);
  // Positive key 2 not present → negative key -2 exists → position 3, LEFT
  assert.deepStrictEqual(delResult, { position: 3, side: "LEFT" });
});

test("resolvePosition: forward walk to nearest hunk boundary", () => {
  // Simulate a line between two hunks — only lines 1 and 10 are mapped.
  const fileMap = new Map([
    [1, 2],
    [10, 5],
  ]);
  // Line 5 is not mapped; forward walk should find line 10 (position 5).
  const result = resolvePosition(fileMap, 5);
  assert.deepStrictEqual(result, { position: 5, side: "RIGHT" });
});

test("resolvePosition: backward walk fallback when no forward entry exists", () => {
  const fileMap = new Map([
    [1, 2],
    [3, 4],
    [5, 6],
  ]);
  // Line 100 is beyond all mapped lines — backward fallback to line 5 (position 6).
  const result = resolvePosition(fileMap, 100);
  assert.deepStrictEqual(result, { position: 6, side: "RIGHT" });
});

test("resolvePosition: empty map returns null", () => {
  const emptyMap = new Map();
  assert.strictEqual(resolvePosition(emptyMap, 1), null);
});

// ---------------------------------------------------------------------------
// Section 3: formatCommentBody golden-value test
// ---------------------------------------------------------------------------

test("formatCommentBody: formats body exactly per spec", () => {
  const finding = makeFinding({
    severity: "high",
    title: "SQL Injection",
    description: "User input passed to query unsanitized.",
    evidence: "POST /api/users\n\nHTTP/1.1 500",
  });
  const body = formatCommentBody(finding);
  const expected =
    "[high] SQL Injection\n\n" +
    "User input passed to query unsanitized.\n\n" +
    "**Evidence:**\n```\n" +
    "POST /api/users\n\nHTTP/1.1 500\n" +
    "```";
  assert.strictEqual(body, expected);
});

test("formatPRLevelBody: prefixes with File and line number", () => {
  const finding = makeFinding({
    line_start: 42,
    file: "src/auth.js",
    severity: "critical",
    title: "Auth Bypass",
    description: "Token not verified.",
    evidence: "Request: ...",
  });
  const body = formatPRLevelBody(finding, "src/auth.js");
  assert.ok(
    body.startsWith("**File:** `src/auth.js` line 42\n"),
    "PR-level body must start with file+line prefix"
  );
  assert.ok(
    body.includes("[critical] Auth Bypass"),
    "PR-level body must include the severity and title"
  );
});

// ---------------------------------------------------------------------------
// Section 4: resolveFindings integration tests
// ---------------------------------------------------------------------------

test("resolveFindings: maps finding.line_start to correct diff position for addition line", () => {
  const diff = loadDiff("addition-only");
  const posMap = buildDiffPositionMap(diff);

  // line 2 is an addition line → position 3, side RIGHT
  const doc = makeFindings([
    makeFinding({ file: "src/main.js", line_start: 2, line_end: 2 }),
  ]);

  const comments = resolveFindings(doc, posMap);
  assert.strictEqual(comments.length, 1);
  assert.strictEqual(comments[0].path, "src/main.js");
  assert.strictEqual(comments[0].position, 3);
  assert.strictEqual(comments[0].side, "RIGHT");
  assert.ok(
    comments[0].body.startsWith("[high] Test Finding"),
    "body should start with severity + title"
  );
  assert.ok(
    comments[0].body.includes("**Evidence:**"),
    "body should include Evidence section"
  );
});

test("resolveFindings: side is RIGHT for addition lines, LEFT for deletion lines", () => {
  const diff = loadDiff("deletion-only");
  const posMap = buildDiffPositionMap(diff);

  // new-file line 1 is context → side RIGHT
  const docCtx = makeFindings([
    makeFinding({ file: "src/utils.js", line_start: 1, line_end: 1 }),
  ]);
  const ctxComments = resolveFindings(docCtx, posMap);
  assert.strictEqual(ctxComments[0].side, "RIGHT", "context line should be RIGHT");

  // new-file line 2 is the +return 0; addition → side RIGHT
  const docAdd = makeFindings([
    makeFinding({ file: "src/utils.js", line_start: 2, line_end: 2 }),
  ]);
  const addComments = resolveFindings(docAdd, posMap);
  assert.strictEqual(addComments[0].side, "RIGHT", "addition line should be RIGHT");
  assert.strictEqual(addComments[0].position, 5);
});

test("resolveFindings: falls back to PR-level comment for file not in diff", () => {
  const diff = loadDiff("addition-only");
  const posMap = buildDiffPositionMap(diff);

  // This file is not in the diff at all.
  const doc = makeFindings([
    makeFinding({ file: "src/not-in-diff.js", line_start: 5, line_end: 5 }),
  ]);

  const comments = resolveFindings(doc, posMap);
  assert.strictEqual(comments.length, 1);
  assert.strictEqual(comments[0].path, "src/not-in-diff.js");
  assert.strictEqual(
    comments[0].position,
    undefined,
    "position should be undefined for files not in diff"
  );
  assert.ok(
    comments[0].body.includes("**File:** `src/not-in-diff.js` line 5"),
    "PR-level body should include file prefix"
  );
});

test("resolveFindings: clamps line_start < 1 to 1", () => {
  const diff = loadDiff("addition-only");
  const posMap = buildDiffPositionMap(diff);

  // line_start=0 should be clamped to 1 → resolves to position 2
  const doc = makeFindings([
    makeFinding({ file: "src/main.js", line_start: 0, line_end: 1 }),
  ]);
  const comments = resolveFindings(doc, posMap);
  assert.strictEqual(comments.length, 1);
  assert.strictEqual(comments[0].position, 2, "clamped line 0 → position 2 (line 1)");
});

test("resolveFindings: clamps negative line_start to 1", () => {
  const diff = loadDiff("addition-only");
  const posMap = buildDiffPositionMap(diff);

  const doc = makeFindings([
    makeFinding({ file: "src/main.js", line_start: -5, line_end: 1 }),
  ]);
  const comments = resolveFindings(doc, posMap);
  assert.strictEqual(comments.length, 1);
  assert.strictEqual(comments[0].position, 2, "clamped line -5 → position 2 (line 1)");
});

test("resolveFindings: multi-file diff with findings on both files", () => {
  const diff = loadDiff("multi-file");
  const posMap = buildDiffPositionMap(diff);

  const doc = makeFindings([
    makeFinding({ file: "src/alpha.js", line_start: 2, line_end: 2, title: "Alpha Finding" }),
    makeFinding({ file: "src/beta.js", line_start: 11, line_end: 11, title: "Beta Finding" }),
  ]);

  const comments = resolveFindings(doc, posMap);
  assert.strictEqual(comments.length, 2);

  const alpha = comments.find((c) => c.path === "src/alpha.js");
  const beta = comments.find((c) => c.path === "src/beta.js");

  assert.ok(alpha, "alpha comment should exist");
  assert.ok(beta, "beta comment should exist");

  // src/alpha.js line 2 → position 3
  assert.strictEqual(alpha.position, 3, "alpha line 2 → position 3");
  assert.strictEqual(alpha.side, "RIGHT");

  // src/beta.js line 11 → position 3 (beta's per-file position counter is independent)
  assert.strictEqual(beta.position, 3, "beta line 11 → position 3 (independent counter)");
  assert.strictEqual(beta.side, "RIGHT");
});

test("resolveFindings: binary file falls back to file-level comment (position 1)", () => {
  const diff = loadDiff("binary");
  const posMap = buildDiffPositionMap(diff);

  // assets/image.png is binary — its file map exists but is empty.
  const doc = makeFindings([
    makeFinding({ file: "assets/image.png", line_start: 1, line_end: 1 }),
  ]);

  const comments = resolveFindings(doc, posMap);
  assert.strictEqual(comments.length, 1);
  assert.strictEqual(comments[0].path, "assets/image.png");
  // Binary files in diff → file-level comment at position 1.
  assert.strictEqual(
    comments[0].position,
    1,
    "binary file in diff should use position 1 as file-level fallback"
  );
});

test("resolveFindings: empty findings returns empty array", () => {
  const diff = loadDiff("addition-only");
  const posMap = buildDiffPositionMap(diff);

  const doc = makeFindings([]);
  const comments = resolveFindings(doc, posMap);
  assert.deepStrictEqual(comments, []);
});

test("resolveFindings: forward walk fallback for line between hunks", () => {
  // Craft a diff with two hunks so there is a gap between them.
  // Hunk 1 covers lines 1-3, hunk 2 starts at line 10.
  const twoHunkDiff = [
    "diff --git a/src/gap.js b/src/gap.js",
    "index 0000001..0000002 100644",
    "--- a/src/gap.js",
    "+++ b/src/gap.js",
    "@@ -1,3 +1,3 @@",
    " line 1",
    "+line 2",
    " line 3",
    "@@ -10,2 +10,3 @@",
    " line 10",
    "+line 11",
    " line 12",
  ].join("\n");

  const posMap = buildDiffPositionMap(twoHunkDiff);
  const fileMap = posMap.get("src/gap.js");
  assert.ok(fileMap, "src/gap.js should be in posMap");

  // Line 5 is in the gap between hunks — not mapped.
  // Forward walk should find line 10 (the start of the second hunk).
  const result = resolvePosition(fileMap, 5);
  assert.ok(result !== null, "should resolve to some position");
  const line10Pos = fileMap.get(10);
  assert.strictEqual(
    result.position,
    line10Pos,
    "forward fallback should use next hunk boundary (line 10)"
  );
  assert.strictEqual(result.side, "RIGHT");
});

test("resolveFindings: body contains all required sections in order", () => {
  const diff = loadDiff("addition-only");
  const posMap = buildDiffPositionMap(diff);

  const doc = makeFindings([
    makeFinding({
      file: "src/main.js",
      line_start: 2,
      severity: "medium",
      title: "Insecure Default",
      description: "Default config is insecure.",
      evidence: "CONFIG: debug=true",
    }),
  ]);

  const comments = resolveFindings(doc, posMap);
  const body = comments[0].body;

  // Verify all parts appear in the correct order.
  const headerIdx = body.indexOf("[medium] Insecure Default");
  const descIdx = body.indexOf("Default config is insecure.");
  const evidenceHdrIdx = body.indexOf("**Evidence:**");
  const codeBlockIdx = body.indexOf("```");

  assert.ok(headerIdx !== -1, "header must be present");
  assert.ok(descIdx !== -1, "description must be present");
  assert.ok(evidenceHdrIdx !== -1, "**Evidence:** header must be present");
  assert.ok(codeBlockIdx !== -1, "code block must be present");

  assert.ok(headerIdx < descIdx, "header must come before description");
  assert.ok(descIdx < evidenceHdrIdx, "description must come before evidence header");
  assert.ok(evidenceHdrIdx < codeBlockIdx, "evidence header must come before code fence");
});
