/**
 * Unit tests for src/resolver.ts — finding-to-comment resolution (A3).
 *
 * Verifies acceptance criteria:
 *   1. resolveFindings returns ResolvedComment[] with position set to the diff
 *      offset for in-diff addition lines.
 *   2. For lines not in the diff (between hunks), falls back to nearest hunk
 *      boundary position via forward then backward walk.
 *   3. Findings on files not in the diff at all produce PR-level comments
 *      (position undefined, body prefixed with filename + line).
 *   4. body is formatted as:
 *      "[{severity}] {title}\n\n{description}\n\n**Evidence:**\n```\n{evidence}\n```"
 *   5. side is 'RIGHT' for additions/context, 'LEFT' for deletions.
 *   6. line_start <= 0 is clamped to 1.
 *   7. Multi-file diff: per-file position counter resets correctly.
 *   8. Binary file in diff: falls back to position 1 (file-level comment).
 *
 * Golden values are manually computed from the fixture diffs in
 * test/fixtures/sample-diffs/.
 */

import { describe, it, expect } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { buildDiffPositionMap } from "../diff.js";
import {
  resolveFindings,
  resolvePosition,
  formatCommentBody,
  formatPRLevelBody,
  type ResolvedComment,
} from "../resolver.js";
import type { DiffReviewFindings, FindingEntry } from "../findings-serializer.js";

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIXTURES = path.join(__dirname, "../../test/fixtures/sample-diffs");

function loadDiff(name: string): string {
  return fs.readFileSync(path.join(FIXTURES, `${name}.txt`), "utf8");
}

/** Build a minimal valid FindingEntry for test use. */
function makeFinding(overrides: Partial<FindingEntry> = {}): FindingEntry {
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

/** Build a minimal valid DiffReviewFindings document. */
function makeFindings(findings: FindingEntry[] = []): DiffReviewFindings {
  return {
    session_id: "ses-test001",
    target_domain: "gh-00000001",
    generated_at: "2026-06-07T00:00:00.000Z",
    impacted_entries: [],
    findings,
  };
}

// ---------------------------------------------------------------------------
// resolvePosition — unit tests for the inner lookup helper.
// ---------------------------------------------------------------------------

describe("resolvePosition", () => {
  it("exact positive key lookup returns RIGHT side", () => {
    const fileMap = new Map([[1, 2], [2, 3], [3, 4]]);
    expect(resolvePosition(fileMap, 2)).toEqual({ position: 3, side: "RIGHT" });
  });

  it("exact negative key lookup returns LEFT side", () => {
    // Deletion-only map: key -2 stores old-file line 2 deletion.
    const fileMap = new Map([[1, 2], [-2, 3]]);
    expect(resolvePosition(fileMap, 2)).toEqual({ position: 3, side: "LEFT" });
  });

  it("positive key takes precedence over negative key for same line number", () => {
    // Both key 2 (addition) and key -2 (deletion of same line) exist.
    const fileMap = new Map([[1, 2], [-2, 3], [2, 5]]);
    // Positive key 2 matches first.
    expect(resolvePosition(fileMap, 2)).toEqual({ position: 5, side: "RIGHT" });
  });

  it("forward walk finds nearest hunk boundary at or after target line", () => {
    // Only lines 1 and 10 are mapped; line 5 is in the gap.
    const fileMap = new Map([[1, 2], [10, 5]]);
    const result = resolvePosition(fileMap, 5);
    // Forward walk should find line 10 (nearest mapped line >= 5).
    expect(result).toEqual({ position: 5, side: "RIGHT" });
  });

  it("backward walk fallback when no forward entry exists", () => {
    const fileMap = new Map([[1, 2], [3, 4], [5, 6]]);
    // Line 100 is beyond all mapped lines; backward walk to line 5 (position 6).
    const result = resolvePosition(fileMap, 100);
    expect(result).toEqual({ position: 6, side: "RIGHT" });
  });

  it("empty map returns null", () => {
    expect(resolvePosition(new Map(), 1)).toBeNull();
  });

  it("forward walk prefers the smallest key >= lineStart (not just any key >= lineStart)", () => {
    const fileMap = new Map([[5, 6], [10, 11], [15, 16]]);
    // Line 7 → forward walk → smallest key >= 7 is 10 (position 11).
    const result = resolvePosition(fileMap, 7);
    expect(result).toEqual({ position: 11, side: "RIGHT" });
  });

  it("backward walk prefers the largest key < lineStart", () => {
    const fileMap = new Map([[1, 2], [3, 4], [5, 6]]);
    // Line 8 → no forward key >= 8 → backward: largest key < 8 is 5 (position 6).
    const result = resolvePosition(fileMap, 8);
    expect(result).toEqual({ position: 6, side: "RIGHT" });
  });
});

// ---------------------------------------------------------------------------
// formatCommentBody golden-value tests.
// ---------------------------------------------------------------------------

describe("formatCommentBody", () => {
  it("formats body exactly per spec", () => {
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
    expect(body).toBe(expected);
  });

  it("includes severity label in square brackets without emoji", () => {
    const body = formatCommentBody(makeFinding({ severity: "critical", title: "T" }));
    expect(body).toMatch(/^\[critical\]/);
    // Project rule: no emoji.
    expect(body).not.toMatch(/[\u{1F600}-\u{1F6FF}]/u);
  });
});

// ---------------------------------------------------------------------------
// formatPRLevelBody golden-value tests.
// ---------------------------------------------------------------------------

describe("formatPRLevelBody", () => {
  it("prefixes body with file path and line number", () => {
    const finding = makeFinding({
      file: "src/auth.js",
      line_start: 42,
      severity: "critical",
      title: "Auth Bypass",
      description: "Token not verified.",
      evidence: "Request: ...",
    });
    const body = formatPRLevelBody(finding, "src/auth.js");
    expect(body.startsWith("**File:** `src/auth.js` line 42\n")).toBe(true);
    expect(body).toContain("[critical] Auth Bypass");
  });

  it("PR-level body includes all normal body sections after the prefix", () => {
    const finding = makeFinding({ line_start: 10 });
    const body = formatPRLevelBody(finding, "src/main.js");
    const prefixEnd = body.indexOf("\n") + 1;
    const rest = body.slice(prefixEnd);
    // Rest should be a complete formatCommentBody output.
    expect(rest).toBe(formatCommentBody(finding));
  });
});

// ---------------------------------------------------------------------------
// Acceptance criterion: resolveFindings maps finding.line_start to correct
// diff position for addition lines.
// ---------------------------------------------------------------------------

describe("resolveFindings: position mapping for in-diff lines", () => {
  it("maps finding.line_start to position 3 for addition line 2 in addition-only fixture", () => {
    const posMap = buildDiffPositionMap(loadDiff("addition-only"));
    // addition-only golden values:
    //   line 1 (ctx) → position 2
    //   line 2 (+)   → position 3  ← target
    //   line 3 (+)   → position 4
    //   line 4 (ctx) → position 5
    const doc = makeFindings([makeFinding({ file: "src/main.js", line_start: 2, line_end: 2 })]);
    const comments = resolveFindings(doc, posMap);

    expect(comments).toHaveLength(1);
    expect(comments[0].path).toBe("src/main.js");
    expect(comments[0].position).toBe(3);
    expect(comments[0].side).toBe("RIGHT");
  });

  it("body contains severity header, description, and evidence sections in order", () => {
    const posMap = buildDiffPositionMap(loadDiff("addition-only"));
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

    const headerIdx = body.indexOf("[medium] Insecure Default");
    const descIdx = body.indexOf("Default config is insecure.");
    const evidenceHdrIdx = body.indexOf("**Evidence:**");
    const codeBlockIdx = body.indexOf("```");

    expect(headerIdx).not.toBe(-1);
    expect(descIdx).not.toBe(-1);
    expect(evidenceHdrIdx).not.toBe(-1);
    expect(codeBlockIdx).not.toBe(-1);

    expect(headerIdx).toBeLessThan(descIdx);
    expect(descIdx).toBeLessThan(evidenceHdrIdx);
    expect(evidenceHdrIdx).toBeLessThan(codeBlockIdx);
  });
});

// ---------------------------------------------------------------------------
// Acceptance criterion: resolveFindings falls back to PR-level comment for
// finding on file not in diff.
// ---------------------------------------------------------------------------

describe("resolveFindings: fallback to PR-level comment for files not in diff", () => {
  it("position is undefined when file is not in the diff at all", () => {
    const posMap = buildDiffPositionMap(loadDiff("addition-only"));
    const doc = makeFindings([
      makeFinding({ file: "src/not-in-diff.js", line_start: 5, line_end: 5 }),
    ]);
    const comments = resolveFindings(doc, posMap);

    expect(comments).toHaveLength(1);
    expect(comments[0].path).toBe("src/not-in-diff.js");
    expect(comments[0].position).toBeUndefined();
  });

  it("PR-level comment body includes the file path and line number prefix", () => {
    const posMap = buildDiffPositionMap(loadDiff("addition-only"));
    const doc = makeFindings([
      makeFinding({ file: "src/not-in-diff.js", line_start: 5, line_end: 5 }),
    ]);
    const comments = resolveFindings(doc, posMap);
    expect(comments[0].body).toContain("**File:** `src/not-in-diff.js` line 5");
  });

  it("PR-level comment still includes severity, title, and evidence", () => {
    const posMap = buildDiffPositionMap(loadDiff("addition-only"));
    const doc = makeFindings([
      makeFinding({
        file: "src/not-in-diff.js",
        line_start: 5,
        severity: "critical",
        title: "RCE",
        evidence: "curl ...",
      }),
    ]);
    const comments = resolveFindings(doc, posMap);
    expect(comments[0].body).toContain("[critical] RCE");
    expect(comments[0].body).toContain("**Evidence:**");
  });
});

// ---------------------------------------------------------------------------
// Acceptance criterion: resolveFindings clamps line_start < 1 to 1.
// ---------------------------------------------------------------------------

describe("resolveFindings: line_start clamping", () => {
  it("clamps line_start=0 to 1 and resolves to position 2 (line 1)", () => {
    const posMap = buildDiffPositionMap(loadDiff("addition-only"));
    // addition-only: line 1 → position 2
    const doc = makeFindings([makeFinding({ file: "src/main.js", line_start: 0, line_end: 1 })]);
    const comments = resolveFindings(doc, posMap);

    expect(comments).toHaveLength(1);
    expect(comments[0].position).toBe(2);
  });

  it("clamps negative line_start to 1 and resolves to position 2", () => {
    const posMap = buildDiffPositionMap(loadDiff("addition-only"));
    const doc = makeFindings([
      makeFinding({ file: "src/main.js", line_start: -5, line_end: 1 }),
    ]);
    const comments = resolveFindings(doc, posMap);
    expect(comments[0].position).toBe(2);
  });

  it("line_start=1 (already valid) resolves normally", () => {
    const posMap = buildDiffPositionMap(loadDiff("addition-only"));
    const doc = makeFindings([makeFinding({ file: "src/main.js", line_start: 1, line_end: 1 })]);
    const comments = resolveFindings(doc, posMap);
    expect(comments[0].position).toBe(2);
    expect(comments[0].side).toBe("RIGHT");
  });
});

// ---------------------------------------------------------------------------
// Acceptance criterion: multi-file diff with correct per-file position reset.
// ---------------------------------------------------------------------------

describe("resolveFindings: multi-file diff per-file position counter", () => {
  it("produces independent positions for findings in different files", () => {
    const posMap = buildDiffPositionMap(loadDiff("multi-file"));
    const doc = makeFindings([
      makeFinding({ file: "src/alpha.js", line_start: 2, line_end: 2, title: "Alpha Finding" }),
      makeFinding({ file: "src/beta.js", line_start: 11, line_end: 11, title: "Beta Finding" }),
    ]);

    const comments = resolveFindings(doc, posMap);
    expect(comments).toHaveLength(2);

    const alpha = comments.find((c: ResolvedComment) => c.path === "src/alpha.js");
    const beta = comments.find((c: ResolvedComment) => c.path === "src/beta.js");

    expect(alpha).toBeDefined();
    expect(beta).toBeDefined();

    // src/alpha.js line 2 → position 3 (independent counter starting at 1)
    expect(alpha!.position).toBe(3);
    expect(alpha!.side).toBe("RIGHT");

    // src/beta.js line 11 → position 3 (independent counter also starts at 1)
    expect(beta!.position).toBe(3);
    expect(beta!.side).toBe("RIGHT");
  });

  it("alpha line 1 maps to position 2 in the multi-file diff", () => {
    const posMap = buildDiffPositionMap(loadDiff("multi-file"));
    const doc = makeFindings([
      makeFinding({ file: "src/alpha.js", line_start: 1, line_end: 1 }),
    ]);
    const comments = resolveFindings(doc, posMap);
    expect(comments[0].position).toBe(2);
  });

  it("beta line 10 maps to position 2 (independent of alpha's position counter)", () => {
    const posMap = buildDiffPositionMap(loadDiff("multi-file"));
    const doc = makeFindings([
      makeFinding({ file: "src/beta.js", line_start: 10, line_end: 10 }),
    ]);
    const comments = resolveFindings(doc, posMap);
    // beta's @@ header is position 1 (in its own independent counter);
    // its first line (10) is position 2.
    expect(comments[0].position).toBe(2);
  });
});

// ---------------------------------------------------------------------------
// Side assignment: RIGHT for addition/context, LEFT for deletion.
// ---------------------------------------------------------------------------

describe("resolveFindings: side assignment", () => {
  it("addition lines (positive key) produce side=RIGHT", () => {
    const posMap = buildDiffPositionMap(loadDiff("addition-only"));
    const doc = makeFindings([makeFinding({ file: "src/main.js", line_start: 2 })]);
    const comments = resolveFindings(doc, posMap);
    expect(comments[0].side).toBe("RIGHT");
  });

  it("context lines (positive key) produce side=RIGHT", () => {
    const posMap = buildDiffPositionMap(loadDiff("addition-only"));
    const doc = makeFindings([makeFinding({ file: "src/main.js", line_start: 1 })]);
    const comments = resolveFindings(doc, posMap);
    expect(comments[0].side).toBe("RIGHT");
  });

  it("deletion lines (negative key) produce side=LEFT via exact negative key lookup", () => {
    // deletion-only: old-file line 2 was deleted → key -2 → position 3, LEFT
    // But finding.line_start is always in new-file space.
    // To trigger LEFT we need a line that only has a negative key (no positive).
    const deletionMap = new Map([[-2, 3]]);
    const result = resolvePosition(deletionMap, 2);
    expect(result).toEqual({ position: 3, side: "LEFT" });
  });

  it("last-resort path: map has only negative deletion keys → uses sideFromKey(negative) → LEFT", () => {
    // This exercises the step-5 last-resort code path in resolvePosition:
    // the map has only deletion (-) keys, no positive keys, and the exact
    // negative key does not match lineStart.
    // e.g. map has -5 (old-line 5 deleted), and we're looking for lineStart=3.
    // Exact positive(3) → miss, exact negative(-3) → miss,
    // forward/backward walk over positive keys → no positive keys exist,
    // so falls through to the "any entry" last resort.
    const deletionOnlyMap = new Map([[-5, 7]]);
    const result = resolvePosition(deletionOnlyMap, 3);
    // Last resort picks the only entry: key -5, position 7, side LEFT.
    expect(result).toEqual({ position: 7, side: "LEFT" });
  });
});

// ---------------------------------------------------------------------------
// Binary file fallback: position 1 file-level comment.
// ---------------------------------------------------------------------------

describe("resolveFindings: binary file fallback", () => {
  it("binary file in diff produces position=1 file-level comment", () => {
    const posMap = buildDiffPositionMap(loadDiff("binary"));
    const doc = makeFindings([
      makeFinding({ file: "assets/image.png", line_start: 1, line_end: 1 }),
    ]);
    const comments = resolveFindings(doc, posMap);

    expect(comments).toHaveLength(1);
    expect(comments[0].path).toBe("assets/image.png");
    // Binary file in diff has empty posMap → file-level fallback to position 1.
    expect(comments[0].position).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// Empty and multi-finding edge cases.
// ---------------------------------------------------------------------------

describe("resolveFindings: edge cases", () => {
  it("empty findings array returns empty comments array", () => {
    const posMap = buildDiffPositionMap(loadDiff("addition-only"));
    const comments = resolveFindings(makeFindings([]), posMap);
    expect(comments).toEqual([]);
  });

  it("multiple findings on the same line both produce comments (duplicates allowed)", () => {
    const posMap = buildDiffPositionMap(loadDiff("addition-only"));
    const doc = makeFindings([
      makeFinding({ file: "src/main.js", line_start: 2, title: "Finding A" }),
      makeFinding({ file: "src/main.js", line_start: 2, title: "Finding B" }),
    ]);
    const comments = resolveFindings(doc, posMap);
    expect(comments).toHaveLength(2);
    expect(comments[0].position).toBe(3);
    expect(comments[1].position).toBe(3);
  });

  it("forward walk fallback resolves line in gap between two hunks", () => {
    const twoHunkDiff = [
      "diff --git a/src/gap.js b/src/gap.js",
      "index 000000..000001 100644",
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
    const doc = makeFindings([
      // Line 5 is in the gap between the two hunks.
      makeFinding({ file: "src/gap.js", line_start: 5, line_end: 5 }),
    ]);
    const comments = resolveFindings(doc, posMap);

    // Forward walk finds line 10 (the start of the second hunk).
    // Two-hunk golden values:
    //   @@ -1,3 +1,3 @@     → position 1 (not stored)
    //    line 1              → position 2 (new-line 1)
    //   +line 2              → position 3 (new-line 2)
    //    line 3              → position 4 (new-line 3)
    //   @@ -10,2 +10,3 @@   → position 5 (not stored)
    //    line 10             → position 6 (new-line 10)
    //   +line 11             → position 7 (new-line 11)
    //    line 12             → position 8 (new-line 12)
    const fileMap = posMap.get("src/gap.js")!;
    expect(comments[0].position).toBe(fileMap.get(10));
    expect(comments[0].side).toBe("RIGHT");
  });

  it("backward walk fallback resolves line beyond last hunk", () => {
    const posMap = buildDiffPositionMap(loadDiff("addition-only"));
    const doc = makeFindings([
      // Line 999 is well beyond the 4 lines in addition-only.txt.
      makeFinding({ file: "src/main.js", line_start: 999, line_end: 999 }),
    ]);
    const comments = resolveFindings(doc, posMap);
    // Backward walk should land on line 4 (position 5 — the last mapped line).
    expect(comments[0].position).toBe(5);
    expect(comments[0].side).toBe("RIGHT");
  });

  it("windows path separators are normalised to forward slashes for map lookup", () => {
    const posMap = buildDiffPositionMap(loadDiff("addition-only"));
    // posMap has "src/main.js"; supply finding.file with backslashes.
    const doc = makeFindings([
      makeFinding({ file: "src\\main.js", line_start: 2 }),
    ]);
    const comments = resolveFindings(doc, posMap);
    // After normalisation the path matches and we get a real position.
    expect(comments[0].position).toBe(3);
  });
});
