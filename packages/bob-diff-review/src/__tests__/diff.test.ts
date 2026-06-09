/**
 * Unit tests for src/diff.ts — diff position mapping (A1).
 *
 * These tests cover the position offset algorithm with golden-value assertions
 * against known correct positions computed manually from fixture diffs.
 * The position algorithm is the most fragile component: off-by-one errors
 * break the GitHub Reviews API createReviewComment endpoint.
 *
 * Fixture diffs are stored in test/fixtures/sample-diffs/ as .txt files.
 *
 * Golden values (manually computed):
 *   addition-only.txt:
 *     @@ header     = position 1 (not stored in map)
 *     line 1 (ctx)  = position 2
 *     line 2 (+)    = position 3
 *     line 3 (+)    = position 4
 *     line 4 (ctx)  = position 5
 *
 *   deletion-only.txt:
 *     @@ header             = position 1 (not stored)
 *     line 1 (ctx)          = position 2  (key: 1)
 *     old-line 2 (-) del    = position 3  (key: -2)
 *     old-line 3 (-) del    = position 4  (key: -3)
 *     line 2 (+) addition   = position 5  (key: 2)
 *     line 3 (ctx)          = position 6  (key: 3)
 *
 *   multi-file.txt (alpha):
 *     @@ header    = position 1 (not stored)
 *     line 1 (ctx) = position 2
 *     line 2 (+)   = position 3
 *     line 3 (ctx) = position 4
 *
 *   multi-file.txt (beta — independent counter):
 *     @@ header     = position 1
 *     line 10 (ctx) = position 2
 *     line 11 (+)   = position 3
 *     line 12 (ctx) = position 4
 *     line 13 (ctx) = position 5
 */

import { describe, it, expect } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { buildDiffPositionMap } from "../diff.js";

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIXTURES = path.join(__dirname, "../../test/fixtures/sample-diffs");

function loadDiff(name: string): string {
  return fs.readFileSync(path.join(FIXTURES, `${name}.txt`), "utf8");
}

// ---------------------------------------------------------------------------
// Acceptance criterion: buildDiffPositionMap produces correct position for
// line 1 of a new file (position=2, after @@ header).
// ---------------------------------------------------------------------------

describe("buildDiffPositionMap: position algorithm golden values", () => {
  it("line 1 of a new file has position 2 (the @@ header is position 1)", () => {
    const posMap = buildDiffPositionMap(loadDiff("addition-only"));
    const fileMap = posMap.get("src/main.js");
    expect(fileMap).toBeDefined();
    // @@ header = position 1 (not stored in map)
    // First line after header is always position 2.
    expect(fileMap!.get(1)).toBe(2);
  });

  it("addition lines map to correct ascending positions", () => {
    const posMap = buildDiffPositionMap(loadDiff("addition-only"));
    const fileMap = posMap.get("src/main.js")!;
    // @@ -1,3 +1,5 @@       → position 1 (header, not in map)
    //  const a = 1;          → position 2 (context, new-file line 1)
    // +const b = 2;          → position 3 (addition, new-file line 2)
    // +const c = 3;          → position 4 (addition, new-file line 3)
    //  const d = 4;          → position 5 (context, new-file line 4)
    expect(fileMap.get(1)).toBe(2);
    expect(fileMap.get(2)).toBe(3);
    expect(fileMap.get(3)).toBe(4);
    expect(fileMap.get(4)).toBe(5);
  });

  it("maps exactly 4 entries for the addition-only fixture", () => {
    const posMap = buildDiffPositionMap(loadDiff("addition-only"));
    const fileMap = posMap.get("src/main.js")!;
    // 4 content lines (1 context + 2 additions + 1 context) — @@ header not stored.
    expect(fileMap.size).toBe(4);
  });
});

// ---------------------------------------------------------------------------
// Deletion lines use negative keys.
// ---------------------------------------------------------------------------

describe("buildDiffPositionMap: deletion line encoding", () => {
  it("deletion lines are stored under negated old-file line numbers", () => {
    const posMap = buildDiffPositionMap(loadDiff("deletion-only"));
    const fileMap = posMap.get("src/utils.js")!;
    // @@ -1,5 +1,3 @@           → position 1 (not stored)
    //  function foo() {          → position 2 (ctx, new-line 1)   key: 1
    // -  const x = badValue();   → position 3 (del, old-line 2)   key: -2
    // -  return x;               → position 4 (del, old-line 3)   key: -3
    // +  return 0;               → position 5 (add, new-line 2)   key: 2
    //  }                         → position 6 (ctx, new-line 3)   key: 3
    expect(fileMap.get(1)).toBe(2);
    expect(fileMap.get(-2)).toBe(3);
    expect(fileMap.get(-3)).toBe(4);
    expect(fileMap.get(2)).toBe(5);
    expect(fileMap.get(3)).toBe(6);
  });

  it("positive and negative keys do not collide in the same map", () => {
    const posMap = buildDiffPositionMap(loadDiff("deletion-only"));
    const fileMap = posMap.get("src/utils.js")!;
    // new-file line 2 (addition) → position 5
    // old-file line 2 (deletion) → position 3 (stored as key -2)
    expect(fileMap.get(2)).toBe(5);
    expect(fileMap.get(-2)).toBe(3);
    expect(fileMap.get(2)).not.toBe(fileMap.get(-2));
  });
});

// ---------------------------------------------------------------------------
// Acceptance criterion: multi-file diff with correct per-file position reset.
// ---------------------------------------------------------------------------

describe("buildDiffPositionMap: multi-file diff position reset", () => {
  it("position counter resets to 0 at each diff --git header", () => {
    const posMap = buildDiffPositionMap(loadDiff("multi-file"));
    const alphaMap = posMap.get("src/alpha.js");
    const betaMap = posMap.get("src/beta.js");

    expect(alphaMap).toBeDefined();
    expect(betaMap).toBeDefined();
  });

  it("src/alpha.js positions start at 2 for its first content line", () => {
    const posMap = buildDiffPositionMap(loadDiff("multi-file"));
    const alphaMap = posMap.get("src/alpha.js")!;
    // @@ -1,3 +1,4 @@   → position 1 (not stored)
    //  const x = 1;     → position 2 (ctx, new-line 1)
    // +const y = 2;     → position 3 (add, new-line 2)
    //  const z = 3;     → position 4 (ctx, new-line 3)
    expect(alphaMap.get(1)).toBe(2);
    expect(alphaMap.get(2)).toBe(3);
    expect(alphaMap.get(3)).toBe(4);
  });

  it("src/beta.js has an independent position counter that also starts at 2", () => {
    const posMap = buildDiffPositionMap(loadDiff("multi-file"));
    const betaMap = posMap.get("src/beta.js")!;
    // @@ -10,3 +10,4 @@  → position 1 (not stored, counter reset independently)
    //  function init() { → position 2 (ctx, new-line 10)
    // +  setup();        → position 3 (add, new-line 11)
    //    run();          → position 4 (ctx, new-line 12)
    //  }                 → position 5 (ctx, new-line 13)
    expect(betaMap.get(10)).toBe(2);
    expect(betaMap.get(11)).toBe(3);
    expect(betaMap.get(12)).toBe(4);
    expect(betaMap.get(13)).toBe(5);
  });

  it("alpha and beta position maps are completely independent", () => {
    const posMap = buildDiffPositionMap(loadDiff("multi-file"));
    const alphaMap = posMap.get("src/alpha.js")!;
    const betaMap = posMap.get("src/beta.js")!;
    // Both have their second content line at position 3 — but they are
    // independent maps, not a cumulative counter across files.
    expect(alphaMap.get(2)).toBe(3);
    expect(betaMap.get(11)).toBe(3);
    // Alpha only goes to line 3; beta starts at line 10.
    expect(alphaMap.has(10)).toBe(false);
    expect(betaMap.has(1)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Binary file handling.
// ---------------------------------------------------------------------------

describe("buildDiffPositionMap: binary file handling", () => {
  it("binary file entry exists in posMap but has an empty inner map", () => {
    const posMap = buildDiffPositionMap(loadDiff("binary"));
    const binaryMap = posMap.get("assets/image.png");
    expect(binaryMap).toBeDefined();
    expect(binaryMap!.size).toBe(0);
  });

  it("text file following a binary section parses correctly", () => {
    const posMap = buildDiffPositionMap(loadDiff("binary"));
    const codeMap = posMap.get("src/code.js")!;
    // @@ -1,2 +1,3 @@ → position 1 (not stored)
    //  const a = 1;    → position 2 (ctx, new-line 1)
    // +const b = 2;   → position 3 (add, new-line 2)
    expect(codeMap.get(1)).toBe(2);
    expect(codeMap.get(2)).toBe(3);
  });
});

// ---------------------------------------------------------------------------
// Empty / edge case inputs.
// ---------------------------------------------------------------------------

describe("buildDiffPositionMap: edge cases", () => {
  it("empty diff string returns an empty map", () => {
    const posMap = buildDiffPositionMap("");
    expect(posMap.size).toBe(0);
  });

  it("diff with only a header line (no hunks) returns empty inner map", () => {
    const headerOnlyDiff = [
      "diff --git a/src/empty.js b/src/empty.js",
      "index 000000..000001 100644",
      "--- a/src/empty.js",
      "+++ b/src/empty.js",
    ].join("\n");
    const posMap = buildDiffPositionMap(headerOnlyDiff);
    const fileMap = posMap.get("src/empty.js");
    expect(fileMap).toBeDefined();
    expect(fileMap!.size).toBe(0);
  });

  it("CRLF line endings are handled the same as LF", () => {
    const crlfDiff = [
      "diff --git a/src/win.js b/src/win.js",
      "index 000000..000001 100644",
      "--- a/src/win.js",
      "+++ b/src/win.js",
      "@@ -1,1 +1,2 @@",
      " existing line",
      "+new line",
    ]
      .join("\r\n")
      .concat("\r\n");

    const posMap = buildDiffPositionMap(crlfDiff);
    const fileMap = posMap.get("src/win.js");
    expect(fileMap).toBeDefined();
    expect(fileMap!.get(1)).toBe(2);
    expect(fileMap!.get(2)).toBe(3);
  });

  it("strips optional +++ header metadata from file paths", () => {
    const diff = [
      "diff --git a/src/file with spaces.js b/src/file with spaces.js",
      "index 000000..000001 100644",
      "--- a/src/file with spaces.js\t2026-06-09 01:00:00 +0000",
      "+++ b/src/file with spaces.js\t2026-06-09 01:00:00 +0000",
      "@@ -1,1 +1,2 @@",
      " existing line",
      "+new line",
    ].join("\n");

    const posMap = buildDiffPositionMap(diff);
    expect(posMap.has("src/file with spaces.js")).toBe(true);
    expect(posMap.has("src/file with spaces.js\t2026-06-09 01:00:00 +0000")).toBe(false);
    expect(posMap.get("src/file with spaces.js")!.get(2)).toBe(3);
  });

  it("diff with two hunks correctly accumulates position across hunks", () => {
    // Hunk 1: lines 1-3. Hunk 2: lines 10-12.
    // The second @@ header continues the per-file position counter.
    const twoHunkDiff = [
      "diff --git a/src/multi-hunk.js b/src/multi-hunk.js",
      "index 000000..000001 100644",
      "--- a/src/multi-hunk.js",
      "+++ b/src/multi-hunk.js",
      "@@ -1,3 +1,3 @@",  // position 1
      " line 1",           // position 2 (new-line 1)
      "+line 2",           // position 3 (new-line 2)
      " line 3",           // position 4 (new-line 3)
      "@@ -10,2 +10,3 @@", // position 5 (second @@ header)
      " line 10",          // position 6 (new-line 10)
      "+line 11",          // position 7 (new-line 11)
      " line 12",          // position 8 (new-line 12)
    ].join("\n");

    const posMap = buildDiffPositionMap(twoHunkDiff);
    const fileMap = posMap.get("src/multi-hunk.js")!;
    expect(fileMap.get(1)).toBe(2);
    expect(fileMap.get(2)).toBe(3);
    expect(fileMap.get(3)).toBe(4);
    // Second hunk: position counter does NOT reset within the same file.
    expect(fileMap.get(10)).toBe(6);
    expect(fileMap.get(11)).toBe(7);
    expect(fileMap.get(12)).toBe(8);
  });
});

// ---------------------------------------------------------------------------
// fetchPRDiff — smoke test the error path (no network calls needed).
// ---------------------------------------------------------------------------

describe("fetchPRDiff: validation", () => {
  it("throws when the API response is not a string", async () => {
    const { fetchPRDiff } = await import("../diff.js");
    const mockOctokit = {
      async request(_route: string, _params: Record<string, unknown>) {
        return { data: 42 }; // number instead of string
      },
    };
    await expect(fetchPRDiff(mockOctokit, "owner", "repo", 1)).rejects.toThrow(
      "fetchPRDiff: expected string response"
    );
  });

  it("returns the raw diff string on success", async () => {
    const { fetchPRDiff } = await import("../diff.js");
    const fakeDiff = "diff --git a/f b/f\n";
    const mockOctokit = {
      async request(_route: string, _params: Record<string, unknown>) {
        return { data: fakeDiff };
      },
    };
    const result = await fetchPRDiff(mockOctokit, "owner", "repo", 1);
    expect(result).toBe(fakeDiff);
  });

  it("returns an empty string without throwing when the API returns an empty diff", async () => {
    const { fetchPRDiff } = await import("../diff.js");
    const mockOctokit = {
      async request(_route: string, _params: Record<string, unknown>) {
        return { data: "" };
      },
    };
    // Empty diff is valid (PR with no changes); should not throw.
    const result = await fetchPRDiff(mockOctokit, "owner", "repo", 42);
    expect(result).toBe("");
  });
});
