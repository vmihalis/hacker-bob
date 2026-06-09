"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const { parseUnifiedDiff } = require("../mcp/lib/unified-diff-parser.js");

const SIMPLE_DIFF = `diff --git a/src/users.js b/src/users.js
index 1111111..2222222 100644
--- a/src/users.js
+++ b/src/users.js
@@ -1,4 +1,5 @@
 const express = require('express');
 const app = express();
 app.get('/users', listUsers);
+app.post('/users', createUser);
 module.exports = app;
`;

const MULTI_FILE_DIFF = `diff --git a/a.js b/a.js
--- a/a.js
+++ b/a.js
@@ -10,3 +10,4 @@
 line10
 line11
 line12
+line13_added
diff --git a/b.py b/b.py
--- a/b.py
+++ b/b.py
@@ -1,2 +1,3 @@
 def foo():
+    return 1
     pass
`;

const NEW_FILE_DIFF = `diff --git a/c.js b/c.js
new file mode 100644
--- /dev/null
+++ b/c.js
@@ -0,0 +1,3 @@
+line1
+line2
+line3
`;

const DELETED_FILE_DIFF = `diff --git a/d.js b/d.js
deleted file mode 100644
--- a/d.js
+++ /dev/null
@@ -1,2 +0,0 @@
-old1
-old2
`;

test("parseUnifiedDiff extracts file + added line range from a single-hunk diff", () => {
  const result = parseUnifiedDiff(SIMPLE_DIFF);
  assert.equal(result.file_count, 1);
  assert.equal(result.diff_files[0].file, "src/users.js");
  assert.deepEqual(result.diff_files[0].line_ranges, [{ start: 4, end: 4 }]);
  assert.equal(result.diff_files[0].added_lines, 1);
  assert.equal(result.diff_files[0].removed_lines, 0);
  assert.equal(result.total_added_lines, 1);
  assert.equal(result.total_removed_lines, 0);
});

test("parseUnifiedDiff handles multi-file diffs with sorted, deterministic output", () => {
  const result = parseUnifiedDiff(MULTI_FILE_DIFF);
  assert.equal(result.file_count, 2);
  assert.equal(result.diff_files[0].file, "a.js");
  assert.equal(result.diff_files[1].file, "b.py");
  assert.deepEqual(result.diff_files[0].line_ranges, [{ start: 13, end: 13 }]);
  assert.deepEqual(result.diff_files[1].line_ranges, [{ start: 2, end: 2 }]);
});

test("parseUnifiedDiff captures new files (--- /dev/null + +++ b/path)", () => {
  const result = parseUnifiedDiff(NEW_FILE_DIFF);
  assert.equal(result.file_count, 1);
  assert.equal(result.diff_files[0].file, "c.js");
  assert.deepEqual(result.diff_files[0].line_ranges, [{ start: 1, end: 3 }]);
  assert.equal(result.diff_files[0].added_lines, 3);
});

test("parseUnifiedDiff captures deleted files (--- a/path + +++ /dev/null) under the deleted file path", () => {
  const result = parseUnifiedDiff(DELETED_FILE_DIFF);
  assert.equal(result.file_count, 1);
  assert.equal(result.diff_files[0].file, "d.js");
  assert.equal(result.diff_files[0].removed_lines, 2);
  assert.deepEqual(result.diff_files[0].line_ranges, [{ start: 1, end: Number.MAX_SAFE_INTEGER }]);
});

test("parseUnifiedDiff gives deletion-only hunks a file-wide fallback range", () => {
  const diff = `diff --git a/src/auth/login.ts b/src/auth/login.ts
--- a/src/auth/login.ts
+++ b/src/auth/login.ts
@@ -10,3 +10,2 @@
 line10
-authCheck()
 line12
`;
  const result = parseUnifiedDiff(diff);
  assert.equal(result.file_count, 1);
  assert.equal(result.diff_files[0].file, "src/auth/login.ts");
  assert.equal(result.diff_files[0].added_lines, 0);
  assert.equal(result.diff_files[0].removed_lines, 1);
  assert.deepEqual(result.diff_files[0].line_ranges, [{ start: 1, end: Number.MAX_SAFE_INTEGER }]);
});

test("parseUnifiedDiff merges adjacent added line ranges into one continuous range", () => {
  const diff = `--- a/x.js
+++ b/x.js
@@ -1,3 +1,5 @@
 a
+b
+c
+d
 e
`;
  const result = parseUnifiedDiff(diff);
  assert.deepEqual(result.diff_files[0].line_ranges, [{ start: 2, end: 4 }]);
});

test("parseUnifiedDiff returns empty diff_files for an empty input", () => {
  const result = parseUnifiedDiff("");
  assert.equal(result.file_count, 0);
  assert.deepEqual(result.diff_files, []);
});

test("parseUnifiedDiff rejects non-string input", () => {
  assert.throws(() => parseUnifiedDiff(null), /rawDiff/);
  assert.throws(() => parseUnifiedDiff({}), /rawDiff/);
});

test("parseUnifiedDiff handles multi-hunk same-file diffs and merges per file", () => {
  const diff = `--- a/multi.js
+++ b/multi.js
@@ -10,2 +10,3 @@
 ten
+eleven
 eleven_after
@@ -50,2 +51,3 @@
 fifty
+fifty_one
 fifty_two
`;
  const result = parseUnifiedDiff(diff);
  assert.equal(result.diff_files[0].file, "multi.js");
  assert.equal(result.diff_files[0].line_ranges.length, 2);
  assert.equal(result.diff_files[0].line_ranges[0].start, 11);
  assert.equal(result.diff_files[0].line_ranges[1].start, 52);
});
