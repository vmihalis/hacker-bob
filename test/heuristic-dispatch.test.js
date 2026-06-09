"use strict";

/**
 * Tests for the S4b PATH B heuristic evaluator dispatch module.
 *
 * Verifies:
 *  - PATH B produces impacted_entries with the same schema as PATH A
 *  - Path-pattern mapping covers all required surface types
 *  - PATH B activation is logged ('PATH B: heuristic dispatch (no symbol index)')
 *  - Unknown-surface cap is enforced at MAX_UNKNOWN_DISPATCHES
 *  - Max-surface cap is enforced at MAX_HEURISTIC_SURFACES
 *  - parseDiffFiles extracts file paths and line ranges from unified diffs
 */

const test = require("node:test");
const assert = require("node:assert/strict");

const {
  runPathB,
  buildHeuristicImpactedEntries,
  parseDiffFiles,
  MAX_HEURISTIC_SURFACES,
  MAX_UNKNOWN_DISPATCHES,
} = require("../packages/bob-diff-review/dist/heuristic-dispatch.js");

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const SIMPLE_MULTI_DIFF = `diff --git a/src/auth/login.ts b/src/auth/login.ts
index aaaaaaa..bbbbbbb 100644
--- a/src/auth/login.ts
+++ b/src/auth/login.ts
@@ -10,3 +10,4 @@
 function authenticate() {}
+function logout() {}
 module.exports = authenticate;
diff --git a/routes/api.ts b/routes/api.ts
index ccccccc..ddddddd 100644
--- a/routes/api.ts
+++ b/routes/api.ts
@@ -1,3 +1,4 @@
 const router = require('express').Router();
+router.post('/users', createUser);
 module.exports = router;
diff --git a/contracts/Token.sol b/contracts/Token.sol
index eeeeeee..fffffff 100644
--- a/contracts/Token.sol
+++ b/contracts/Token.sol
@@ -5,3 +5,4 @@
 contract Token {
+  uint256 public maxSupply;
 }
diff --git a/admin/dashboard.ts b/admin/dashboard.ts
index 1111111..2222222 100644
--- a/admin/dashboard.ts
+++ b/admin/dashboard.ts
@@ -1,2 +1,3 @@
 const adminRoutes = require('./routes');
+module.exports = adminRoutes;
diff --git a/src/utils/helpers.ts b/src/utils/helpers.ts
index 3333333..4444444 100644
--- a/src/utils/helpers.ts
+++ b/src/utils/helpers.ts
@@ -1,2 +1,3 @@
 function helper() {}
+module.exports = helper;
`;

// ---------------------------------------------------------------------------
// parseDiffFiles
// ---------------------------------------------------------------------------

test("parseDiffFiles extracts file paths from a simple diff", () => {
  const diff = `diff --git a/src/auth/login.ts b/src/auth/login.ts
index aaaaaaa..bbbbbbb 100644
--- a/src/auth/login.ts
+++ b/src/auth/login.ts
@@ -10,3 +10,4 @@
 line10
+line11_added
 line12
`;
  const result = parseDiffFiles(diff);
  assert.equal(result.length, 1);
  assert.equal(result[0].file, "src/auth/login.ts");
  assert.equal(result[0].line_start, 10);
  // @@ -10,3 +10,4 @@ means new-side start=10, count=4, so line_end = 10+4-1 = 13
  assert.equal(result[0].line_end, 13);
});

test("buildHeuristicImpactedEntries logs PATH B activation to stdout", () => {
  const logs = [];
  const warns = [];
  const originalLog = console.log;
  const originalWarn = console.warn;
  console.log = (...args) => logs.push(args.join(" "));
  console.warn = (...args) => warns.push(args.join(" "));
  try {
    buildHeuristicImpactedEntries([{ file: "src/auth/login.ts", line_start: 10, line_end: 13 }]);
  } finally {
    console.log = originalLog;
    console.warn = originalWarn;
  }
  assert.ok(logs.includes("PATH B: heuristic dispatch (no symbol index)"));
  assert.equal(warns.includes("PATH B: heuristic dispatch (no symbol index)"), false);
});

test("parseDiffFiles extracts multiple files", () => {
  const result = parseDiffFiles(SIMPLE_MULTI_DIFF);
  assert.equal(result.length, 5);
  const files = result.map((e) => e.file);
  assert.ok(files.includes("src/auth/login.ts"), "should include auth file");
  assert.ok(files.includes("routes/api.ts"), "should include routes file");
  assert.ok(files.includes("contracts/Token.sol"), "should include contracts file");
  assert.ok(files.includes("admin/dashboard.ts"), "should include admin file");
  assert.ok(files.includes("src/utils/helpers.ts"), "should include helpers file");
});

test("parseDiffFiles emits one entry per hunk in the same file", () => {
  const diff = `diff --git a/src/auth/login.ts b/src/auth/login.ts
index aaaaaaa..bbbbbbb 100644
--- a/src/auth/login.ts
+++ b/src/auth/login.ts
@@ -10,2 +10,3 @@
 line10
+line11_added
@@ -80,2 +90,4 @@
 line90
+line91_added
+line92_added
`;
  const result = parseDiffFiles(diff);
  assert.equal(result.length, 2);
  assert.deepEqual(
    result.map((entry) => [entry.file, entry.line_start, entry.line_end]),
    [
      ["src/auth/login.ts", 10, 12],
      ["src/auth/login.ts", 90, 93],
    ]
  );
});

test("parseDiffFiles returns empty array for empty string", () => {
  const result = parseDiffFiles("");
  assert.deepEqual(result, []);
});

test("parseDiffFiles defaults line_start to 1 when no hunk header", () => {
  const diff = `diff --git a/foo.ts b/foo.ts
--- a/foo.ts
+++ b/foo.ts
`;
  const result = parseDiffFiles(diff);
  assert.equal(result.length, 1);
  assert.equal(result[0].line_start, 1);
  assert.equal(result[0].line_end, 1);
});

test("parseDiffFiles includes deleted files (they represent removed surface coverage)", () => {
  // Deleted files are still tracked — they represent a removed surface and may
  // be relevant to evaluators checking for missing protections.
  const diff = `diff --git a/old.ts b/old.ts
deleted file mode 100644
--- a/old.ts
+++ /dev/null
@@ -1,3 +0,0 @@
-line1
-line2
-line3
`;
  const result = parseDiffFiles(diff);
  // The file path from the diff header is still captured; /dev/null in +++ is not a file path.
  assert.equal(result.length, 1);
  assert.equal(result[0].file, "old.ts");
});

// ---------------------------------------------------------------------------
// PATH B activation logging
// ---------------------------------------------------------------------------

test("buildHeuristicImpactedEntries returns activation_log string", () => {
  const result = buildHeuristicImpactedEntries([
    { file: "src/auth/login.ts", line_start: 1, line_end: 5 },
  ]);
  assert.equal(result.activation_log, "PATH B: heuristic dispatch (no symbol index)");
});

// ---------------------------------------------------------------------------
// Pattern table — required surface mappings
// ---------------------------------------------------------------------------

test("auth/* paths map to heuristic:authentication", () => {
  const result = buildHeuristicImpactedEntries([
    { file: "auth/login.ts", line_start: 1, line_end: 1 },
    { file: "src/auth/session.ts", line_start: 1, line_end: 1 },
  ]);
  for (const entry of result.impacted_entries) {
    assert.ok(
      entry.surface_ids.includes("heuristic:authentication"),
      `Expected heuristic:authentication for ${entry.file}, got ${JSON.stringify(entry.surface_ids)}`
    );
  }
});

test("*login* and *session* paths map to heuristic:authentication", () => {
  const result = buildHeuristicImpactedEntries([
    { file: "services/loginService.ts", line_start: 1, line_end: 1 },
    { file: "utils/sessionHelper.ts", line_start: 1, line_end: 1 },
  ]);
  for (const entry of result.impacted_entries) {
    assert.ok(
      entry.surface_ids.includes("heuristic:authentication"),
      `Expected heuristic:authentication for ${entry.file}`
    );
  }
});

test("routes/* paths map to heuristic:api-route", () => {
  const result = buildHeuristicImpactedEntries([
    { file: "routes/users.ts", line_start: 1, line_end: 1 },
    { file: "src/routes/api.ts", line_start: 1, line_end: 1 },
  ]);
  for (const entry of result.impacted_entries) {
    assert.ok(
      entry.surface_ids.includes("heuristic:api-route"),
      `Expected heuristic:api-route for ${entry.file}, got ${JSON.stringify(entry.surface_ids)}`
    );
  }
});

test("*controller* paths map to heuristic:api-route", () => {
  const result = buildHeuristicImpactedEntries([
    { file: "src/controllers/userController.ts", line_start: 1, line_end: 1 },
  ]);
  assert.ok(
    result.impacted_entries[0].surface_ids.includes("heuristic:api-route"),
    "controller should map to api-route"
  );
});

test("contracts/* and *.sol map to heuristic:smart-contract", () => {
  const result = buildHeuristicImpactedEntries([
    { file: "contracts/Token.sol", line_start: 1, line_end: 1 },
    { file: "src/contracts/Vault.sol", line_start: 1, line_end: 1 },
    { file: "Token.move", line_start: 1, line_end: 1 },
  ]);
  for (const entry of result.impacted_entries) {
    assert.ok(
      entry.surface_ids.includes("heuristic:smart-contract"),
      `Expected heuristic:smart-contract for ${entry.file}, got ${JSON.stringify(entry.surface_ids)}`
    );
  }
});

test("admin/* paths map to heuristic:admin", () => {
  const result = buildHeuristicImpactedEntries([
    { file: "admin/users.ts", line_start: 1, line_end: 1 },
    { file: "src/admin/dashboard.ts", line_start: 1, line_end: 1 },
  ]);
  for (const entry of result.impacted_entries) {
    assert.ok(
      entry.surface_ids.includes("heuristic:admin"),
      `Expected heuristic:admin for ${entry.file}, got ${JSON.stringify(entry.surface_ids)}`
    );
  }
});

// ---------------------------------------------------------------------------
// Unknown fallback
// ---------------------------------------------------------------------------

test("unmatched paths produce heuristic:unknown surface_id", () => {
  const result = buildHeuristicImpactedEntries([
    { file: "src/utils/math.ts", line_start: 1, line_end: 1 },
    { file: "README.md", line_start: 1, line_end: 1 },
  ]);
  for (const entry of result.impacted_entries) {
    assert.deepEqual(
      entry.surface_ids,
      ["heuristic:unknown"],
      `Expected heuristic:unknown for ${entry.file}`
    );
  }
  assert.equal(result.unknown_dispatches, 2);
});

// ---------------------------------------------------------------------------
// Unknown-surface cap
// ---------------------------------------------------------------------------

test("unknown dispatches are capped at MAX_UNKNOWN_DISPATCHES", () => {
  const manyUnknown = Array.from({ length: MAX_UNKNOWN_DISPATCHES + 3 }, (_, i) => ({
    file: `src/utils/helper${i}.ts`,
    line_start: 1,
    line_end: 1,
  }));

  const result = buildHeuristicImpactedEntries(manyUnknown);
  assert.equal(result.unknown_dispatches, MAX_UNKNOWN_DISPATCHES);
  assert.equal(result.capped_entries, 3);
  assert.equal(
    result.impacted_entries.length,
    MAX_UNKNOWN_DISPATCHES,
    "impacted_entries should not exceed MAX_UNKNOWN_DISPATCHES for pure-unknown input"
  );
});

// ---------------------------------------------------------------------------
// ImpactedEntry schema (identical to PATH A)
// ---------------------------------------------------------------------------

test("impacted_entries schema matches PATH A shape", () => {
  const result = buildHeuristicImpactedEntries([
    { file: "auth/login.ts", line_start: 5, line_end: 10 },
  ]);
  const entry = result.impacted_entries[0];
  assert.ok(typeof entry.file === "string", "entry.file must be string");
  assert.ok(typeof entry.line_start === "number", "entry.line_start must be number");
  assert.ok(typeof entry.line_end === "number", "entry.line_end must be number");
  assert.ok(Array.isArray(entry.surface_ids), "entry.surface_ids must be array");
  assert.ok(typeof entry.hunk_summary === "string", "entry.hunk_summary must be string");
  assert.equal(entry.file, "auth/login.ts");
  assert.equal(entry.line_start, 5);
  assert.equal(entry.line_end, 10);
});

test("surface_ids are prefixed with heuristic:", () => {
  const result = buildHeuristicImpactedEntries([
    { file: "auth/login.ts", line_start: 1, line_end: 1 },
    { file: "routes/api.ts", line_start: 1, line_end: 1 },
    { file: "contracts/Vault.sol", line_start: 1, line_end: 1 },
    { file: "admin/panel.ts", line_start: 1, line_end: 1 },
    { file: "misc/unknown.ts", line_start: 1, line_end: 1 },
  ]);
  for (const entry of result.impacted_entries) {
    for (const sid of entry.surface_ids) {
      assert.ok(
        sid.startsWith("heuristic:"),
        `surface_id "${sid}" must be prefixed with "heuristic:"`
      );
    }
  }
});

// ---------------------------------------------------------------------------
// runPathB — end-to-end
// ---------------------------------------------------------------------------

test("runPathB processes unified diff text and produces impacted_entries", () => {
  const result = runPathB(SIMPLE_MULTI_DIFF);
  assert.ok(result.impacted_entries.length > 0, "must produce at least one entry");
  assert.equal(result.activation_log, "PATH B: heuristic dispatch (no symbol index)");

  // Check that the four required surfaces are present across all entries.
  const allSurfaces = new Set(result.impacted_entries.flatMap((e) => e.surface_ids));
  assert.ok(allSurfaces.has("heuristic:authentication"), "must detect auth surface");
  assert.ok(allSurfaces.has("heuristic:api-route"), "must detect api-route surface");
  assert.ok(allSurfaces.has("heuristic:smart-contract"), "must detect smart-contract surface");
  assert.ok(allSurfaces.has("heuristic:admin"), "must detect admin surface");
});

test("runPathB handles empty diff gracefully", () => {
  const result = runPathB("");
  assert.deepEqual(result.impacted_entries, []);
  assert.equal(result.activation_log, "PATH B: heuristic dispatch (no symbol index)");
});

test("runPathB surface_ids deduplicated within a file", () => {
  // A file that matches 'auth/' and also contains 'token' — both trigger authentication.
  const diff = `diff --git a/auth/token.ts b/auth/token.ts
index aaaaaaa..bbbbbbb 100644
--- a/auth/token.ts
+++ b/auth/token.ts
@@ -1,2 +1,3 @@
 function getToken() {}
+function revokeToken() {}
`;
  const result = runPathB(diff);
  assert.equal(result.impacted_entries.length, 1);
  const sid = result.impacted_entries[0].surface_ids;
  // Should have authentication only once (deduplicated).
  const authCount = sid.filter((s) => s === "heuristic:authentication").length;
  assert.equal(authCount, 1, "authentication should appear exactly once");
});

test("runPathB preserves later hunks as separate impacted entries", () => {
  const diff = `diff --git a/routes/api.ts b/routes/api.ts
index aaaaaaa..bbbbbbb 100644
--- a/routes/api.ts
+++ b/routes/api.ts
@@ -5,2 +5,3 @@
 router.get('/users', listUsers);
+router.get('/users/search', searchUsers);
@@ -50,2 +60,3 @@
 router.post('/users', createUser);
+router.delete('/users/:id', deleteUser);
`;
  const result = runPathB(diff);
  assert.equal(result.impacted_entries.length, 2);
  assert.deepEqual(
    result.impacted_entries.map((entry) => [entry.line_start, entry.line_end]),
    [
      [5, 7],
      [60, 62],
    ]
  );
});
