"use strict";

/**
 * Tests for S4 PATH A — diff impact analysis via bob_summarize_diff_impact.
 *
 * Verifies:
 *   - normaliseDiffImpactResult handles success shapes (flat and data-nested)
 *   - normaliseDiffImpactResult handles MCP error shapes
 *   - impacted_entries schema matches the required {file, line_start, line_end,
 *     surface_ids[], hunk_summary} shape
 *   - Empty impacted_entries is a valid success (is_empty flag is set)
 *   - logPathAActivation emits 'PATH A: diff impact via symbol index'
 *   - logPathASuccess emits 'S4 PATH A: N impacted entries from symbol index'
 *   - logNoImpactedSurfaces emits 'no impacted surfaces'
 *   - buildDiffImpactArtifact produces valid DiffImpactArtifact with path_used:'A'
 *   - formatS4FailureJson returns a parseable JSON string with step 'S4.path_a'
 */

const test = require("node:test");
const assert = require("node:assert/strict");

const {
  normaliseDiffImpactResult,
  formatS4FailureJson,
  logPathAActivation,
  logPathASuccess,
  logNoImpactedSurfaces,
  buildDiffImpactArtifact,
} = require("../packages/bob-diff-review/dist/diff-impact.js");

// ---------------------------------------------------------------------------
// normaliseDiffImpactResult — success paths
// ---------------------------------------------------------------------------

test("normaliseDiffImpactResult handles flat impacted_entries array", () => {
  const raw = {
    ok: true,
    impacted_entries: [
      {
        file: "src/auth/login.ts",
        line_start: 10,
        line_end: 25,
        surface_ids: ["auth:login-handler"],
        hunk_summary: "Added logout function",
      },
    ],
  };
  const result = normaliseDiffImpactResult(raw);
  assert.ok(result.ok, "result must be ok");
  assert.equal(result.entry_count, 1);
  assert.equal(result.is_empty, false);
  const entry = result.impacted_entries[0];
  assert.equal(entry.file, "src/auth/login.ts");
  assert.equal(entry.line_start, 10);
  assert.equal(entry.line_end, 25);
  assert.deepEqual(entry.surface_ids, ["auth:login-handler"]);
  assert.equal(entry.hunk_summary, "Added logout function");
});

test("normaliseDiffImpactResult handles data-nested impacted_entries", () => {
  const raw = {
    ok: true,
    data: {
      impacted_entries: [
        {
          file: "contracts/Token.sol",
          line_start: 5,
          line_end: 12,
          surface_ids: ["smart-contract:token"],
          hunk_summary: "Added maxSupply field",
        },
        {
          file: "src/routes/api.ts",
          line_start: 1,
          line_end: 30,
          surface_ids: ["api-route:users"],
          hunk_summary: "Added POST /users route",
        },
      ],
    },
  };
  const result = normaliseDiffImpactResult(raw);
  assert.ok(result.ok);
  assert.equal(result.entry_count, 2);
  assert.equal(result.is_empty, false);
});

test("normaliseDiffImpactResult accepts entries array key", () => {
  const raw = {
    data: {
      entries: [
        {
          file: "admin/settings.ts",
          line_start: 1,
          line_end: 5,
          surface_ids: ["admin:settings"],
          hunk_summary: "Changed admin config",
        },
      ],
    },
  };
  const result = normaliseDiffImpactResult(raw);
  assert.ok(result.ok);
  assert.equal(result.entry_count, 1);
});

test("normaliseDiffImpactResult produces empty impacted_entries on empty MCP result", () => {
  const raw = {
    ok: true,
    impacted_entries: [],
  };
  const result = normaliseDiffImpactResult(raw);
  assert.ok(result.ok);
  assert.equal(result.entry_count, 0);
  assert.equal(result.is_empty, true);
  assert.deepEqual(result.impacted_entries, []);
});

test("normaliseDiffImpactResult handles missing impacted_entries key as empty", () => {
  const raw = { ok: true };
  const result = normaliseDiffImpactResult(raw);
  assert.ok(result.ok);
  assert.equal(result.is_empty, true);
});

// ---------------------------------------------------------------------------
// normaliseDiffImpactResult — entry field aliases
// ---------------------------------------------------------------------------

test("normaliseDiffImpactResult handles start_line/end_line aliases", () => {
  const raw = {
    impacted_entries: [
      {
        file: "src/utils/crypto.ts",
        start_line: 3,
        end_line: 8,
        surface_ids: ["crypto:key-gen"],
        hunk_summary: "Added key derivation",
      },
    ],
  };
  const result = normaliseDiffImpactResult(raw);
  assert.ok(result.ok);
  const entry = result.impacted_entries[0];
  assert.equal(entry.line_start, 3);
  assert.equal(entry.line_end, 8);
});

test("normaliseDiffImpactResult handles raw MCP line alias", () => {
  const raw = {
    impacted_entries: [
      {
        file: "src/auth/login.ts",
        line: 12,
        surface_ids: ["auth:login"],
      },
    ],
  };
  const result = normaliseDiffImpactResult(raw);
  assert.equal(result.ok, true);
  if (!result.ok) throw new Error("expected success");
  assert.equal(result.impacted_entries[0].line_start, 12);
  assert.equal(result.impacted_entries[0].line_end, 12);
});

test("normaliseDiffImpactResult handles path alias for file", () => {
  const raw = {
    impacted_entries: [
      {
        path: "src/upload/handler.ts",
        line_start: 1,
        line_end: 20,
        surface_ids: ["upload:handler"],
        hunk_summary: "File upload refactor",
      },
    ],
  };
  const result = normaliseDiffImpactResult(raw);
  assert.ok(result.ok);
  assert.equal(result.impacted_entries[0].file, "src/upload/handler.ts");
});

test("normaliseDiffImpactResult generates hunk_summary fallback when missing", () => {
  const raw = {
    impacted_entries: [
      {
        file: "src/db/models.ts",
        line_start: 10,
        line_end: 15,
        surface_ids: ["data-model:user"],
      },
    ],
  };
  const result = normaliseDiffImpactResult(raw);
  assert.ok(result.ok);
  const entry = result.impacted_entries[0];
  assert.ok(
    typeof entry.hunk_summary === "string" && entry.hunk_summary.length > 0,
    "hunk_summary fallback must be a non-empty string"
  );
});

test("normaliseDiffImpactResult skips entries missing the file field", () => {
  const raw = {
    impacted_entries: [
      {
        line_start: 1,
        line_end: 5,
        surface_ids: ["auth:login"],
        hunk_summary: "No file field",
      },
      {
        file: "src/good.ts",
        line_start: 1,
        line_end: 5,
        surface_ids: ["api-route:good"],
        hunk_summary: "Valid entry",
      },
    ],
  };
  const result = normaliseDiffImpactResult(raw);
  assert.ok(result.ok);
  assert.equal(result.entry_count, 1, "malformed entries must be skipped");
  assert.equal(result.impacted_entries[0].file, "src/good.ts");
});

// ---------------------------------------------------------------------------
// normaliseDiffImpactResult — error paths
// ---------------------------------------------------------------------------

test("normaliseDiffImpactResult handles Error instance", () => {
  const err = new Error("MCP connection timeout");
  const result = normaliseDiffImpactResult(err);
  assert.equal(result.ok, false);
  assert.equal(result.error.code, "mcp_error");
  assert.ok(result.error.message.includes("timeout"));
});

test("normaliseDiffImpactResult handles object with error key", () => {
  const raw = {
    error: {
      code: "index_stale",
      message: "symbol-surface-index.json is older than 24h",
    },
  };
  const result = normaliseDiffImpactResult(raw);
  assert.equal(result.ok, false);
  assert.equal(result.error.code, "index_stale");
});

test("normaliseDiffImpactResult handles unexpected value type", () => {
  const result = normaliseDiffImpactResult(null);
  assert.equal(result.ok, false);
  assert.equal(result.error.code, "unknown");
});

test("normaliseDiffImpactResult handles string error value", () => {
  const result = normaliseDiffImpactResult("not a valid response");
  assert.equal(result.ok, false);
});

// ---------------------------------------------------------------------------
// Logging helpers — output content validation
// ---------------------------------------------------------------------------

test("logPathAActivation logs the exact required string", () => {
  const messages = [];
  const original = console.log;
  console.log = (...args) => messages.push(args.join(" "));
  try {
    logPathAActivation();
  } finally {
    console.log = original;
  }
  assert.ok(
    messages.some((m) => m === "PATH A: diff impact via symbol index"),
    `Expected 'PATH A: diff impact via symbol index', got: ${JSON.stringify(messages)}`
  );
});

test("logPathASuccess logs the entry count in the required format", () => {
  const messages = [];
  const original = console.log;
  console.log = (...args) => messages.push(args.join(" "));
  try {
    logPathASuccess(7);
  } finally {
    console.log = original;
  }
  assert.ok(
    messages.some((m) => m === "S4 PATH A: 7 impacted entries from symbol index"),
    `Expected 'S4 PATH A: 7 impacted entries from symbol index', got: ${JSON.stringify(messages)}`
  );
});

test("logNoImpactedSurfaces logs the required string", () => {
  const messages = [];
  const original = console.log;
  console.log = (...args) => messages.push(args.join(" "));
  try {
    logNoImpactedSurfaces();
  } finally {
    console.log = original;
  }
  assert.ok(
    messages.some((m) => m === "no impacted surfaces"),
    `Expected 'no impacted surfaces', got: ${JSON.stringify(messages)}`
  );
});

// ---------------------------------------------------------------------------
// buildDiffImpactArtifact
// ---------------------------------------------------------------------------

test("buildDiffImpactArtifact produces correct schema with path_used A", () => {
  const successResult = {
    ok: true,
    impacted_entries: [
      {
        file: "src/auth/login.ts",
        line_start: 1,
        line_end: 10,
        surface_ids: ["auth:login"],
        hunk_summary: "Login change",
      },
    ],
    entry_count: 1,
    is_empty: false,
  };
  const artifact = buildDiffImpactArtifact(successResult, "gh-12345678");
  assert.equal(artifact.schema_version, 1);
  assert.equal(artifact.target_domain, "gh-12345678");
  assert.equal(artifact.path_used, "A");
  assert.equal(artifact.entry_count, 1);
  assert.equal(artifact.impacted_entries.length, 1);
  assert.equal(artifact.impacted_entries[0].file, "src/auth/login.ts");
});

test("buildDiffImpactArtifact handles empty impacted_entries", () => {
  const successResult = {
    ok: true,
    impacted_entries: [],
    entry_count: 0,
    is_empty: true,
  };
  const artifact = buildDiffImpactArtifact(successResult, "gh-99999999");
  assert.equal(artifact.entry_count, 0);
  assert.deepEqual(artifact.impacted_entries, []);
  assert.equal(artifact.path_used, "A");
});

// ---------------------------------------------------------------------------
// formatS4FailureJson
// ---------------------------------------------------------------------------

test("formatS4FailureJson returns valid JSON with step S4.path_a", () => {
  const json = formatS4FailureJson({ code: "index_stale", message: "index too old" });
  const parsed = JSON.parse(json);
  assert.equal(parsed.step, "S4.path_a");
  assert.equal(parsed.ok, false);
  assert.equal(parsed.error.code, "index_stale");
  assert.equal(parsed.error.message, "index too old");
});

test("formatS4FailureJson produces pretty-printed JSON", () => {
  const json = formatS4FailureJson({ code: "mcp_error", message: "timeout" });
  assert.ok(json.includes("\n"), "should be pretty-printed with newlines");
});

// ---------------------------------------------------------------------------
// ImpactedEntry schema conformance (acceptance criterion)
// ---------------------------------------------------------------------------

test("each impacted_entry has the required fields: file, line_start, line_end, surface_ids[], hunk_summary", () => {
  const raw = {
    impacted_entries: [
      {
        file: "src/auth/session.ts",
        line_start: 20,
        line_end: 35,
        surface_ids: ["auth:session-manager", "crypto:hmac"],
        hunk_summary: "Refactored session token generation",
      },
    ],
  };
  const result = normaliseDiffImpactResult(raw);
  assert.ok(result.ok);
  const entry = result.impacted_entries[0];
  assert.ok(typeof entry.file === "string" && entry.file.length > 0, "file must be non-empty string");
  assert.ok(typeof entry.line_start === "number" && entry.line_start >= 1, "line_start must be positive number");
  assert.ok(typeof entry.line_end === "number" && entry.line_end >= 1, "line_end must be positive number");
  assert.ok(Array.isArray(entry.surface_ids), "surface_ids must be array");
  assert.ok(typeof entry.hunk_summary === "string", "hunk_summary must be string");
  assert.equal(entry.file, "src/auth/session.ts");
  assert.equal(entry.line_start, 20);
  assert.equal(entry.line_end, 35);
  assert.deepEqual(entry.surface_ids, ["auth:session-manager", "crypto:hmac"]);
});

test("surface_ids is always an array even when entry has surfaces alias", () => {
  const raw = {
    impacted_entries: [
      {
        file: "src/api/users.ts",
        line_start: 1,
        line_end: 10,
        surfaces: ["api-route:users"],
        hunk_summary: "Added user creation endpoint",
      },
    ],
  };
  const result = normaliseDiffImpactResult(raw);
  assert.ok(result.ok);
  assert.ok(Array.isArray(result.impacted_entries[0].surface_ids));
});
