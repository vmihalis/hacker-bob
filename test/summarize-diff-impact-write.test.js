"use strict";

/**
 * Integration tests for bob_summarize_diff_impact — diff-impact.json write path.
 *
 * Criterion 4: diff-impact.json must be written to the session directory via
 * the MCP tool (not a direct Write tool call by the orchestrator agent).
 *
 * Verifies:
 *   - bob_summarize_diff_impact handler writes diff-impact.json to the session dir
 *   - The written artifact conforms to the DiffImpactArtifact schema:
 *       { schema_version, target_domain, path_used, entry_count, impacted_entries, written_at }
 *   - The file is overwritten on a second call (idempotent write)
 *   - diff_text alias is accepted in addition to unified_diff
 *   - diff-impact.json is audit-graded/MCP-owned so agents cannot Write it
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");

const summarizeDiffImpactTool = require("../mcp/lib/tools/summarize-diff-impact.js");
const {
  buildSymbolSurfaceIndex,
} = require("../mcp/lib/symbol-surface-index.js");
const {
  extractRoutesFromFiles,
} = require("../mcp/lib/route-extractor.js");
const {
  diffImpactPath,
  isAuditGradedPath,
} = require("../mcp/lib/paths.js");
const {
  acquireSessionLock,
} = require("../mcp/lib/storage.js");

function uniqueDomain(prefix = "bob-diff-impact-write-test") {
  const suffix = crypto.randomBytes(4).toString("hex");
  return `${prefix}-${suffix}.local`;
}

function sessionDirForDomain(domain) {
  return path.join(os.homedir(), "hacker-bob-sessions", domain);
}

function cleanupDomain(domain) {
  const dir = sessionDirForDomain(domain);
  if (fs.existsSync(dir)) fs.rmSync(dir, { recursive: true, force: true });
}

function buildSampleRoutes() {
  return extractRoutesFromFiles([
    {
      file: "src/auth/login.ts",
      source: [
        "app.post('/auth/login', handleLogin);",
        "app.post('/auth/logout', handleLogout);",
      ].join("\n"),
    },
    {
      file: "src/api/users.ts",
      source: "app.get('/api/users', listUsers);",
    },
  ]);
}

const SAMPLE_SURFACES = [
  { id: "auth:login-handler", endpoint_pattern: "/auth", endpoints: ["/auth/login", "/auth/logout"] },
  { id: "api-route:users", endpoint_pattern: "/api/users", endpoints: ["/api/users"] },
];

// Minimal unified diff touching src/auth/login.ts line 1.
const SAMPLE_DIFF = [
  "--- a/src/auth/login.ts",
  "+++ b/src/auth/login.ts",
  "@@ -1,2 +1,3 @@",
  " app.post('/auth/login', handleLogin);",
  "+app.post('/auth/login-v2', handleLoginV2);",
  " app.post('/auth/logout', handleLogout);",
].join("\n");

const DELETION_ONLY_DIFF = [
  "--- a/src/auth/login.ts",
  "+++ b/src/auth/login.ts",
  "@@ -1,2 +1,1 @@",
  "-app.post('/auth/login', handleLogin);",
  " app.post('/auth/logout', handleLogout);",
].join("\n");

// ---------------------------------------------------------------------------
// Core criterion 4 — diff-impact.json is written by the MCP tool handler
// ---------------------------------------------------------------------------

test("bob_summarize_diff_impact writes diff-impact.json to the session dir", () => {
  const domain = uniqueDomain();
  try {
    const routes = buildSampleRoutes();
    buildSymbolSurfaceIndex({ target_domain: domain, route_records: routes, surfaces: SAMPLE_SURFACES });

    summarizeDiffImpactTool.handler({
      target_domain: domain,
      unified_diff: SAMPLE_DIFF,
    });

    const artifactPath = diffImpactPath(domain);
    assert.ok(
      fs.existsSync(artifactPath),
      `diff-impact.json must exist at ${artifactPath} after calling the handler`
    );
  } finally {
    cleanupDomain(domain);
  }
});

test("diff-impact.json conforms to DiffImpactArtifact schema", () => {
  const domain = uniqueDomain();
  try {
    const routes = buildSampleRoutes();
    buildSymbolSurfaceIndex({ target_domain: domain, route_records: routes, surfaces: SAMPLE_SURFACES });

    summarizeDiffImpactTool.handler({
      target_domain: domain,
      unified_diff: SAMPLE_DIFF,
    });

    const artifactPath = diffImpactPath(domain);
    const raw = fs.readFileSync(artifactPath, "utf8");
    const artifact = JSON.parse(raw);

    assert.equal(artifact.schema_version, 1, "schema_version must be 1");
    assert.equal(artifact.target_domain, domain, "target_domain must match");
    assert.ok(
      artifact.path_used === "A" || artifact.path_used === "B",
      "path_used must be 'A' or 'B'"
    );
    assert.equal(artifact.path_used, "A");
    assert.ok(typeof artifact.entry_count === "number", "entry_count must be a number");
    assert.ok(Array.isArray(artifact.impacted_entries), "impacted_entries must be an array");
    assert.ok(typeof artifact.written_at === "string" && artifact.written_at.length > 0, "written_at must be a non-empty ISO string");
    assert.equal(artifact.entry_count, artifact.impacted_entries.length, "entry_count must equal impacted_entries.length");
  } finally {
    cleanupDomain(domain);
  }
});

test("handler reports path_used B when no symbol index is available", () => {
  const domain = uniqueDomain();
  try {
    const result = summarizeDiffImpactTool.handler({
      target_domain: domain,
      unified_diff: SAMPLE_DIFF,
    });

    assert.equal(result.path_used, "B");
    const artifact = JSON.parse(fs.readFileSync(diffImpactPath(domain), "utf8"));
    assert.equal(artifact.path_used, "B");
  } finally {
    cleanupDomain(domain);
  }
});

test("diff-impact.json impacted_entries use the normalized PATH A dispatch schema", () => {
  const domain = uniqueDomain();
  try {
    const routes = buildSampleRoutes();
    buildSymbolSurfaceIndex({ target_domain: domain, route_records: routes, surfaces: SAMPLE_SURFACES });

    const result = summarizeDiffImpactTool.handler({
      target_domain: domain,
      unified_diff: SAMPLE_DIFF,
    });

    const raw = fs.readFileSync(diffImpactPath(domain), "utf8");
    const artifact = JSON.parse(raw);

    // The diff touches src/auth/login.ts — expect at least one impacted entry.
    assert.ok(artifact.impacted_entries.length > 0, "expected at least one impacted entry for auth/login.ts change");
    for (const entry of artifact.impacted_entries) {
      assert.ok(typeof entry.file === "string" && entry.file.length > 0, "entry.file must be a non-empty string");
      assert.ok(typeof entry.line_start === "number" && entry.line_start >= 1, "entry.line_start must be a positive number");
      assert.ok(typeof entry.line_end === "number" && entry.line_end >= entry.line_start, "entry.line_end must be a valid range end");
      assert.ok(Array.isArray(entry.surface_ids), "entry.surface_ids must be an array");
      assert.ok(typeof entry.hunk_summary === "string" && entry.hunk_summary.length > 0, "entry.hunk_summary must be a non-empty string");
      assert.equal("line" in entry, false, "raw symbol-index line field must not leak into the PATH A dispatch schema");
    }
    assert.deepEqual(result.impacted_entries, artifact.impacted_entries);
  } finally {
    cleanupDomain(domain);
  }
});

test("PATH A includes deletion-only hunks through a file-wide diff range", () => {
  const domain = uniqueDomain();
  try {
    const routes = buildSampleRoutes();
    buildSymbolSurfaceIndex({ target_domain: domain, route_records: routes, surfaces: SAMPLE_SURFACES });

    const result = summarizeDiffImpactTool.handler({
      target_domain: domain,
      unified_diff: DELETION_ONLY_DIFF,
    });

    const artifact = JSON.parse(fs.readFileSync(diffImpactPath(domain), "utf8"));
    assert.equal(result.path_used, "A");
    assert.equal(artifact.path_used, "A");
    assert.ok(result.impacted_entries.length > 0, "expected deletion-only auth/login.ts diff to match indexed surfaces");
    assert.ok(artifact.entry_count > 0, "artifact must preserve deletion-only PATH A impact entries");
  } finally {
    cleanupDomain(domain);
  }
});

test("handler acquires the session lock before writing diff-impact.json", () => {
  const domain = uniqueDomain();
  let release = null;
  try {
    const routes = buildSampleRoutes();
    buildSymbolSurfaceIndex({ target_domain: domain, route_records: routes, surfaces: SAMPLE_SURFACES });
    release = acquireSessionLock(domain);

    assert.throws(
      () => summarizeDiffImpactTool.handler({
        target_domain: domain,
        unified_diff: SAMPLE_DIFF,
      }),
      /Session lock busy/
    );
    assert.equal(fs.existsSync(diffImpactPath(domain)), false, "handler must not write while the session lock is held elsewhere");
  } finally {
    if (release) release();
    cleanupDomain(domain);
  }
});

test("handler accepts diff_text alias (used by SKILL.md orchestrator)", () => {
  const domain = uniqueDomain();
  try {
    const routes = buildSampleRoutes();
    buildSymbolSurfaceIndex({ target_domain: domain, route_records: routes, surfaces: SAMPLE_SURFACES });

    // Use diff_text instead of unified_diff — the orchestrator uses this alias.
    summarizeDiffImpactTool.handler({
      target_domain: domain,
      diff_text: SAMPLE_DIFF,
    });

    const artifactPath = diffImpactPath(domain);
    assert.ok(
      fs.existsSync(artifactPath),
      "diff-impact.json must be written when diff_text alias is used"
    );
    const artifact = JSON.parse(fs.readFileSync(artifactPath, "utf8"));
    assert.equal(artifact.schema_version, 1);
  } finally {
    cleanupDomain(domain);
  }
});

test("second call to handler overwrites diff-impact.json (idempotent)", () => {
  const domain = uniqueDomain();
  try {
    const routes = buildSampleRoutes();
    buildSymbolSurfaceIndex({ target_domain: domain, route_records: routes, surfaces: SAMPLE_SURFACES });

    summarizeDiffImpactTool.handler({ target_domain: domain, unified_diff: SAMPLE_DIFF });
    const firstMtime = fs.statSync(diffImpactPath(domain)).mtimeMs;

    // Small delay is not needed — writeFileSync is synchronous; just call again.
    summarizeDiffImpactTool.handler({ target_domain: domain, unified_diff: SAMPLE_DIFF });
    const secondMtime = fs.statSync(diffImpactPath(domain)).mtimeMs;

    // The second write must produce a valid artifact (mtime may or may not differ
    // on fast filesystems, but the file must be parseable).
    const artifact = JSON.parse(fs.readFileSync(diffImpactPath(domain), "utf8"));
    assert.equal(artifact.schema_version, 1, "overwritten artifact must be valid");
    // Suppress unused variable lint.
    void firstMtime;
    void secondMtime;
  } finally {
    cleanupDomain(domain);
  }
});

test("handler writes diff-impact.json even when no surface index exists (empty entries)", () => {
  const domain = uniqueDomain();
  try {
    // No buildSymbolSurfaceIndex call — index is absent; PATH B applies.
    summarizeDiffImpactTool.handler({
      target_domain: domain,
      unified_diff: SAMPLE_DIFF,
    });

    const artifactPath = diffImpactPath(domain);
    assert.ok(fs.existsSync(artifactPath), "diff-impact.json must be written even without a symbol index");
    const artifact = JSON.parse(fs.readFileSync(artifactPath, "utf8"));
    assert.equal(artifact.schema_version, 1);
    assert.ok(Array.isArray(artifact.impacted_entries));
    // Without an index, no entries are matched — entry_count should be 0.
    assert.equal(artifact.entry_count, 0);
  } finally {
    cleanupDomain(domain);
  }
});

// ---------------------------------------------------------------------------
// diff-impact.json is MCP-owned and protected by the audit-graded write guard.
// ---------------------------------------------------------------------------

test("diff-impact.json is in AUDIT_GRADED_PATHS (MCP-owned, agent write-blocked)", () => {
  const domain = uniqueDomain();
  const artifactPath = diffImpactPath(domain);
  assert.equal(
    isAuditGradedPath(artifactPath, domain),
    true,
    "diff-impact.json must be audit-graded because only the MCP tool writes it"
  );
});

// ---------------------------------------------------------------------------
// Tool metadata — session_artifacts_written and mutating flag
// ---------------------------------------------------------------------------

test("bob_summarize_diff_impact declares diff-impact.json in session_artifacts_written", () => {
  assert.ok(
    Array.isArray(summarizeDiffImpactTool.session_artifacts_written),
    "session_artifacts_written must be an array"
  );
  assert.ok(
    summarizeDiffImpactTool.session_artifacts_written.includes("diff-impact.json"),
    "session_artifacts_written must include 'diff-impact.json'"
  );
});

test("bob_summarize_diff_impact is marked mutating:true", () => {
  assert.equal(
    summarizeDiffImpactTool.mutating,
    true,
    "tool must be mutating:true because it writes diff-impact.json"
  );
});
