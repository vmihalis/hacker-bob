"use strict";

/**
 * Tests for A2 — bob-runner.ts.
 *
 * Verifies acceptance criteria:
 *   1. Spawns: claude --dangerously-skip-permissions --print
 *      "/bob-diff-review --repo <abs-path> --diff-file <path>
 *        --output-dir <tmp-dir>"
 *   2. ANTHROPIC_API_KEY set in child process env from action input.
 *   3. Process timeout: 10 minutes, SIGTERM then SIGKILL.
 *   4. Exit 0 → read and JSON-parse diff-review-findings.json → DiffReviewFindings.
 *   5. Non-zero exit → throw BobRunnerError with stderr captured.
 *   6. diff-review-findings.json schema validated before returning.
 *   7. Missing output file distinguishable from JSON parse error.
 *   8. resolveOutputDir creates dir when provided; creates temp dir when not.
 *   9. validateDiffReviewFindings rejects malformed inputs with TypeError.
 *  10. BobRunnerError carries exitCode, signal, stderr, timedOut fields.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

// ---------------------------------------------------------------------------
// Import from dist (compiled output) so this mirrors what downstream consumers
// (action-entrypoint.ts) will use.
// ---------------------------------------------------------------------------

const dist = path.join(__dirname, "..", "packages", "bob-diff-review", "dist");
const {
  BOB_RUNNER_TIMEOUT_MS,
  BobRunnerError,
  buildClaudeChildEnv,
  validateDiffReviewFindings,
  resolveOutputDir,
} = require(path.join(dist, "bob-runner.js"));

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Build a minimal valid DiffReviewFindings object for use in tests.
 */
function makeValidFindings(overrides = {}) {
  return {
    session_id: "ses-abc123",
    target_domain: "gh-99999999",
    generated_at: new Date().toISOString(),
    impacted_entries: [],
    findings: [],
    ...overrides,
  };
}

/**
 * Build a minimal valid FindingEntry for use in tests.
 */
function makeValidFinding(overrides = {}) {
  return {
    surface_id: "surf-1",
    file: "src/foo.ts",
    line_start: 10,
    line_end: 20,
    title: "SQL injection in query param",
    severity: "high",
    description: "The `id` param is concatenated into a SQL query without sanitisation.",
    evidence: "GET /api?id=1' OR 1=1--",
    hunk_text: "@@ -8,5 +8,7 @@\n+const q = `SELECT * FROM users WHERE id=${id}`;",
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

test("BOB_RUNNER_TIMEOUT_MS equals 10 minutes", () => {
  assert.strictEqual(BOB_RUNNER_TIMEOUT_MS, 10 * 60 * 1000);
});

// ---------------------------------------------------------------------------
// BobRunnerError
// ---------------------------------------------------------------------------

test("BobRunnerError carries all required fields", () => {
  const err = new BobRunnerError({
    message: "process exited with code 1",
    exitCode: 1,
    signal: null,
    stderr: "some stderr output",
    timedOut: false,
  });

  assert.strictEqual(err.name, "BobRunnerError");
  assert.strictEqual(err.exitCode, 1);
  assert.strictEqual(err.signal, null);
  assert.strictEqual(err.stderr, "some stderr output");
  assert.strictEqual(err.timedOut, false);
  assert.ok(err instanceof Error);
  assert.ok(err instanceof BobRunnerError);
});

test("BobRunnerError with timedOut=true and signal", () => {
  const err = new BobRunnerError({
    message: "timed out",
    exitCode: null,
    signal: "SIGTERM",
    stderr: "",
    timedOut: true,
  });

  assert.strictEqual(err.timedOut, true);
  assert.strictEqual(err.exitCode, null);
  assert.strictEqual(err.signal, "SIGTERM");
});

// ---------------------------------------------------------------------------
// validateDiffReviewFindings — schema validation
// ---------------------------------------------------------------------------

test("validateDiffReviewFindings accepts a minimal valid document (no findings)", () => {
  const doc = makeValidFindings();
  const result = validateDiffReviewFindings(doc);
  assert.strictEqual(result.session_id, "ses-abc123");
  assert.strictEqual(result.target_domain, "gh-99999999");
  assert.deepStrictEqual(result.findings, []);
  assert.deepStrictEqual(result.impacted_entries, []);
});

test("validateDiffReviewFindings accepts a document with valid findings", () => {
  const finding = makeValidFinding();
  const doc = makeValidFindings({ findings: [finding] });
  const result = validateDiffReviewFindings(doc);
  assert.strictEqual(result.findings.length, 1);
  assert.strictEqual(result.findings[0].severity, "high");
});

test("validateDiffReviewFindings accepts all valid severity levels", () => {
  const severities = ["critical", "high", "medium", "low", "info"];
  for (const sev of severities) {
    const finding = makeValidFinding({ severity: sev });
    const doc = makeValidFindings({ findings: [finding] });
    assert.doesNotThrow(() => validateDiffReviewFindings(doc), `severity "${sev}" should be valid`);
  }
});

test("validateDiffReviewFindings rejects null", () => {
  assert.throws(
    () => validateDiffReviewFindings(null),
    (err) => err instanceof TypeError && err.message.includes("null")
  );
});

test("validateDiffReviewFindings rejects an array at top level", () => {
  assert.throws(
    () => validateDiffReviewFindings([]),
    (err) => err instanceof TypeError && err.message.includes("array")
  );
});

test("validateDiffReviewFindings accepts missing session_id as degraded-run metadata", () => {
  const doc = makeValidFindings();
  delete doc.session_id;
  const result = validateDiffReviewFindings(doc);
  assert.strictEqual(result.session_id, "");
});

test("validateDiffReviewFindings accepts empty session_id", () => {
  const doc = makeValidFindings({ session_id: "" });
  const result = validateDiffReviewFindings(doc);
  assert.strictEqual(result.session_id, "");
});

test("validateDiffReviewFindings rejects missing target_domain", () => {
  const doc = makeValidFindings();
  delete doc.target_domain;
  assert.throws(
    () => validateDiffReviewFindings(doc),
    (err) => err instanceof TypeError && err.message.includes("target_domain")
  );
});

test("validateDiffReviewFindings accepts missing generated_at as degraded-run metadata", () => {
  const doc = makeValidFindings();
  delete doc.generated_at;
  const result = validateDiffReviewFindings(doc);
  assert.strictEqual(result.generated_at, "");
});

test("validateDiffReviewFindings rejects non-array impacted_entries", () => {
  const doc = makeValidFindings({ impacted_entries: "not-an-array" });
  assert.throws(
    () => validateDiffReviewFindings(doc),
    (err) => err instanceof TypeError && err.message.includes("impacted_entries")
  );
});

test("validateDiffReviewFindings rejects non-array findings", () => {
  const doc = makeValidFindings({ findings: null });
  assert.throws(
    () => validateDiffReviewFindings(doc),
    (err) => err instanceof TypeError && err.message.includes("findings")
  );
});

test("validateDiffReviewFindings rejects finding with missing file", () => {
  const finding = makeValidFinding();
  delete finding.file;
  const doc = makeValidFindings({ findings: [finding] });
  assert.throws(
    () => validateDiffReviewFindings(doc),
    (err) => err instanceof TypeError && err.message.includes("file")
  );
});

test("validateDiffReviewFindings rejects finding with non-number line_start", () => {
  const finding = makeValidFinding({ line_start: "ten" });
  const doc = makeValidFindings({ findings: [finding] });
  assert.throws(
    () => validateDiffReviewFindings(doc),
    (err) => err instanceof TypeError && err.message.includes("line_start")
  );
});

test("validateDiffReviewFindings rejects finding with non-number line_end", () => {
  const finding = makeValidFinding({ line_end: "twenty" });
  const doc = makeValidFindings({ findings: [finding] });
  assert.throws(
    () => validateDiffReviewFindings(doc),
    (err) => err instanceof TypeError && err.message.includes("line_end")
  );
});

test("validateDiffReviewFindings rejects finding with invalid severity", () => {
  const finding = makeValidFinding({ severity: "extreme" });
  const doc = makeValidFindings({ findings: [finding] });
  assert.throws(
    () => validateDiffReviewFindings(doc),
    (err) => err instanceof TypeError && err.message.includes("severity")
  );
});

test("validateDiffReviewFindings defaults missing title to empty string", () => {
  const finding = makeValidFinding();
  delete finding.title;
  const doc = makeValidFindings({ findings: [finding] });
  const result = validateDiffReviewFindings(doc);
  assert.strictEqual(result.findings[0].title, "");
});

test("validateDiffReviewFindings defaults missing description to empty string", () => {
  const finding = makeValidFinding();
  delete finding.description;
  const doc = makeValidFindings({ findings: [finding] });
  const result = validateDiffReviewFindings(doc);
  assert.strictEqual(result.findings[0].description, "");
});

test("validateDiffReviewFindings defaults missing evidence to empty string", () => {
  const finding = makeValidFinding();
  delete finding.evidence;
  const doc = makeValidFindings({ findings: [finding] });
  const result = validateDiffReviewFindings(doc);
  assert.strictEqual(result.findings[0].evidence, "");
});

test("validateDiffReviewFindings rejects finding with NaN line_start", () => {
  const finding = makeValidFinding({ line_start: NaN });
  const doc = makeValidFindings({ findings: [finding] });
  assert.throws(
    () => validateDiffReviewFindings(doc),
    (err) => err instanceof TypeError && err.message.includes("line_start")
  );
});

// ---------------------------------------------------------------------------
// resolveOutputDir
// ---------------------------------------------------------------------------

test("resolveOutputDir returns existing path when provided", () => {
  const tmpBase = os.tmpdir();
  const dirName = `bob-test-resolve-${Date.now()}`;
  const explicit = path.join(tmpBase, dirName);
  try {
    const result = resolveOutputDir(explicit);
    assert.strictEqual(result, path.resolve(explicit));
    assert.ok(fs.existsSync(result), "directory should have been created");
  } finally {
    fs.rmSync(explicit, { recursive: true, force: true });
  }
});

test("resolveOutputDir creates nested dirs when provided a deep path", () => {
  const tmpBase = os.tmpdir();
  const deep = path.join(tmpBase, `bob-test-deep-${Date.now()}`, "a", "b", "c");
  try {
    const result = resolveOutputDir(deep);
    assert.ok(fs.existsSync(result), "nested directories should have been created");
  } finally {
    // Clean up from the first new segment.
    const topLevel = path.join(tmpBase, path.relative(tmpBase, deep).split(path.sep)[0]);
    fs.rmSync(topLevel, { recursive: true, force: true });
  }
});

test("resolveOutputDir creates a temp dir under os.tmpdir() when not provided", () => {
  const result = resolveOutputDir();
  try {
    assert.ok(result.startsWith(os.tmpdir()), "temp dir should be under os.tmpdir()");
    assert.ok(fs.existsSync(result), "temp dir should exist");
  } finally {
    fs.rmSync(result, { recursive: true, force: true });
  }
});

test("resolveOutputDir temp dir name starts with 'bob-diff-'", () => {
  const result = resolveOutputDir();
  try {
    assert.ok(
      path.basename(result).startsWith("bob-diff-"),
      `expected dir name to start with 'bob-diff-', got '${path.basename(result)}'`
    );
  } finally {
    fs.rmSync(result, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// runBobDiffReview — integration-style tests using a fake claude binary
// ---------------------------------------------------------------------------

const EXTRACT_OUTPUT_DIR_SH = `
OUTPUT_DIR=""
PREV_ARG=""
for arg in "$@"; do
  if [ "$PREV_ARG" = "--output-dir" ]; then
    OUTPUT_DIR="$arg"
  fi
  if printf '%s\\n' "$arg" | grep -q -- "--output-dir "; then
    FROM_PROMPT="$(printf '%s\\n' "$arg" | sed -n 's/.*--output-dir "\\([^"]*\\)".*/\\1/p')"
    if [ -z "$FROM_PROMPT" ]; then
      FROM_PROMPT="$(printf '%s\\n' "$arg" | sed -n 's/.*--output-dir \\([^ ]*\\).*/\\1/p')"
    fi
    if [ -n "$FROM_PROMPT" ]; then
      OUTPUT_DIR="$FROM_PROMPT"
    fi
  fi
  PREV_ARG="$arg"
done
`;

/**
 * Write a tiny shell script to act as a fake "claude" binary for a test.
 * The script writes a findings JSON to --output-dir and exits with exitCode.
 *
 * @param {string} binDir    - Directory in which to place the fake binary.
 * @param {number} exitCode  - Exit code the fake binary should use.
 * @param {object|null} findingsDoc - Document to write (null = don't write).
 * @param {string} [stderrMsg]      - Optional message to emit on stderr.
 */
function writeFakeClaude(binDir, exitCode, findingsDoc, stderrMsg = "") {
  fs.mkdirSync(binDir, { recursive: true });
  const binPath = path.join(binDir, "claude");

  const findingsJson = findingsDoc !== null
    ? JSON.stringify(findingsDoc, null, 2).replace(/'/g, "'\"'\"'")
    : null;

  // Parse --output-dir from the arguments passed to the fake binary.
  // The fake binary writes diff-review-findings.json there and exits.
  const stderrLine = stderrMsg
    ? `echo '${stderrMsg.replace(/'/g, "'\\''")}' >&2`
    : "";

  const writeFindings = findingsDoc !== null
    ? `
${EXTRACT_OUTPUT_DIR_SH}
if [ -n "$OUTPUT_DIR" ]; then
  mkdir -p "$OUTPUT_DIR"
  cat > "$OUTPUT_DIR/diff-review-findings.json" << 'FINDINGJSON'
${JSON.stringify(findingsDoc, null, 2)}
FINDINGJSON
fi
`
    : "";

  const script = `#!/bin/sh
${stderrLine}
${writeFindings}
exit ${exitCode}
`;

  fs.writeFileSync(binPath, script, { mode: 0o755 });
  return binPath;
}

/**
 * Run runBobDiffReview with a fake claude binary injected via PATH.
 *
 * @param {string} fakeBinDir   - Directory containing the fake claude binary.
 * @param {object} paramsExtra  - Extra params to merge into BobRunnerParams.
 */
async function runWithFakeClaude(fakeBinDir, paramsExtra = {}) {
  // Dynamically require bob-runner so we can use the real implementation
  // with a mocked PATH.
  const originalPath = process.env["PATH"];
  process.env["PATH"] = `${fakeBinDir}:${originalPath ?? ""}`;
  try {
    const { runBobDiffReview } = require(path.join(dist, "bob-runner.js"));
    const tmpRepo = fs.mkdtempSync(path.join(os.tmpdir(), "bob-test-repo-"));
    const tmpDiff = path.join(tmpRepo, "pr.diff");
    fs.writeFileSync(tmpDiff, "--- a/foo.ts\n+++ b/foo.ts\n@@ -1,1 +1,1 @@\n-old\n+new\n");

    const result = await runBobDiffReview({
      repo: tmpRepo,
      diffFile: tmpDiff,
      targetDomainOverride: "gh-12345678",
      anthropicApiKey: "sk-test-key",
      ...paramsExtra,
    });
    fs.rmSync(tmpRepo, { recursive: true, force: true });
    return result;
  } finally {
    process.env["PATH"] = originalPath;
  }
}

test("runBobDiffReview returns DiffReviewFindings on exit 0 with valid output", async () => {
  const binDir = fs.mkdtempSync(path.join(os.tmpdir(), "bob-fake-claude-"));
  try {
    const doc = makeValidFindings({ session_id: "ses-integration", target_domain: "gh-12345678" });
    writeFakeClaude(binDir, 0, doc);
    const result = await runWithFakeClaude(binDir);
    assert.strictEqual(result.session_id, "ses-integration");
    assert.strictEqual(result.target_domain, "gh-12345678");
    assert.deepStrictEqual(result.findings, []);
  } finally {
    fs.rmSync(binDir, { recursive: true, force: true });
  }
});

test("runBobDiffReview returns findings array with valid entries", async () => {
  const binDir = fs.mkdtempSync(path.join(os.tmpdir(), "bob-fake-claude-"));
  try {
    const finding = makeValidFinding({ severity: "critical" });
    const doc = makeValidFindings({ findings: [finding] });
    writeFakeClaude(binDir, 0, doc);
    const result = await runWithFakeClaude(binDir);
    assert.strictEqual(result.findings.length, 1);
    assert.strictEqual(result.findings[0].severity, "critical");
  } finally {
    fs.rmSync(binDir, { recursive: true, force: true });
  }
});

test("runBobDiffReview throws BobRunnerError on non-zero exit", async () => {
  const binDir = fs.mkdtempSync(path.join(os.tmpdir(), "bob-fake-claude-"));
  try {
    writeFakeClaude(binDir, 1, null, "fatal skill error");
    await assert.rejects(
      async () => runWithFakeClaude(binDir),
      (err) => {
        assert.ok(err instanceof BobRunnerError, "should be BobRunnerError");
        assert.strictEqual(err.exitCode, 1, "exitCode should be 1");
        assert.strictEqual(err.timedOut, false);
        return true;
      }
    );
  } finally {
    fs.rmSync(binDir, { recursive: true, force: true });
  }
});

test("runBobDiffReview BobRunnerError captures stderr output", async () => {
  const binDir = fs.mkdtempSync(path.join(os.tmpdir(), "bob-fake-claude-"));
  try {
    writeFakeClaude(binDir, 2, null, "custom error from skill");
    await assert.rejects(
      async () => runWithFakeClaude(binDir),
      (err) => {
        assert.ok(err instanceof BobRunnerError);
        assert.ok(
          err.stderr.includes("custom error from skill"),
          `stderr should contain the error message, got: ${JSON.stringify(err.stderr)}`
        );
        return true;
      }
    );
  } finally {
    fs.rmSync(binDir, { recursive: true, force: true });
  }
});

test("runBobDiffReview throws BobRunnerError when findings file not written (exit 0)", async () => {
  const binDir = fs.mkdtempSync(path.join(os.tmpdir(), "bob-fake-claude-"));
  try {
    // Exit 0 but don't write any findings file.
    writeFakeClaude(binDir, 0, null);
    await assert.rejects(
      async () => runWithFakeClaude(binDir),
      (err) => {
        assert.ok(err instanceof BobRunnerError);
        assert.ok(
          err.message.includes("not written") || err.message.includes("ENOENT"),
          `message should mention file not written, got: ${err.message}`
        );
        assert.strictEqual(err.exitCode, 0);
        return true;
      }
    );
  } finally {
    fs.rmSync(binDir, { recursive: true, force: true });
  }
});

test("runBobDiffReview throws BobRunnerError on invalid JSON in findings file", async () => {
  const binDir = fs.mkdtempSync(path.join(os.tmpdir(), "bob-fake-claude-"));
  try {
    // Write a script that produces invalid JSON.
    const binPath = path.join(binDir, "claude");
    const script = `#!/bin/sh
${EXTRACT_OUTPUT_DIR_SH}
if [ -n "$OUTPUT_DIR" ]; then
  mkdir -p "$OUTPUT_DIR"
  printf 'NOT VALID JSON {{{' > "$OUTPUT_DIR/diff-review-findings.json"
fi
exit 0
`;
    fs.writeFileSync(binPath, script, { mode: 0o755 });

    await assert.rejects(
      async () => runWithFakeClaude(binDir),
      (err) => {
        assert.ok(err instanceof BobRunnerError);
        assert.ok(
          err.message.toLowerCase().includes("json") ||
          err.message.toLowerCase().includes("valid"),
          `message should mention JSON parse error, got: ${err.message}`
        );
        assert.ok(
          !err.message.includes("NOT VALID JSON"),
          `message should not echo raw findings content, got: ${err.message}`
        );
        return true;
      }
    );
  } finally {
    fs.rmSync(binDir, { recursive: true, force: true });
  }
});

test("runBobDiffReview throws BobRunnerError on schema validation failure", async () => {
  const binDir = fs.mkdtempSync(path.join(os.tmpdir(), "bob-fake-claude-"));
  try {
    // Write valid JSON with a malformed required 'findings' field.
    const badDoc = {
      target_domain: "gh-12345678",
      generated_at: new Date().toISOString(),
      impacted_entries: [],
      findings: "not-an-array",
    };
    writeFakeClaude(binDir, 0, badDoc);
    await assert.rejects(
      async () => runWithFakeClaude(binDir),
      (err) => {
        assert.ok(err instanceof BobRunnerError);
        assert.ok(
          err.message.includes("schema") || err.message.includes("findings"),
          `message should mention validation failure, got: ${err.message}`
        );
        return true;
      }
    );
  } finally {
    fs.rmSync(binDir, { recursive: true, force: true });
  }
});

test("runBobDiffReview uses provided outputDir and writes findings there", async () => {
  const binDir = fs.mkdtempSync(path.join(os.tmpdir(), "bob-fake-claude-"));
  const explicitOutputDir = fs.mkdtempSync(path.join(os.tmpdir(), "bob-test-output-"));
  try {
    const doc = makeValidFindings({ session_id: "ses-explicit-dir" });
    writeFakeClaude(binDir, 0, doc);
    const result = await runWithFakeClaude(binDir, { outputDir: explicitOutputDir });
    assert.strictEqual(result.session_id, "ses-explicit-dir");
    // Confirm findings file is in explicitOutputDir.
    const findingsPath = path.join(explicitOutputDir, "diff-review-findings.json");
    assert.ok(fs.existsSync(findingsPath), "findings file should exist in explicit outputDir");
  } finally {
    fs.rmSync(binDir, { recursive: true, force: true });
    fs.rmSync(explicitOutputDir, { recursive: true, force: true });
  }
});

test("runBobDiffReview injects ANTHROPIC_API_KEY into child env (verified via env echo)", async () => {
  const binDir = fs.mkdtempSync(path.join(os.tmpdir(), "bob-fake-claude-"));
  try {
    // Write a fake claude that echoes ANTHROPIC_API_KEY into a sentinel file
    // inside the output dir, then writes valid findings.
    const doc = makeValidFindings();
    const binPath = path.join(binDir, "claude");
    const script = `#!/bin/sh
${EXTRACT_OUTPUT_DIR_SH}
if [ -n "$OUTPUT_DIR" ]; then
  mkdir -p "$OUTPUT_DIR"
  echo "$ANTHROPIC_API_KEY" > "$OUTPUT_DIR/api-key-seen.txt"
  cat > "$OUTPUT_DIR/diff-review-findings.json" << 'FINDINGJSON'
${JSON.stringify(doc, null, 2)}
FINDINGJSON
fi
exit 0
`;
    fs.writeFileSync(binPath, script, { mode: 0o755 });

    const explicitOutputDir = fs.mkdtempSync(path.join(os.tmpdir(), "bob-test-env-"));
    try {
      await runWithFakeClaude(binDir, {
        outputDir: explicitOutputDir,
        // anthropicApiKey is set to "sk-test-key" by runWithFakeClaude.
      });
      const sentinel = path.join(explicitOutputDir, "api-key-seen.txt");
      assert.ok(fs.existsSync(sentinel), "sentinel file should exist");
      const keyValue = fs.readFileSync(sentinel, "utf8").trim();
      assert.strictEqual(keyValue, "sk-test-key", "ANTHROPIC_API_KEY should be passed to child");
    } finally {
      fs.rmSync(explicitOutputDir, { recursive: true, force: true });
    }
  } finally {
    fs.rmSync(binDir, { recursive: true, force: true });
  }
});

test("buildClaudeChildEnv allowlists runtime env and does not forward ambient secrets", () => {
  const env = buildClaudeChildEnv({
    anthropicApiKey: "sk-action-key",
    anthropicModel: "claude-test-model",
    sourceEnv: {
      PATH: "/usr/bin",
      HOME: "/tmp/bob-home",
      BOB_MCP_SERVER_PATH: "/tmp/bob/mcp/server.js",
      SKIP_SURFACE_BUILD: "true",
      INPUT_GITHUB_TOKEN: "input-secret",
      GITHUB_TOKEN: "github-secret",
      BOB_INSTALL_TOKEN: "install-secret",
      ANTHROPIC_API_KEY: "ambient-secret",
      CLAUDE_CODE_OAUTH_TOKEN: "ambient-oauth",
      HTTPS_PROXY: "http://user:pass@proxy.example:8080",
    },
  });

  assert.strictEqual(env.PATH, "/usr/bin");
  assert.strictEqual(env.HOME, "/tmp/bob-home");
  assert.strictEqual(env.BOB_MCP_SERVER_PATH, "/tmp/bob/mcp/server.js");
  assert.strictEqual(env.SKIP_SURFACE_BUILD, "true");
  assert.strictEqual(env.ANTHROPIC_MODEL, "claude-test-model");
  assert.strictEqual(env.ANTHROPIC_API_KEY, "sk-action-key");
  assert.equal("INPUT_GITHUB_TOKEN" in env, false);
  assert.equal("GITHUB_TOKEN" in env, false);
  assert.equal("BOB_INSTALL_TOKEN" in env, false);
  assert.equal("CLAUDE_CODE_OAUTH_TOKEN" in env, false);
  assert.equal("HTTPS_PROXY" in env, false);
});
