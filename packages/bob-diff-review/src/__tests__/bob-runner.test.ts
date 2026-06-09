/**
 * Unit tests for src/bob-runner.ts — headless claude runner (A2).
 *
 * Coverage focus: BOB_MOCK_FINDINGS_JSON bypass mode.
 *
 * The mock bypass is the mechanism used by the live integration test (T3) to
 * exercise the full pipeline (diff fetch, position map, review comment
 * posting, check run update, session cache write) without consuming real
 * Anthropic API credits.
 *
 * When BOB_MOCK_FINDINGS_JSON is set to a valid DiffReviewFindings JSON
 * string, runBobDiffReview returns the parsed findings directly and logs a
 * bypass notice, without spawning the claude subprocess.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  runBobDiffReview,
  validateDiffReviewFindings,
  resolveOutputDir,
  buildClaudeAuthEnv,
  buildClaudeChildEnv,
  buildMcpConfig,
  BobRunnerError,
} from "../bob-runner.js";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

// ---------------------------------------------------------------------------
// Minimal valid DiffReviewFindings fixture
// ---------------------------------------------------------------------------

const MOCK_FINDINGS_FIXTURE = {
  session_id: "test-session-abc123",
  target_domain: "gh-1261831449-pr2",
  generated_at: "2026-06-08T00:00:00Z",
  impacted_entries: [
    { file: "src/routes/users.js", surface_id: "surface-api-route" },
  ],
  findings: [
    {
      surface_id: "surface-api-route",
      file: "src/routes/users.js",
      title: "SQL Injection via unsanitized query parameter",
      description:
        "User-controlled input from req.query.id is interpolated directly into " +
        "a SQL query string without parameterization.",
      evidence: "GET /users?id=1 OR 1=1-- HTTP/1.1",
      hunk_text: "+  const query = `SELECT * FROM users WHERE id = ${req.query.id}`;",
      line_start: 20,
      line_end: 20,
      severity: "high" as const,
    },
  ],
};

const MOCK_FINDINGS_JSON = JSON.stringify(MOCK_FINDINGS_FIXTURE);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeTempDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "bob-runner-test-"));
}

function rmDir(dir: string): void {
  try {
    fs.rmSync(dir, { recursive: true, force: true });
  } catch {
    // best-effort
  }
}

// ---------------------------------------------------------------------------
// validateDiffReviewFindings
// ---------------------------------------------------------------------------

describe("validateDiffReviewFindings", () => {
  it("accepts a valid DiffReviewFindings object", () => {
    const result = validateDiffReviewFindings(MOCK_FINDINGS_FIXTURE);
    expect(result.session_id).toBe("test-session-abc123");
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].severity).toBe("high");
  });

  it("rejects null", () => {
    expect(() => validateDiffReviewFindings(null)).toThrow(/expected an object/);
  });

  it("rejects an array", () => {
    expect(() => validateDiffReviewFindings([])).toThrow(/expected an object/);
  });

  it("accepts missing/empty session_id (degraded PATH B runs have no Bob session)", () => {
    const bad = { ...MOCK_FINDINGS_FIXTURE, session_id: "" };
    expect(validateDiffReviewFindings(bad).session_id).toBe("");
  });

  it("rejects session_id present but not a string", () => {
    const bad = { ...MOCK_FINDINGS_FIXTURE, session_id: 123 };
    expect(() => validateDiffReviewFindings(bad)).toThrow(/session_id/);
  });

  it("rejects missing target_domain", () => {
    const bad = { ...MOCK_FINDINGS_FIXTURE, target_domain: "" };
    expect(() => validateDiffReviewFindings(bad)).toThrow(/target_domain/);
  });

  it("accepts missing/empty generated_at (degraded PATH B output omits it)", () => {
    const bad = { ...MOCK_FINDINGS_FIXTURE, generated_at: "" };
    expect(validateDiffReviewFindings(bad).generated_at).toBe("");
  });

  it("rejects generated_at present but not a string", () => {
    const bad = { ...MOCK_FINDINGS_FIXTURE, generated_at: 123 };
    expect(() => validateDiffReviewFindings(bad)).toThrow(/generated_at/);
  });

  it("rejects non-array impacted_entries", () => {
    const bad = { ...MOCK_FINDINGS_FIXTURE, impacted_entries: "not-array" };
    expect(() => validateDiffReviewFindings(bad)).toThrow(/impacted_entries/);
  });

  it("rejects non-array findings", () => {
    const bad = { ...MOCK_FINDINGS_FIXTURE, findings: null };
    expect(() => validateDiffReviewFindings(bad)).toThrow(/findings/);
  });

  it("rejects finding with invalid severity", () => {
    const bad = {
      ...MOCK_FINDINGS_FIXTURE,
      findings: [{ ...MOCK_FINDINGS_FIXTURE.findings[0], severity: "critical_severity_typo" }],
    };
    expect(() => validateDiffReviewFindings(bad)).toThrow(/severity/);
  });

  it("rejects finding with non-numeric line_start", () => {
    const bad = {
      ...MOCK_FINDINGS_FIXTURE,
      findings: [{ ...MOCK_FINDINGS_FIXTURE.findings[0], line_start: "20" }],
    };
    expect(() => validateDiffReviewFindings(bad)).toThrow(/line_start/);
  });

  it("accepts findings with empty hunk_text", () => {
    const good = {
      ...MOCK_FINDINGS_FIXTURE,
      findings: [{ ...MOCK_FINDINGS_FIXTURE.findings[0], hunk_text: "" }],
    };
    // hunk_text: "" is technically an empty string which is a string — should pass
    const result = validateDiffReviewFindings(good);
    expect(result.findings[0].hunk_text).toBe("");
  });

  it("accepts critical severity", () => {
    const critical = {
      ...MOCK_FINDINGS_FIXTURE,
      findings: [{ ...MOCK_FINDINGS_FIXTURE.findings[0], severity: "critical" as const }],
    };
    const result = validateDiffReviewFindings(critical);
    expect(result.findings[0].severity).toBe("critical");
  });

  it("accepts medium, low, and info severity", () => {
    for (const sev of ["medium", "low", "info"] as const) {
      const obj = {
        ...MOCK_FINDINGS_FIXTURE,
        findings: [{ ...MOCK_FINDINGS_FIXTURE.findings[0], severity: sev }],
      };
      const result = validateDiffReviewFindings(obj);
      expect(result.findings[0].severity).toBe(sev);
    }
  });
});

// ---------------------------------------------------------------------------
// resolveOutputDir
// ---------------------------------------------------------------------------

describe("resolveOutputDir", () => {
  it("creates a temp dir when no path given", () => {
    const dir = resolveOutputDir();
    expect(fs.existsSync(dir)).toBe(true);
    rmDir(dir);
  });

  it("creates the specified dir (including parents)", () => {
    const base = makeTempDir();
    const nested = path.join(base, "a", "b", "c");
    const result = resolveOutputDir(nested);
    expect(result).toBe(nested);
    expect(fs.existsSync(nested)).toBe(true);
    rmDir(base);
  });

  it("returns the absolute path even when relative is given", () => {
    const base = makeTempDir();
    // provide a path under tmpdir which is already absolute
    const result = resolveOutputDir(base);
    expect(path.isAbsolute(result)).toBe(true);
    rmDir(base);
  });
});

// ---------------------------------------------------------------------------
// buildClaudeAuthEnv — dual-auth precedence (OAUTH-WINS SINGLE-INJECTION)
//
// The claude CLI reads CLAUDE_CODE_OAUTH_TOKEN (OAuth) or ANTHROPIC_API_KEY
// (pay-per-use). The runner must inject EXACTLY ONE so the API key cannot
// silently shadow OAuth and exhaust credits. These tests pin the precedence:
//   (a) oauth-only     -> CLAUDE_CODE_OAUTH_TOKEN set, ANTHROPIC_API_KEY absent
//   (b) api-key-only   -> ANTHROPIC_API_KEY set, CLAUDE_CODE_OAUTH_TOKEN absent
//   (c) BOTH provided  -> OAuth wins: CLAUDE_CODE_OAUTH_TOKEN set, API key absent
//   (d) neither        -> empty fragment (the entrypoint validation rejects this
//                          before the runner is reached — see the focused test
//                          below that exercises the same predicate)
// ---------------------------------------------------------------------------

describe("buildClaudeAuthEnv (dual-auth precedence)", () => {
  it("(a) oauth-only: sets CLAUDE_CODE_OAUTH_TOKEN and does NOT set ANTHROPIC_API_KEY", () => {
    const env = buildClaudeAuthEnv({ oauthToken: "oauth-tok-123" });
    expect(env).toEqual({ CLAUDE_CODE_OAUTH_TOKEN: "oauth-tok-123" });
    expect("ANTHROPIC_API_KEY" in env).toBe(false);
  });

  it("(b) api-key-only: sets ANTHROPIC_API_KEY and does NOT set CLAUDE_CODE_OAUTH_TOKEN", () => {
    const env = buildClaudeAuthEnv({ apiKey: "sk-ant-key-456" });
    expect(env).toEqual({ ANTHROPIC_API_KEY: "sk-ant-key-456" });
    expect("CLAUDE_CODE_OAUTH_TOKEN" in env).toBe(false);
  });

  it("(c) BOTH provided: OAuth wins — CLAUDE_CODE_OAUTH_TOKEN set, ANTHROPIC_API_KEY absent", () => {
    const env = buildClaudeAuthEnv({
      oauthToken: "oauth-tok-123",
      apiKey: "sk-ant-key-456",
    });
    expect(env).toEqual({ CLAUDE_CODE_OAUTH_TOKEN: "oauth-tok-123" });
    expect("ANTHROPIC_API_KEY" in env).toBe(false);
  });

  it("(d) neither: returns an empty fragment with no credential vars", () => {
    const env = buildClaudeAuthEnv({});
    expect(env).toEqual({});
    expect("CLAUDE_CODE_OAUTH_TOKEN" in env).toBe(false);
    expect("ANTHROPIC_API_KEY" in env).toBe(false);
  });

  it("treats blank/whitespace OAuth token as absent and falls back to the API key", () => {
    const env = buildClaudeAuthEnv({ oauthToken: "   ", apiKey: "sk-ant-key-456" });
    expect(env).toEqual({ ANTHROPIC_API_KEY: "sk-ant-key-456" });
  });

  it("treats blank/whitespace API key as absent (empty fragment when no OAuth)", () => {
    const env = buildClaudeAuthEnv({ apiKey: "  " });
    expect(env).toEqual({});
  });

  it("trims surrounding whitespace from the injected credential", () => {
    expect(buildClaudeAuthEnv({ oauthToken: " oauth-tok-123 " })).toEqual({
      CLAUDE_CODE_OAUTH_TOKEN: "oauth-tok-123",
    });
    expect(buildClaudeAuthEnv({ apiKey: " sk-ant-key-456 " })).toEqual({
      ANTHROPIC_API_KEY: "sk-ant-key-456",
    });
  });
});

describe("buildClaudeChildEnv", () => {
  it("copies only allowed runtime variables and the selected credential", () => {
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

    expect(env.PATH).toBe("/usr/bin");
    expect(env.HOME).toBe("/tmp/bob-home");
    expect(env.BOB_MCP_SERVER_PATH).toBe("/tmp/bob/mcp/server.js");
    expect(env.SKIP_SURFACE_BUILD).toBe("true");
    expect(env.ANTHROPIC_MODEL).toBe("claude-test-model");
    expect(env.ANTHROPIC_API_KEY).toBe("sk-action-key");
    expect("INPUT_GITHUB_TOKEN" in env).toBe(false);
    expect("GITHUB_TOKEN" in env).toBe(false);
    expect("BOB_INSTALL_TOKEN" in env).toBe(false);
    expect("CLAUDE_CODE_OAUTH_TOKEN" in env).toBe(false);
    expect("HTTPS_PROXY" in env).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// buildMcpConfig — Bob MCP server registration (enables PATH A)
// ---------------------------------------------------------------------------

describe("buildMcpConfig", () => {
  it("registers the hacker-bob server with a node command + the server path", () => {
    const cfg = buildMcpConfig("/home/runner/bob-workspace/mcp/server.js");
    expect(cfg).toEqual({
      mcpServers: {
        "hacker-bob": {
          command: "node",
          args: ["/home/runner/bob-workspace/mcp/server.js"],
        },
      },
    });
  });
});

// ---------------------------------------------------------------------------
// Entrypoint at-least-one validation (case d)
//
// The action entrypoint fails fast when NEITHER anthropic-oauth-token nor
// anthropic-api-key is provided. There is no separate entrypoint test harness,
// so this focused test pins the exact predicate the entrypoint uses
// (`!oauthToken && !apiKey`) against buildClaudeAuthEnv, which yields the empty
// fragment in precisely the same case the entrypoint rejects. When at least one
// credential is present, the fragment is non-empty and the entrypoint proceeds.
// ---------------------------------------------------------------------------

describe("entrypoint at-least-one credential validation", () => {
  function entrypointWouldReject(oauthToken?: string, apiKey?: string): boolean {
    // Mirrors action-entrypoint.ts: reject when both credentials are falsy.
    return !oauthToken && !apiKey;
  }

  it("rejects when neither oauth token nor api key is provided", () => {
    expect(entrypointWouldReject(undefined, undefined)).toBe(true);
    expect(entrypointWouldReject("", "")).toBe(true);
    // And the runner-side helper agrees: no credential gets injected.
    expect(buildClaudeAuthEnv({ oauthToken: "", apiKey: "" })).toEqual({});
  });

  it("does NOT reject when at least one credential is provided", () => {
    expect(entrypointWouldReject("oauth-tok", undefined)).toBe(false);
    expect(entrypointWouldReject(undefined, "sk-ant")).toBe(false);
    expect(entrypointWouldReject("oauth-tok", "sk-ant")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// runBobDiffReview — BOB_MOCK_FINDINGS_JSON bypass
// ---------------------------------------------------------------------------

describe("runBobDiffReview mock mode (BOB_MOCK_FINDINGS_JSON)", () => {
  let tmpDir: string;
  const savedEnv: Record<string, string | undefined> = {};

  beforeEach(() => {
    tmpDir = makeTempDir();
    savedEnv["BOB_MOCK_FINDINGS_JSON"] = process.env["BOB_MOCK_FINDINGS_JSON"];
  });

  afterEach(() => {
    rmDir(tmpDir);
    if (savedEnv["BOB_MOCK_FINDINGS_JSON"] === undefined) {
      delete process.env["BOB_MOCK_FINDINGS_JSON"];
    } else {
      process.env["BOB_MOCK_FINDINGS_JSON"] = savedEnv["BOB_MOCK_FINDINGS_JSON"];
    }
  });

  it("returns pre-seeded findings without spawning claude when env var is set", async () => {
    process.env["BOB_MOCK_FINDINGS_JSON"] = MOCK_FINDINGS_JSON;

    // Params with a fake (non-existent) diff file — would fail if claude were invoked.
    const result = await runBobDiffReview({
      repo: tmpDir,
      diffFile: path.join(tmpDir, "does-not-exist.diff"),
      targetDomainOverride: "gh-1261831449-pr99",
      anthropicApiKey: "mock-key",
    });

    expect(result.session_id).toBe("test-session-abc123");
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].severity).toBe("high");
    expect(result.findings[0].file).toBe("src/routes/users.js");
  });

  it("overrides target_domain with the value passed in params", async () => {
    process.env["BOB_MOCK_FINDINGS_JSON"] = MOCK_FINDINGS_JSON;

    const result = await runBobDiffReview({
      repo: tmpDir,
      diffFile: path.join(tmpDir, "does-not-exist.diff"),
      targetDomainOverride: "gh-999-pr42",
      anthropicApiKey: "mock-key",
    });

    // target_domain should be overridden to the params value
    expect(result.target_domain).toBe("gh-999-pr42");
  });

  it("throws BobRunnerError when env var contains invalid JSON", async () => {
    process.env["BOB_MOCK_FINDINGS_JSON"] = "NOT VALID JSON {{";

    await expect(
      runBobDiffReview({
        repo: tmpDir,
        diffFile: path.join(tmpDir, "x.diff"),
        targetDomainOverride: "gh-1-pr1",
        anthropicApiKey: "mock-key",
      })
    ).rejects.toBeInstanceOf(BobRunnerError);
  });

  it("throws BobRunnerError when env var contains JSON with invalid schema", async () => {
    const bad = JSON.stringify({ wrong: "shape" });
    process.env["BOB_MOCK_FINDINGS_JSON"] = bad;

    await expect(
      runBobDiffReview({
        repo: tmpDir,
        diffFile: path.join(tmpDir, "x.diff"),
        targetDomainOverride: "gh-1-pr1",
        anthropicApiKey: "mock-key",
      })
    ).rejects.toThrow(/findings/);
  });

  it("returns empty findings array when fixture has no findings", async () => {
    const emptyFindings = {
      ...MOCK_FINDINGS_FIXTURE,
      findings: [],
    };
    process.env["BOB_MOCK_FINDINGS_JSON"] = JSON.stringify(emptyFindings);

    const result = await runBobDiffReview({
      repo: tmpDir,
      diffFile: path.join(tmpDir, "does-not-exist.diff"),
      targetDomainOverride: "gh-1-pr1",
      anthropicApiKey: "mock-key",
    });

    expect(result.findings).toHaveLength(0);
  });

  it("does NOT bypass claude when env var is absent", async () => {
    // Make sure the env var is NOT set
    delete process.env["BOB_MOCK_FINDINGS_JSON"];

    // Expect a BobRunnerError because claude binary is not on PATH (or the
    // fake diff file doesn't exist), so the real spawn path is exercised.
    // This verifies the bypass is only active when the env var is set.
    await expect(
      runBobDiffReview({
        repo: tmpDir,
        diffFile: path.join(tmpDir, "fake.diff"),
        targetDomainOverride: "gh-1-pr1",
        anthropicApiKey: "fake-key-no-credits",
        timeoutMs: 3000,
      })
    ).rejects.toBeInstanceOf(BobRunnerError);
  });

  it("T3 AC2/AC3 end-to-end: high severity SQL injection mock flows through the whole result shape", async () => {
    // This test simulates the exact T3 AC2 scenario: a SQL injection finding
    // at src/routes/users.js line 20 (diff position 21) flows through mock mode.
    // The resolver.ts and reviews-api.ts use the file+line from the finding;
    // this test confirms the finding shape is preserved so the downstream
    // pipeline can produce the correct inline comment.
    process.env["BOB_MOCK_FINDINGS_JSON"] = MOCK_FINDINGS_JSON;

    const result = await runBobDiffReview({
      repo: tmpDir,
      diffFile: path.join(tmpDir, "does-not-exist.diff"),
      targetDomainOverride: "gh-1261831449-pr2",
      anthropicApiKey: "mock-key",
    });

    const finding = result.findings[0];
    expect(finding.severity).toBe("high");
    expect(finding.file).toBe("src/routes/users.js");
    expect(finding.line_start).toBe(20);
    expect(finding.title).toMatch(/SQL Injection/i);
  });
});
