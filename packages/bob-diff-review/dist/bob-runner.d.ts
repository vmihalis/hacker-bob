/**
 * A2 — bob-runner: invoke claude headlessly with the bob-diff-review skill.
 *
 * Spawns the claude CLI as a child process:
 *
 *   claude --dangerously-skip-permissions --print \
 *     "/bob-diff-review --repo <abs-path> --diff-file <path> \
 *        --target-domain-override <gh-id> --output-dir <tmp-dir>"
 *
 * Lifecycle:
 *   1. Create a temp output directory under os.tmpdir().
 *   2. Spawn the claude process with exactly one Anthropic credential injected
 *      from params (OAuth token wins over API key — see buildClaudeAuthEnv).
 *   3. Stream stdout/stderr to the parent process (GitHub Actions log).
 *   4. Apply a 10-minute timeout via AbortController: SIGTERM first, then SIGKILL.
 *   5. On exit 0:  read and validate diff-review-findings.json, return DiffReviewFindings.
 *   6. On non-zero: throw BobRunnerError with captured stderr.
 *
 * Acceptance criteria (A2):
 *   - Spawns correct command with all four -- arguments.
 *   - Exactly one Anthropic credential set in child process env from action
 *     input: CLAUDE_CODE_OAUTH_TOKEN when an OAuth token is present (and
 *     ANTHROPIC_API_KEY omitted), otherwise ANTHROPIC_API_KEY.
 *   - 10-minute timeout: SIGTERM → SIGKILL.
 *   - Exit 0 → JSON-parse diff-review-findings.json → return DiffReviewFindings.
 *   - Non-zero exit → throw BobRunnerError with stderr.
 *   - diff-review-findings.json schema validated against DiffReviewFindings type.
 *
 * Implementation notes:
 *   - child_process.spawn (not exec) to stream stdout/stderr as they arrive.
 *   - AbortController abort() triggers SIGTERM on the process group; a 5-second
 *     follow-up timer escalates to SIGKILL if the process has not yet exited.
 *   - Output directory is created by this module (mkdtemp); the skill writes
 *     diff-review-findings.json into it.
 *   - Path to the claude binary is resolved from the PATH environment variable.
 *     If not found, a descriptive error is thrown before spawning.
 *
 * Failure modes guarded here:
 *   - claude binary not on PATH — emits a clear diagnostic including the
 *     current PATH value so the caller can adjust $PATH before running.
 *   - diff-review-findings.json not written on claude crash — distinguishes
 *     ENOENT (file never created) from JSON.parse errors (file created but
 *     malformed).
 *   - Schema validation failure — validateDiffReviewFindings() checks the
 *     top-level keys and finding entry shapes before returning to the caller.
 */
import type { DiffReviewFindings } from "./findings-serializer.js";
/** Total time allowed for the headless claude process to exit. */
export declare const BOB_RUNNER_TIMEOUT_MS: number;
/**
 * Parameters accepted by runBobDiffReview.
 */
export interface BobRunnerParams {
    /** Absolute path to the repository on disk. */
    repo: string;
    /** Absolute path to the unified diff file. */
    diffFile: string;
    /**
     * Target domain override — typically a GitHub PR identifier such as
     * "gh-12345678" used by Bob to scope the session.
     */
    targetDomainOverride: string;
    /**
     * Anthropic OAuth token (recommended path).  Long-lived token produced by
     * `claude setup-token`.  When present it is injected into the child process
     * env as CLAUDE_CODE_OAUTH_TOKEN and takes precedence over anthropicApiKey:
     * the API key is NOT injected so it cannot silently shadow OAuth and exhaust
     * pay-per-use credits.  Optional, but at least one of anthropicOauthToken or
     * anthropicApiKey must be provided (enforced by the action entrypoint).
     */
    anthropicOauthToken?: string;
    /**
     * Anthropic API key (pay-per-use fallback).  When no OAuth token is present
     * it is injected into the child process env as ANTHROPIC_API_KEY.  The key is
     * never written to disk or logged.  Optional, but at least one of
     * anthropicOauthToken or anthropicApiKey must be provided.
     */
    anthropicApiKey?: string;
    /**
     * Optional Anthropic model override.  When provided, injected into the child
     * process env as ANTHROPIC_MODEL so the claude CLI uses this model instead of
     * its default.  Useful for cost optimisation (e.g. "claude-haiku-4-5") or
     * testing against a specific release.  When omitted, the claude CLI default
     * is used.
     */
    anthropicModel?: string;
    /**
     * Override the output directory.  When omitted, a fresh temporary directory
     * is created under os.tmpdir() with the prefix "bob-diff-".
     *
     * Providing this is useful in tests to inspect the output without searching
     * for the generated temp path.
     */
    outputDir?: string;
    /**
     * Override the timeout in milliseconds.  Defaults to BOB_RUNNER_TIMEOUT_MS
     * (10 minutes).  Exposed for testing.
     */
    timeoutMs?: number;
}
/**
 * Structured error thrown when the headless claude process exits with a
 * non-zero status code or is killed due to a timeout.
 */
export declare class BobRunnerError extends Error {
    /** The process exit code, or null if the process was killed by a signal. */
    readonly exitCode: number | null;
    /** The signal that killed the process, or null if it exited normally. */
    readonly signal: NodeJS.Signals | null;
    /** Captured stderr output from the claude process. */
    readonly stderr: string;
    /** Whether the process was terminated due to a timeout. */
    readonly timedOut: boolean;
    constructor(opts: {
        message: string;
        exitCode: number | null;
        signal: NodeJS.Signals | null;
        stderr: string;
        timedOut: boolean;
    });
}
/**
 * Build the Anthropic credential portion of the child process environment for
 * the headless `claude` subprocess, applying the OAUTH-WINS SINGLE-INJECTION
 * precedence contract.
 *
 * The claude CLI reads two different env vars depending on auth mode:
 *   - CLAUDE_CODE_OAUTH_TOKEN  (long-lived token from `claude setup-token`)
 *   - ANTHROPIC_API_KEY        (pay-per-use Anthropic API key)
 *
 * Precedence (deterministic, exactly one credential injected):
 *   - If an OAuth token is present: return { CLAUDE_CODE_OAUTH_TOKEN } only.
 *     ANTHROPIC_API_KEY is deliberately NOT included so a stray API key cannot
 *     silently shadow OAuth and exhaust pay-per-use credits — the exact bug
 *     this dual-auth rewire fixes.
 *   - Else if an API key is present: return { ANTHROPIC_API_KEY } only.
 *   - Else: return {} (the entrypoint validates at-least-one before reaching
 *     the runner; this branch is defensive).
 *
 * A token/key is considered "present" only when it is a non-empty string after
 * trimming, so blank inputs do not accidentally win precedence.
 *
 * This is a pure function (no process.env access, no side effects) so the
 * precedence can be unit-tested directly without spawning a subprocess. Callers
 * spread the result into childEnv and must NOT set either credential elsewhere.
 *
 * Credential values are never logged here or by callers.
 *
 * @param creds.oauthToken - Optional OAuth token (CLAUDE_CODE_OAUTH_TOKEN).
 * @param creds.apiKey     - Optional API key (ANTHROPIC_API_KEY).
 * @returns An env fragment containing exactly zero or one credential var.
 */
export declare function buildClaudeAuthEnv(creds: {
    oauthToken?: string;
    apiKey?: string;
}): {
    CLAUDE_CODE_OAUTH_TOKEN: string;
} | {
    ANTHROPIC_API_KEY: string;
} | Record<string, never>;
/**
 * Build the complete child process environment for the claude subprocess.
 *
 * Only non-secret runtime variables are copied from the parent process. GitHub
 * Actions injects action inputs and secrets into INPUT_* and token-shaped env
 * variables; forwarding process.env wholesale would expose those values to the
 * model-driven child process and any tools it invokes.
 */
export declare function buildClaudeChildEnv(opts: {
    anthropicOauthToken?: string;
    anthropicApiKey?: string;
    anthropicModel?: string;
    sourceEnv?: NodeJS.ProcessEnv;
}): NodeJS.ProcessEnv;
/**
 * Build the claude `--mcp-config` payload that registers the Bob MCP server.
 *
 * Wiring this server is what enables PATH A in the skill: with the bob_* tools
 * available the skill runs bob_init_repo_session -> bob_repo_inventory ->
 * bob_extract_routes -> bob_build_symbol_surface_index -> bob_summarize_diff_impact
 * (real symbol-surface analysis + session cache). Without it the skill falls
 * back to PATH B heuristic dispatch.
 *
 * @param serverPath - Absolute path to the hacker-bob mcp/server.js.
 */
export declare function buildMcpConfig(serverPath: string): {
    mcpServers: Record<string, {
        command: string;
        args: string[];
    }>;
};
/**
 * Validate that a parsed JSON value matches the DiffReviewFindings schema.
 *
 * This is a runtime structural check — TypeScript types are erased at runtime
 * so we verify the required fields and their types explicitly.
 *
 * @param value - The parsed JSON to validate.
 * @returns The validated DiffReviewFindings.
 * @throws TypeError if validation fails.
 */
export declare function validateDiffReviewFindings(value: unknown): DiffReviewFindings;
/**
 * Create (or verify) the output directory for the bob-diff review run.
 *
 * When outputDir is provided it is created with mkdirSync({ recursive: true })
 * so the caller can pass a deterministic path for testing.  When omitted, a
 * fresh unique directory is created via mkdtempSync.
 *
 * @param outputDir - Optional explicit path.
 * @returns Absolute path to the output directory.
 */
export declare function resolveOutputDir(outputDir?: string): string;
/**
 * Run the bob-diff-review skill headlessly via the claude CLI.
 *
 * @param params - Runner parameters (see BobRunnerParams).
 * @returns Parsed and validated DiffReviewFindings from diff-review-findings.json.
 * @throws BobRunnerError on non-zero exit, timeout, or missing/invalid output.
 */
export declare function runBobDiffReview(params: BobRunnerParams): Promise<DiffReviewFindings>;
//# sourceMappingURL=bob-runner.d.ts.map