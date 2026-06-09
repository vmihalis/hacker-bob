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

import * as child_process from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import type { DiffReviewFindings, FindingEntry } from "./findings-serializer.js";
import { VALID_SEVERITIES } from "./findings-serializer.js";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Total time allowed for the headless claude process to exit. */
export const BOB_RUNNER_TIMEOUT_MS = 10 * 60 * 1000; // 10 minutes

/** Grace period between SIGTERM and SIGKILL. */
const SIGKILL_GRACE_MS = 5_000;

/** Non-secret environment variables the claude subprocess needs to run. */
const CLAUDE_CHILD_ENV_ALLOWLIST = Object.freeze([
  "PATH",
  "Path",
  "HOME",
  "USER",
  "LOGNAME",
  "SHELL",
  "TMPDIR",
  "TMP",
  "TEMP",
  "LANG",
  "LC_ALL",
  "LC_CTYPE",
  "TERM",
  "CI",
  "GITHUB_ACTIONS",
  "RUNNER_ARCH",
  "RUNNER_OS",
  "RUNNER_TEMP",
  "RUNNER_TOOL_CACHE",
  "NO_COLOR",
  "FORCE_COLOR",
  "NODE_OPTIONS",
  "NODE_EXTRA_CA_CERTS",
  "SSL_CERT_FILE",
  "BOB_MCP_SERVER_PATH",
  "SKIP_SURFACE_BUILD",
] as const);

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

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
export class BobRunnerError extends Error {
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
  }) {
    super(opts.message);
    this.name = "BobRunnerError";
    this.exitCode = opts.exitCode;
    this.signal = opts.signal;
    this.stderr = opts.stderr;
    this.timedOut = opts.timedOut;
  }
}

// ---------------------------------------------------------------------------
// Claude auth env construction (dual-auth precedence)
// ---------------------------------------------------------------------------

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
export function buildClaudeAuthEnv(creds: {
  oauthToken?: string;
  apiKey?: string;
}): { CLAUDE_CODE_OAUTH_TOKEN: string } | { ANTHROPIC_API_KEY: string } | Record<string, never> {
  const oauthToken = creds.oauthToken?.trim();
  const apiKey = creds.apiKey?.trim();

  if (oauthToken) {
    // OAuth wins: inject ONLY the OAuth token, never the API key.
    return { CLAUDE_CODE_OAUTH_TOKEN: oauthToken };
  }
  if (apiKey) {
    return { ANTHROPIC_API_KEY: apiKey };
  }
  // Defensive: no credential available. The entrypoint enforces at-least-one.
  return {};
}

/**
 * Build the complete child process environment for the claude subprocess.
 *
 * Only non-secret runtime variables are copied from the parent process. GitHub
 * Actions injects action inputs and secrets into INPUT_* and token-shaped env
 * variables; forwarding process.env wholesale would expose those values to the
 * model-driven child process and any tools it invokes.
 */
export function buildClaudeChildEnv(opts: {
  anthropicOauthToken?: string;
  anthropicApiKey?: string;
  anthropicModel?: string;
  sourceEnv?: NodeJS.ProcessEnv;
}): NodeJS.ProcessEnv {
  const sourceEnv = opts.sourceEnv ?? process.env;
  const childEnv: NodeJS.ProcessEnv = {};

  for (const key of CLAUDE_CHILD_ENV_ALLOWLIST) {
    const value = sourceEnv[key];
    if (value !== undefined) {
      childEnv[key] = value;
    }
  }

  if (opts.anthropicModel?.trim()) {
    childEnv["ANTHROPIC_MODEL"] = opts.anthropicModel.trim();
  }

  Object.assign(
    childEnv,
    buildClaudeAuthEnv({
      oauthToken: opts.anthropicOauthToken,
      apiKey: opts.anthropicApiKey,
    })
  );

  return childEnv;
}

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
export function buildMcpConfig(
  serverPath: string
): { mcpServers: Record<string, { command: string; args: string[] }> } {
  return {
    mcpServers: {
      "hacker-bob": { command: "node", args: [serverPath] },
    },
  };
}

// ---------------------------------------------------------------------------
// Schema validation
// ---------------------------------------------------------------------------

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
export function validateDiffReviewFindings(value: unknown): DiffReviewFindings {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(
      `diff-review-findings.json: expected an object at the top level, got ${
        value === null ? "null" : Array.isArray(value) ? "array" : typeof value
      }`
    );
  }

  const obj = value as Record<string, unknown>;

  // target_domain is the only required top-level string: it scopes the review
  // and the runner injects it from the invocation when the skill omits it.
  if (typeof obj["target_domain"] !== "string" || (obj["target_domain"] as string).length === 0) {
    throw new TypeError(
      `diff-review-findings.json: required string field "target_domain" is missing or empty`
    );
  }
  // session_id and generated_at are metadata, NOT required: degraded / PATH B
  // runs (Bob MCP server unavailable, heuristic dispatch) have no Bob session
  // and the skill may omit them. They are not needed to post comments; when
  // present they must be strings, and default to "" when absent.
  for (const key of ["session_id", "generated_at"] as const) {
    if (obj[key] !== undefined && typeof obj[key] !== "string") {
      throw new TypeError(
        `diff-review-findings.json: "${key}" must be a string when present`
      );
    }
    if (obj[key] === undefined) {
      obj[key] = "";
    }
  }

  // impacted_entries: optional. PATH A produces the symbol-surface intersection;
  // degraded / PATH B runs omit it. Defaults to []; when present must be an array.
  // The resolver maps findings to diff positions via the diff position map, so an
  // empty impacted_entries still yields inline comments (or PR-level fallbacks).
  if (obj["impacted_entries"] === undefined) {
    obj["impacted_entries"] = [];
  } else if (!Array.isArray(obj["impacted_entries"])) {
    throw new TypeError(
      `diff-review-findings.json: "impacted_entries" must be an array`
    );
  }

  // findings must be an array (may be empty).
  if (!Array.isArray(obj["findings"])) {
    throw new TypeError(
      `diff-review-findings.json: "findings" must be an array`
    );
  }

  // Validate each finding entry shape.
  const findings = obj["findings"] as unknown[];
  for (let i = 0; i < findings.length; i++) {
    validateFindingEntry(findings[i], i);
  }

  return obj as unknown as DiffReviewFindings;
}

/**
 * Validate a single FindingEntry object within the findings array.
 *
 * @param entry - The raw value to validate.
 * @param index - The 0-based index in the findings array (for error messages).
 * @throws TypeError on validation failure.
 */
function validateFindingEntry(entry: unknown, index: number): asserts entry is FindingEntry {
  const prefix = `diff-review-findings.json findings[${index}]`;

  if (entry === null || typeof entry !== "object" || Array.isArray(entry)) {
    throw new TypeError(`${prefix}: expected an object, got ${typeof entry}`);
  }

  const e = entry as Record<string, unknown>;

  // Essential string fields — a comment cannot be posted without a file path.
  if (typeof e["file"] !== "string" || (e["file"] as string).length === 0) {
    throw new TypeError(
      `${prefix}: field "file" must be a non-empty string, got ${typeof e["file"]}`
    );
  }

  // Essential numeric field — the inline position needs a start line.
  if (typeof e["line_start"] !== "number" || !Number.isFinite(e["line_start"] as number)) {
    throw new TypeError(
      `${prefix}: field "line_start" must be a finite number, got ${typeof e["line_start"]}`
    );
  }

  // Severity enum — drives the comment body and the Check Run conclusion.
  if (!(VALID_SEVERITIES as ReadonlyArray<unknown>).includes(e["severity"])) {
    throw new TypeError(
      `${prefix}: field "severity" must be one of ${VALID_SEVERITIES.join(", ")}, ` +
        `got ${JSON.stringify(e["severity"])}`
    );
  }

  // Supplementary string fields — present in PATH A output but the degraded /
  // PATH B path may omit them. Default to "" so downstream (body builder,
  // resolver) always sees a string; reject only a present non-string value.
  for (const key of ["surface_id", "title", "description", "evidence", "hunk_text"] as const) {
    if (e[key] === undefined || e[key] === null) {
      e[key] = "";
    } else if (typeof e[key] !== "string") {
      throw new TypeError(
        `${prefix}: field "${key}" must be a string when present, got ${typeof e[key]}`
      );
    }
  }

  // line_end is optional — default it to line_start (single-line finding).
  if (e["line_end"] === undefined || e["line_end"] === null) {
    e["line_end"] = e["line_start"];
  } else if (typeof e["line_end"] !== "number" || !Number.isFinite(e["line_end"] as number)) {
    throw new TypeError(
      `${prefix}: field "line_end" must be a finite number when present, got ${typeof e["line_end"]}`
    );
  }
}

// ---------------------------------------------------------------------------
// Output directory helper
// ---------------------------------------------------------------------------

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
export function resolveOutputDir(outputDir?: string): string {
  if (outputDir) {
    fs.mkdirSync(outputDir, { recursive: true });
    return path.resolve(outputDir);
  }
  return fs.mkdtempSync(path.join(os.tmpdir(), "bob-diff-"));
}

function quoteSkillPromptValue(value: string): string {
  return `"${value.replace(/(["\\$`])/g, "\\$1")}"`;
}

// ---------------------------------------------------------------------------
// Main runner
// ---------------------------------------------------------------------------

/**
 * Run the bob-diff-review skill headlessly via the claude CLI.
 *
 * @param params - Runner parameters (see BobRunnerParams).
 * @returns Parsed and validated DiffReviewFindings from diff-review-findings.json.
 * @throws BobRunnerError on non-zero exit, timeout, or missing/invalid output.
 */
export async function runBobDiffReview(
  params: BobRunnerParams
): Promise<DiffReviewFindings> {
  const {
    repo,
    diffFile,
    targetDomainOverride,
    anthropicOauthToken,
    anthropicApiKey,
    anthropicModel,
    timeoutMs = BOB_RUNNER_TIMEOUT_MS,
  } = params;

  // ---------------------------------------------------------------------------
  // Mock mode: BOB_MOCK_FINDINGS_JSON bypass
  //
  // When the environment variable BOB_MOCK_FINDINGS_JSON is set to a
  // non-empty string, skip the Claude subprocess entirely and return the
  // pre-seeded findings JSON directly.  This is used by the live integration
  // test (T3) to exercise the full pipeline (diff fetch, position map, review
  // comment posting, check run update, session cache write) without consuming
  // real Anthropic API credits.
  //
  // The value must be a valid JSON string matching DiffReviewFindings schema.
  // A TypeError from validateDiffReviewFindings() is re-thrown as-is so the
  // caller (action-entrypoint) can surface a clear schema-mismatch error.
  //
  // SECURITY: This bypass is only active when the env var is explicitly set.
  // It must never be set in production workflows — guard with an Actions
  // environment condition or a repo-level variable that is absent in prod.
  // ---------------------------------------------------------------------------
  const mockFindingsJson = process.env["BOB_MOCK_FINDINGS_JSON"];
  if (mockFindingsJson) {
    process.stdout.write(
      `[bob-runner] BOB_MOCK_FINDINGS_JSON set — bypassing Claude subprocess (mock mode).\n`
    );
    let parsed: unknown;
    try {
      parsed = JSON.parse(mockFindingsJson);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      throw new BobRunnerError({
        message: `BOB_MOCK_FINDINGS_JSON is not valid JSON: ${msg}`,
        exitCode: null,
        signal: null,
        stderr: "",
        timedOut: false,
      });
    }
    // Override target_domain so the returned findings reflect the current run.
    if (parsed !== null && typeof parsed === "object" && !Array.isArray(parsed)) {
      (parsed as Record<string, unknown>)["target_domain"] = targetDomainOverride;
    }
    return validateDiffReviewFindings(parsed);
  }

  // 1. Resolve output directory.
  const outputDir = resolveOutputDir(params.outputDir);

  // 2. Build the command and arguments.
  //
  //    claude --dangerously-skip-permissions --print \
  //      "/bob-diff-review --repo <abs-path> --diff-file <path>
  //         --target-domain-override <gh-id> --output-dir <tmp-dir>"
  //
  // Skills are invoked as a slash-command prompt in print (-p) mode. The
  // claude CLI does not support a --skill flag; skills resolve via /skill-name
  // in the prompt argument.
  // NOTE: we deliberately do NOT pass --target-domain-override to the skill.
  // The MCP repo-session authority requires the server-derived
  // `repo-<name>-<sha8>` slug and rejects any other value (normalization_failed),
  // so the skill must let bob_init_repo_session derive the session domain. The
  // Runner-owned metadata (targetDomainOverride) is stamped into
  // diff-review-findings.json after the skill returns; handing it to the skill
  // only tempts it to feed a caller-provided slug to the MCP (PATH B).
  const skillPrompt = [
    `/bob-diff-review`,
    `--repo`, quoteSkillPromptValue(path.resolve(repo)),
    `--diff-file`, quoteSkillPromptValue(path.resolve(diffFile)),
    `--output-dir`, quoteSkillPromptValue(outputDir),
  ].join(" ");
  const claudeArgs: string[] = [
    "--dangerously-skip-permissions",
    "--print",
  ];

  // Wire the Bob MCP server when available so the skill can run PATH A
  // (symbol-surface index + diff-impact via bob_* tools). The cache-bob-workspace
  // action installs the hacker-bob runtime and exports BOB_MCP_SERVER_PATH. When
  // it is set and the file exists, write a strict mcp-config and pass it to
  // claude; otherwise the skill falls back to PATH B (heuristic dispatch).
  const mcpServerPath = process.env["BOB_MCP_SERVER_PATH"];
  if (mcpServerPath && fs.existsSync(mcpServerPath)) {
    const mcpConfigPath = path.join(outputDir, "bob-mcp-config.json");
    fs.writeFileSync(
      mcpConfigPath,
      JSON.stringify(buildMcpConfig(path.resolve(mcpServerPath))),
      "utf8"
    );
    // --strict-mcp-config: ignore any ambient .mcp.json so only the Bob server
    // loads. The variadic --mcp-config consumes the file path and stops at the
    // next flag, keeping the skill prompt as the trailing positional argument.
    claudeArgs.push("--mcp-config", mcpConfigPath, "--strict-mcp-config");
    process.stderr.write(
      `[bob-runner] Bob MCP wired (PATH A enabled): ${mcpServerPath}\n`
    );
  } else {
    process.stderr.write(
      `[bob-runner] BOB_MCP_SERVER_PATH not set or file missing — skill will use PATH B (heuristic dispatch)\n`
    );
  }

  claudeArgs.push(skillPrompt);

  // 3. Build child process environment from an explicit allowlist plus exactly
  //    one Anthropic credential. Do not forward process.env wholesale: Actions
  //    inputs, GitHub tokens, package tokens, proxy credentials, and unrelated
  //    operator secrets can all be present in the parent environment.
  const childEnv = buildClaudeChildEnv({
    anthropicOauthToken,
    anthropicApiKey,
    anthropicModel,
  });

  // 4. Set up AbortController for the 10-minute timeout.
  const abortController = new AbortController();
  let timedOut = false;
  let sigkillTimer: ReturnType<typeof setTimeout> | null = null;

  const timeoutHandle = setTimeout(() => {
    timedOut = true;
    abortController.abort();
  }, timeoutMs);

  // 5. Spawn the process.
  //    Use spawn (not exec) to stream stdout/stderr to the GitHub Actions log
  //    as the child produces output, rather than buffering everything.
  let proc: child_process.ChildProcess;
  try {
    proc = child_process.spawn("claude", claudeArgs, {
      env: childEnv,
      stdio: ["ignore", "pipe", "pipe"],
      // AbortSignal: when the controller aborts, Node.js sends SIGTERM.
      // We escalate to SIGKILL after SIGKILL_GRACE_MS if needed.
      signal: abortController.signal,
    });
  } catch (spawnErr: unknown) {
    clearTimeout(timeoutHandle);
    const msg =
      spawnErr instanceof Error ? spawnErr.message : String(spawnErr);
    // Distinguish ENOENT (binary not found) from other spawn errors.
    if (msg.includes("ENOENT")) {
      throw new BobRunnerError({
        message:
          `claude binary not found on PATH. ` +
          `Ensure ~/bob-workspace/bin (or the directory containing the claude CLI) ` +
          `is prepended to PATH before running this action. ` +
          `Current PATH: ${process.env["PATH"] ?? "(unset)"}`,
        exitCode: null,
        signal: null,
        stderr: "",
        timedOut: false,
      });
    }
    throw new BobRunnerError({
      message: `Failed to spawn claude process: ${msg}`,
      exitCode: null,
      signal: null,
      stderr: "",
      timedOut: false,
    });
  }

  // 6. Stream stdout/stderr.
  const stderrChunks: Buffer[] = [];

  proc.stdout?.on("data", (chunk: Buffer) => {
    process.stdout.write(chunk);
  });

  proc.stderr?.on("data", (chunk: Buffer) => {
    process.stderr.write(chunk);
    stderrChunks.push(chunk);
  });

  // 7. Wait for the process to exit.
  const { exitCode, signal } = await new Promise<{
    exitCode: number | null;
    signal: NodeJS.Signals | null;
  }>((resolve) => {
    proc.on("close", (code, sig) => {
      clearTimeout(timeoutHandle);
      if (sigkillTimer !== null) {
        clearTimeout(sigkillTimer);
        sigkillTimer = null;
      }
      resolve({
        exitCode: code,
        signal: sig as NodeJS.Signals | null,
      });
    });

    proc.on("error", (err: NodeJS.ErrnoException) => {
      // AbortController abort() triggers an "AbortError" here; the 'close'
      // event follows shortly after.  We capture the error but let 'close'
      // do the final resolution so we always get a consistent exitCode/signal.
      if (err.name !== "AbortError") {
        // Unexpected spawn error after the process started — log and let close resolve.
        process.stderr.write(`[bob-runner] spawn error: ${err.message}\n`);
      }

      // If we aborted due to timeout, escalate to SIGKILL after grace period.
      if (timedOut && proc.pid !== undefined) {
        sigkillTimer = setTimeout(() => {
          try {
            process.kill(proc.pid!, "SIGKILL");
          } catch {
            // Process already exited — ignore.
          }
        }, SIGKILL_GRACE_MS);
      }
    });
  });

  const stderrOutput = Buffer.concat(stderrChunks).toString("utf8");

  // 8. Handle timeout.
  if (timedOut) {
    throw new BobRunnerError({
      message:
        `Bob diff-review process timed out after ${timeoutMs / 1000}s ` +
        `(limit: ${BOB_RUNNER_TIMEOUT_MS / 1000}s). ` +
        `The process was terminated with SIGTERM (then SIGKILL after ${SIGKILL_GRACE_MS / 1000}s).`,
      exitCode,
      signal,
      stderr: stderrOutput,
      timedOut: true,
    });
  }

  // 9. Handle non-zero exit.
  if (exitCode !== 0) {
    const stderrSnippet =
      stderrOutput.length > 2000
        ? stderrOutput.slice(-2000)
        : stderrOutput;
    throw new BobRunnerError({
      message:
        `Bob diff-review process exited with code ${exitCode ?? "(killed)"}` +
        (signal ? ` (signal: ${signal})` : "") +
        (stderrSnippet.trim().length > 0
          ? `\n\nStderr (last 2000 chars):\n${stderrSnippet}`
          : ""),
      exitCode,
      signal,
      stderr: stderrOutput,
      timedOut: false,
    });
  }

  // 10. Read diff-review-findings.json.
  const findingsPath = path.join(outputDir, "diff-review-findings.json");
  let rawJson: string;
  try {
    rawJson = fs.readFileSync(findingsPath, "utf8");
  } catch (readErr: unknown) {
    const errMsg =
      readErr instanceof Error ? readErr.message : String(readErr);
    const isNotFound =
      readErr instanceof Error &&
      (readErr as NodeJS.ErrnoException).code === "ENOENT";
    throw new BobRunnerError({
      message: isNotFound
        ? `diff-review-findings.json was not written to output-dir (${outputDir}). ` +
          `The claude process exited 0 but did not produce the expected output file. ` +
          `This typically means the bob-diff-review skill crashed during serialization. ` +
          `Check stdout above for details.`
        : `Failed to read diff-review-findings.json from ${findingsPath}: ${errMsg}`,
      exitCode: 0,
      signal: null,
      stderr: stderrOutput,
      timedOut: false,
    });
  }

  // 11. Parse the JSON.
  let parsed: unknown;
  try {
    parsed = JSON.parse(rawJson);
  } catch (parseErr: unknown) {
    const errType =
      parseErr instanceof Error ? parseErr.name || "SyntaxError" : "SyntaxError";
    throw new BobRunnerError({
      message:
        `diff-review-findings.json at ${findingsPath} is not valid JSON (${errType}). ` +
        `Raw file content was not logged because findings may contain sensitive evidence.`,
      exitCode: 0,
      signal: null,
      stderr: stderrOutput,
      timedOut: false,
    });
  }

  // 12. Enrich with runner-authoritative metadata, then validate.
  //     The skill's degraded / PATH B output may omit target_domain and
  //     generated_at. The runner knows the target domain it was invoked with
  //     and can stamp the generation time, so inject both when missing rather
  //     than failing a review that has valid findings.
  if (parsed !== null && typeof parsed === "object" && !Array.isArray(parsed)) {
    const p = parsed as Record<string, unknown>;
    if (typeof p["target_domain"] !== "string" || !(p["target_domain"] as string)) {
      p["target_domain"] = targetDomainOverride;
    }
    if (typeof p["generated_at"] !== "string" || !(p["generated_at"] as string)) {
      p["generated_at"] = new Date().toISOString();
    }
  }

  let findings: DiffReviewFindings;
  try {
    findings = validateDiffReviewFindings(parsed);
  } catch (validationErr: unknown) {
    const errMsg =
      validationErr instanceof Error
        ? validationErr.message
        : String(validationErr);
    throw new BobRunnerError({
      message:
        `diff-review-findings.json schema validation failed: ${errMsg}`,
      exitCode: 0,
      signal: null,
      stderr: stderrOutput,
      timedOut: false,
    });
  }

  return findings;
}
