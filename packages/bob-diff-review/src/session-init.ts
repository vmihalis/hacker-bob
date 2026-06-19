/**
 * S2 — Session init + inventory.
 *
 * Implements the two MCP calls that form the structural foundation of the
 * bob-diff-review pipeline:
 *
 *   1. bob_init_repo_session — binds a Bob session to the locally checked-out
 *      repo.  Uses the deterministic `gh-<repository_id>` target_domain from
 *      C2 so the session path is stable across PR runs.  Passes resume:true
 *      (via existing-dir detection) so a C2 cache restore is honoured rather
 *      than overwritten.
 *
 *   2. bob_repo_inventory — walks the bound repo and materialises
 *      repo-inventory.json plus frontier surface.observed events. Required
 *      before S3 (symbol surface index) or S4b (heuristic dispatch) can run.
 *
 * All MCP calls are executed by the orchestrator agent; this module only
 * provides the TypeScript types and helper functions that bob-runner.ts uses
 * to drive those calls and interpret their results.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";

// ---------------------------------------------------------------------------
// Re-export session-cache helpers so callers only need one import
// ---------------------------------------------------------------------------
export { buildTargetDomain, resolveSessionDir, resolveCacheState } from "./session-cache.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/**
 * Parameters passed to the bob_init_repo_session MCP tool by the S2 step.
 *
 * Note: `resume` is not a native MCP parameter — it is inferred from whether
 * the session directory already exists (C2 cache hit). When true, the agent
 * skips rewriting existing session state and calls bob_init_repo_session with
 * the same target_domain so the MCP server merges rather than overwrites.
 */
export interface InitRepoSessionParams {
  /** Absolute path to the locally checked-out repository. */
  repo_path: string;
  /**
   * Deterministic target_domain override.
   * Must be 'gh-' + github.repository_id to match the C2 cache key.
   */
  target_domain: string;
  /** Optional 7-64 hex commit SHA for provenance and docker image tag. */
  commit?: string;
  /** Optional branch name for provenance. */
  branch?: string;
  /** Optional upstream source URL for provenance (never used to clone). */
  source_url?: string;
  /** Egress profile; defaults to 'default'. */
  egress_profile?: string;
  /** Enable deep mode scanning. Defaults to false for diff-review. */
  deep_mode?: boolean;
  /**
   * Whether the session directory already existed before this call.
   * When true, the agent treats bob_init_repo_session as a resume rather
   * than a fresh init.  Not sent to the MCP tool; used by bob-runner.ts
   * to set log context and skip redundant state initialisation.
   */
  is_resume?: boolean;
}

/**
 * Structured result returned by the S2 session-init step.
 *
 * On success `ok` is true and `session_id`, `session_dir`, and
 * `target_domain` are set.  On failure `ok` is false and `error` is set.
 */
export type S2InitResult =
  | {
      ok: true;
      session_id: string;
      session_dir: string;
      target_domain: string;
      is_resume: boolean;
    }
  | {
      ok: false;
      error: S2InitError;
    };

/**
 * Structured error produced when bob_init_repo_session fails.
 *
 * The `code` field maps to known MCP error codes so callers can handle
 * specific failure modes without string-matching error messages.
 */
export interface S2InitError {
  code:
    | "repo_path_not_found"
    | "repo_path_not_directory"
    | "repo_path_remote_shape"
    | "target_domain_mismatch"
    | "session_corrupt"
    | "inventory_empty"
    | "mcp_error"
    | "unknown";
  message: string;
  /** Raw MCP error object, if available. */
  cause?: unknown;
}

/**
 * Result of the bob_repo_inventory MCP call.
 *
 * The MCP tool returns an inventory artifact; we surface only the fields
 * bob-runner.ts needs for pipeline decisions.
 */
export interface S2InventoryResult {
  ok: boolean;
  /** Total number of files enumerated. */
  file_count: number;
  /**
   * Representative sample of file entries with language tags.
   * The full inventory is persisted to repo-inventory.json in the session dir
   * by the MCP server; this subset is for logging and fast dispatch decisions.
   */
  sample: InventoryEntry[];
  /** Language distribution map: language → file count. */
  languages: Record<string, number>;
  /** Error details if ok is false. */
  error?: { code: string; message: string };
}

/** A single inventory entry as reported by bob_repo_inventory. */
export interface InventoryEntry {
  /** Repo-relative file path. */
  path: string;
  /** Detected language tag (e.g. 'typescript', 'solidity', 'go'). */
  language?: string;
  /** File kind: 'source', 'config', 'manifest', 'ci', 'test', 'other'. */
  kind?: string;
}

// ---------------------------------------------------------------------------
// Repo path validation helpers
// ---------------------------------------------------------------------------

/**
 * Remote-shape patterns that are never valid for --repo.
 * The agent must refuse these before calling bob_init_repo_session.
 */
const REMOTE_SHAPE_PATTERNS: ReadonlyArray<RegExp> = [
  /^git@/,
  /^git\+/,
  /^ssh:\/\//,
  /^https?:\/\//,
  // Bare "owner/repo" slug — two non-empty path segments with no leading slash.
  /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/,
];

/**
 * Validate the --repo argument before calling bob_init_repo_session.
 *
 * Returns null on success, or a structured S2InitError on failure.
 *
 * @param repoPath - The value supplied via --repo (may be relative at entry).
 * @param resolved  - The resolved absolute path (from path.resolve(repoPath)).
 */
export function validateRepoPath(
  repoPath: string,
  resolved: string
): S2InitError | null {
  // 1. Refuse remote shapes (checked against the raw input, not the resolved
  //    path, since remote shapes cannot produce a valid local absolute path).
  for (const pattern of REMOTE_SHAPE_PATTERNS) {
    if (pattern.test(repoPath.trim())) {
      return {
        code: "repo_path_remote_shape",
        message:
          `--repo value looks like a remote reference: "${repoPath}". ` +
          "bob-diff-review requires a locally checked-out directory. " +
          "Pass an absolute path to a directory on the runner filesystem.",
      };
    }
  }

  // 2. Must exist.
  if (!fs.existsSync(resolved)) {
    return {
      code: "repo_path_not_found",
      message:
        `Resolved repo path "${resolved}" does not exist. ` +
        "Ensure the repository is checked out before invoking the skill.",
    };
  }

  // 3. Must be a directory.
  const stat = fs.statSync(resolved);
  if (!stat.isDirectory()) {
    return {
      code: "repo_path_not_directory",
      message:
        `Resolved repo path "${resolved}" exists but is not a directory (it is a file). ` +
        "Pass the repository root, not a file path.",
    };
  }

  return null;
}

/**
 * Detect whether a Bob session already exists for this target_domain.
 *
 * The session directory lives at ~/hacker-bob-sessions/<target_domain>.
 * When it exists (restored from C2 cache), bob_init_repo_session should be
 * called with the same arguments so the MCP server resumes rather than
 * creating a fresh session.  bob-runner.ts logs this as a cache resume.
 *
 * @param targetDomain - e.g. 'gh-12345678'
 * @returns true when the session directory exists.
 */
export function sessionDirExists(targetDomain: string): boolean {
  const sessionDir = path.join(
    os.homedir(),
    "hacker-bob-sessions",
    targetDomain
  );
  return fs.existsSync(sessionDir);
}

/**
 * Build the bob_init_repo_session parameters for the S2 step.
 *
 * The caller should pass these to the MCP tool via the orchestrator agent.
 * `is_resume` is set based on whether the session directory already exists
 * so the agent can log the correct context without re-checking the filesystem.
 *
 * @param repoPath     - Validated absolute path to the checked-out repo.
 * @param targetDomain - 'gh-' + github.repository_id from C2.
 * @param opts         - Optional provenance and profile overrides.
 */
export function buildInitParams(
  repoPath: string,
  targetDomain: string,
  opts: {
    commit?: string;
    branch?: string;
    source_url?: string;
    egress_profile?: string;
    deep_mode?: boolean;
  } = {}
): InitRepoSessionParams {
  const is_resume = sessionDirExists(targetDomain);

  return {
    repo_path: repoPath,
    target_domain: targetDomain,
    egress_profile: opts.egress_profile ?? "default",
    deep_mode: opts.deep_mode ?? false,
    is_resume,
    ...(opts.commit !== undefined && { commit: opts.commit }),
    ...(opts.branch !== undefined && { branch: opts.branch }),
    ...(opts.source_url !== undefined && { source_url: opts.source_url }),
  };
}

// ---------------------------------------------------------------------------
// MCP result normalisation
// ---------------------------------------------------------------------------

/**
 * Normalise a raw bob_init_repo_session MCP response into an S2InitResult.
 *
 * The MCP tool returns a JSON object whose shape varies between success and
 * error. This function coerces either shape into the discriminated union used
 * by bob-runner.ts so that all error handling is in one place.
 *
 * @param raw        - Raw MCP response (parsed JSON or thrown error object).
 * @param params     - Parameters that were passed to the MCP call.
 * @param isResume   - Whether the call was a resume (session dir pre-existed).
 */
export function normaliseInitResult(
  raw: unknown,
  params: InitRepoSessionParams,
  isResume: boolean
): S2InitResult {
  // MCP errors are typically thrown as objects with a `code` and `message`.
  if (raw instanceof Error || (typeof raw === "object" && raw !== null && "error" in raw)) {
    const errObj = raw as Record<string, unknown>;
    const code = (errObj["code"] as string | undefined) ?? "mcp_error";
    const message =
      (errObj["message"] as string | undefined) ??
      (raw instanceof Error ? raw.message : JSON.stringify(raw));

    return {
      ok: false,
      error: {
        code: mapMcpErrorCode(code),
        message,
        cause: raw,
      },
    };
  }

  // Success path: MCP returns an object with session_id and session_dir.
  if (typeof raw === "object" && raw !== null) {
    const resp = raw as Record<string, unknown>;
    const session_id =
      (resp["session_id"] as string | undefined) ??
      (resp["data"] as Record<string, unknown> | undefined)?.["session_id"] as string | undefined;
    const session_dir =
      (resp["session_dir"] as string | undefined) ??
      (resp["data"] as Record<string, unknown> | undefined)?.["session_dir"] as string | undefined;

    if (session_id && session_dir) {
      return {
        ok: true,
        session_id,
        session_dir,
        target_domain: params.target_domain,
        is_resume: isResume,
      };
    }

    // Got an object but missing required fields — treat as unknown error.
    return {
      ok: false,
      error: {
        code: "mcp_error",
        message:
          `bob_init_repo_session returned an unexpected response shape: ` +
          JSON.stringify(raw).slice(0, 500),
        cause: raw,
      },
    };
  }

  return {
    ok: false,
    error: {
      code: "unknown",
      message:
        `bob_init_repo_session returned an unexpected value type (${typeof raw}): ` +
        String(raw).slice(0, 200),
      cause: raw,
    },
  };
}

/**
 * Map raw MCP error code strings to our typed S2InitError codes.
 */
function mapMcpErrorCode(raw: string): S2InitError["code"] {
  const MAP: Record<string, S2InitError["code"]> = {
    repo_path_not_found: "repo_path_not_found",
    repo_path_not_directory: "repo_path_not_directory",
    remote_repo_forbidden: "repo_path_remote_shape",
    target_domain_mismatch: "target_domain_mismatch",
    session_corrupt: "session_corrupt",
  };
  return MAP[raw] ?? "mcp_error";
}

/**
 * Normalise a raw bob_repo_inventory MCP response into an S2InventoryResult.
 *
 * @param raw - Raw MCP response object.
 */
export function normaliseInventoryResult(raw: unknown): S2InventoryResult {
  if (raw instanceof Error || (typeof raw === "object" && raw !== null && "error" in (raw as object))) {
    const errObj = raw as Record<string, unknown>;
    return {
      ok: false,
      file_count: 0,
      sample: [],
      languages: {},
      error: {
        code: (errObj["code"] as string | undefined) ?? "mcp_error",
        message:
          (errObj["message"] as string | undefined) ??
          (raw instanceof Error ? raw.message : JSON.stringify(raw)),
      },
    };
  }

  if (typeof raw === "object" && raw !== null) {
    const resp = raw as Record<string, unknown>;
    // Support both flat and nested `data` wrappers from the MCP server.
    const data = (resp["data"] as Record<string, unknown> | undefined) ?? resp;

    const file_count =
      (data["file_count"] as number | undefined) ??
      (data["total_files"] as number | undefined) ??
      (Array.isArray(data["files"]) ? (data["files"] as unknown[]).length : 0);

    const rawFiles = (data["files"] as unknown[] | undefined) ?? [];
    const sample: InventoryEntry[] = rawFiles.slice(0, 50).map((f) => {
      if (typeof f === "object" && f !== null) {
        const fe = f as Record<string, unknown>;
        return {
          path: (fe["path"] as string | undefined) ?? (fe["file"] as string | undefined) ?? "",
          language: (fe["language"] as string | undefined) ?? (fe["lang"] as string | undefined),
          kind: (fe["kind"] as string | undefined) ?? (fe["type"] as string | undefined),
        };
      }
      return { path: String(f) };
    });

    const rawLangs = (data["languages"] as Record<string, number> | undefined) ?? {};
    const languages: Record<string, number> = {};
    for (const [lang, count] of Object.entries(rawLangs)) {
      if (typeof count === "number") languages[lang] = count;
    }

    return { ok: true, file_count, sample, languages };
  }

  return {
    ok: false,
    file_count: 0,
    sample: [],
    languages: {},
    error: {
      code: "unknown",
      message: `bob_repo_inventory returned unexpected value type (${typeof raw})`,
    },
  };
}

// ---------------------------------------------------------------------------
// S2 step driver (called by the bob-diff-review orchestrator agent)
// ---------------------------------------------------------------------------

/**
 * Arguments accepted by the S2 step driver function.
 */
export interface S2StepArgs {
  /** Raw --repo value from $ARGUMENTS (may be relative). */
  repo_arg: string;
  /** target_domain from C2 (always 'gh-' + github.repository_id). */
  target_domain: string;
  /** Optional commit SHA for provenance. */
  commit?: string;
  /** Optional branch name for provenance. */
  branch?: string;
  /** Optional upstream source URL for provenance. */
  source_url?: string;
}

/**
 * Combined S2 result returned after both MCP calls complete.
 */
export interface S2StepResult {
  init: S2InitResult;
  inventory: S2InventoryResult | null;
  /**
   * Structured error JSON string to surface when init fails.
   * Set when init.ok is false; null otherwise.
   */
  failure_json: string | null;
}

/**
 * Validate repo_arg, derive InitRepoSessionParams, and return both the params
 * and a pre-flight validation error (if any) so the orchestrator agent can
 * perform the MCP calls itself.
 *
 * This function does NOT call MCP tools — it is a pure helper that the agent
 * uses to determine what to pass and whether to proceed.
 *
 * Pattern:
 *   1. Agent calls `prepareS2` to validate inputs and learn resume semantics.
 *   2. Agent calls `mcp__hacker-bob__bob_init_repo_session` with params.mcp_params.
 *   3. Agent calls `normaliseInitResult` on the response.
 *   4. Agent calls `mcp__hacker-bob__bob_repo_inventory` with params.target_domain.
 *   5. Agent calls `normaliseInventoryResult` on the response.
 *   6. Agent surfaces failure_json if either step fails.
 */
export function prepareS2(args: S2StepArgs): {
  validation_error: S2InitError | null;
  mcp_params: InitRepoSessionParams | null;
  resolved_repo_path: string;
  is_resume: boolean;
} {
  const resolved = path.resolve(args.repo_arg);
  const validation_error = validateRepoPath(args.repo_arg, resolved);
  if (validation_error !== null) {
    return {
      validation_error,
      mcp_params: null,
      resolved_repo_path: resolved,
      is_resume: false,
    };
  }

  const mcp_params = buildInitParams(resolved, args.target_domain, {
    commit: args.commit,
    branch: args.branch,
    source_url: args.source_url,
    egress_profile: "default",
    deep_mode: false,
  });

  return {
    validation_error: null,
    mcp_params,
    resolved_repo_path: resolved,
    is_resume: mcp_params.is_resume ?? false,
  };
}

/**
 * Format a structured JSON error string for step failure surfacing.
 *
 * The orchestrator agent writes this to stdout as a JSON line so that
 * downstream callers (bob-runner.ts, GitHub Actions step summary) can parse it
 * without regex-scraping prose error messages.
 *
 * @param step   - Pipeline step label, e.g. 'S2.init' or 'S2.inventory'.
 * @param error  - The S2InitError to serialise.
 */
export function formatStepFailureJson(
  step: string,
  error: S2InitError
): string {
  return JSON.stringify(
    {
      step,
      ok: false,
      error: {
        code: error.code,
        message: error.message,
      },
    },
    null,
    2
  );
}
