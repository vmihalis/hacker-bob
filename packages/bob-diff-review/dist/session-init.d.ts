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
export { buildTargetDomain, resolveSessionDir, resolveCacheState } from "./session-cache.js";
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
export type S2InitResult = {
    ok: true;
    session_id: string;
    session_dir: string;
    target_domain: string;
    is_resume: boolean;
} | {
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
    code: "repo_path_not_found" | "repo_path_not_directory" | "repo_path_remote_shape" | "target_domain_mismatch" | "session_corrupt" | "inventory_empty" | "mcp_error" | "unknown";
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
    error?: {
        code: string;
        message: string;
    };
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
/**
 * Validate the --repo argument before calling bob_init_repo_session.
 *
 * Returns null on success, or a structured S2InitError on failure.
 *
 * @param repoPath - The value supplied via --repo (may be relative at entry).
 * @param resolved  - The resolved absolute path (from path.resolve(repoPath)).
 */
export declare function validateRepoPath(repoPath: string, resolved: string): S2InitError | null;
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
export declare function sessionDirExists(targetDomain: string): boolean;
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
export declare function buildInitParams(repoPath: string, targetDomain: string, opts?: {
    commit?: string;
    branch?: string;
    source_url?: string;
    egress_profile?: string;
    deep_mode?: boolean;
}): InitRepoSessionParams;
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
export declare function normaliseInitResult(raw: unknown, params: InitRepoSessionParams, isResume: boolean): S2InitResult;
/**
 * Normalise a raw bob_repo_inventory MCP response into an S2InventoryResult.
 *
 * @param raw - Raw MCP response object.
 */
export declare function normaliseInventoryResult(raw: unknown): S2InventoryResult;
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
export declare function prepareS2(args: S2StepArgs): {
    validation_error: S2InitError | null;
    mcp_params: InitRepoSessionParams | null;
    resolved_repo_path: string;
    is_resume: boolean;
};
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
export declare function formatStepFailureJson(step: string, error: S2InitError): string;
//# sourceMappingURL=session-init.d.ts.map