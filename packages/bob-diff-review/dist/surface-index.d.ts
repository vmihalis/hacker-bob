/**
 * S3 — Route extraction + symbol surface index (conditional on cache miss).
 *
 * This module implements the conditional logic that guards the two expensive
 * MCP calls in the S3 pipeline step:
 *
 *   1. bob_extract_routes — analyzes framework-specific routing (Express,
 *      FastAPI, Rails, etc.) and returns a route list persisted to the session.
 *
 *   2. bob_build_symbol_surface_index — links routes to handler symbols and
 *      their transitive callees, writing symbol-surface-index.json to the
 *      session directory.
 *
 * Both calls are skipped entirely when the SKIP_SURFACE_BUILD environment
 * variable is set to "true" (signal emitted by the C2 cache step when a warm
 * session already contains symbol-surface-index.json).
 *
 * All MCP calls are executed by the orchestrator agent (SKILL.md); this module
 * provides only the TypeScript types and helper functions that bob-runner.ts
 * uses to drive those calls and interpret their results.
 */
/** Filename written by bob_build_symbol_surface_index to the session dir. */
export declare const SYMBOL_INDEX_FILENAME = "symbol-surface-index.json";
/**
 * A single entry in symbol-surface-index.json.
 *
 * The MCP tool bob_build_symbol_surface_index writes an array of these to
 * the session directory. bob_summarize_diff_impact reads the index to resolve
 * diff hunks (file + line range) to the security-relevant surfaces they touch.
 */
export interface SymbolSurfaceEntry {
    /** Fully-qualified symbol name (function, class, route handler, etc.). */
    symbol: string;
    /** Repo-relative file path where the symbol is defined. */
    file: string;
    /** Line number of the symbol definition start (1-indexed). */
    line_start: number;
    /** Line number of the symbol definition end (1-indexed, inclusive). */
    line_end: number;
    /**
     * Surface identifier this symbol belongs to.
     * Matches the surface_id used in bob session surface graph nodes.
     */
    surface_id: string;
    /**
     * Broad surface classification for dispatch.
     * Common values: 'api-route', 'authentication', 'authorization',
     * 'admin', 'smart-contract', 'data-model', 'upload', 'crypto', 'other'.
     */
    surface_type: string;
}
/**
 * A single route entry returned by bob_extract_routes.
 */
export interface ExtractedRoute {
    /** HTTP method, e.g. 'GET', 'POST'. Empty for non-HTTP entry points. */
    method?: string;
    /** Route path pattern, e.g. '/api/v1/users/:id'. */
    path: string;
    /** Repo-relative path to the file containing the handler. */
    handler_file: string;
    /** Name of the handler function, class method, or entry point. */
    handler_symbol?: string;
    /** Line number of the handler definition (1-indexed). */
    handler_line?: number;
    /**
     * Framework that produced this route, e.g. 'express', 'fastapi', 'rails',
     * 'gin', 'nextjs', 'unknown'.
     */
    framework?: string;
    /** Surface ID inferred from the route path pattern (may be updated by S3). */
    surface_id?: string;
}
/**
 * Result of the bob_extract_routes MCP call.
 */
export interface S3RoutesResult {
    ok: boolean;
    /** Number of routes/entry-points extracted. */
    route_count: number;
    /** Representative sample of extracted routes (first 20). */
    sample: ExtractedRoute[];
    /** Error details if ok is false. */
    error?: {
        code: string;
        message: string;
    };
}
/**
 * Result of the bob_build_symbol_surface_index MCP call.
 */
export interface S3IndexResult {
    ok: boolean;
    /**
     * Number of distinct surfaces discovered.
     * Logged for smoke-test validation per acceptance criteria.
     */
    surface_count: number;
    /**
     * Number of symbol entries written to symbol-surface-index.json.
     */
    symbol_count: number;
    /** Absolute path to the written symbol-surface-index.json. */
    index_path?: string;
    /** Error details if ok is false. */
    error?: {
        code: string;
        message: string;
    };
}
/**
 * Outcome of the S3 step returned by prepareS3 for decision-making.
 *
 * When `skipped` is true, no MCP calls are made and both `routes` and `index`
 * are null. When `skipped` is false, the orchestrator agent executes the MCP
 * calls and passes their responses to normaliseRoutesResult /
 * normaliseIndexResult.
 */
export type S3StepDecision = {
    skipped: true;
    reason: "env_var" | "file_exists";
} | {
    skipped: false;
    target_domain: string;
    session_dir: string;
};
/**
 * Return true when the SKIP_SURFACE_BUILD environment variable is set to
 * "true" (case-insensitive). The C2 cache step sets this when it detects a
 * warm symbol-surface-index.json in the restored session dir.
 */
export declare function isSkipEnvSet(): boolean;
/**
 * Return true when symbol-surface-index.json already exists in the session
 * directory (direct filesystem check, used as a belt-and-suspenders guard
 * alongside the env-var signal).
 *
 * @param targetDomain - e.g. 'gh-12345678'
 */
export declare function indexFileExists(targetDomain: string): boolean;
/**
 * Determine whether the S3 step should run or be skipped.
 *
 * The step is skipped when either:
 *   a) SKIP_SURFACE_BUILD=true is set in the environment (set by C2 cache step
 *      or resolveCacheState() in session-cache.ts), OR
 *   b) symbol-surface-index.json already exists in the session directory
 *      (filesystem fallback for cases where the env var was cleared).
 *
 * Logs the skip reason or build intent to stdout for observability.
 *
 * @param targetDomain - 'gh-' + github.repository_id from C2
 * @returns S3StepDecision — callers branch on `skipped` before calling MCP
 */
export declare function decideS3(targetDomain: string): S3StepDecision;
/**
 * Normalise a raw bob_extract_routes MCP response into an S3RoutesResult.
 *
 * @param raw - Raw MCP response (parsed JSON or thrown error object).
 */
export declare function normaliseRoutesResult(raw: unknown): S3RoutesResult;
/**
 * Normalise a raw bob_build_symbol_surface_index MCP response into an
 * S3IndexResult.
 *
 * Logs the surface count on success for smoke-test validation (acceptance
 * criterion: "surface count is logged for smoke-test validation").
 *
 * @param raw - Raw MCP response (parsed JSON or thrown error object).
 */
export declare function normaliseIndexResult(raw: unknown): S3IndexResult;
/**
 * Format a structured JSON error string for S3 step failure surfacing.
 *
 * The orchestrator agent writes this to stdout so downstream callers
 * (bob-runner.ts, GitHub Actions step summary) can parse it without
 * regex-scraping prose messages.
 *
 * @param sub_step - Sub-step label, e.g. 'S3.extract_routes' or 'S3.index'.
 * @param error    - The error detail object.
 */
export declare function formatS3FailureJson(sub_step: string, error: {
    code: string;
    message: string;
}): string;
//# sourceMappingURL=surface-index.d.ts.map