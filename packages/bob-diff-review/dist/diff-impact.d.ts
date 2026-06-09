/**
 * S4 — Diff impact analysis via bob_summarize_diff_impact (PATH A).
 *
 * This module implements PATH A of the diff impact step: passing the full
 * unified diff text to the bob_summarize_diff_impact MCP tool, which
 * cross-references each changed hunk against the symbol surface index to
 * produce impacted_entries — the list of {file, line_start, line_end,
 * surface_ids[], hunk_summary} objects that drive evaluator agent spawning in
 * S5.
 *
 * PATH A is always the preferred path because it provides precise, index-backed
 * surface targeting. The orchestrator agent falls back to PATH B (heuristic
 * dispatch in heuristic-dispatch.ts) only when bob_summarize_diff_impact is
 * unavailable or returns an error.
 *
 * All MCP calls are executed by the orchestrator agent (SKILL.md); this module
 * provides the TypeScript types and helper functions that bob-runner.ts uses to
 * drive those calls and interpret their results.
 */
export type { ImpactedEntry } from "./heuristic-dispatch.js";
/**
 * The raw MCP response shape from bob_summarize_diff_impact.
 *
 * The tool may nest its result under a `data` key or return it flat; the
 * normaliser handles both shapes.
 */
export interface RawDiffImpactResponse {
    /** Whether the tool call succeeded. */
    ok?: boolean;
    /** Impacted entries when nested under data. */
    data?: {
        impacted_entries?: unknown[];
        path_used?: string;
        [key: string]: unknown;
    };
    /** Impacted entries when returned flat. */
    impacted_entries?: unknown[];
    /** PATH token (e.g. "A" or "symbol_index"). */
    path_used?: string;
    /** Error detail when ok is false. */
    error?: {
        code?: string;
        message?: string;
    };
    [key: string]: unknown;
}
/**
 * A normalised impacted entry produced by bob_summarize_diff_impact (PATH A).
 *
 * The schema is intentionally identical to the PATH B ImpactedEntry so that S5
 * and S6 are path-agnostic. Re-exported from heuristic-dispatch for alignment.
 */
/**
 * The result of the S4 PATH A step.
 */
export type S4PathAResult = {
    ok: true;
    /** Impacted entries derived from the symbol surface index. */
    impacted_entries: import("./heuristic-dispatch.js").ImpactedEntry[];
    /**
     * Number of impacted entries produced. Used for the required log line:
     * 'S4 PATH A: N impacted entries from symbol index'.
     */
    entry_count: number;
    /**
     * Whether the result set was empty. When true, the orchestrator should
     * log 'no impacted surfaces' and exit cleanly rather than spawning
     * evaluator agents.
     */
    is_empty: boolean;
} | {
    ok: false;
    error: {
        code: string;
        message: string;
    };
};
/**
 * Input parameters for the bob_summarize_diff_impact MCP call.
 *
 * The orchestrator agent passes these directly to the MCP tool.
 */
export interface DiffImpactParams {
    /** Bob session target_domain (e.g. 'gh-12345678'). */
    target_domain: string;
    /**
     * Full unified diff text including a/ b/ headers.
     * Must be the output of `git diff base...head` — the complete diff, not a
     * per-file slice.
     */
    diff_text: string;
}
/**
 * Normalise a raw bob_summarize_diff_impact MCP response into an S4PathAResult.
 *
 * Handles both flat and data-nested response shapes. An empty impacted_entries
 * array is a valid success (not an error); the caller should check is_empty and
 * log 'no impacted surfaces' before exiting cleanly.
 *
 * @param raw - Raw MCP response (parsed JSON or thrown error object).
 */
export declare function normaliseDiffImpactResult(raw: unknown): S4PathAResult;
/**
 * Format a structured JSON failure string for S4 PATH A error surfacing.
 *
 * @param error - The error detail object.
 */
export declare function formatS4FailureJson(error: {
    code: string;
    message: string;
}): string;
/**
 * Log PATH A activation to stdout.
 *
 * This is the exact string required by the acceptance criterion:
 *   "PATH A activation is logged: 'PATH A: diff impact via symbol index'"
 *
 * The orchestrator agent should call this before executing
 * bob_summarize_diff_impact.
 */
export declare function logPathAActivation(): void;
/**
 * Log the impacted entry count after a successful PATH A call.
 *
 * Produces: "S4 PATH A: N impacted entries from symbol index"
 *
 * @param entryCount - Length of the impacted_entries array.
 */
export declare function logPathASuccess(entryCount: number): void;
/**
 * Log the clean exit when PATH A produces zero impacted entries.
 *
 * Produces: "no impacted surfaces"
 */
export declare function logNoImpactedSurfaces(): void;
/**
 * Top-level schema of diff-impact.json written to the session dir via MCP.
 *
 * This artifact is written by the orchestrator agent using an MCP write call
 * (not a direct Write tool call), satisfying the acceptance criterion:
 *   "diff-impact.json written to session dir via MCP (not direct Write)"
 *
 * Specifically, the orchestrator passes this payload to the appropriate MCP
 * persistence tool after bob_summarize_diff_impact returns.
 */
export interface DiffImpactArtifact {
    /** Schema version for forward-compatibility. */
    schema_version: 1;
    /** Bob session target_domain. */
    target_domain: string;
    /** Which path produced the entries: "A" (symbol index) or "B" (heuristic). */
    path_used: "A" | "B";
    /** Total number of impacted entries. */
    entry_count: number;
    /** All impacted entries with file, line range, surface IDs, and hunk summary. */
    impacted_entries: import("./heuristic-dispatch.js").ImpactedEntry[];
}
/**
 * Build the DiffImpactArtifact payload from a successful PATH A result.
 *
 * The orchestrator agent writes this to the session dir via MCP after S4.
 *
 * @param result       - Successful S4PathAResult (ok must be true).
 * @param targetDomain - Bob session target_domain.
 */
export declare function buildDiffImpactArtifact(result: Extract<S4PathAResult, {
    ok: true;
}>, targetDomain: string): DiffImpactArtifact;
//# sourceMappingURL=diff-impact.d.ts.map