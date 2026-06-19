/**
 * S4b — PATH B fallback: heuristic evaluator dispatch.
 *
 * Activates when bob_summarize_diff_impact (PATH A) is unavailable or the
 * symbol surface index does not exist. Maps changed file paths to surface IDs
 * using well-known path patterns so that S5 and S6 can operate identically
 * regardless of which path produced impacted_entries.
 *
 * PATH B surface_ids are prefixed "heuristic:" to distinguish them from
 * index-derived IDs produced by PATH A.
 *
 * Failure modes guarded here:
 *   - Too many heuristic surfaces: capped at MAX_HEURISTIC_SURFACES (8).
 *   - Too many unknown dispatches: capped at MAX_UNKNOWN_DISPATCHES (5).
 *   - PATH B activation logged loudly before dispatch.
 */
/**
 * A single impacted entry produced by either PATH A (bob_summarize_diff_impact)
 * or PATH B (heuristic dispatch). Schema is intentionally identical so S5 and
 * S6 are path-agnostic.
 */
export interface ImpactedEntry {
    /** Repo-relative file path, e.g. "src/auth/login.ts". */
    file: string;
    /**
     * First changed line in the file (1-indexed). PATH B uses 1 when line
     * information is unavailable from the diff header.
     */
    line_start: number;
    /**
     * Last changed line in the file (1-indexed). PATH B uses line_start when
     * only a single-line range is known.
     */
    line_end: number;
    /**
     * Surface IDs assigned to this entry. PATH B values are prefixed "heuristic:".
     * May contain multiple surface IDs if the file path matches several patterns.
     */
    surface_ids: string[];
    /**
     * Human-readable summary of what changed in this hunk. PATH B produces a
     * minimal summary ("heuristic match: <pattern>") when no structural analysis
     * is available.
     */
    hunk_summary: string;
}
/**
 * Result returned by buildHeuristicImpactedEntries.
 */
export interface PathBResult {
    /** Impacted entries produced by heuristic dispatch. */
    impacted_entries: ImpactedEntry[];
    /**
     * Number of entries with surface_id "heuristic:unknown" that were produced
     * before the cap was applied. Zero when all files matched at least one
     * pattern.
     */
    unknown_dispatches: number;
    /**
     * Number of entries trimmed by the cap on heuristic surfaces. Zero when the
     * total unique surface count was within bounds.
     */
    capped_entries: number;
    /**
     * Activation message — always 'PATH B: heuristic dispatch (no symbol index)'.
     * Callers should log this loudly.
     */
    activation_log: string;
}
/** Maximum distinct heuristic surface_ids per run (guards S5 agent explosion). */
export declare const MAX_HEURISTIC_SURFACES = 8;
/** Maximum entries with surface_id "heuristic:unknown" (guards S5 flooding). */
export declare const MAX_UNKNOWN_DISPATCHES = 5;
/**
 * A single pattern rule: if any element of `patterns` matches the file path,
 * assign `surface_id`.
 *
 * Patterns are tested as case-insensitive substring matches or glob-style
 * prefix/suffix tests to keep the implementation dependency-free.
 */
interface PatternRule {
    /** Displayable label for hunk_summary generation. */
    label: string;
    /**
     * Predicate applied to the normalized (lower-case, forward-slash) file path.
     * Returns true when the rule matches.
     */
    test: (normalizedPath: string) => boolean;
    /** Surface ID assigned when the rule matches. Always "heuristic:<name>". */
    surface_id: string;
}
/**
 * A lightweight parsed diff file entry used as input to PATH B.
 *
 * PATH B does not require full diff parsing — it only needs the file path and
 * an optional line range from the diff `@@ -old +new @@` header.
 */
export interface DiffFileEntry {
    /** Repo-relative file path (b-side / new file path from the diff header). */
    file: string;
    /**
     * First changed line (new-file side). 1 when not determinable from the diff.
     */
    line_start?: number;
    /**
     * Last changed line (new-file side). Equals line_start when not
     * determinable.
     */
    line_end?: number;
}
/**
 * Parse the unified diff text and extract per-file change metadata.
 *
 * This is a lightweight parser — it extracts `diff --git` / `--- ` / `+++ `
 * headers and every `@@` hunk header per file to capture the changed ranges.
 * PATH B keeps one entry per hunk so later-hunk findings are not orphaned.
 *
 * @param diffText - Raw unified diff string (git diff output).
 * @returns Array of DiffFileEntry, one per changed file.
 */
export declare function parseDiffFiles(diffText: string): DiffFileEntry[];
/**
 * Build the PATH B impacted_entries list from a set of changed files.
 *
 * This is the main export for S4b. It:
 *   1. Logs the PATH B activation message.
 *   2. Maps each file to surface_ids via the pattern table.
 *   3. Caps heuristic:unknown dispatches at MAX_UNKNOWN_DISPATCHES.
 *   4. Caps total unique surface_ids at MAX_HEURISTIC_SURFACES.
 *   5. Returns the same ImpactedEntry schema as PATH A.
 *
 * @param changedFiles  - Array of changed files extracted from the diff.
 * @param extraRules    - Optional caller-supplied pattern rules (runtime override).
 * @returns PathBResult with impacted_entries and diagnostic counters.
 */
export declare function buildHeuristicImpactedEntries(changedFiles: DiffFileEntry[], extraRules?: ReadonlyArray<PatternRule>): PathBResult;
/**
 * High-level PATH B entry point.
 *
 * Parses the raw unified diff text and produces impacted_entries via heuristic
 * dispatch. This is the function the orchestrator agent calls when PATH A fails.
 *
 * Logs:
 *   - 'PATH B: heuristic dispatch (no symbol index)'  (always)
 *   - 'S4b: N impacted entries produced by heuristic dispatch'
 *   - 'S4b: M unknown-surface entries capped at MAX_UNKNOWN_DISPATCHES'  (when > 0)
 *   - 'S4b: K entries trimmed by MAX_HEURISTIC_SURFACES cap'  (when > 0)
 *
 * @param diffText   - Raw unified diff text (git diff output).
 * @param extraRules - Optional caller-supplied pattern overrides.
 * @returns PathBResult — callers pass impacted_entries directly to S5.
 */
export declare function runPathB(diffText: string, extraRules?: ReadonlyArray<PatternRule>): PathBResult;
export {};
//# sourceMappingURL=heuristic-dispatch.d.ts.map