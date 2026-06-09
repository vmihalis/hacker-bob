/**
 * Session cache helpers for bob-runner.
 *
 * After the C2 composite action restores ~/hacker-bob-sessions/gh-<repository_id>,
 * these utilities determine whether the S3 phase (route extraction + symbol index
 * build) can be skipped, and resolve the deterministic target_domain override used
 * throughout the bob-diff-review pipeline.
 */
export interface SessionCacheInfo {
    /** Absolute path to the session directory, e.g. ~/hacker-bob-sessions/gh-12345678 */
    sessionDir: string;
    /**
     * target_domain string to pass to bob_init_repo_session.
     * Always 'gh-' + repositoryId so the session path is deterministic across runs.
     */
    targetDomain: string;
    /** Whether symbol-surface-index.json exists in the restored session dir. */
    hasSymbolIndex: boolean;
}
/**
 * Return the deterministic target_domain string for a GitHub repository.
 *
 * The 'gh-' prefix distinguishes GitHub-action sessions from human-launched
 * sessions (which use a real hostname). The numeric repository_id guarantees
 * uniqueness across forks and renames.
 *
 * @param repositoryId - github.repository_id (numeric, but passed as string)
 */
export declare function buildTargetDomain(repositoryId: string): string;
/**
 * Return the absolute path to the Bob session directory for a given repository.
 *
 * This must match the cache path used by the C2 composite action:
 *   ~/hacker-bob-sessions/gh-<repository_id>
 *
 * @param repositoryId - github.repository_id (numeric, but passed as string)
 */
export declare function resolveSessionDir(repositoryId: string): string;
/**
 * Check whether symbol-surface-index.json exists in the session directory.
 *
 * Returns true only when the file is present AND readable. A stale or
 * zero-byte file is accepted here; downstream validation (mtime check against
 * the diff) is the responsibility of the S3 step in bob-runner.
 *
 * @param sessionDir - absolute path returned by resolveSessionDir
 */
export declare function hasSymbolSurfaceIndex(sessionDir: string): boolean;
/**
 * Collect all session cache metadata from the environment after the C2 action
 * has run. Reads GITHUB_OUTPUT-style env vars set by the composite action, with
 * a filesystem fallback so the module also works in local/dry-run mode.
 *
 * Sets the SKIP_SURFACE_BUILD environment variable if symbol-surface-index.json
 * is detected, matching the W1 workflow's expectation.
 *
 * @param repositoryId - github.repository_id (numeric string)
 * @returns SessionCacheInfo — callers pass sessionDir and targetDomain to MCP
 */
export declare function resolveCacheState(repositoryId: string): SessionCacheInfo;
/**
 * Write a key=value pair to the GITHUB_OUTPUT file if running inside a
 * GitHub Actions runner. No-op otherwise.
 *
 * @param name  - output variable name
 * @param value - string value
 */
export declare function setOutput(name: string, value: string): void;
/**
 * Emit all C2-relevant outputs to GITHUB_OUTPUT and log a summary.
 * Call this from bob-runner.ts after resolveCacheState.
 */
export declare function emitCacheOutputs(info: SessionCacheInfo): void;
//# sourceMappingURL=session-cache.d.ts.map