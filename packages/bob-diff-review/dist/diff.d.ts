/**
 * Diff fetching and position mapping for the bob-diff-review pipeline.
 *
 * Two responsibilities:
 *   1. fetchPRDiff   — retrieve the raw unified diff for a PR via GitHub API.
 *   2. buildDiffPositionMap — parse that diff into a file → line → position
 *      lookup table for the GitHub Reviews API createReviewComment endpoint.
 */
import type { DiffPositionMap } from "./types.js";
export type { DiffPositionMap, DiffHunk, PositionEntry } from "./types.js";
/**
 * Minimal Octokit-compatible interface. Accepts the real @octokit/rest client
 * or any compatible mock that implements request().
 */
export interface OctokitLike {
    request(route: string, params: Record<string, unknown>): Promise<{
        data: unknown;
    }>;
}
/**
 * Fetch the raw unified diff for a GitHub pull request.
 *
 * Uses the GitHub Pulls API with `Accept: application/vnd.github.v3.diff` so
 * the response body is the diff text rather than JSON.
 *
 * @param octokit     - Octokit instance (or compatible mock).
 * @param owner       - Repository owner (org or user).
 * @param repo        - Repository name.
 * @param pullNumber  - Pull request number.
 * @returns The raw unified diff string.
 * @throws If the API request fails or the response is not a string.
 */
export declare function fetchPRDiff(octokit: OctokitLike, owner: string, repo: string, pullNumber: number): Promise<string>;
/**
 * Parse a unified diff string and build a position map used by the GitHub
 * Reviews API.
 *
 * Algorithm (per GitHub's diff position spec):
 *   - For each file in the diff, a position counter starts at 1 for the first
 *     hunk header and increments for every subsequent diff line (including
 *     further @@ headers, context lines, addition lines, and deletion lines).
 *   - The position value stored is the running counter at the time each line
 *     is encountered.
 *   - For addition (+) and context lines, the new-file line number is used as
 *     the map key. For deletion (-) lines, the old-file line number is used.
 *   - Binary file hunks produce no position entries for that file.
 *
 * @param unifiedDiff - Raw unified diff string (possibly multi-file).
 * @returns DiffPositionMap — Map<filePath, Map<lineNumber, position>>.
 */
export declare function buildDiffPositionMap(unifiedDiff: string): DiffPositionMap;
//# sourceMappingURL=diff.d.ts.map