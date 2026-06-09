/**
 * A3 — resolver.ts: convert Bob findings into GitHub Reviews API comment params.
 *
 * Takes a DiffReviewFindings document (produced by the bob-diff-review skill via
 * A2/S6) and a DiffPositionMap (produced by buildDiffPositionMap in diff.ts) and
 * returns an array of ResolvedComment objects ready for the GitHub Reviews API.
 *
 * Position lookup strategy (per GitHub diff position spec):
 *   1. Look up finding.file in DiffPositionMap.
 *   2. Look up finding.line_start in the file's inner Map (positive key = new-file
 *      line, negative key = old-file deletion line).
 *   3. If the exact line is not in the map, walk FORWARD through the file's Map
 *      to find the nearest mapped position at or after finding.line_start
 *      (hunk boundary fallback).
 *   4. If no forward entry exists, fall back to the last known position in the
 *      file (nearest hunk boundary before the line).
 *   5. If the file is not in the diff at all, produce a PR-level comment:
 *      no position field, body prefixed with "**File:** `{path}` line {line}\n".
 *
 * Body format:
 *   "[{severity}] {title}\n\n{description}\n\n**Evidence:**\n```\n{evidence}\n```"
 *
 * Side:
 *   - "RIGHT" for addition (+) lines and context lines (new-file side).
 *   - "LEFT" for deletion (-) lines (old-file side, negative key in posMap).
 *
 * Acceptance criteria (A3):
 *   1. resolveFindings returns ResolvedComment[] with position set to the diff
 *      offset for in-diff lines.
 *   2. For lines not in the diff (context-only or between hunks), falls back to
 *      nearest hunk boundary position.
 *   3. Findings on files not in the diff at all are converted to PR-level
 *      comments (position omitted, body prefixed with filename + line).
 *   4. body is formatted as:
 *      "[{severity}] {title}\n\n{description}\n\n**Evidence:**\n```\n{evidence}\n```"
 *   5. side is "RIGHT" for additions/context, "LEFT" for deletions.
 *
 * Failure modes guarded here:
 *   - line_start <= 0 from malformed Bob output: clamped to 1.
 *   - Two findings on the same line: both included (duplicates are accepted by
 *     the GitHub API, though slightly noisy).
 *   - Binary files produce empty position maps: treated as "file not in diff"
 *     and converted to PR-level comments.
 */
import type { DiffPositionMap } from "./types.js";
import type { DiffReviewFindings, FindingEntry } from "./findings-serializer.js";
/**
 * A resolved comment ready for the GitHub Reviews API createReview endpoint.
 *
 * When `position` is undefined, the comment could not be anchored to a diff
 * line and should be submitted as a PR-level (body-only) comment, with the
 * file and line information embedded in the body text.
 */
export interface ResolvedComment {
    /** File path relative to the repository root (as it appears in the diff). */
    path: string;
    /**
     * GitHub Reviews API diff position offset (1-indexed count of diff lines
     * within the file's diff blob, including @@ hunk headers). Undefined for
     * PR-level (body-only) comments.
     */
    position?: number;
    /** Formatted comment body. */
    body: string;
    /** Which side of the diff this comment targets. */
    side: "RIGHT" | "LEFT";
}
/**
 * Format a finding into a GitHub PR review comment body.
 *
 * Format:
 *   [{severity}] {title}
 *
 *   {description}
 *
 *   **Evidence:**
 *   ```
 *   {evidence}
 *   ```
 *
 * Per project rules: no emoji, plain text severity label.
 *
 * @param finding - The finding entry from diff-review-findings.json.
 * @returns The formatted comment body string.
 */
export declare function formatCommentBody(finding: FindingEntry): string;
/**
 * Format a PR-level fallback comment body when the finding cannot be anchored
 * to a diff position.
 *
 * Prepends a "**File:** `{path}` line {line}" prefix before the normal body.
 *
 * @param finding  - The finding entry.
 * @param filePath - The file path (as it appears in the finding).
 * @returns The formatted fallback comment body string.
 */
export declare function formatPRLevelBody(finding: FindingEntry, filePath: string): string;
/**
 * Look up the best diff position and side for a finding's line_start within a
 * single file's position Map.
 *
 * Strategy (per A3 spec and GitHub diff position requirements):
 *   1. Exact positive-key lookup: new-file line (addition or context).
 *   2. Exact negative-key lookup: deletion line (-line_start).
 *   3. Forward walk: find the smallest mapped positive key >= line_start
 *      (nearest hunk boundary at or after the target line).
 *   4. Backward walk: find the largest mapped positive key < line_start
 *      (nearest hunk boundary before the target line — last resort).
 *   5. If the file map is empty (binary file), return null.
 *
 * @param fileMap  - Map<lineKey, diffPosition> for the specific file.
 * @param lineStart - The 1-indexed line number from the finding (already clamped >= 1).
 * @returns {position, side} if a diff position can be resolved, null otherwise.
 */
export declare function resolvePosition(fileMap: Map<number, number>, lineStart: number): {
    position: number;
    side: "RIGHT" | "LEFT";
} | null;
/**
 * Convert a DiffReviewFindings document into GitHub Reviews API comment params.
 *
 * For each FindingEntry:
 *   - If the file is in the DiffPositionMap and the line can be resolved, emits
 *     a ResolvedComment with path, position, body, and side.
 *   - If the file is in the diff but the line cannot be resolved (empty map /
 *     binary file), emits a PR-level comment (position: 1 if the file has any
 *     positions, otherwise undefined).
 *   - If the file is not in the diff at all, emits a PR-level comment with
 *     the body prefixed by the file path and line number.
 *
 * @param findings - Parsed and validated DiffReviewFindings from diff-review-findings.json.
 * @param posMap   - DiffPositionMap built by buildDiffPositionMap from the PR diff.
 * @returns Array of ResolvedComment objects for submitPRReview.
 */
export declare function resolveFindings(findings: DiffReviewFindings, posMap: DiffPositionMap): ResolvedComment[];
//# sourceMappingURL=resolver.d.ts.map