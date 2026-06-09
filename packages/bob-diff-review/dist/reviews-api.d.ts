/**
 * GitHub Reviews API submission module for the bob-diff-review pipeline.
 *
 * Submits an advisory PR review (event: 'COMMENT') with inline diff comments
 * produced by the resolver. Handles rate limits with exponential backoff and
 * recovers from 422 Unprocessable errors caused by bad diff positions.
 */
import type { SeverityBreakdown } from "./check-run.js";
export type { SeverityBreakdown };
/**
 * A single resolved comment ready to post to the GitHub Reviews API.
 * Matches the output type of resolver.ts (A3).
 */
export interface ResolvedComment {
    /** File path relative to the repository root, as it appears in the diff. */
    path: string;
    /**
     * GitHub Reviews API diff position offset (1-indexed count of diff lines
     * in the file's diff blob, including @@ hunk headers).
     */
    position: number;
    /** Formatted comment body. */
    body: string;
    /** Which side of the diff this comment targets. */
    side: "RIGHT" | "LEFT";
}
/**
 * Metadata injected into the review body.
 */
export interface ReviewSummary {
    session_id: string;
    target_domain: string;
    finding_count: number;
    severity: SeverityBreakdown;
    /** Finding bodies that could not be anchored to a diff position. */
    pr_level_comments?: string[];
}
/**
 * Minimal Octokit interface for the Reviews API.
 * Accepts @octokit/rest, @actions/github context.octokit, or a compatible mock.
 */
export interface ReviewsOctokitLike {
    rest: {
        pulls: {
            createReview(params: {
                owner: string;
                repo: string;
                pull_number: number;
                event: "COMMENT" | "APPROVE" | "REQUEST_CHANGES";
                body: string;
                comments?: Array<{
                    path: string;
                    position: number;
                    body: string;
                }>;
            }): Promise<{
                data: {
                    id: number;
                    html_url: string;
                };
            }>;
        };
    };
}
/**
 * Submit an advisory PR review with inline comments.
 *
 * - Always uses event:'COMMENT' (Bob is advisory only).
 * - If comments[] is empty, posts a PR-level review with a completion message.
 * - Retries up to MAX_RETRIES times on 429 Too Many Requests (exponential backoff).
 * - On 422 Unprocessable (bad diff position): logs the offending comment and
 *   submits a second review with the remaining valid comments.
 *
 * @param octokit     - Octokit instance with rest.pulls.createReview.
 * @param owner       - Repository owner (org or user).
 * @param repo        - Repository name.
 * @param pull_number - Pull request number.
 * @param comments    - Resolved inline comments from the diff resolver.
 * @param summary     - Session metadata for the review body header.
 * @returns The HTML URL of the submitted review (first review if two were posted).
 */
export declare function submitPRReview(octokit: ReviewsOctokitLike, owner: string, repo: string, pull_number: number, comments: ResolvedComment[], summary: ReviewSummary): Promise<string>;
//# sourceMappingURL=reviews-api.d.ts.map