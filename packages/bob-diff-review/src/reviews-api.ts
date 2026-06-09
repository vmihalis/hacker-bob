/**
 * GitHub Reviews API submission module for the bob-diff-review pipeline.
 *
 * Submits an advisory PR review (event: 'COMMENT') with inline diff comments
 * produced by the resolver. Handles rate limits with exponential backoff and
 * recovers from 422 Unprocessable errors caused by bad diff positions.
 */

import type { SeverityBreakdown } from "./check-run.js";

// Re-export so callers can import everything from reviews-api.
export type { SeverityBreakdown };

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

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
      }): Promise<{ data: { id: number; html_url: string } }>;
    };
  };
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MAX_RETRIES = 3;
const BASE_DELAY_MS = 1_000; // 1 second base for exponential backoff

const EMPTY_BODY =
  "Bob diff review complete. No findings in impacted surfaces.";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Build the top-level review body string from session metadata.
 */
function buildReviewBody(summary: ReviewSummary): string {
  const { session_id, target_domain, finding_count, severity } = summary;
  const { critical, high, medium, low } = severity;
  const lines = [
    "## Bob Diff Review",
    `**Session:** ${session_id}`,
    `**Target:** ${target_domain}`,
    `**Findings:** ${finding_count} (${critical} critical, ${high} high, ${medium} medium, ${low} low)`,
  ];

  const prLevelComments = summary.pr_level_comments ?? [];
  if (prLevelComments.length > 0) {
    lines.push("", "### Unanchored Findings");
    prLevelComments.forEach((body, index) => {
      lines.push("", `#### Finding ${index + 1}`, body.trim());
    });
  }

  return lines.join("\n");
}

/**
 * Sleep for `ms` milliseconds. Used by the exponential backoff loop.
 */
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Attempt a single createReview call with exponential backoff on 429.
 *
 * @param octokit      - Octokit instance.
 * @param owner        - Repository owner.
 * @param repo         - Repository name.
 * @param pull_number  - Pull request number.
 * @param body         - Top-level review body string.
 * @param comments     - Inline comments to attach (may be empty).
 * @returns The review HTML URL.
 * @throws On non-retryable errors or after MAX_RETRIES exhausted.
 */
async function createReviewWithBackoff(
  octokit: ReviewsOctokitLike,
  owner: string,
  repo: string,
  pull_number: number,
  body: string,
  comments: Array<{ path: string; position: number; body: string }>
): Promise<string> {
  let lastError: unknown;

  for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
    try {
      const params: Parameters<
        typeof octokit.rest.pulls.createReview
      >[0] = {
        owner,
        repo,
        pull_number,
        event: "COMMENT",
        body,
      };

      if (comments.length > 0) {
        params.comments = comments;
      }

      const response = await octokit.rest.pulls.createReview(params);
      return response.data.html_url;
    } catch (err: unknown) {
      lastError = err;

      const status = getStatusCode(err);

      if (status === 429) {
        // Rate limited — back off and retry.
        const delay = BASE_DELAY_MS * Math.pow(2, attempt);
        console.warn(
          `[reviews-api] GitHub rate limit (429) on attempt ${attempt + 1}/${MAX_RETRIES + 1}. ` +
            `Retrying in ${delay}ms…`
        );
        await sleep(delay);
        continue;
      }

      // Non-retryable error — rethrow immediately.
      throw err;
    }
  }

  // All retries exhausted.
  throw new Error(
    `[reviews-api] createReview failed after ${MAX_RETRIES + 1} attempts (429 rate limit). ` +
      `Last error: ${String(lastError)}`
  );
}

/**
 * Extract the HTTP status code from an unknown error value.
 * Works with @octokit/request-error and plain objects with a `status` field.
 */
function getStatusCode(err: unknown): number | undefined {
  if (
    err !== null &&
    typeof err === "object" &&
    "status" in err &&
    typeof (err as Record<string, unknown>)["status"] === "number"
  ) {
    return (err as Record<string, unknown>)["status"] as number;
  }
  return undefined;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

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
export async function submitPRReview(
  octokit: ReviewsOctokitLike,
  owner: string,
  repo: string,
  pull_number: number,
  comments: ResolvedComment[],
  summary: ReviewSummary
): Promise<string> {
  const reviewBody = buildReviewBody(summary);
  const hasPrLevelFindings = (summary.pr_level_comments?.length ?? 0) > 0;

  // ------------------------------------------------------------------
  // Case 1: No findings — post a PR-level body-only review.
  // ------------------------------------------------------------------
  if (comments.length === 0 && !hasPrLevelFindings) {
    console.log("[reviews-api] No findings — posting body-only review.");
    return createReviewWithBackoff(
      octokit,
      owner,
      repo,
      pull_number,
      EMPTY_BODY,
      []
    );
  }

  // ------------------------------------------------------------------
  // Case 2: Findings present — attempt to post all inline comments.
  // ------------------------------------------------------------------

  // Map ResolvedComment to the shape GitHub's createReview expects.
  // GitHub's createReview comments parameter does not accept a `side` field
  // at the top-level (only via pull_request_review_comment endpoint), so we
  // strip it here and rely on `position` to identify the correct side.
  const ghComments = comments.map((c) => ({
    path: c.path,
    position: c.position,
    body: c.body,
  }));

  try {
    const reviewUrl = await createReviewWithBackoff(
      octokit,
      owner,
      repo,
      pull_number,
      reviewBody,
      ghComments
    );
    console.log(
      `[reviews-api] Review posted with ${comments.length} inline comment(s): ${reviewUrl}`
    );
    return reviewUrl;
  } catch (err: unknown) {
    const status = getStatusCode(err);

    if (status !== 422) {
      // Not a position error — rethrow.
      throw err;
    }

    // ------------------------------------------------------------------
    // 422 Unprocessable: at least one comment has a bad diff position.
    // Strategy: probe each comment individually to identify which positions
    // are bad, log offenders, then submit the remaining valid comments as
    // inline comments in a second createReview call.
    // ------------------------------------------------------------------
    console.warn(
      "[reviews-api] 422 Unprocessable on initial review batch. " +
        "Probing comments individually to isolate bad diff positions…"
    );

    const { valid: validComments, invalid: invalidComments } =
      await partitionCommentsByValidity(
        octokit,
        owner,
        repo,
        pull_number,
        ghComments
      );

    for (const comment of invalidComments) {
      console.error(
        `[reviews-api] Offending comment (bad diff position): ` +
          `path=${comment.path} position=${comment.position}`
      );
    }

    if (validComments.length > 0) {
      // Submit the remaining valid comments inline in a second review call.
      // Preserve invalid-position findings in the PR-level body so recovery
      // does not silently discard advisory content.
      const recoveryBody =
        invalidComments.length > 0
          ? buildBodyFallback(reviewBody, invalidComments)
          : reviewBody;
      const reviewUrl = await createReviewWithBackoff(
        octokit,
        owner,
        repo,
        pull_number,
        recoveryBody,
        validComments
      );
      console.log(
        `[reviews-api] Recovery review posted with ${validComments.length} valid inline comment(s) ` +
          `(${invalidComments.length} bad position finding(s) preserved as body text): ${reviewUrl}`
      );
      return reviewUrl;
    }

    // All comments had bad positions — fall back to body-only review.
    console.warn(
      "[reviews-api] All comment positions invalid — falling back to body-only review."
    );
    const inlinedBody = buildBodyFallback(reviewBody, comments);
    const reviewUrl = await createReviewWithBackoff(
      octokit,
      owner,
      repo,
      pull_number,
      inlinedBody,
      []
    );
    console.log(
      `[reviews-api] Recovery review posted with ${comments.length} finding(s) as body text ` +
        `(all inline positions rejected): ${reviewUrl}`
    );
    return reviewUrl;
  }
}

// ---------------------------------------------------------------------------
// 422 Recovery helpers
// ---------------------------------------------------------------------------

/**
 * Probe each comment individually to determine which ones have valid diff
 * positions and which trigger 422 Unprocessable errors from GitHub.
 *
 * We use a minimal "probe" review body so we don't create a full visible
 * review per comment — the probe is just a validity check. Only the final
 * second review call (in submitPRReview) will be the advisory review with
 * the real body.
 *
 * NOTE: This approach does make one createReview API call per comment when
 * diagnosing a 422 batch failure. Each probe review appears on the PR but
 * is a necessary trade-off to isolate bad positions without discarding valid
 * findings. An alternative approach (binary search) would reduce probe count
 * but is significantly more complex and still creates intermediate reviews.
 */
async function partitionCommentsByValidity(
  octokit: ReviewsOctokitLike,
  owner: string,
  repo: string,
  pull_number: number,
  comments: Array<{ path: string; position: number; body: string }>
): Promise<{
  valid: Array<{ path: string; position: number; body: string }>;
  invalid: Array<{ path: string; position: number; body: string }>;
}> {
  const valid: Array<{ path: string; position: number; body: string }> = [];
  const invalid: Array<{ path: string; position: number; body: string }> = [];

  for (const comment of comments) {
    const isValid = await probeComment(
      octokit,
      owner,
      repo,
      pull_number,
      comment
    );
    if (isValid) {
      valid.push(comment);
    } else {
      invalid.push(comment);
    }
  }

  return { valid, invalid };
}

/**
 * Attempt to post a single comment as a probe review to test if its diff
 * position is valid. Returns true if the position is accepted (2xx), false
 * if GitHub returns 422 Unprocessable.
 *
 * 429 rate limits during probing are retried with the same exponential
 * backoff as primary calls. All other errors are treated as valid (the
 * error is not a position problem) to avoid discarding good comments.
 */
async function probeComment(
  octokit: ReviewsOctokitLike,
  owner: string,
  repo: string,
  pull_number: number,
  comment: { path: string; position: number; body: string }
): Promise<boolean> {
  try {
    await createReviewWithBackoff(
      octokit,
      owner,
      repo,
      pull_number,
      `[Bob probe] Validating diff position for ${comment.path}:${comment.position}`,
      [comment]
    );
    return true;
  } catch (err: unknown) {
    const status = getStatusCode(err);
    if (status === 422) {
      return false;
    }
    // Any other error (network, auth, etc.) — treat the comment as valid so
    // we don't silently drop findings due to transient failures.
    console.warn(
      `[reviews-api] Unexpected error probing ${comment.path}:${comment.position} ` +
        `(status=${status ?? "unknown"}) — treating as valid.`
    );
    return true;
  }
}

/**
 * Build a fallback review body when all inline comment positions are invalid.
 * Embeds each finding as a quoted block inside the PR-level review body.
 */
function buildBodyFallback(
  reviewBody: string,
  comments: Array<{ path: string; position: number; body: string }>
): string {
  const sections = comments.map(
    (c, i) =>
      `### Finding ${i + 1}: \`${c.path}\` (position ${c.position})\n\n${c.body}`
  );
  return [reviewBody, "", ...sections].join("\n\n");
}
