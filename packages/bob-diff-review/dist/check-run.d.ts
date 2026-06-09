/**
 * GitHub Check Runs API integration for the Bob Diff Review action.
 *
 * Creates a Check Run named "Bob Diff Review" on the PR head SHA, updates it
 * to a terminal state when the review pipeline completes, and summarises
 * findings by severity in the check output body.
 *
 * Usage pattern (enforced by A6 entrypoint):
 *
 *   const runId = await startCheckRun(octokit, owner, repo, sha);
 *   try {
 *     // … run bob, resolve findings, post review …
 *     await completeCheckRun(octokit, owner, repo, runId, status);
 *   } finally {
 *     // try/finally guarantees the check run never stays in_progress even if
 *     // the pipeline throws.  completeCheckRun is idempotent if called twice.
 *     await completeCheckRun(octokit, owner, repo, runId, status).catch(() => {});
 *   }
 *
 * The simpler one-shot helper createCheckRun() is provided for callers that
 * already have a final CheckRunStatus and do not need the in_progress phase.
 */
/**
 * Severity labels used by the Bob findings pipeline.
 * The string values match what the bob-runner and resolver produce.
 */
export type Severity = "critical" | "high" | "medium" | "low" | "info";
/**
 * Conclusion values accepted by the GitHub Checks API.
 */
export type Conclusion = "success" | "failure" | "neutral";
/**
 * Summary of a completed Bob Diff Review run, used to determine the check
 * run conclusion and populate the output summary.
 */
export interface CheckRunStatus {
    /**
     * The overall conclusion for the check run.
     *
     * - "failure"  — at least one finding with severity "critical" or "high".
     * - "neutral"  — findings present but all are "medium", "low", or "info".
     * - "success"  — zero findings.
     */
    conclusion: Conclusion;
    /**
     * Total number of findings across all severities.
     */
    findings_count: number;
    /**
     * Number of findings with severity "critical".
     */
    critical_count: number;
}
/**
 * Minimal Octokit interface required by this module.
 * Accepts the real @octokit/rest client or any compatible mock.
 */
export interface ChecksOctokitLike {
    rest: {
        checks: {
            create(params: {
                owner: string;
                repo: string;
                name: string;
                head_sha: string;
                status: "in_progress" | "completed";
                started_at?: string;
                conclusion?: Conclusion;
                completed_at?: string;
                output?: {
                    title: string;
                    summary: string;
                };
            }): Promise<{
                data: {
                    id: number;
                };
            }>;
            update(params: {
                owner: string;
                repo: string;
                check_run_id: number;
                status: "completed";
                conclusion: Conclusion;
                completed_at: string;
                output?: {
                    title: string;
                    summary: string;
                };
            }): Promise<{
                data: {
                    id: number;
                };
            }>;
        };
    };
}
/**
 * Count findings per severity tier from a list of finding objects that carry
 * a `severity` field.  Unknown severity values are counted under "info".
 */
export interface SeverityBreakdown {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
}
/**
 * Derive a CheckRunStatus and SeverityBreakdown from an array of finding
 * objects.  Each finding must have a `severity` string property.
 *
 * @param findings - Array of objects with at least { severity: string }.
 * @returns Tuple of [CheckRunStatus, SeverityBreakdown].
 */
export declare function deriveCheckRunStatus(findings: ReadonlyArray<{
    severity: string;
}>): [CheckRunStatus, SeverityBreakdown];
/**
 * Create a check run in the "in_progress" state and return its numeric ID.
 *
 * Call this at the start of the action pipeline before running bob.  Pass the
 * returned ID to completeCheckRun() when the pipeline finishes (or fails).
 *
 * GITHUB_TOKEN must have the `checks: write` permission.
 *
 * @param octokit - Octokit instance with rest.checks.create.
 * @param owner   - Repository owner.
 * @param repo    - Repository name.
 * @param sha     - PR head commit SHA (from github.context.payload.pull_request.head.sha).
 * @returns The numeric check_run_id, or null if creation failed (caller should
 *          log but continue — check runs are non-fatal UX enhancements).
 */
export declare function startCheckRun(octokit: ChecksOctokitLike, owner: string, repo: string, sha: string): Promise<number | null>;
/**
 * Update an existing in_progress check run to "completed".
 *
 * This is idempotent — calling it more than once for the same check_run_id is
 * safe (the API will return 422 on a duplicate, which we swallow).
 *
 * @param octokit     - Octokit instance with rest.checks.update.
 * @param owner       - Repository owner.
 * @param repo        - Repository name.
 * @param checkRunId  - The ID returned by startCheckRun().
 * @param status      - Final review outcome.
 * @param breakdown   - Per-severity counts for the summary (optional).
 */
export declare function completeCheckRun(octokit: ChecksOctokitLike, owner: string, repo: string, checkRunId: number, status: CheckRunStatus, breakdown?: SeverityBreakdown): Promise<void>;
/**
 * Create a completed check run in a single API call.
 *
 * Use this when you already have the final CheckRunStatus (e.g. in tests or
 * when the entrypoint calls this after the full pipeline has run).  For
 * production use where you want the "in_progress" spinner during the run,
 * prefer startCheckRun() + completeCheckRun() with a try/finally.
 *
 * Per A5 acceptance criteria the check run must never be left in_progress even
 * if the bob-runner errors.  The recommended pattern in the entrypoint (A6) is:
 *
 *   let checkRunId: number | null = null;
 *   let status: CheckRunStatus = { conclusion: "neutral", findings_count: 0, critical_count: 0 };
 *   let breakdown: SeverityBreakdown | undefined;
 *   checkRunId = await startCheckRun(octokit, owner, repo, sha);
 *   try {
 *     // … pipeline …
 *     [status, breakdown] = deriveCheckRunStatus(findings);
 *   } finally {
 *     if (checkRunId !== null) {
 *       await completeCheckRun(octokit, owner, repo, checkRunId, status, breakdown);
 *     }
 *   }
 *
 * @param octokit - Octokit instance with rest.checks.create.
 * @param owner   - Repository owner.
 * @param repo    - Repository name.
 * @param sha     - PR head commit SHA.
 * @param status  - Final review outcome.
 */
export declare function createCheckRun(octokit: ChecksOctokitLike, owner: string, repo: string, sha: string, status: CheckRunStatus): Promise<void>;
//# sourceMappingURL=check-run.d.ts.map