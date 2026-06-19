"use strict";
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
Object.defineProperty(exports, "__esModule", { value: true });
exports.deriveCheckRunStatus = deriveCheckRunStatus;
exports.startCheckRun = startCheckRun;
exports.completeCheckRun = completeCheckRun;
exports.createCheckRun = createCheckRun;
/**
 * Derive a CheckRunStatus and SeverityBreakdown from an array of finding
 * objects.  Each finding must have a `severity` string property.
 *
 * @param findings - Array of objects with at least { severity: string }.
 * @returns Tuple of [CheckRunStatus, SeverityBreakdown].
 */
function deriveCheckRunStatus(findings) {
    const breakdown = {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
    };
    for (const f of findings) {
        const sev = (f.severity ?? "info").toLowerCase();
        if (sev === "critical")
            breakdown.critical += 1;
        else if (sev === "high")
            breakdown.high += 1;
        else if (sev === "medium")
            breakdown.medium += 1;
        else if (sev === "low")
            breakdown.low += 1;
        else
            breakdown.info += 1;
    }
    const findings_count = findings.length;
    const critical_count = breakdown.critical;
    let conclusion;
    if (findings_count === 0) {
        conclusion = "success";
    }
    else if (breakdown.critical > 0 || breakdown.high > 0) {
        conclusion = "failure";
    }
    else {
        conclusion = "neutral";
    }
    return [{ conclusion, findings_count, critical_count }, breakdown];
}
// ---------------------------------------------------------------------------
// Output summary builder
// ---------------------------------------------------------------------------
const CHECK_RUN_NAME = "Bob Diff Review";
/**
 * Build the markdown summary text for a completed check run.
 */
function buildSummary(status, breakdown) {
    if (status.findings_count === 0) {
        return "Bob Diff Review found no issues in this pull request.";
    }
    const rows = [
        "| Severity | Count |",
        "| -------- | ----- |",
    ];
    const severities = [
        ["critical", "Critical"],
        ["high", "High"],
        ["medium", "Medium"],
        ["low", "Low"],
        ["info", "Info"],
    ];
    for (const [key, label] of severities) {
        if (breakdown[key] > 0) {
            rows.push(`| ${label} | ${breakdown[key]} |`);
        }
    }
    rows.push("");
    rows.push(`**Total findings: ${status.findings_count}**`);
    return rows.join("\n");
}
// ---------------------------------------------------------------------------
// Check run title builder
// ---------------------------------------------------------------------------
function buildTitle(status) {
    if (status.findings_count === 0) {
        return "No issues found";
    }
    const parts = [];
    if (status.critical_count > 0) {
        parts.push(`${status.critical_count} critical`);
    }
    parts.push(`${status.findings_count} total finding${status.findings_count !== 1 ? "s" : ""}`);
    return parts.join(", ");
}
// ---------------------------------------------------------------------------
// Public API — two-phase (in_progress → completed)
// ---------------------------------------------------------------------------
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
async function startCheckRun(octokit, owner, repo, sha) {
    try {
        const response = await octokit.rest.checks.create({
            owner,
            repo,
            name: CHECK_RUN_NAME,
            head_sha: sha,
            status: "in_progress",
            started_at: new Date().toISOString(),
        });
        return response.data.id;
    }
    catch (err) {
        // Likely cause: GITHUB_TOKEN lacks checks: write.
        console.error(`[bob-diff-review] startCheckRun failed — ` +
            `ensure GITHUB_TOKEN has checks:write permission. Error: ${String(err)}`);
        return null;
    }
}
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
async function completeCheckRun(octokit, owner, repo, checkRunId, status, breakdown) {
    const resolvedBreakdown = breakdown ?? {
        critical: status.critical_count,
        high: status.findings_count - status.critical_count > 0
            ? status.findings_count - status.critical_count
            : 0,
        medium: 0,
        low: 0,
        info: 0,
    };
    const summary = buildSummary(status, resolvedBreakdown);
    const title = buildTitle(status);
    try {
        await octokit.rest.checks.update({
            owner,
            repo,
            check_run_id: checkRunId,
            status: "completed",
            conclusion: status.conclusion,
            completed_at: new Date().toISOString(),
            output: {
                title,
                summary,
            },
        });
    }
    catch (err) {
        // Log but do not throw — a failed update must never crash the action.
        console.error(`[bob-diff-review] completeCheckRun failed for run ${checkRunId}: ${String(err)}`);
    }
}
// ---------------------------------------------------------------------------
// Public API — one-shot helper
// ---------------------------------------------------------------------------
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
async function createCheckRun(octokit, owner, repo, sha, status) {
    const [, breakdown] = deriveCheckRunStatus(
    // Reconstruct a synthetic findings array from the status counts so we can
    // reuse buildSummary.  We do not have the original findings list here so
    // the breakdown will be approximate (critical vs the rest is preserved;
    // high/medium/low/info split is unknown without the full list).
    [
        ...Array(status.critical_count).fill({ severity: "critical" }),
        ...Array(Math.max(0, status.findings_count - status.critical_count)).fill({
            severity: "high",
        }),
    ]);
    const summary = buildSummary(status, breakdown);
    const title = buildTitle(status);
    try {
        await octokit.rest.checks.create({
            owner,
            repo,
            name: CHECK_RUN_NAME,
            head_sha: sha,
            status: "completed",
            conclusion: status.conclusion,
            completed_at: new Date().toISOString(),
            output: {
                title,
                summary,
            },
        });
    }
    catch (err) {
        console.error(`[bob-diff-review] createCheckRun failed — ` +
            `ensure GITHUB_TOKEN has checks:write permission. Error: ${String(err)}`);
    }
}
//# sourceMappingURL=check-run.js.map