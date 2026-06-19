"use strict";
/**
 * GitHub Action entrypoint for the Bob Diff Review pipeline.
 *
 * This module is the main entry point compiled to dist/index.js and executed
 * by the "Run Bob diff review" step in action.yml.
 *
 * Lifecycle:
 *   1. Read action inputs and resolve GitHub context.
 *   2. Start a "Bob Diff Review" check run (in_progress).
 *   3. try { run the full pipeline } finally { complete the check run }.
 *      The finally block guarantees the check run is never left in_progress
 *      even if the pipeline throws an unrecoverable error.
 *   4. Set action outputs and call core.setFailed on unrecoverable errors.
 *
 * Pipeline (A6 orchestration):
 *   fetchPRDiff -> buildDiffPositionMap -> runBobDiffReview ->
 *   resolveFindings -> submitPRReview -> createCheckRun (via completeCheckRun)
 *
 * Dependencies wired here:
 *   - check-run.ts   (A5) — startCheckRun / completeCheckRun / deriveCheckRunStatus
 *   - diff.ts             — fetchPRDiff / buildDiffPositionMap
 *   - reviews-api.ts (A4) — submitPRReview
 *   - bob-runner.ts       — runBobDiffReview
 *   - resolver.ts    (A3) — resolveFindings
 *
 * -----------------------------------------------------------------------
 * Bundling note:
 * -----------------------------------------------------------------------
 * This file is compiled and bundled (via @vercel/ncc or esbuild) into a
 * single dist/index.js that is checked in alongside the action.  The
 * @actions/core and @actions/github packages are listed as peer dependencies
 * and must be available at bundle time.  At runtime no node_modules directory
 * is required — everything is inlined into dist/index.js.
 *
 * Install the peer deps before running `npm run build`:
 *   npm install --save-dev @actions/core @actions/github
 */
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
const crypto = __importStar(require("node:crypto"));
const fs = __importStar(require("node:fs"));
const os = __importStar(require("node:os"));
const path = __importStar(require("node:path"));
const check_run_js_1 = require("./check-run.js");
const diff_js_1 = require("./diff.js");
const bob_runner_js_1 = require("./bob-runner.js");
const resolver_js_1 = require("./resolver.js");
const reviews_api_js_1 = require("./reviews-api.js");
function deriveRepoTargetDomain(repoPath) {
    const real = fs.realpathSync(repoPath);
    const base = path.basename(real).trim() || "repo";
    const safe = base.replace(/[^A-Za-z0-9._-]+/g, "-").replace(/^-+|-+$/g, "") || "repo";
    const sha = crypto.createHash("sha256").update(real).digest("hex").slice(0, 8);
    return `repo-${safe}-${sha}`;
}
// ---------------------------------------------------------------------------
// Runtime shim loader
//
// In production (dist/index.js bundled by ncc/esbuild) these resolve to the
// real @actions/* packages inlined into the bundle.  In unit tests the caller
// can override process.env.ACTIONS_CORE_MOCK / ACTIONS_GITHUB_MOCK to inject
// test doubles without touching the module registry.
// ---------------------------------------------------------------------------
function loadCore() {
    try {
        // eslint-disable-next-line @typescript-eslint/no-require-imports
        return require("@actions/core");
    }
    catch {
        // Fallback stub for local type-checking / non-action environments.
        return {
            getInput: (name) => process.env[name.replace(/-/g, "_").toUpperCase()] ?? "",
            setOutput: (name, value) => {
                const outputFile = process.env["GITHUB_OUTPUT"];
                if (outputFile) {
                    const fsSync = require("node:fs");
                    fsSync.appendFileSync(outputFile, `${name}=${value}\n`);
                }
            },
            setFailed: (msg) => { console.error(`::error::${msg}`); process.exitCode = 1; },
            info: (msg) => console.log(msg),
            error: (msg) => console.error(`::error::${msg}`),
            warning: (msg) => console.warn(`::warning::${msg}`),
        };
    }
}
function loadGithub() {
    try {
        // eslint-disable-next-line @typescript-eslint/no-require-imports
        return require("@actions/github");
    }
    catch {
        throw new Error("@actions/github is required at runtime. " +
            "Bundle this file with ncc or esbuild so @actions/github is inlined.");
    }
}
// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------
async function run() {
    const core = loadCore();
    // -------------------------------------------------------------------------
    // 1. Read inputs via @actions/core (input names match action.yml `inputs:`)
    // -------------------------------------------------------------------------
    const githubToken = core.getInput("github-token") || core.getInput("github_token", { required: true });
    // Dual-auth: BOTH credentials are optional, but at least one MUST be present.
    // OAuth is the recommended path (long-lived token from `claude setup-token`);
    // it wins precedence over the API key inside the runner so a stray API key
    // cannot silently shadow OAuth and exhaust pay-per-use credits.
    const anthropicOauthToken = core.getInput("anthropic-oauth-token") || core.getInput("anthropic_oauth_token");
    const anthropicApiKey = core.getInput("anthropic-api-key") || core.getInput("anthropic_api_key");
    if (!anthropicOauthToken && !anthropicApiKey) {
        core.setFailed("No Anthropic credential provided. Set at least one of " +
            "'anthropic-oauth-token' (recommended — a long-lived token from " +
            "`claude setup-token`) or 'anthropic-api-key' (pay-per-use Anthropic " +
            "API key). When both are supplied, the OAuth token takes precedence.");
        return;
    }
    // bob-install-token is used by composite workflow steps for authenticated
    // package/source access; this action only warns when it is absent.
    const bobInstallToken = core.getInput("bob-install-token") || core.getInput("bob_install_token");
    const minSeverityForFailure = core.getInput("min-severity-for-failure") || core.getInput("min_severity_for_failure") || "high";
    // Optional model override.  When provided (e.g. "claude-haiku-4-5") it is
    // forwarded as ANTHROPIC_MODEL to the claude CLI subprocess so callers can
    // select a cheaper model for cost-sensitive environments.
    const anthropicModel = core.getInput("anthropic-model") || core.getInput("anthropic_model") || process.env["ANTHROPIC_MODEL"] || undefined;
    // Optional explicit PR number. Used for manual (workflow_dispatch) runs where
    // there is no pull_request event payload; the PR is then resolved via the API.
    const prNumberInput = core.getInput("pr-number") || core.getInput("pr_number") || "";
    // Integration test bypass: pre-seeded findings JSON (see action.yml for docs).
    // This input is ignored unless BOB_DIFF_REVIEW_ALLOW_MOCK_FINDINGS=true is
    // set in the runner environment. Public reusable workflows must not expose a
    // caller-controlled path that bypasses the Claude/Bob review.
    const allowMockFindings = process.env["BOB_DIFF_REVIEW_ALLOW_MOCK_FINDINGS"] === "true";
    const mockFindingsInput = core.getInput("mock-findings-json") || core.getInput("mock_findings_json") || "";
    if (mockFindingsInput) {
        if (allowMockFindings) {
            // Override the env var so bob-runner picks it up through its existing path.
            process.env["BOB_MOCK_FINDINGS_JSON"] = mockFindingsInput;
        }
        else {
            core.warning("mock-findings-json input was provided but ignored because " +
                "BOB_DIFF_REVIEW_ALLOW_MOCK_FINDINGS is not true.");
        }
    }
    if (!allowMockFindings && process.env["BOB_MOCK_FINDINGS_JSON"]) {
        delete process.env["BOB_MOCK_FINDINGS_JSON"];
        core.warning("BOB_MOCK_FINDINGS_JSON was set in the runner environment but ignored because " +
            "BOB_DIFF_REVIEW_ALLOW_MOCK_FINDINGS is not true.");
    }
    // Delay in ms to simulate S3 surface-build time when mock mode is active and
    // SKIP_SURFACE_BUILD is not set (i.e., first run without a cache hit).
    const mockS3DelayMsRaw = core.getInput("mock-s3-delay-ms") || core.getInput("mock_s3_delay_ms") || "45000";
    const mockS3DelayMs = Math.max(0, parseInt(mockS3DelayMsRaw, 10) || 45000);
    // Warn (non-fatal) when BOB_INSTALL_TOKEN is absent — the npm install step
    // will fail if packages need to be resolved, but the diff-review itself may
    // still work when the workspace is cached.
    if (!bobInstallToken) {
        core.warning("bob-install-token input is empty. If @bobnetsec packages are not already " +
            "installed this action will fail when npm ci tries to resolve them.");
    }
    // -------------------------------------------------------------------------
    // 2. Resolve GitHub context
    // -------------------------------------------------------------------------
    const { context, getOctokit } = loadGithub();
    const { owner, repo } = context.repo;
    const octokit = getOctokit(githubToken);
    // Resolve the PR to review. Two paths:
    //   - pull_request event: read head SHA + number from the payload.
    //   - workflow_dispatch (or any non-PR event): fetch the PR named by the
    //     pr-number input via the API. This makes manual re-runs / backfills work.
    let headSha;
    let pullNumber;
    const pr = context.payload.pull_request;
    if (pr) {
        headSha = pr.head.sha;
        pullNumber = pr.number;
    }
    else if (prNumberInput) {
        const parsed = parseInt(prNumberInput, 10);
        if (!Number.isInteger(parsed) || parsed <= 0) {
            core.setFailed(`Invalid pr-number input: "${prNumberInput}". Expected a positive integer.`);
            return;
        }
        try {
            const { data } = await octokit.rest.pulls.get({ owner, repo, pull_number: parsed });
            headSha = data.head.sha;
            pullNumber = data.number;
        }
        catch (err) {
            core.setFailed(`Failed to fetch PR #${parsed} from ${owner}/${repo}: ` +
                `${err instanceof Error ? err.message : String(err)}`);
            return;
        }
    }
    else {
        core.setFailed("No pull request to review. Trigger this action on a pull_request event, " +
            "or pass the 'pr-number' input for manual (workflow_dispatch) runs.");
        return;
    }
    if (!headSha) {
        core.setFailed("Could not resolve the pull request head SHA.");
        return;
    }
    // -------------------------------------------------------------------------
    // 3. Start the check run (in_progress)
    //
    //    checkRunId is null if GITHUB_TOKEN lacks checks:write — the pipeline
    //    continues without the check run (PR comments still post).
    //    See GITHUB_TOKEN permission requirements in:
    //      .github/workflows/bob-diff-review.yml -> jobs.bob-diff-review.permissions
    // -------------------------------------------------------------------------
    let checkRunId = null;
    // Accumulate pipeline outputs so the finally block can always call
    // completeCheckRun with a terminal conclusion.
    let finalStatus = {
        conclusion: "neutral",
        findings_count: 0,
        critical_count: 0,
    };
    let finalBreakdown;
    // Cast to the specific Octokit sub-interfaces expected by each module.
    // FullOctokitLike is a structural superset but TypeScript cannot verify this
    // across separately-defined interface shapes, so explicit casts are required.
    const checksOctokit = octokit;
    const reviewsOctokit = octokit;
    const diffOctokit = octokit;
    let diffTmpDir = null;
    try {
        checkRunId = await (0, check_run_js_1.startCheckRun)(checksOctokit, owner, repo, headSha);
    }
    catch (checkStartErr) {
        // Non-fatal: log the error and continue without a check run.
        core.warning(`Failed to start Bob Diff Review check run (checks:write permission may be missing): ` +
            `${checkStartErr instanceof Error ? checkStartErr.message : String(checkStartErr)}`);
    }
    // -------------------------------------------------------------------------
    // 4. Run the pipeline inside try/finally so the check run is ALWAYS
    //    completed — it is never left in_progress even if the pipeline throws.
    // -------------------------------------------------------------------------
    try {
        // -----------------------------------------------------------------------
        // 4a. Fetch the PR diff text from the GitHub API.
        // -----------------------------------------------------------------------
        core.info(`[bob-diff-review] Fetching diff for PR #${pullNumber} (${owner}/${repo})`);
        const diffText = await (0, diff_js_1.fetchPRDiff)(diffOctokit, owner, repo, pullNumber);
        core.info(`[bob-diff-review] Diff fetched (${diffText.length} bytes)`);
        // -----------------------------------------------------------------------
        // 4b. Build the DiffPositionMap (file -> line -> diff-position offset).
        //     This is consumed by resolveFindings to anchor Bob findings to exact
        //     diff line positions for the GitHub Reviews API.
        // -----------------------------------------------------------------------
        const positionMap = (0, diff_js_1.buildDiffPositionMap)(diffText);
        core.info(`[bob-diff-review] Built position map for ${positionMap.size} file(s)`);
        // -----------------------------------------------------------------------
        // 4c. Write the diff to a temp file so bob-runner can pass it to the
        //     headless claude process via --diff-file.
        // -----------------------------------------------------------------------
        diffTmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "bob-diff-input-"));
        const diffFilePath = path.join(diffTmpDir, "pr.diff");
        fs.writeFileSync(diffFilePath, diffText, "utf8");
        core.info(`[bob-diff-review] Diff written to ${diffFilePath}`);
        // -----------------------------------------------------------------------
        // 4d. Resolve the repository path on disk.
        //     In a GitHub Actions runner the workspace is GITHUB_WORKSPACE.
        //     Fall back to process.cwd() for local/test runs.
        // -----------------------------------------------------------------------
        const repoPath = process.env["GITHUB_WORKSPACE"] ?? process.cwd();
        // -----------------------------------------------------------------------
        // 4e. Build the target domain override.
        //     Prefer the C2 cache action's BOB_TARGET_DOMAIN because it derives the
        //     same repo-session slug as bob_init_repo_session. Local/test runs fall
        //     back to the same realpath-derived repo-<safeName>-<sha8> algorithm.
        // -----------------------------------------------------------------------
        const targetDomainOverride = process.env["BOB_TARGET_DOMAIN"] || deriveRepoTargetDomain(repoPath);
        // -----------------------------------------------------------------------
        // 4f. Run the Bob diff-review skill headlessly.
        //     runBobDiffReview spawns claude CLI, streams output to the Actions
        //     log, applies a 10-minute timeout, and returns validated findings.
        //
        //     Mock mode (integration testing): when BOB_MOCK_FINDINGS_JSON is set
        //     (either via env var or the mock-findings-json action input processed
        //     above), runBobDiffReview returns pre-seeded findings. If SKIP_SURFACE_BUILD
        //     is not 'true' (i.e. first run, no cache hit), we sleep for mock-s3-delay-ms
        //     to simulate the S3 phase duration, producing a measurable speedup on run 2
        //     (which hits the cache and skips the delay). After mock mode completes, we
        //     write a placeholder symbol-surface-index.json to the session directory so
        //     subsequent runs on the same PR trigger a C2 cache hit.
        // -----------------------------------------------------------------------
        core.info(`[bob-diff-review] Invoking bob-diff-review skill (target: ${targetDomainOverride})`);
        if (anthropicModel) {
            core.info(`[bob-diff-review] Using model override: ${anthropicModel}`);
        }
        // Mock mode pre-check: apply S3 simulation delay before invoking the runner.
        const isMockMode = !!process.env["BOB_MOCK_FINDINGS_JSON"];
        const skipSurfaceBuild = process.env["SKIP_SURFACE_BUILD"] === "true";
        if (isMockMode) {
            if (!skipSurfaceBuild && mockS3DelayMs > 0) {
                core.info(`[bob-diff-review] Mock mode: simulating S3 surface-build phase ` +
                    `(SKIP_SURFACE_BUILD=false, sleeping ${mockS3DelayMs}ms) ...`);
                await new Promise((resolve) => setTimeout(resolve, mockS3DelayMs));
                core.info(`[bob-diff-review] Mock mode: S3 simulation complete.`);
            }
            else if (skipSurfaceBuild) {
                core.info(`[bob-diff-review] Mock mode: SKIP_SURFACE_BUILD=true — S3 simulation skipped (C2 cache hit).`);
            }
        }
        const bobFindings = await (0, bob_runner_js_1.runBobDiffReview)({
            repo: repoPath,
            diffFile: diffFilePath,
            targetDomainOverride,
            anthropicOauthToken,
            anthropicApiKey,
            anthropicModel,
        });
        // Mock mode post-run: write symbol-surface-index.json so the next run on
        // this PR gets a C2 cache hit and SKIP_SURFACE_BUILD=true is set.
        //
        // The session directory matches the path used by the cache-bob-session
        // composite action. This is the directory that actions/cache@v4 saves and
        // restores, and where detect-symbol-index looks for the file.
        if (isMockMode) {
            const cacheSessionDir = path.join(os.homedir(), "hacker-bob-sessions", targetDomainOverride);
            const symbolIndexPath = path.join(cacheSessionDir, "symbol-surface-index.json");
            if (!fs.existsSync(symbolIndexPath)) {
                try {
                    fs.mkdirSync(cacheSessionDir, { recursive: true });
                    fs.writeFileSync(symbolIndexPath, JSON.stringify({
                        generated_at: new Date().toISOString(),
                        source: "mock-mode-placeholder",
                        target_domain: targetDomainOverride,
                        surfaces: [],
                    }), "utf8");
                    core.info(`[bob-diff-review] Mock mode: wrote symbol-surface-index.json to ${cacheSessionDir} ` +
                        `(enables C2 cache hit on next run).`);
                }
                catch (writeErr) {
                    core.warning(`[bob-diff-review] Mock mode: could not write symbol-surface-index.json: ` +
                        `${writeErr instanceof Error ? writeErr.message : String(writeErr)}`);
                }
            }
            else {
                core.info(`[bob-diff-review] Mock mode: symbol-surface-index.json already exists (C2 warm).`);
            }
        }
        core.info(`[bob-diff-review] Bob review complete: ${bobFindings.findings.length} finding(s) ` +
            `from session ${bobFindings.session_id}`);
        // -----------------------------------------------------------------------
        // 4g. Resolve findings to GitHub diff positions.
        //     Each finding is anchored to its diff line position (or falls back
        //     to a PR-level comment when the line is not in the diff).
        // -----------------------------------------------------------------------
        const allResolved = (0, resolver_js_1.resolveFindings)(bobFindings, positionMap);
        core.info(`[bob-diff-review] Resolved ${allResolved.length} comment(s) total`);
        // Split into inline comments (position defined) and PR-level (no position).
        // submitPRReview expects position to be a number on every comment, so
        // PR-level fallback comments (position: undefined) must be excluded from
        // the inline comments array — they are captured in the review body text.
        const resolvedComments = allResolved
            .filter((c) => c.position !== undefined)
            .map((c) => ({ path: c.path, position: c.position, body: c.body, side: c.side }));
        const prLevelComments = allResolved.filter((c) => c.position === undefined);
        if (prLevelComments.length > 0) {
            core.info(`[bob-diff-review] ${prLevelComments.length} finding(s) could not be anchored to a diff ` +
                `position and will appear in the review body only`);
        }
        core.info(`[bob-diff-review] ${resolvedComments.length} inline comment(s) to post`);
        // -----------------------------------------------------------------------
        // 4h. Derive check run status and severity breakdown from the findings.
        // -----------------------------------------------------------------------
        [finalStatus, finalBreakdown] = (0, check_run_js_1.deriveCheckRunStatus)(bobFindings.findings);
        // Apply the min_severity_for_failure threshold override.
        finalStatus = applyFailureThreshold(finalStatus, finalBreakdown, minSeverityForFailure);
        // -----------------------------------------------------------------------
        // 4i. Build the review summary for the top-level review body.
        // -----------------------------------------------------------------------
        const reviewSummary = {
            session_id: bobFindings.session_id ?? "",
            target_domain: bobFindings.target_domain,
            finding_count: bobFindings.findings.length,
            severity: {
                critical: finalBreakdown?.critical ?? 0,
                high: finalBreakdown?.high ?? 0,
                medium: finalBreakdown?.medium ?? 0,
                low: finalBreakdown?.low ?? 0,
                info: finalBreakdown?.info ?? 0,
            },
            pr_level_comments: prLevelComments.map((c) => c.body),
        };
        // -----------------------------------------------------------------------
        // 4j. Submit the PR review (advisory COMMENT event — not APPROVE or
        //     REQUEST_CHANGES). Returns the HTML URL of the posted review.
        // -----------------------------------------------------------------------
        core.info(`[bob-diff-review] Submitting PR review for #${pullNumber}`);
        let reviewUrl = "";
        try {
            reviewUrl = await (0, reviews_api_js_1.submitPRReview)(reviewsOctokit, owner, repo, pullNumber, resolvedComments, reviewSummary);
            core.info(`[bob-diff-review] PR review posted: ${reviewUrl}`);
        }
        catch (reviewErr) {
            // PR review submission failure is non-fatal for the check run but should
            // surface as a warning so the operator knows the review did not post.
            core.warning(`[bob-diff-review] Failed to post PR review (pull-requests:write permission may be missing): ` +
                `${reviewErr instanceof Error ? reviewErr.message : String(reviewErr)}`);
        }
        // -----------------------------------------------------------------------
        // 4k. Set action outputs.
        // -----------------------------------------------------------------------
        core.setOutput("findings_count", String(finalStatus.findings_count));
        core.setOutput("critical_count", String(finalStatus.critical_count));
        core.setOutput("review_url", reviewUrl);
    }
    catch (err) {
        // Fail the check run and mark the action as failed.
        finalStatus = {
            conclusion: "failure",
            findings_count: 0,
            critical_count: 0,
        };
        core.setFailed(`Bob Diff Review pipeline error: ${err instanceof Error ? err.message : String(err)}`);
    }
    finally {
        // -----------------------------------------------------------------------
        // Always complete the check run, even if the pipeline threw.
        // completeCheckRun swallows its own errors so this finally block never
        // throws; the check run will never remain in_progress after this point.
        // -----------------------------------------------------------------------
        if (checkRunId !== null) {
            await (0, check_run_js_1.completeCheckRun)(checksOctokit, owner, repo, checkRunId, finalStatus, finalBreakdown);
        }
        if (diffTmpDir !== null) {
            fs.rmSync(diffTmpDir, { recursive: true, force: true });
        }
    }
}
// ---------------------------------------------------------------------------
// Failure threshold override
// ---------------------------------------------------------------------------
/**
 * Apply the min_severity_for_failure input to override the default conclusion.
 *
 * By default, deriveCheckRunStatus produces "failure" only for critical/high.
 * When min_severity_for_failure is "medium" or "low", medium/low findings also
 * trigger "failure" instead of "neutral".
 *
 * @param status    - Base status from deriveCheckRunStatus.
 * @param breakdown - Per-severity counts (undefined if no findings).
 * @param threshold - Action input value: "critical" | "high" | "medium" | "low".
 */
function applyFailureThreshold(status, breakdown, threshold) {
    if (!breakdown || status.findings_count === 0) {
        return status;
    }
    const t = threshold.toLowerCase();
    let shouldFail = false;
    if (t === "critical") {
        shouldFail = breakdown.critical > 0;
    }
    else if (t === "high") {
        shouldFail = breakdown.critical > 0 || breakdown.high > 0;
    }
    else if (t === "medium") {
        shouldFail = breakdown.critical > 0 || breakdown.high > 0 || breakdown.medium > 0;
    }
    else if (t === "low") {
        // Any finding triggers failure.
        shouldFail = status.findings_count > 0;
    }
    else {
        // Unknown threshold — fall back to default (high).
        shouldFail = breakdown.critical > 0 || breakdown.high > 0;
    }
    if (shouldFail && status.conclusion !== "failure") {
        return { ...status, conclusion: "failure" };
    }
    if (!shouldFail && status.conclusion === "failure") {
        // Downgrade failure to neutral (some findings present, none meet threshold).
        return { ...status, conclusion: "neutral" };
    }
    return status;
}
// ---------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------
run().catch((err) => {
    // Last-resort handler — core.setFailed is already called inside run() for
    // known error paths.  This catches truly unexpected throws from run() itself
    // (e.g. errors inside the finally block's completeCheckRun call).
    const message = `Unhandled error in bob-diff-review action: ` +
        `${err instanceof Error ? err.message : String(err)}`;
    try {
        loadCore().setFailed(message);
    }
    catch {
        // If @actions/core itself is unavailable (non-Actions environment), fall
        // back to stderr. Do NOT call process.exit — let the process end naturally
        // with the non-zero exit code that @actions/core sets via process.exitCode.
        console.error(`::error::${message}`);
        process.exitCode = 1;
    }
});
//# sourceMappingURL=action-entrypoint.js.map