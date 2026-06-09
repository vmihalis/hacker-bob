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
export {};
//# sourceMappingURL=action-entrypoint.d.ts.map