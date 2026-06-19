"use strict";
/**
 * Diff fetching and position mapping for the bob-diff-review pipeline.
 *
 * Two responsibilities:
 *   1. fetchPRDiff   — retrieve the raw unified diff for a PR via GitHub API.
 *   2. buildDiffPositionMap — parse that diff into a file → line → position
 *      lookup table for the GitHub Reviews API createReviewComment endpoint.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.fetchPRDiff = fetchPRDiff;
exports.buildDiffPositionMap = buildDiffPositionMap;
// ---------------------------------------------------------------------------
// fetchPRDiff
// ---------------------------------------------------------------------------
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
async function fetchPRDiff(octokit, owner, repo, pullNumber) {
    const response = await octokit.request("GET /repos/{owner}/{repo}/pulls/{pull_number}", {
        owner,
        repo,
        pull_number: pullNumber,
        headers: {
            Accept: "application/vnd.github.v3.diff",
        },
    });
    const diff = response.data;
    if (typeof diff !== "string") {
        throw new Error(`fetchPRDiff: expected string response from GitHub API, got ${typeof diff}`);
    }
    if (diff.length === 0) {
        console.warn(`[bob-diff-review] fetchPRDiff: PR #${pullNumber} returned an empty diff`);
    }
    // Warn on very large diffs that may be truncated by the API.
    const LARGE_DIFF_THRESHOLD = 3_000_000; // ~3 MB
    if (diff.length > LARGE_DIFF_THRESHOLD) {
        console.warn(`[bob-diff-review] fetchPRDiff: diff is ${diff.length} bytes ` +
            "(>3 MB). Very large PRs may be truncated by the GitHub API.");
    }
    return diff;
}
// ---------------------------------------------------------------------------
// buildDiffPositionMap
// ---------------------------------------------------------------------------
// Matches "diff --git a/path b/path" (possibly with CRLF endings).
const DIFF_GIT_HEADER_RE = /^diff --git a\/.+ b\/(.+?)\r?$/;
// Matches "+++ b/path" or "+++ /dev/null" header lines.
const PLUS_PLUS_HEADER_RE = /^\+\+\+ (?:b\/(.+)|\/dev\/null)\r?$/;
// Matches "@@ -oldStart[,oldCount] +newStart[,newCount] @@" hunk headers.
// The trailing optional function name context ("@@ … @@ funcName") is ignored.
const HUNK_HEADER_RE = /^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@/;
function stripDiffHeaderMetadata(filePath) {
    return filePath.replace(/\t.*$/, "");
}
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
function buildDiffPositionMap(unifiedDiff) {
    const result = new Map();
    // Normalize CRLF → LF so the regex always works.
    const lines = unifiedDiff.replace(/\r\n/g, "\n").split("\n");
    let currentFile = null;
    let fileMap = null;
    let isBinary = false;
    // Position counter — reset to 0 at each "diff --git" header.
    // The first hunk @@ header within a file is position 1.
    let position = 0;
    // Line trackers for the new (right-hand) and old (left-hand) files.
    let newLine = 0;
    let oldLine = 0;
    // Whether we are currently inside a hunk (after the first @@ for this file).
    let inHunk = false;
    for (const rawLine of lines) {
        // ----------------------------------------------------------------
        // "diff --git a/… b/…" — start of a new file section
        // ----------------------------------------------------------------
        const gitHeaderMatch = DIFF_GIT_HEADER_RE.exec(rawLine);
        if (gitHeaderMatch) {
            // Commit the previous file's map if any.
            if (currentFile !== null && fileMap !== null) {
                result.set(currentFile, fileMap);
            }
            currentFile = gitHeaderMatch[1];
            fileMap = new Map();
            isBinary = false;
            inHunk = false;
            position = 0;
            newLine = 0;
            oldLine = 0;
            continue;
        }
        // ----------------------------------------------------------------
        // "+++ b/path" header — may override the file path parsed from the
        // "diff --git" line (e.g. renames with path quoting).
        // ----------------------------------------------------------------
        const plusHeaderMatch = PLUS_PLUS_HEADER_RE.exec(rawLine);
        if (plusHeaderMatch && !inHunk) {
            // plusHeaderMatch[1] is undefined for /dev/null (new-file deletions).
            const overridePath = plusHeaderMatch[1];
            if (overridePath && currentFile !== null) {
                // Only override if it differs — "diff --git" is usually correct.
                // The +++ header is more reliable for renames with special chars.
                // Re-key the in-progress map.
                currentFile = stripDiffHeaderMetadata(overridePath);
            }
            continue;
        }
        // ----------------------------------------------------------------
        // Binary file marker — skip all hunk content for this file.
        // ----------------------------------------------------------------
        if (rawLine.startsWith("Binary files ")) {
            isBinary = true;
            continue;
        }
        // Skip all further processing for binary files in this section.
        if (isBinary)
            continue;
        // Skip preamble lines before the first hunk within a file section
        // ("index …", "--- a/…", "+++ b/…", "old mode …", etc.).
        if (currentFile === null)
            continue;
        // ----------------------------------------------------------------
        // @@ hunk header
        // ----------------------------------------------------------------
        const hunkMatch = HUNK_HEADER_RE.exec(rawLine);
        if (hunkMatch) {
            position += 1;
            inHunk = true;
            oldLine = parseInt(hunkMatch[1], 10);
            newLine = parseInt(hunkMatch[2], 10);
            // The @@ header itself does not correspond to a file line, so we
            // do not insert it into the file map.
            continue;
        }
        // ----------------------------------------------------------------
        // Hunk body lines — only processed after a @@ header.
        // ----------------------------------------------------------------
        if (!inHunk)
            continue;
        if (rawLine.startsWith("+")) {
            // Addition line — right-hand (new) file only.
            position += 1;
            // Store under the new-file (right-hand) line number.
            fileMap.set(newLine, position);
            newLine += 1;
        }
        else if (rawLine.startsWith("-")) {
            // Deletion line — left-hand (old) file only.
            // Stored under the negated old-line number to avoid collisions with
            // new-file line numbers in the same Map. The A3 resolver uses negative
            // keys to distinguish deletions from additions/context.
            position += 1;
            fileMap.set(-oldLine, position);
            oldLine += 1;
        }
        else if (rawLine.startsWith(" ")) {
            // Context line — present in both files.
            // Note: empty strings ("") from the trailing newline split are NOT
            // context lines; they are ignored below.
            position += 1;
            // Store under the new-file line number (right-hand view).
            fileMap.set(newLine, position);
            newLine += 1;
            oldLine += 1;
        }
        // Any other line (e.g. "\ No newline at end of file", or the empty string
        // produced by splitting on the trailing newline) is silently skipped.
    }
    // Commit the last file.
    if (currentFile !== null && fileMap !== null) {
        result.set(currentFile, fileMap);
    }
    return result;
}
//# sourceMappingURL=diff.js.map