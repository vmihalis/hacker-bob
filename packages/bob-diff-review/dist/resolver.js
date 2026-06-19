"use strict";
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
Object.defineProperty(exports, "__esModule", { value: true });
exports.formatCommentBody = formatCommentBody;
exports.formatPRLevelBody = formatPRLevelBody;
exports.resolvePosition = resolvePosition;
exports.resolveFindings = resolveFindings;
// ---------------------------------------------------------------------------
// Body formatting
// ---------------------------------------------------------------------------
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
function formatCommentBody(finding) {
    const header = `[${finding.severity}] ${finding.title}`;
    const evidence = `**Evidence:**\n\`\`\`\n${finding.evidence}\n\`\`\``;
    return `${header}\n\n${finding.description}\n\n${evidence}`;
}
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
function formatPRLevelBody(finding, filePath) {
    const filePrefix = `**File:** \`${filePath}\` line ${finding.line_start}`;
    return `${filePrefix}\n${formatCommentBody(finding)}`;
}
// ---------------------------------------------------------------------------
// Position lookup helpers
// ---------------------------------------------------------------------------
/**
 * Determine whether a line number key in the DiffPositionMap represents a
 * deletion line (negative key) or an addition/context line (positive key).
 *
 * GitHub's createReview uses "LEFT" for deletion lines and "RIGHT" for
 * addition/context lines. The DiffPositionMap encodes deletions under negated
 * old-file line numbers (negative keys) to avoid collisions.
 *
 * @param key - The raw map key (may be negative for deletions).
 * @returns "LEFT" if the key is negative (deletion), "RIGHT" otherwise.
 */
function sideFromKey(key) {
    return key < 0 ? "LEFT" : "RIGHT";
}
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
function resolvePosition(fileMap, lineStart) {
    if (fileMap.size === 0)
        return null;
    // 1. Exact addition/context lookup (positive key = new-file line).
    const exactPos = fileMap.get(lineStart);
    if (exactPos !== undefined) {
        return { position: exactPos, side: "RIGHT" };
    }
    // 2. Exact deletion lookup (negative key = negated old-file line).
    const deletionPos = fileMap.get(-lineStart);
    if (deletionPos !== undefined) {
        return { position: deletionPos, side: "LEFT" };
    }
    // 3. Forward walk: find the nearest mapped positive key >= lineStart.
    //    Collect all positive keys (addition/context lines) and sort ascending.
    //    Use the smallest key that is >= lineStart.
    let forwardBest = null;
    let backwardBest = null;
    for (const [key, pos] of fileMap) {
        if (key <= 0)
            continue; // Skip deletion keys for the forward/backward search.
        if (key >= lineStart) {
            // Forward candidate.
            if (forwardBest === null || key < forwardBest.key) {
                forwardBest = { key, position: pos };
            }
        }
        else {
            // Backward candidate (key < lineStart).
            if (backwardBest === null || key > backwardBest.key) {
                backwardBest = { key, position: pos };
            }
        }
    }
    if (forwardBest !== null) {
        return { position: forwardBest.position, side: "RIGHT" };
    }
    // 4. Backward walk fallback: last mapped positive key before lineStart.
    if (backwardBest !== null) {
        return { position: backwardBest.position, side: "RIGHT" };
    }
    // 5. Map contained only deletion keys and none matched exactly — use any
    //    entry as last resort (should be extremely rare in practice).
    const anyEntry = fileMap.entries().next();
    if (!anyEntry.done) {
        const [key, pos] = anyEntry.value;
        return { position: pos, side: sideFromKey(key) };
    }
    return null;
}
// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------
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
function resolveFindings(findings, posMap) {
    const resolved = [];
    for (const finding of findings.findings) {
        // Clamp line_start to >= 1 to guard against malformed Bob output.
        const lineStart = Math.max(1, finding.line_start);
        const normalizedFinding = { ...finding, line_start: lineStart };
        // Normalize file path separators for cross-platform consistency.
        const filePath = finding.file.replace(/\\/g, "/");
        // Look up the file in the diff position map.
        const fileMap = posMap.get(filePath);
        if (fileMap === undefined) {
            // File is not in the diff at all — PR-level comment.
            resolved.push({
                path: filePath,
                // No position: this is a PR-level comment body.
                body: formatPRLevelBody(normalizedFinding, filePath),
                side: "RIGHT",
            });
            continue;
        }
        // File is in the diff — attempt to resolve to a diff position.
        const posResult = resolvePosition(fileMap, lineStart);
        if (posResult !== null) {
            // Successfully resolved to a specific diff line.
            resolved.push({
                path: filePath,
                position: posResult.position,
                body: formatCommentBody(normalizedFinding),
                side: posResult.side,
            });
        }
        else {
            // File is in the diff but has no resolvable positions (e.g. binary file
            // with an empty map). Use position: 1 if the file is in the diff header
            // at all — this corresponds to the first @@ hunk header position which
            // is always valid.
            //
            // If the map is completely empty we still know the file is in the diff
            // (it's in posMap), so we use position 1 per the spec:
            // "file-level comments (position: 1 for that file, if file is in diff)".
            resolved.push({
                path: filePath,
                position: 1,
                body: formatPRLevelBody(normalizedFinding, filePath),
                side: "RIGHT",
            });
        }
    }
    return resolved;
}
//# sourceMappingURL=resolver.js.map