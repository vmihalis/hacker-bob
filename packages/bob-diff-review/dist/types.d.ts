/**
 * Shared types for the bob-diff-review package.
 */
/**
 * A single position entry mapping a file line number to a GitHub Reviews API
 * diff position offset.
 *
 * The diff_position is the 1-indexed line count within the per-file diff blob
 * (counting @@ hunk headers, context lines, addition lines, and deletion
 * lines). This is the value GitHub's createReviewComment endpoint expects for
 * the `position` field.
 */
export interface PositionEntry {
    /** The file's line number in the post-merge (right-hand) view. */
    line: number;
    /**
     * The diff position offset (1-indexed, counting all diff lines including
     * @@ headers for this file).
     */
    position: number;
    /** Whether this line is an addition (+), deletion (-), or context ( ). */
    kind: "addition" | "deletion" | "context";
}
/**
 * A parsed unified-diff hunk with its metadata and position entries.
 */
export interface DiffHunk {
    /** The raw @@ header line, e.g. "@@ -1,3 +1,5 @@" */
    header: string;
    /** Starting line number in the old (left-hand) file. */
    oldStart: number;
    /** Starting line number in the new (right-hand) file. */
    newStart: number;
    /** All position entries within this hunk. */
    entries: PositionEntry[];
}
/**
 * Maps a file path (as it appears in the diff header) to a Map of
 * line number → diff position offset.
 *
 * Key encoding:
 *   - Positive keys (1, 2, 3, …): new-file (right-hand) line numbers for
 *     addition (+) and context lines.
 *   - Negative keys (-1, -2, -3, …): negated old-file (left-hand) line
 *     numbers for deletion (-) lines. Use `map.get(-oldLine)` to look up a
 *     deletion's diff position.
 *
 * This encoding avoids key collisions when both a deletion and a context/
 * addition line share the same numeric line number (e.g. old line 1 deleted,
 * new line 1 is a context line).
 *
 * Consumers (e.g. resolver.ts) that only need new-file lookup can call
 * `posMap.get(filePath)?.get(lineNumber)` with positive lineNumber.
 */
export type DiffPositionMap = Map<string, Map<number, number>>;
//# sourceMappingURL=types.d.ts.map