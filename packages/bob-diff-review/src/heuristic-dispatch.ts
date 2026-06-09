/**
 * S4b — PATH B fallback: heuristic evaluator dispatch.
 *
 * Activates when bob_summarize_diff_impact (PATH A) is unavailable or the
 * symbol surface index does not exist. Maps changed file paths to surface IDs
 * using well-known path patterns so that S5 and S6 can operate identically
 * regardless of which path produced impacted_entries.
 *
 * PATH B surface_ids are prefixed "heuristic:" to distinguish them from
 * index-derived IDs produced by PATH A.
 *
 * Failure modes guarded here:
 *   - Too many heuristic surfaces: capped at MAX_HEURISTIC_SURFACES (8).
 *   - Too many unknown dispatches: capped at MAX_UNKNOWN_DISPATCHES (5).
 *   - PATH B activation logged loudly before dispatch.
 */

// ---------------------------------------------------------------------------
// Types — identical schema to PATH A impacted_entries
// ---------------------------------------------------------------------------

/**
 * A single impacted entry produced by either PATH A (bob_summarize_diff_impact)
 * or PATH B (heuristic dispatch). Schema is intentionally identical so S5 and
 * S6 are path-agnostic.
 */
export interface ImpactedEntry {
  /** Repo-relative file path, e.g. "src/auth/login.ts". */
  file: string;
  /**
   * First changed line in the file (1-indexed). PATH B uses 1 when line
   * information is unavailable from the diff header.
   */
  line_start: number;
  /**
   * Last changed line in the file (1-indexed). PATH B uses line_start when
   * only a single-line range is known.
   */
  line_end: number;
  /**
   * Surface IDs assigned to this entry. PATH B values are prefixed "heuristic:".
   * May contain multiple surface IDs if the file path matches several patterns.
   */
  surface_ids: string[];
  /**
   * Human-readable summary of what changed in this hunk. PATH B produces a
   * minimal summary ("heuristic match: <pattern>") when no structural analysis
   * is available.
   */
  hunk_summary: string;
}

/**
 * Result returned by buildHeuristicImpactedEntries.
 */
export interface PathBResult {
  /** Impacted entries produced by heuristic dispatch. */
  impacted_entries: ImpactedEntry[];
  /**
   * Number of entries with surface_id "heuristic:unknown" that were produced
   * before the cap was applied. Zero when all files matched at least one
   * pattern.
   */
  unknown_dispatches: number;
  /**
   * Number of entries trimmed by the cap on heuristic surfaces. Zero when the
   * total unique surface count was within bounds.
   */
  capped_entries: number;
  /**
   * Activation message — always 'PATH B: heuristic dispatch (no symbol index)'.
   * Callers should log this loudly.
   */
  activation_log: string;
}

// ---------------------------------------------------------------------------
// Pattern table
// ---------------------------------------------------------------------------

/** Maximum distinct heuristic surface_ids per run (guards S5 agent explosion). */
export const MAX_HEURISTIC_SURFACES = 8;

/** Maximum entries with surface_id "heuristic:unknown" (guards S5 flooding). */
export const MAX_UNKNOWN_DISPATCHES = 5;

/**
 * A single pattern rule: if any element of `patterns` matches the file path,
 * assign `surface_id`.
 *
 * Patterns are tested as case-insensitive substring matches or glob-style
 * prefix/suffix tests to keep the implementation dependency-free.
 */
interface PatternRule {
  /** Displayable label for hunk_summary generation. */
  label: string;
  /**
   * Predicate applied to the normalized (lower-case, forward-slash) file path.
   * Returns true when the rule matches.
   */
  test: (normalizedPath: string) => boolean;
  /** Surface ID assigned when the rule matches. Always "heuristic:<name>". */
  surface_id: string;
}

/**
 * Hardcoded pattern table. Rules are evaluated in order; the first matching
 * rule wins for the primary surface_id assignment. A file can accumulate
 * multiple surface_ids if multiple rules match.
 *
 * Extend this table via the runtime override mechanism (S4b argument) in the
 * SKILL.md pattern-source note.
 */
const PATTERN_TABLE: ReadonlyArray<PatternRule> = [
  // -------------------------------------------------------------------------
  // smart-contract (checked before auth/routes to catch *.sol / *.move first)
  // -------------------------------------------------------------------------
  {
    label: "smart-contract",
    surface_id: "heuristic:smart-contract",
    test: (p) =>
      p.includes("/contracts/") ||
      p.startsWith("contracts/") ||
      p.endsWith(".sol") ||
      p.endsWith(".move") ||
      p.endsWith(".vy") ||
      p.includes("/contract/") ||
      p.startsWith("contract/"),
  },

  // -------------------------------------------------------------------------
  // authentication
  // -------------------------------------------------------------------------
  {
    label: "authentication",
    surface_id: "heuristic:authentication",
    test: (p) =>
      p.includes("/auth/") ||
      p.startsWith("auth/") ||
      p.includes("login") ||
      p.includes("logout") ||
      p.includes("session") ||
      p.includes("password") ||
      p.includes("credential") ||
      p.includes("token") ||
      p.includes("oauth") ||
      p.includes("jwt") ||
      p.includes("sso") ||
      p.includes("saml") ||
      p.includes("mfa") ||
      p.includes("2fa"),
  },

  // -------------------------------------------------------------------------
  // admin
  // -------------------------------------------------------------------------
  {
    label: "admin",
    surface_id: "heuristic:admin",
    test: (p) =>
      p.includes("/admin/") ||
      p.startsWith("admin/") ||
      p.includes("/dashboard/") ||
      p.includes("/management/") ||
      p.includes("/backoffice/") ||
      p.includes("_admin"),
  },

  // -------------------------------------------------------------------------
  // api-route / controller
  // -------------------------------------------------------------------------
  {
    label: "api-route",
    surface_id: "heuristic:api-route",
    test: (p) =>
      p.includes("/routes/") ||
      p.startsWith("routes/") ||
      p.includes("/api/") ||
      p.startsWith("api/") ||
      p.includes("controller") ||
      p.includes("handler") ||
      p.includes("middleware") ||
      p.includes("/router") ||
      p.includes("endpoint"),
  },
];

// ---------------------------------------------------------------------------
// Core implementation
// ---------------------------------------------------------------------------

/**
 * Normalise a file path for pattern matching.
 * Converts backslashes to forward slashes and lowercases the result.
 */
function normalizePath(filePath: string): string {
  return filePath.replace(/\\/g, "/").toLowerCase();
}

/**
 * Apply the pattern table to a single file path.
 * Returns the array of matching surface_ids (may be empty = unknown).
 */
function matchSurfaceIds(
  filePath: string,
  extraRules: ReadonlyArray<PatternRule> = []
): string[] {
  const normalized = normalizePath(filePath);
  const matched: string[] = [];
  const allRules = [...PATTERN_TABLE, ...extraRules];

  for (const rule of allRules) {
    if (rule.test(normalized)) {
      // Deduplicate surface_ids (a file can satisfy multiple rules with the
      // same surface_id e.g. auth/token.ts matches both "auth/" and "token").
      if (!matched.includes(rule.surface_id)) {
        matched.push(rule.surface_id);
      }
    }
  }

  return matched;
}

/**
 * Build a minimal hunk_summary string for PATH B entries.
 */
function buildHunkSummary(
  filePath: string,
  surface_ids: string[]
): string {
  if (surface_ids.length === 0) {
    return `heuristic match: unknown (no pattern matched ${filePath})`;
  }
  const labels = surface_ids.map((id) => id.replace("heuristic:", ""));
  return `heuristic match: ${labels.join(", ")} — ${filePath}`;
}

/**
 * A lightweight parsed diff file entry used as input to PATH B.
 *
 * PATH B does not require full diff parsing — it only needs the file path and
 * an optional line range from the diff `@@ -old +new @@` header.
 */
export interface DiffFileEntry {
  /** Repo-relative file path (b-side / new file path from the diff header). */
  file: string;
  /**
   * First changed line (new-file side). 1 when not determinable from the diff.
   */
  line_start?: number;
  /**
   * Last changed line (new-file side). Equals line_start when not
   * determinable.
   */
  line_end?: number;
}

/**
 * Parse the unified diff text and extract per-file change metadata.
 *
 * This is a lightweight parser — it extracts `diff --git` / `--- ` / `+++ `
 * headers and every `@@` hunk header per file to capture the changed ranges.
 * PATH B keeps one entry per hunk so later-hunk findings are not orphaned.
 *
 * @param diffText - Raw unified diff string (git diff output).
 * @returns Array of DiffFileEntry, one per changed file.
 */
export function parseDiffFiles(diffText: string): DiffFileEntry[] {
  const entries: DiffFileEntry[] = [];

  // Split on "diff --git" boundaries to process one file at a time.
  const fileBlocks = diffText.split(/^diff --git /m).slice(1);

  for (const block of fileBlocks) {
    // Extract the b-side path from "diff --git a/foo b/foo" or "+++ b/foo".
    let filePath: string | null = null;

    // Prefer "b/<path>" from the diff header line (first line of block).
    const headerMatch = block.match(/^[^\n]* b\/(\S+)/);
    if (headerMatch) {
      filePath = headerMatch[1];
    } else {
      // Fallback: extract from "+++ b/<path>" line.
      const plusMatch = block.match(/^\+\+\+ b\/(.+)$/m);
      if (plusMatch) {
        filePath = plusMatch[1].trim();
      }
    }

    if (!filePath || filePath === "/dev/null") {
      continue;
    }

    const hunkMatches = Array.from(
      block.matchAll(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/gm)
    );

    if (hunkMatches.length === 0) {
      entries.push({ file: filePath, line_start: 1, line_end: 1 });
      continue;
    }

    for (const hunkMatch of hunkMatches) {
      const line_start = Math.max(parseInt(hunkMatch[1], 10) || 1, 1);
      const count = parseInt(hunkMatch[2] ?? "1", 10);
      const line_end = Math.max(line_start, line_start + count - 1);
      entries.push({ file: filePath, line_start, line_end });
    }
  }

  return entries;
}

/**
 * Build the PATH B impacted_entries list from a set of changed files.
 *
 * This is the main export for S4b. It:
 *   1. Logs the PATH B activation message.
 *   2. Maps each file to surface_ids via the pattern table.
 *   3. Caps heuristic:unknown dispatches at MAX_UNKNOWN_DISPATCHES.
 *   4. Caps total unique surface_ids at MAX_HEURISTIC_SURFACES.
 *   5. Returns the same ImpactedEntry schema as PATH A.
 *
 * @param changedFiles  - Array of changed files extracted from the diff.
 * @param extraRules    - Optional caller-supplied pattern rules (runtime override).
 * @returns PathBResult with impacted_entries and diagnostic counters.
 */
export function buildHeuristicImpactedEntries(
  changedFiles: DiffFileEntry[],
  extraRules: ReadonlyArray<PatternRule> = []
): PathBResult {
  const ACTIVATION_LOG = "PATH B: heuristic dispatch (no symbol index)";

  // Log loudly to stdout so the activation is visible in CI logs.
  // The exact string must match the acceptance criterion; supplementary lines
  // may carry the [S4b] prefix.
  console.log(ACTIVATION_LOG);

  const entries: ImpactedEntry[] = [];
  let unknownCount = 0;
  let cappedEntries = 0;

  // Track unique surface_ids to enforce the max-surfaces cap.
  const seenSurfaces = new Set<string>();

  for (const changed of changedFiles) {
    const surface_ids = matchSurfaceIds(changed.file, extraRules);
    const isUnknown = surface_ids.length === 0;

    if (isUnknown) {
      // Cap unknown dispatches.
      if (unknownCount >= MAX_UNKNOWN_DISPATCHES) {
        cappedEntries++;
        continue;
      }
      unknownCount++;
      const unknownId = "heuristic:unknown";
      seenSurfaces.add(unknownId);

      entries.push({
        file: changed.file,
        line_start: changed.line_start ?? 1,
        line_end: changed.line_end ?? changed.line_start ?? 1,
        surface_ids: [unknownId],
        hunk_summary: buildHunkSummary(changed.file, []),
      });
    } else {
      // Check whether adding these surface_ids would exceed the cap.
      const newSurfaces = surface_ids.filter((id) => !seenSurfaces.has(id));
      const projectedSize = seenSurfaces.size + newSurfaces.length;

      if (projectedSize > MAX_HEURISTIC_SURFACES) {
        // Only include surface_ids already seen; skip if none survive the cap.
        const allowedIds = surface_ids.filter((id) => seenSurfaces.has(id));
        if (allowedIds.length === 0) {
          cappedEntries++;
          continue;
        }

        entries.push({
          file: changed.file,
          line_start: changed.line_start ?? 1,
          line_end: changed.line_end ?? changed.line_start ?? 1,
          surface_ids: allowedIds,
          hunk_summary: buildHunkSummary(changed.file, allowedIds),
        });
      } else {
        // Add all matched surface_ids.
        for (const id of newSurfaces) seenSurfaces.add(id);

        entries.push({
          file: changed.file,
          line_start: changed.line_start ?? 1,
          line_end: changed.line_end ?? changed.line_start ?? 1,
          surface_ids,
          hunk_summary: buildHunkSummary(changed.file, surface_ids),
        });
      }
    }
  }

  return {
    impacted_entries: entries,
    unknown_dispatches: unknownCount,
    capped_entries: cappedEntries,
    activation_log: ACTIVATION_LOG,
  };
}

/**
 * High-level PATH B entry point.
 *
 * Parses the raw unified diff text and produces impacted_entries via heuristic
 * dispatch. This is the function the orchestrator agent calls when PATH A fails.
 *
 * Logs:
 *   - 'PATH B: heuristic dispatch (no symbol index)'  (always)
 *   - 'S4b: N impacted entries produced by heuristic dispatch'
 *   - 'S4b: M unknown-surface entries capped at MAX_UNKNOWN_DISPATCHES'  (when > 0)
 *   - 'S4b: K entries trimmed by MAX_HEURISTIC_SURFACES cap'  (when > 0)
 *
 * @param diffText   - Raw unified diff text (git diff output).
 * @param extraRules - Optional caller-supplied pattern overrides.
 * @returns PathBResult — callers pass impacted_entries directly to S5.
 */
export function runPathB(
  diffText: string,
  extraRules: ReadonlyArray<PatternRule> = []
): PathBResult {
  const changedFiles = parseDiffFiles(diffText);
  const result = buildHeuristicImpactedEntries(changedFiles, extraRules);

  console.log(
    `[S4b] ${result.impacted_entries.length} impacted entries produced by heuristic dispatch`
  );

  if (result.unknown_dispatches > 0) {
    console.warn(
      `[S4b] ${result.unknown_dispatches} unknown-surface entries (no pattern matched); ` +
        `cap is ${MAX_UNKNOWN_DISPATCHES}`
    );
  }

  if (result.capped_entries > 0) {
    console.warn(
      `[S4b] ${result.capped_entries} entries trimmed by surface cap (MAX_HEURISTIC_SURFACES=${MAX_HEURISTIC_SURFACES})`
    );
  }

  return result;
}
