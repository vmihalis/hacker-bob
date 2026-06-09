/**
 * S4 — Diff impact analysis via bob_summarize_diff_impact (PATH A).
 *
 * This module implements PATH A of the diff impact step: passing the full
 * unified diff text to the bob_summarize_diff_impact MCP tool, which
 * cross-references each changed hunk against the symbol surface index to
 * produce impacted_entries — the list of {file, line_start, line_end,
 * surface_ids[], hunk_summary} objects that drive evaluator agent spawning in
 * S5.
 *
 * PATH A is always the preferred path because it provides precise, index-backed
 * surface targeting. The orchestrator agent falls back to PATH B (heuristic
 * dispatch in heuristic-dispatch.ts) only when bob_summarize_diff_impact is
 * unavailable or returns an error.
 *
 * All MCP calls are executed by the orchestrator agent (SKILL.md); this module
 * provides the TypeScript types and helper functions that bob-runner.ts uses to
 * drive those calls and interpret their results.
 */

// ---------------------------------------------------------------------------
// Re-export ImpactedEntry from heuristic-dispatch so both paths share the same
// schema type. Callers import ImpactedEntry from either module interchangeably.
// ---------------------------------------------------------------------------
export type { ImpactedEntry } from "./heuristic-dispatch.js";

// ---------------------------------------------------------------------------
// PATH A result types
// ---------------------------------------------------------------------------

/**
 * The raw MCP response shape from bob_summarize_diff_impact.
 *
 * The tool may nest its result under a `data` key or return it flat; the
 * normaliser handles both shapes.
 */
export interface RawDiffImpactResponse {
  /** Whether the tool call succeeded. */
  ok?: boolean;
  /** Impacted entries when nested under data. */
  data?: {
    impacted_entries?: unknown[];
    path_used?: string;
    [key: string]: unknown;
  };
  /** Impacted entries when returned flat. */
  impacted_entries?: unknown[];
  /** PATH token (e.g. "A" or "symbol_index"). */
  path_used?: string;
  /** Error detail when ok is false. */
  error?: { code?: string; message?: string };
  [key: string]: unknown;
}

/**
 * A normalised impacted entry produced by bob_summarize_diff_impact (PATH A).
 *
 * The schema is intentionally identical to the PATH B ImpactedEntry so that S5
 * and S6 are path-agnostic. Re-exported from heuristic-dispatch for alignment.
 */
// (imported via re-export above; kept as a named alias here for documentation)

/**
 * The result of the S4 PATH A step.
 */
export type S4PathAResult =
  | {
      ok: true;
      /** Impacted entries derived from the symbol surface index. */
      impacted_entries: import("./heuristic-dispatch.js").ImpactedEntry[];
      /**
       * Number of impacted entries produced. Used for the required log line:
       * 'S4 PATH A: N impacted entries from symbol index'.
       */
      entry_count: number;
      /**
       * Whether the result set was empty. When true, the orchestrator should
       * log 'no impacted surfaces' and exit cleanly rather than spawning
       * evaluator agents.
       */
      is_empty: boolean;
    }
  | {
      ok: false;
      error: { code: string; message: string };
    };

/**
 * Input parameters for the bob_summarize_diff_impact MCP call.
 *
 * The orchestrator agent passes these directly to the MCP tool.
 */
export interface DiffImpactParams {
  /** Bob session target_domain (e.g. 'gh-12345678'). */
  target_domain: string;
  /**
   * Full unified diff text including a/ b/ headers.
   * Must be the output of `git diff base...head` — the complete diff, not a
   * per-file slice.
   */
  diff_text: string;
}

// ---------------------------------------------------------------------------
// Normalisation helpers
// ---------------------------------------------------------------------------

/**
 * Normalise a single raw impacted entry from the MCP response into the typed
 * ImpactedEntry shape.
 *
 * Returns null if the entry is malformed (missing file or surface_ids).
 */
function normaliseEntry(raw: unknown): import("./heuristic-dispatch.js").ImpactedEntry | null {
  if (typeof raw !== "object" || raw === null) return null;
  const e = raw as Record<string, unknown>;

  const file = (e["file"] as string | undefined) ?? (e["path"] as string | undefined);
  if (!file || typeof file !== "string") return null;

  const line_start =
    typeof e["line_start"] === "number"
      ? e["line_start"]
      : typeof e["start_line"] === "number"
        ? e["start_line"]
        : typeof e["line"] === "number"
          ? e["line"]
          : 1;

  const line_end =
    typeof e["line_end"] === "number"
      ? e["line_end"]
      : typeof e["end_line"] === "number"
        ? e["end_line"]
        : line_start;

  const rawSurfaces = e["surface_ids"] ?? e["surfaces"];
  const surface_ids: string[] = Array.isArray(rawSurfaces)
    ? (rawSurfaces as unknown[]).filter((s): s is string => typeof s === "string")
    : [];

  const hunk_summary =
    (e["hunk_summary"] as string | undefined) ??
    (e["summary"] as string | undefined) ??
    (e["description"] as string | undefined) ??
    `diff hunk at ${file}:${line_start}-${line_end}`;

  return { file, line_start, line_end, surface_ids, hunk_summary };
}

/**
 * Normalise a raw bob_summarize_diff_impact MCP response into an S4PathAResult.
 *
 * Handles both flat and data-nested response shapes. An empty impacted_entries
 * array is a valid success (not an error); the caller should check is_empty and
 * log 'no impacted surfaces' before exiting cleanly.
 *
 * @param raw - Raw MCP response (parsed JSON or thrown error object).
 */
export function normaliseDiffImpactResult(raw: unknown): S4PathAResult {
  // MCP errors surface as Error instances or objects with an `error` key.
  if (raw instanceof Error) {
    return {
      ok: false,
      error: {
        code: "mcp_error",
        message: raw.message,
      },
    };
  }

  if (typeof raw === "object" && raw !== null && "error" in raw) {
    const errObj = raw as Record<string, unknown>;
    const errField = errObj["error"];
    if (typeof errField === "object" && errField !== null) {
      const e = errField as Record<string, unknown>;
      return {
        ok: false,
        error: {
          code: (e["code"] as string | undefined) ?? "mcp_error",
          message: (e["message"] as string | undefined) ?? JSON.stringify(errField),
        },
      };
    }
    // Top-level error string.
    return {
      ok: false,
      error: {
        code: "mcp_error",
        message: String(errField ?? JSON.stringify(raw)),
      },
    };
  }

  if (typeof raw === "object" && raw !== null) {
    const resp = raw as Record<string, unknown>;

    // Unwrap data envelope if present.
    const payload =
      (resp["data"] as Record<string, unknown> | undefined) ?? resp;

    const rawEntries =
      (payload["impacted_entries"] as unknown[] | undefined) ??
      (payload["entries"] as unknown[] | undefined) ??
      [];

    const impacted_entries = rawEntries
      .map(normaliseEntry)
      .filter((e): e is import("./heuristic-dispatch.js").ImpactedEntry => e !== null);

    return {
      ok: true,
      impacted_entries,
      entry_count: impacted_entries.length,
      is_empty: impacted_entries.length === 0,
    };
  }

  return {
    ok: false,
    error: {
      code: "unknown",
      message: `bob_summarize_diff_impact returned unexpected value type (${typeof raw})`,
    },
  };
}

/**
 * Format a structured JSON failure string for S4 PATH A error surfacing.
 *
 * @param error - The error detail object.
 */
export function formatS4FailureJson(error: { code: string; message: string }): string {
  return JSON.stringify(
    {
      step: "S4.path_a",
      ok: false,
      error: {
        code: error.code,
        message: error.message,
      },
    },
    null,
    2
  );
}

// ---------------------------------------------------------------------------
// Logging helpers used by the orchestrator agent / bob-runner.ts
// ---------------------------------------------------------------------------

/**
 * Log PATH A activation to stdout.
 *
 * This is the exact string required by the acceptance criterion:
 *   "PATH A activation is logged: 'PATH A: diff impact via symbol index'"
 *
 * The orchestrator agent should call this before executing
 * bob_summarize_diff_impact.
 */
export function logPathAActivation(): void {
  console.log("PATH A: diff impact via symbol index");
}

/**
 * Log the impacted entry count after a successful PATH A call.
 *
 * Produces: "S4 PATH A: N impacted entries from symbol index"
 *
 * @param entryCount - Length of the impacted_entries array.
 */
export function logPathASuccess(entryCount: number): void {
  console.log(`S4 PATH A: ${entryCount} impacted entries from symbol index`);
}

/**
 * Log the clean exit when PATH A produces zero impacted entries.
 *
 * Produces: "no impacted surfaces"
 */
export function logNoImpactedSurfaces(): void {
  console.log("no impacted surfaces");
}

// ---------------------------------------------------------------------------
// diff-impact.json schema
// ---------------------------------------------------------------------------

/**
 * Top-level schema of diff-impact.json written to the session dir via MCP.
 *
 * This artifact is written by the orchestrator agent using an MCP write call
 * (not a direct Write tool call), satisfying the acceptance criterion:
 *   "diff-impact.json written to session dir via MCP (not direct Write)"
 *
 * Specifically, the orchestrator passes this payload to the appropriate MCP
 * persistence tool after bob_summarize_diff_impact returns.
 */
export interface DiffImpactArtifact {
  /** Schema version for forward-compatibility. */
  schema_version: 1;
  /** Bob session target_domain. */
  target_domain: string;
  /** Which path produced the entries: "A" (symbol index) or "B" (heuristic). */
  path_used: "A" | "B";
  /** Total number of impacted entries. */
  entry_count: number;
  /** All impacted entries with file, line range, surface IDs, and hunk summary. */
  impacted_entries: import("./heuristic-dispatch.js").ImpactedEntry[];
}

/**
 * Build the DiffImpactArtifact payload from a successful PATH A result.
 *
 * The orchestrator agent writes this to the session dir via MCP after S4.
 *
 * @param result       - Successful S4PathAResult (ok must be true).
 * @param targetDomain - Bob session target_domain.
 */
export function buildDiffImpactArtifact(
  result: Extract<S4PathAResult, { ok: true }>,
  targetDomain: string
): DiffImpactArtifact {
  return {
    schema_version: 1,
    target_domain: targetDomain,
    path_used: "A",
    entry_count: result.entry_count,
    impacted_entries: result.impacted_entries,
  };
}
