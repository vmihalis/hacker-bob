"use strict";
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
Object.defineProperty(exports, "__esModule", { value: true });
exports.normaliseDiffImpactResult = normaliseDiffImpactResult;
exports.formatS4FailureJson = formatS4FailureJson;
exports.logPathAActivation = logPathAActivation;
exports.logPathASuccess = logPathASuccess;
exports.logNoImpactedSurfaces = logNoImpactedSurfaces;
exports.buildDiffImpactArtifact = buildDiffImpactArtifact;
// ---------------------------------------------------------------------------
// Normalisation helpers
// ---------------------------------------------------------------------------
/**
 * Normalise a single raw impacted entry from the MCP response into the typed
 * ImpactedEntry shape.
 *
 * Returns null if the entry is malformed (missing file or surface_ids).
 */
function normaliseEntry(raw) {
    if (typeof raw !== "object" || raw === null)
        return null;
    const e = raw;
    const file = e["file"] ?? e["path"];
    if (!file || typeof file !== "string")
        return null;
    const line_start = typeof e["line_start"] === "number"
        ? e["line_start"]
        : typeof e["start_line"] === "number"
            ? e["start_line"]
            : typeof e["line"] === "number"
                ? e["line"]
                : 1;
    const line_end = typeof e["line_end"] === "number"
        ? e["line_end"]
        : typeof e["end_line"] === "number"
            ? e["end_line"]
            : line_start;
    const rawSurfaces = e["surface_ids"] ?? e["surfaces"];
    const surface_ids = Array.isArray(rawSurfaces)
        ? rawSurfaces.filter((s) => typeof s === "string")
        : [];
    const hunk_summary = e["hunk_summary"] ??
        e["summary"] ??
        e["description"] ??
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
function normaliseDiffImpactResult(raw) {
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
        const errObj = raw;
        const errField = errObj["error"];
        if (typeof errField === "object" && errField !== null) {
            const e = errField;
            return {
                ok: false,
                error: {
                    code: e["code"] ?? "mcp_error",
                    message: e["message"] ?? JSON.stringify(errField),
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
        const resp = raw;
        // Unwrap data envelope if present.
        const payload = resp["data"] ?? resp;
        const rawEntries = payload["impacted_entries"] ??
            payload["entries"] ??
            [];
        const impacted_entries = rawEntries
            .map(normaliseEntry)
            .filter((e) => e !== null);
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
function formatS4FailureJson(error) {
    return JSON.stringify({
        step: "S4.path_a",
        ok: false,
        error: {
            code: error.code,
            message: error.message,
        },
    }, null, 2);
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
function logPathAActivation() {
    console.log("PATH A: diff impact via symbol index");
}
/**
 * Log the impacted entry count after a successful PATH A call.
 *
 * Produces: "S4 PATH A: N impacted entries from symbol index"
 *
 * @param entryCount - Length of the impacted_entries array.
 */
function logPathASuccess(entryCount) {
    console.log(`S4 PATH A: ${entryCount} impacted entries from symbol index`);
}
/**
 * Log the clean exit when PATH A produces zero impacted entries.
 *
 * Produces: "no impacted surfaces"
 */
function logNoImpactedSurfaces() {
    console.log("no impacted surfaces");
}
/**
 * Build the DiffImpactArtifact payload from a successful PATH A result.
 *
 * The orchestrator agent writes this to the session dir via MCP after S4.
 *
 * @param result       - Successful S4PathAResult (ok must be true).
 * @param targetDomain - Bob session target_domain.
 */
function buildDiffImpactArtifact(result, targetDomain) {
    return {
        schema_version: 1,
        target_domain: targetDomain,
        path_used: "A",
        entry_count: result.entry_count,
        impacted_entries: result.impacted_entries,
    };
}
//# sourceMappingURL=diff-impact.js.map