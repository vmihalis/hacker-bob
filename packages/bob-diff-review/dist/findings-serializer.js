"use strict";
/**
 * S6 — Findings serialization: diff-review-findings.json.
 *
 * After all S5 evaluator agents complete, this module reads candidate claims
 * via bob_read_candidate_claims and joins them with impacted_entries to produce
 * diff-review-findings.json. Each finding entry maps a Bob candidate claim to a
 * specific file + line_range so that resolver.ts (A3) can convert it to a GitHub
 * diff position.
 *
 * Join semantics:
 *   - A finding is included only when its file + line range overlaps at least
 *     one impacted_entry with a matching surface_id.
 *   - Findings whose file does not appear in any impacted_entry are orphaned and
 *     excluded from the output (spec: "Findings with no matching impacted_entry
 *     are excluded").
 *
 * File is written to --output-dir (NOT to the session dir) so that bob-runner.ts
 * (A2) can read it after the headless Claude process exits. diff-review-findings.json
 * is NOT in AUDIT_GRADED_PATHS and must be written via the Bash Write tool or fs.
 *
 * Acceptance criteria implemented here:
 *   1. Top-level keys: session_id, target_domain, generated_at, impacted_entries[], findings[].
 *   2. Each finding: surface_id, file, line_start, line_end, title, severity, description,
 *      evidence (capped at EVIDENCE_MAX_CHARS), hunk_text.
 *   3. Findings with no matching impacted_entry are excluded.
 *   4. Zero-findings case: file still written with empty findings[].
 *   5. Output is valid JSON (CI runs `jq . diff-review-findings.json`).
 *
 * Failure modes guarded here:
 *   - output-dir does not exist — callers must mkdir -p before calling writeFindings.
 *   - Claims from prior session runs — filtered by session_id before joining.
 *   - Binary evidence bytes causing JSON parse errors — evidence is sanitised through
 *     sanitiseEvidence() which base64-encodes non-UTF8 fragments.
 *   - Neither S4 nor S4b produced impacted_entries — detected by empty array check.
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
exports.VALID_SEVERITIES = exports.EVIDENCE_MAX_CHARS = void 0;
exports.normaliseSeverity = normaliseSeverity;
exports.truncate = truncate;
exports.sanitiseEvidence = sanitiseEvidence;
exports.normaliseCandidateClaim = normaliseCandidateClaim;
exports.rangesOverlap = rangesOverlap;
exports.findMatchingEntry = findMatchingEntry;
exports.serializeFindings = serializeFindings;
exports.writeFindings = writeFindings;
exports.validateJsonFile = validateJsonFile;
exports.formatS6FailureJson = formatS6FailureJson;
const fs = __importStar(require("node:fs"));
const path = __importStar(require("node:path"));
const os = __importStar(require("node:os"));
// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------
/**
 * Maximum characters for the evidence field.
 * Keeps PR review comments readable; longer evidence is truncated with a
 * "[truncated]" marker.
 */
exports.EVIDENCE_MAX_CHARS = 2000;
/**
 * Valid severity values as required by the acceptance criteria.
 */
exports.VALID_SEVERITIES = ["critical", "high", "medium", "low", "info"];
// ---------------------------------------------------------------------------
// Normalisation helpers
// ---------------------------------------------------------------------------
/**
 * Normalise a raw severity string to one of the valid FindingSeverity values.
 * Unknown values default to "info".
 */
function normaliseSeverity(raw) {
    const s = (raw ?? "").toLowerCase().trim();
    if (exports.VALID_SEVERITIES.includes(s)) {
        return s;
    }
    // Common aliases.
    if (s === "critical" || s === "crit")
        return "critical";
    if (s === "high" || s === "severe")
        return "high";
    if (s === "medium" || s === "med" || s === "moderate")
        return "medium";
    if (s === "low" || s === "minor")
        return "low";
    return "info";
}
/**
 * Truncate a string to at most maxChars, appending "[truncated]" when cut.
 */
function truncate(value, maxChars) {
    if (value.length <= maxChars)
        return value;
    const marker = "[truncated]";
    return value.slice(0, maxChars - marker.length) + marker;
}
/**
 * Sanitise an evidence string to ensure it is safe to embed in JSON.
 *
 * Base64-encodes any fragment that contains non-printable control characters
 * outside the normal whitespace range (\t, \n, \r) to prevent JSON parse
 * errors from binary content.
 */
function sanitiseEvidence(raw) {
    if (!raw)
        return "";
    // Check for binary/non-UTF8 control characters that would break JSON.
    // eslint-disable-next-line no-control-regex
    if (/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/.test(raw)) {
        return "[binary evidence base64] " + Buffer.from(raw).toString("base64");
    }
    return raw;
}
/**
 * Normalise a raw candidate claim into a typed shape ready for joining.
 * Returns null if the claim lacks the minimum required fields (file, title).
 */
function normaliseCandidateClaim(raw) {
    const file = raw.file?.trim();
    if (!file)
        return null;
    const title = raw.title?.trim();
    if (!title)
        return null;
    const session_id = raw.session_id ?? "";
    const surface_id = raw.surface_id ?? "";
    const line_start = typeof raw.line_start === "number" && raw.line_start > 0
        ? raw.line_start
        : 1;
    const line_end = typeof raw.line_end === "number" && raw.line_end >= line_start
        ? raw.line_end
        : line_start;
    return {
        session_id,
        surface_id,
        file,
        line_start,
        line_end,
        title,
        severity: normaliseSeverity(raw.severity),
        description: truncate(raw.description ?? "", 500),
        evidence: truncate(sanitiseEvidence(raw.evidence), exports.EVIDENCE_MAX_CHARS),
        hunk_text: raw.hunk_text ?? "",
    };
}
// ---------------------------------------------------------------------------
// Line range overlap
// ---------------------------------------------------------------------------
/**
 * Test whether two line ranges overlap (inclusive on both ends).
 *
 * Two ranges [aStart, aEnd] and [bStart, bEnd] overlap when neither ends
 * strictly before the other starts.
 */
function rangesOverlap(aStart, aEnd, bStart, bEnd) {
    return aStart <= bEnd && bStart <= aEnd;
}
// ---------------------------------------------------------------------------
// Join logic
// ---------------------------------------------------------------------------
/**
 * Find the impacted_entry that best matches a candidate claim.
 *
 * Matching rules:
 *   1. Files must be equal (after normalizing path separators).
 *   2. Line ranges must overlap.
 *   3. If the claim carries a surface_id, prefer an entry that includes it;
 *      fall back to any entry with an overlapping line range on the same file.
 *
 * Returns the first (best) match, or null if no match exists.
 *
 * @param claim           - Normalised claim to match.
 * @param impactedEntries - Full list of impacted entries from S4/S4b.
 */
function findMatchingEntry(claim, impactedEntries) {
    const claimFile = claim.file.replace(/\\/g, "/");
    // Gather candidates that match on file + line overlap.
    const candidates = impactedEntries.filter((entry) => {
        const entryFile = entry.file.replace(/\\/g, "/");
        return (entryFile === claimFile &&
            rangesOverlap(claim.line_start, claim.line_end, entry.line_start, entry.line_end));
    });
    if (candidates.length === 0)
        return null;
    // Prefer a candidate that carries the claim's surface_id.
    if (claim.surface_id) {
        const preferred = candidates.find((e) => e.surface_ids.includes(claim.surface_id));
        if (preferred)
            return preferred;
    }
    // Fall back to the first candidate by line range proximity.
    return candidates[0];
}
// ---------------------------------------------------------------------------
// Core serialization
// ---------------------------------------------------------------------------
/**
 * Produce the DiffReviewFindings document from raw claims and impacted entries.
 *
 * Steps:
 *   1. Filter claims to the current session_id.
 *   2. Normalise each claim.
 *   3. Join with impacted_entries via file + line range overlap.
 *   4. Populate hunk_text from the matched impacted_entry when the claim
 *      carries no hunk_text.
 *   5. Exclude orphaned claims (no matching impacted_entry).
 *
 * @param params - SerializeParams as described above.
 * @returns SerializeResult containing the findings document and diagnostics.
 */
function serializeFindings(params) {
    const { session_id, target_domain, impacted_entries, raw_claims, generated_at = new Date().toISOString(), } = params;
    const log_lines = [];
    let session_filtered_count = 0;
    let orphaned_count = 0;
    // Step 1: Filter claims to the current session.
    const sessionClaims = raw_claims.filter((claim) => {
        const claimSession = claim.session_id ?? "";
        if (claimSession && claimSession !== session_id) {
            session_filtered_count++;
            return false;
        }
        return true;
    });
    if (session_filtered_count > 0) {
        log_lines.push(`S6: filtered ${session_filtered_count} claim(s) from prior session runs`);
    }
    log_lines.push(`S6: ${sessionClaims.length} candidate claim(s) for session ${session_id}`);
    // Step 2: Guard against missing impacted_entries (both S4 and S4b failed).
    if (impacted_entries.length === 0) {
        log_lines.push("S6: no impacted_entries available — all claims will be orphaned; writing empty findings");
        return {
            findings_doc: {
                session_id,
                target_domain,
                generated_at,
                impacted_entries: [],
                findings: [],
            },
            orphaned_count: sessionClaims.length,
            session_filtered_count,
            log_lines,
        };
    }
    // Step 3: Normalise and join each claim.
    const findings = [];
    for (const raw of sessionClaims) {
        const claim = normaliseCandidateClaim(raw);
        if (!claim) {
            // Missing required fields — treat as orphaned.
            orphaned_count++;
            log_lines.push(`S6: claim missing required fields (file/title) — orphaned`);
            continue;
        }
        const matchedEntry = findMatchingEntry(claim, impacted_entries);
        if (!matchedEntry) {
            orphaned_count++;
            log_lines.push(`S6: orphaned claim — no impacted_entry for ${claim.file}:${claim.line_start}-${claim.line_end}`);
            continue;
        }
        // Populate hunk_text from the matched entry when the claim has none.
        const hunk_text = claim.hunk_text.length > 0
            ? claim.hunk_text
            : matchedEntry.hunk_summary;
        findings.push({
            surface_id: claim.surface_id || (matchedEntry.surface_ids[0] ?? ""),
            file: claim.file,
            line_start: claim.line_start,
            line_end: claim.line_end,
            title: claim.title,
            severity: claim.severity,
            description: claim.description,
            evidence: claim.evidence,
            hunk_text,
        });
    }
    if (orphaned_count > 0) {
        log_lines.push(`S6: ${orphaned_count} orphaned claim(s) excluded from diff-review-findings.json`);
    }
    log_lines.push(`S6: ${findings.length} finding(s) written to diff-review-findings.json`);
    return {
        findings_doc: {
            session_id,
            target_domain,
            generated_at,
            impacted_entries,
            findings,
        },
        orphaned_count,
        session_filtered_count,
        log_lines,
    };
}
// ---------------------------------------------------------------------------
// File I/O
// ---------------------------------------------------------------------------
function pathContains(root, candidate) {
    const relative = path.relative(root, candidate);
    return relative === "" || (!!relative && !relative.startsWith("..") && !path.isAbsolute(relative));
}
function assertSafeOutputDir(outputDir) {
    if (!path.isAbsolute(outputDir)) {
        throw new Error("outputDir must be an absolute path");
    }
    const resolved = path.resolve(outputDir);
    const roots = [process.env["RUNNER_TEMP"], os.tmpdir()]
        .filter((value) => typeof value === "string" && value.length > 0)
        .map((value) => path.resolve(value));
    if (!roots.some((root) => pathContains(root, resolved))) {
        throw new Error("outputDir must be under RUNNER_TEMP or the system temp directory");
    }
    return resolved;
}
/**
 * Write the DiffReviewFindings document to the output directory.
 *
 * The output directory must already exist (callers must `mkdir -p`). This
 * function creates or overwrites diff-review-findings.json atomically by
 * writing to a temp file and renaming, preventing A2 from reading a partial
 * file if the process is interrupted.
 *
 * @param outputDir    - Absolute path to the output directory.
 * @param findingsDoc  - The document to serialize.
 * @returns Absolute path to the written file.
 */
function writeFindings(outputDir, findingsDoc) {
    const safeOutputDir = assertSafeOutputDir(outputDir);
    const outPath = path.join(safeOutputDir, "diff-review-findings.json");
    const tmpPath = outPath + ".tmp";
    const json = JSON.stringify(findingsDoc, null, 2);
    fs.mkdirSync(safeOutputDir, { recursive: true });
    fs.writeFileSync(tmpPath, json, "utf8");
    fs.renameSync(tmpPath, outPath);
    return outPath;
}
/**
 * Validate that a file at the given path is valid JSON.
 *
 * Used as a post-write sanity check (mirrors the CI `jq .` lint step).
 *
 * @param filePath - Absolute path to the file to validate.
 * @returns true if the file contains valid JSON, false otherwise.
 */
function validateJsonFile(filePath) {
    try {
        const content = fs.readFileSync(filePath, "utf8");
        JSON.parse(content);
        return true;
    }
    catch {
        return false;
    }
}
// ---------------------------------------------------------------------------
// Failure formatting
// ---------------------------------------------------------------------------
/**
 * Format a structured JSON failure string for S6 error surfacing.
 *
 * @param error - Error detail.
 */
function formatS6FailureJson(error) {
    return JSON.stringify({
        step: "S6.findings_serialization",
        ok: false,
        error: {
            code: error.code,
            message: error.message,
        },
    }, null, 2);
}
//# sourceMappingURL=findings-serializer.js.map