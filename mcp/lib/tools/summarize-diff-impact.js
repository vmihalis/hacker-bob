"use strict";

const fs = require("fs");
const { parseUnifiedDiff } = require("../unified-diff-parser.js");
const { summarizeImpactedSurfacesForDiff } = require("../symbol-surface-index.js");
const { assertSafeDomain, diffImpactPath, sessionDir } = require("../paths.js");
const { withSessionLock, writeFileAtomic } = require("../storage.js");

function isPlainObject(value) {
  return value != null && typeof value === "object" && !Array.isArray(value);
}

function normalizeLineNumber(value) {
  if (typeof value !== "number" || !Number.isFinite(value)) return null;
  return Math.max(1, Math.trunc(value));
}

function normalizeStringArray(value) {
  if (!Array.isArray(value)) return [];
  return value.filter((item) => typeof item === "string" && item.length > 0);
}

function optionalString(value) {
  return typeof value === "string" && value.length > 0 ? value : null;
}

function normalizeImpactedEntry(entry) {
  if (!isPlainObject(entry)) return null;
  const file = optionalString(entry.file);
  if (!file) return null;
  const lineStart =
    normalizeLineNumber(entry.line_start) ??
    normalizeLineNumber(entry.start_line) ??
    normalizeLineNumber(entry.line) ??
    1;
  const lineEndCandidate =
    normalizeLineNumber(entry.line_end) ??
    normalizeLineNumber(entry.end_line) ??
    lineStart;
  const lineEnd = Math.max(lineStart, lineEndCandidate);
  const method = optionalString(entry.method);
  const routePath = optionalString(entry.path);
  const hunkSummary =
    optionalString(entry.hunk_summary) ??
    optionalString(entry.summary) ??
    (routePath
      ? `${method ? `${method} ` : ""}${routePath} at ${file}:${lineStart}-${lineEnd}`
      : `diff hunk at ${file}:${lineStart}-${lineEnd}`);
  const normalized = {
    file,
    line_start: lineStart,
    line_end: lineEnd,
    surface_ids: normalizeStringArray(entry.surface_ids),
    hunk_summary: hunkSummary,
  };
  for (const key of ["framework", "method", "path", "handler_hint", "edge_kind"]) {
    const value = optionalString(entry[key]);
    if (value) normalized[key] = value;
  }
  return normalized;
}

function normalizeImpactedEntries(entries) {
  if (!Array.isArray(entries)) return [];
  return entries.map(normalizeImpactedEntry).filter(Boolean);
}

function collectSurfaceIds(entries) {
  const surfaceIds = new Set();
  for (const entry of entries) {
    for (const surfaceId of entry.surface_ids) {
      surfaceIds.add(surfaceId);
    }
  }
  return Array.from(surfaceIds).sort();
}

function summarizeDiffImpactHandler(args) {
  const domain = assertSafeDomain(args.target_domain);
  let diffFiles = args.diff_files;
  let parseSummary = null;
  if (typeof args.unified_diff === "string" && args.unified_diff.length > 0) {
    parseSummary = parseUnifiedDiff(args.unified_diff);
    diffFiles = parseSummary.diff_files;
  }
  // Support diff_text alias used by the SKILL.md orchestrator agent.
  if (!Array.isArray(diffFiles) && typeof args.diff_text === "string" && args.diff_text.length > 0) {
    parseSummary = parseUnifiedDiff(args.diff_text);
    diffFiles = parseSummary.diff_files;
  }
  if (!Array.isArray(diffFiles)) {
    throw new TypeError("diff_files must be an array, or unified_diff/diff_text must be supplied");
  }
  const result = summarizeImpactedSurfacesForDiff({
    target_domain: domain,
    diff_files: diffFiles,
  });
  const impactedEntries = normalizeImpactedEntries(result.impacted_entries);
  const impactedSurfaceIds = collectSurfaceIds(impactedEntries);

  // Build and persist diff-impact.json to the session directory via MCP
  // (satisfies criterion 4: diff-impact.json written to session dir via MCP).
  return withSessionLock(domain, () => {
    const artifact = {
      schema_version: 1,
      target_domain: domain,
      path_used: result.path_used,
      entry_count: impactedEntries.length,
      impacted_entries: impactedEntries,
      written_at: new Date().toISOString(),
    };
    const dir = sessionDir(domain);
    fs.mkdirSync(dir, { recursive: true });
    writeFileAtomic(diffImpactPath(domain), `${JSON.stringify(artifact, null, 2)}\n`);

    return {
      schema_version: 1,
      target_domain: domain,
      parse_summary: parseSummary,
      path_used: result.path_used,
      impacted_surface_ids: impactedSurfaceIds,
      impacted_entries: impactedEntries,
      scanned_files: result.scanned_files,
    };
  });
}

module.exports = Object.freeze({
  name: "bob_summarize_diff_impact",
  aliases: ["bounty_summarize_diff_impact"],
  description:
    "Given a unified diff (or pre-parsed diff_files) and a target's symbol-surface-index, return the surface IDs the diff touches. Pass unified_diff to let the tool parse + intersect in one call, or pass diff_files: [{file, line_ranges?}] when you've already parsed elsewhere. The orchestrator can feed the returned impacted_surface_ids into bob_start_wave for a focused diff-aware regression evaluate.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
      unified_diff: {
        type: "string",
        description: "Raw unified diff text (e.g. output of `git diff <base>..<head>` or a webhook payload).",
      },
      diff_text: {
        type: "string",
        description: "Alias for unified_diff used by the bob-diff-review skill orchestrator.",
      },
      diff_files: {
        type: "array",
        description: "Pre-parsed [{file, line_ranges?}] entries; supplied when the caller has already parsed the diff. line_ranges defaults to whole-file when omitted.",
      },
    },
    required: ["target_domain"],
  },
  handler: summarizeDiffImpactHandler,
  role_bundles: ["orchestrator"],
  mutating: true,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: ["diff-impact.json"],
});
