"use strict";

const fs = require("fs");
const { parseUnifiedDiff } = require("../unified-diff-parser.js");
const { summarizeImpactedSurfacesForDiff, readSymbolSurfaceIndex } = require("../symbol-surface-index.js");
const { assertSafeDomain, diffImpactPath, sessionDir } = require("../paths.js");

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

  // Determine path_used from symbol index presence.
  const index = readSymbolSurfaceIndex(domain);
  const pathUsed = index ? "A" : "B";

  // Build and persist diff-impact.json to the session directory via MCP
  // (satisfies criterion 4: diff-impact.json written to session dir via MCP).
  const artifact = {
    schema_version: 1,
    target_domain: domain,
    path_used: pathUsed,
    entry_count: result.impacted_entries.length,
    impacted_entries: result.impacted_entries,
    written_at: new Date().toISOString(),
  };
  const dir = sessionDir(domain);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(diffImpactPath(domain), `${JSON.stringify(artifact, null, 2)}\n`, "utf8");

  return {
    schema_version: 1,
    target_domain: domain,
    parse_summary: parseSummary,
    impacted_surface_ids: result.impacted_surface_ids,
    impacted_entries: result.impacted_entries,
    scanned_files: result.scanned_files,
  };
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
