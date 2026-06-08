"use strict";

const {
  DIFFERENTIAL_CONTROL_KINDS,
  DIFFERENTIAL_VERDICTS,
  writeEvidencePacks,
} = require("../evidence.js");
const { wrapWriteTool } = require("./_write-base.js");

module.exports = wrapWriteTool({
  name: "bob_write_evidence_packs",
  aliases: ["bounty_write_evidence_packs"],
  description:
    "Write bounded evidence packs for every final reportable finding to authoritative JSON plus a markdown mirror.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
      packs: {
        type: "array",
        items: {
          type: "object",
          properties: {
            finding_id: { type: "string", pattern: "^F-[1-9][0-9]*$" },
            sample_type: { type: "string" },
            sample_count: { type: "number", minimum: 0, maximum: 1000 },
            aggregate_counts: {
              type: "object",
              additionalProperties: { type: "number", minimum: 0 },
            },
            representative_samples: {
              type: "array",
              maxItems: 10,
              items: {
                type: "object",
                additionalProperties: true,
              },
            },
            sensitive_clusters: {
              type: "array",
              maxItems: 20,
              items: {
                oneOf: [
                  { type: "string" },
                  { type: "object", additionalProperties: true },
                ],
              },
            },
            replay_summary: { type: "string" },
            redaction_notes: { type: ["string", "null"] },
            report_snippet: { type: "string" },
            differential: {
              type: "object",
              properties: {
                control_kind: { type: "string", enum: DIFFERENTIAL_CONTROL_KINDS },
                vuln_run_id: { type: "string" },
                control_run_id: { type: "string" },
                control_ref: { type: "string" },
                vuln_fired: { type: "boolean" },
                control_fired: { type: "boolean" },
                verdict: { type: "string", enum: DIFFERENTIAL_VERDICTS },
                control_summary: { type: "string" },
              },
              required: [
                "control_kind",
                "vuln_run_id",
                "control_run_id",
                "control_ref",
                "vuln_fired",
                "control_fired",
                "verdict",
                "control_summary",
              ],
              additionalProperties: false,
              description: "Optional C10 patched-vs-unpatched differential proof. Run IDs must resolve to live non-dry-run --network none bob_repo_docker_run rows with matching replay_command_hash; fired booleans are caller-interpreted while Bob binds exit codes, stdout hashes, and self_patch diffs by sha256.",
            },
          },
          required: [
            "finding_id",
            "sample_type",
            "sample_count",
            "aggregate_counts",
            "representative_samples",
            "sensitive_clusters",
            "replay_summary",
            "redaction_notes",
            "report_snippet",
          ],
        },
      },
    },
    required: ["target_domain", "packs"],
  },
  handler: writeEvidencePacks,
  role_bundles: ["evidence"],
  mutating: true,
  global_preapproval: true,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: ["evidence-packs.json", "evidence-packs.md", "verification-manifest.json"],
});
