"use strict";

const { ingestSarif } = require("../sarif-ingest.js");

module.exports = Object.freeze({
  name: "bob_ingest_sarif",
  description:
    "Ingest already-captured SARIF from a completed repo docker run stdout or a /work SARIF artifact. " +
    "Normalizes redacted, content-addressed lead seeds into static-analysis-results.jsonl, indexes them, " +
    "and records unverified static-analysis surface leads; never runs docker, " +
    "never returns raw SARIF, and never records findings or suppresses hunting.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: {
        type: "string",
        description: "Repo session target_domain derived by bob_init_repo_session.",
      },
      run_id: {
        type: "string",
        description: "Completed bob_repo_docker_run id; reads <session>/repo-runs/<run_id>.stdout.",
      },
      artifact_path: {
        type: "string",
        description: "SARIF path under the session /work mount, e.g. /work/trivy.sarif.",
      },
      tool_name: {
        type: "string",
        description: "Optional scanner name override when the SARIF driver name is absent or intentionally normalized.",
      },
    },
    required: ["target_domain"],
  },
  handler: ingestSarif,
  role_bundles: ["evaluator-shared", "orchestrator"],
  mutating: true,
  global_preapproval: true,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: [
    "static-analysis-results.jsonl",
    "static-analysis-index.jsonl",
    "surface-leads.json",
    "frontier-events.jsonl",
  ],
  ingestSarif,
});
