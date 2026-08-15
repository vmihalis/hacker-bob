"use strict";

const {
  runPathCompositionExperiment,
} = require("../core/differential/composition-experiment-harness.js");

module.exports = Object.freeze({
  name: "bob_run_path_composition_experiment",
  description:
    "Run an evidence-bound path-composition experiment. Confirms a composed cross-surface path only when every ordered leaf binds to a replayable frontier event (frontier_event:<event_id>); a path with any unbound leaf is refused (result: \"fail\") with the offending leaves reported. Appends the outcome to the capped composition-results.jsonl ledger.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
      path: {
        type: "array",
        minItems: 1,
        description:
          "Ordered list of leaf edges. Each leaf must carry an evidence_ref of the form frontier_event:<event_id> bound to a real frontier observation.",
        items: {
          type: "object",
          properties: {
            evidence_ref: { type: "string" },
            edge_id: { type: "string" },
          },
          required: ["evidence_ref"],
        },
      },
    },
    required: ["target_domain", "path"],
  },
  handler: ({ target_domain, path } = {}) =>
    runPathCompositionExperiment(target_domain, { path }),
  role_bundles: ["orchestrator"],
  mutating: true,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: ["composition-results.jsonl"],
});
